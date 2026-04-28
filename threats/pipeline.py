"""Full pipeline orchestration: collect → process → store → generate → render."""

from __future__ import annotations
import logging
import os
from datetime import date, datetime, timezone, timedelta
from pathlib import Path

import yaml
from dotenv import load_dotenv

load_dotenv()

from threats.collectors import load_collectors
from threats.processors import run_pipeline
from threats.processors.llm_analyzer import LLMAnalyzer
from threats.processors.clusterer import run_clustering
from threats.storage import Database, Repository
from threats.generators import build_briefing, generate_sigma_rules, render_briefing, generate_ioc_export
from threats.generators.emailer import send_briefing_email, send_no_data_email
from threats.processors.sigma_reviewer import SigmaReviewer
from threats.processors.ioc_validator import IOCValidator
from threats.processors.ioc_researcher import IOCResearcher
from threats.collectors.source_discovery import SourceDiscovery
from threats.utils.logging import setup_logging

log = logging.getLogger(__name__)


def _load_settings(settings_path: str = "config/settings.yaml") -> dict:
    with open(settings_path) as f:
        return yaml.safe_load(f)


def run_pipeline_full(
    briefing_date: date | None = None,
    settings_path: str = "config/settings.yaml",
    feeds_path: str = "config/feeds.yaml",
    db_path: str | None = None,
    briefings_dir: str | None = None,
    sigma_dir: str | None = None,
) -> dict:
    """
    Run the complete threat intel pipeline.
    Returns stats dict: {collected, stored, iocs, sigma, briefing_path}.
    """
    cfg = _load_settings(settings_path)
    log_cfg = cfg.get("logging", {})
    setup_logging(
        level=os.getenv("LOG_LEVEL", log_cfg.get("level", "INFO")),
        log_file=log_cfg.get("log_file", "logs/threats.log"),
    )

    if briefing_date is None:
        briefing_date = date.today()

    db_path = db_path or cfg["storage"]["db_path"]
    briefings_dir = briefings_dir or cfg["output"]["briefings_dir"]
    sigma_dir = sigma_dir or cfg["output"]["sigma_dir"]

    log.info("=== Daily Threat Intel Pipeline | %s ===", briefing_date)

    db = Database(db_path)
    db.connect()
    repo = Repository(db)

    run_id = repo.start_run(briefing_date.isoformat())
    stats: dict = {"collected": 0, "stored": 0, "iocs": 0, "sigma": 0}
    llm_warning: str = ""

    def _is_credit_error(exc: Exception) -> bool:
        return "credit balance is too low" in str(exc).lower()

    try:
        # ── Build LLM client (shared across all AI steps) ─────────────────────
        llm_cfg = cfg.get("llm", {})
        llm: LLMAnalyzer | None = None
        if not llm_cfg.get("disabled") and os.getenv("ANTHROPIC_API_KEY"):
            llm = LLMAnalyzer(
                model=llm_cfg.get("model", "claude-opus-4-6"),
                rpm_limit=llm_cfg.get("rpm_limit", 40),
                max_body_chars=llm_cfg.get("max_body_chars", 4000),
            )
        elif not os.getenv("ANTHROPIC_API_KEY"):
            log.warning("ANTHROPIC_API_KEY not set — skipping LLM enrichment")

        # ── 0. Source discovery (curated lists + citation mining) ────────────
        if llm:
            try:
                discovery = SourceDiscovery(
                    repo=repo,
                    feeds_path=feeds_path,
                    llm_client=llm._client,
                    model=llm.model,
                    limiter=llm._limiter,
                )
                new_sources = discovery.run()
                if new_sources:
                    log.info("Source discovery added %d new feed(s) — included this run", new_sources)
            except Exception as exc:
                log.warning("Source discovery step failed (continuing): %s", exc)
        else:
            log.debug("Source discovery skipped (LLM disabled or no API key)")

        # ── 1. Determine "since" window from last successful run ───────────────
        now = datetime.now(timezone.utc)
        last_run_at = repo.get_last_successful_run_at()

        if last_run_at:
            hours_since = (now - last_run_at).total_seconds() / 3600
            # Add 10% buffer so we never miss articles published right at the boundary
            lookback_hours = max(int(hours_since * 1.1) + 1, 6)
            since = last_run_at
            log.info(
                "Last successful run: %s (%.1fh ago) → lookback %dh",
                last_run_at.strftime("%Y-%m-%d %H:%M UTC"), hours_since, lookback_hours,
            )
        else:
            lookback_hours = cfg.get("pipeline", {}).get("lookback_hours", 72)
            since = now - timedelta(hours=lookback_hours)
            log.info("No prior run found → using config lookback_hours=%d", lookback_hours)

        since_label = since.strftime("%Y-%m-%d %H:%M UTC")

        # ── 1. Collect ────────────────────────────────────────────────────────
        collectors = load_collectors(feeds_path, lookback_hours=lookback_hours)
        all_raw = []
        for collector in collectors:
            items = collector.collect()
            all_raw.extend(items)
        stats["collected"] = len(all_raw)
        log.info("Collected %d raw items from %d sources", len(all_raw), len(collectors))

        # ── 2. Process ────────────────────────────────────────────────────────
        seen_hashes = repo.get_seen_hashes()
        enriched = run_pipeline(all_raw, seen_hashes, llm)
        log.info("Processed %d enriched items", len(enriched))

        # ── 2b. IOC validation pass (LLM second opinion on FP candidates) ─────
        if llm and enriched:
            try:
                validator = IOCValidator(llm._client, llm.model, llm._limiter)
                fp_flagged = validator.validate_batch(enriched)
                log.info("IOC validator flagged %d additional false positives", fp_flagged)
            except Exception as exc:
                if _is_credit_error(exc):
                    llm_warning = "Anthropic API credit balance depleted — LLM enrichment unavailable. Replenish credits at console.anthropic.com → Plans & Billing."
                log.warning("IOC validation pass failed (continuing without): %s", exc)

        # ── 2c. IOC research pass (assess attack-specificity for fidelity scoring) ──
        if llm and enriched:
            try:
                researcher = IOCResearcher(llm._client, llm.model, llm._limiter)
                assessed = researcher.research_batch(enriched)
                log.info("IOC researcher assessed %d IOCs for attack specificity", assessed)
            except Exception as exc:
                if _is_credit_error(exc):
                    llm_warning = "Anthropic API credit balance depleted — LLM enrichment unavailable. Replenish credits at console.anthropic.com → Plans & Billing."
                log.warning("IOC research pass failed (continuing without): %s", exc)

        # ── 3. Store ──────────────────────────────────────────────────────────
        stored = repo.store_enriched_batch(enriched)
        stats["stored"] = stored
        stats["iocs"] = sum(len(i.iocs) for i in enriched)
        log.info("Stored %d new items, %d IOCs", stored, stats["iocs"])

        # ── 3b. Cluster related items ─────────────────────────────────────────
        n_clusters = run_clustering(repo)
        log.info("Clustering complete: %d clusters", n_clusters)

        # ── 4. Build Briefing ─────────────────────────────────────────────────
        exec_summary = ""
        if llm and enriched:
            try:
                exec_summary = llm.generate_executive_summary(enriched)
            except Exception as exc:
                if _is_credit_error(exc):
                    llm_warning = "Anthropic API credit balance depleted — LLM enrichment unavailable. Replenish credits at console.anthropic.com → Plans & Billing."
                log.warning("Executive summary generation failed: %s", exc)

        briefing = build_briefing(repo, briefing_date, exec_summary, since=since)
        briefing.since_label = since_label
        briefing.llm_warning = llm_warning

        # ── 4b. No new data path ──────────────────────────────────────────────
        if briefing.is_empty:
            log.info("No new threat data since %s", since_label)
            if not cfg.get("email", {}).get("disabled"):
                send_no_data_email(briefing, cfg, last_run_at)
            log.info("=== Pipeline complete | no new data ===")
            return stats

        # ── 5. Generate Sigma Rules (new items only, then mark done) ─────────
        sigma_date_dir = Path(sigma_dir) / briefing_date.isoformat()
        rules = generate_sigma_rules(briefing, sigma_date_dir, repo=repo)

        # ── 5b. FP review pass — tighten rules and add expiry metadata ────────
        if llm and rules:
            try:
                reviewer = SigmaReviewer(llm._client, llm.model, llm._limiter)
                rules = reviewer.review_rules(rules, briefing.items, briefing_date)
            except Exception as exc:
                if _is_credit_error(exc):
                    llm_warning = "Anthropic API credit balance depleted — LLM enrichment unavailable. Replenish credits at console.anthropic.com → Plans & Billing."
                log.warning("Sigma FP review failed (rules kept as-is): %s", exc)

        # ── 5c. IOC export ────────────────────────────────────────────────────
        ioc_export_path = generate_ioc_export(briefing, Path(briefings_dir) / "ioc_exports")
        if ioc_export_path:
            briefing.ioc_export_path = str(ioc_export_path)
            stats["ioc_export"] = str(ioc_export_path)

        briefing.sigma_rules = rules
        stats["sigma"] = len(rules)
        marked = repo.mark_sigma_done_since(since)
        log.info("Generated %d Sigma rules; marked %d items sigma_done", len(rules), marked)

        # ── 6. Render Output ──────────────────────────────────────────────────
        formats = cfg["output"].get("formats", "md,json").split(",")
        written = render_briefing(briefing, Path(briefings_dir), formats)
        stats["briefing_path"] = str(written.get("md", ""))

        # ── 7. Email briefing ─────────────────────────────────────────────────
        if written.get("md") and not cfg.get("email", {}).get("disabled"):
            send_briefing_email(briefing, written["md"], cfg, sigma_dir=sigma_date_dir)

        log.info(
            "=== Pipeline complete | %d items | %d IOCs | %d Sigma rules ===",
            stats["stored"], stats["iocs"], stats["sigma"],
        )

    except Exception as exc:
        log.error("Pipeline error: %s", exc, exc_info=True)
        raise
    finally:
        repo.finish_run(run_id, stats)
        db.close()

    return stats
