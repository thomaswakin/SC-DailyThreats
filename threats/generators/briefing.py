"""Build a DailyBriefing from items stored in the repository."""

from __future__ import annotations
import json
import logging
from datetime import date, datetime, timezone, timedelta

from threats.models import EnrichedIntelItem, DailyBriefing
from threats.models.briefing import IncidentCluster
from threats.models.threat_actor import ThreatActor
from threats.models.ioc import IOC, IOCType
from threats.models.ttp import TTP
from threats.storage import Repository
from threats.processors.ioc_extractor import _load_fp_config, _is_context_dependent_domain

log = logging.getLogger(__name__)


def build_briefing(
    repo: Repository,
    briefing_date: date | None = None,
    executive_summary: str = "",
    since: datetime | None = None,
) -> DailyBriefing:
    """
    Query the repository and assemble a DailyBriefing for the period since `since`.

    Intel items: only those fetched after `since`.
    IOCs/TTPs: split into NEW (first seen after `since`) vs RE-OBSERVED (seen before, active again).
    Actors: split into NEW vs RETURNING.
    If `since` is None, defaults to midnight of briefing_date (backward-compatible).
    """
    if briefing_date is None:
        briefing_date = date.today()

    if since is None:
        since = datetime.combine(briefing_date, datetime.min.time()).replace(tzinfo=timezone.utc)

    # ── New intel items fetched today ─────────────────────────────────────────
    raw_items = repo.get_items_since(since)
    items = [_row_to_item(r, repo) for r in raw_items]
    log.info("Building briefing for %s: %d new items", briefing_date, len(items))

    # ── IOCs: new vs re-observed ──────────────────────────────────────────────
    new_iocs = [_row_to_ioc(r) for r in repo.get_new_iocs_since(since)]
    reobserved_iocs = [_row_to_ioc(r) for r in repo.get_reobserved_iocs_since(since)]
    _flag_likely_fps(new_iocs + reobserved_iocs, items)
    fp_count = sum(1 for i in new_iocs + reobserved_iocs if i.likely_fp)
    log.info("IOCs: %d new, %d re-observed (%d likely FP)", len(new_iocs), len(reobserved_iocs), fp_count)

    # ── TTPs: new vs re-observed ──────────────────────────────────────────────
    new_ttps = [_row_to_ttp(r) for r in repo.get_new_ttps_since(since)]
    reobserved_ttps = [_row_to_ttp(r) for r in repo.get_reobserved_ttps_since(since)]
    log.info("TTPs: %d new, %d re-observed", len(new_ttps), len(reobserved_ttps))

    # ── Actors ────────────────────────────────────────────────────────────────
    new_actors = [_row_to_actor(r) for r in repo.get_new_actors_since(since)]
    returning_actors = [_row_to_actor(r) for r in repo.get_returning_actors_since(since)]

    # ── Incident clusters ─────────────────────────────────────────────────────
    cluster_rows = repo.get_clusters_since(since)
    clusters = [_row_to_cluster(cr, repo) for cr in cluster_rows]
    log.info(
        "Clusters: %d total (%d multi-source, %d singleton)",
        len(clusters),
        sum(1 for c in clusters if c.is_multi_source),
        sum(1 for c in clusters if not c.is_multi_source),
    )

    briefing = DailyBriefing(
        briefing_date=briefing_date,
        generated_at=datetime.now(timezone.utc),
        clusters=clusters,
        items=items,
        new_iocs=new_iocs,
        reobserved_iocs=reobserved_iocs,
        new_ttps=new_ttps,
        reobserved_ttps=reobserved_ttps,
        new_actors=new_actors,
        returning_actors=returning_actors,
        executive_summary=executive_summary,
    )
    briefing.compute_ioc_counts()
    return briefing


def _row_to_item(row: dict, repo: Repository) -> EnrichedIntelItem:
    item = EnrichedIntelItem(
        source_name=row["source_name"],
        source_url=row["source_url"],
        title=row["title"],
        body=row.get("body", ""),
        summary=row.get("summary", ""),
        severity=row.get("severity", 0.0),
        confidence=row.get("confidence", 0.5),
        llm_enriched=bool(row.get("llm_enriched", 0)),
        targeted_sectors=json.loads(row.get("targeted_sectors") or "[]"),
        targeted_regions=json.loads(row.get("targeted_regions") or "[]"),
        detection_artifacts=json.loads(row.get("detection_artifacts") or "[]"),
    )
    # Attach IOCs from junction table
    ioc_rows = repo.conn.execute(
        "SELECT i.* FROM iocs i JOIN item_iocs ii ON i.id=ii.ioc_id "
        "WHERE ii.item_id=(SELECT id FROM intel_items WHERE content_hash=?)",
        (row["content_hash"],),
    ).fetchall()
    item.iocs = [_row_to_ioc(dict(r)) for r in ioc_rows]

    # Attach TTPs
    ttp_rows = repo.conn.execute(
        "SELECT t.* FROM ttps t JOIN item_ttps it ON t.id=it.ttp_id "
        "WHERE it.item_id=(SELECT id FROM intel_items WHERE content_hash=?)",
        (row["content_hash"],),
    ).fetchall()
    item.ttps = [_row_to_ttp(dict(r)) for r in ttp_rows]

    return item


def _row_to_ioc(row: dict) -> IOC:
    from datetime import datetime
    return IOC(
        type=IOCType(row["type"]),
        value=row["value"],
        confidence=row.get("confidence", 0.5),
        first_seen=datetime.fromisoformat(row["first_seen"]),
        last_seen=datetime.fromisoformat(row["last_seen"]),
        source_count=row.get("source_count", 1) or 1,
        specificity=row.get("specificity") or "unknown",
        specificity_note=row.get("specificity_note") or "",
        tags=json.loads(row.get("tags") or "[]"),
    )


def _row_to_ttp(row: dict) -> TTP:
    from threats.models.ttp import MITRETactic
    tactic = None
    if row.get("tactic"):
        try:
            tactic = MITRETactic(row["tactic"])
        except ValueError:
            pass
    return TTP(technique_id=row["technique_id"], tactic=tactic, name=row.get("name", ""))


def _flag_likely_fps(iocs: list[IOC], items: list[EnrichedIntelItem]) -> None:
    """
    Flag IOCs that are likely false positives or context-dependent based on heuristics:
    - likely_fp=True: domain/IP is a known-good value that should be suppressed entirely
    - context_dependent=True: FP-prone in isolation; only useful correlated with other indicators
    Mutates iocs in-place.
    """
    fp_domains, fp_ips, fp_suffixes, _, _ = _load_fp_config()

    # Build map: ioc value → source URLs it appeared in
    ioc_sources: dict[str, list[str]] = {}
    for item in items:
        for ioc in item.iocs:
            ioc_sources.setdefault(ioc.value.lower(), []).append(item.source_url.lower())

    for ioc in iocs:
        val = ioc.value.lower()

        # Already filtered at extraction — this catches any that slipped in via DB
        if ioc.type == IOCType.DOMAIN:
            if val in fp_domains or any(val.endswith(s) for s in fp_suffixes):
                ioc.likely_fp = True
                continue
            # Re-apply context_dependent flag for IOCs read back from DB (where it wasn't stored)
            if not ioc.context_dependent:
                ioc.context_dependent = _is_context_dependent_domain(val)
        elif ioc.type == IOCType.IP:
            if val in fp_ips:
                ioc.likely_fp = True
                continue

        # Heuristic: domain value appears as part of the article's own source URL
        # (e.g. "snort.org" in an article from talosintelligence.com about Snort)
        if ioc.type == IOCType.DOMAIN:
            sources = ioc_sources.get(val, [])
            for src_url in sources:
                # If the IOC domain is referenced in a source URL from a known-good vendor
                if any(src_url.startswith(f"https://{vendor}") or f"/{vendor}" in src_url
                       for vendor in ["blog.talosintelligence.com", "talosintelligence.com",
                                      "unit42.paloaltonetworks.com", "crowdstrike.com",
                                      "sentinelone.com", "welivesecurity.com", "mandiant.com",
                                      "recordedfuture.com", "redcanary.com", "lumen.com",
                                      "blog.lumen.com", "huntress.com", "wiz.io", "sysdig.com",
                                      "nccgroup.com", "sekoia.io", "microsoft.com", "elastic.co"]):
                    ioc.likely_fp = True
                    break


def _row_to_cluster(cr: dict, repo: Repository) -> IncidentCluster:
    items = [_row_to_item(r, repo) for r in cr.get("items", [])]
    iocs = [_row_to_ioc(r) for r in cr.get("iocs", [])]
    ttps = [_row_to_ttp(r) for r in cr.get("ttps", [])]
    sources = list({i.source_name for i in items})
    return IncidentCluster(
        cluster_id=cr["id"],
        name=cr.get("name", ""),
        source_count=cr.get("source_count", len(sources)),
        sources=sources,
        items=items,
        iocs=iocs,
        ttps=ttps,
        first_seen=datetime.fromisoformat(cr["first_seen"]),
        last_seen=datetime.fromisoformat(cr["last_seen"]),
    )


def _row_to_actor(row: dict) -> ThreatActor:
    from datetime import datetime
    return ThreatActor(
        name=row["name"],
        aliases=json.loads(row.get("aliases") or "[]"),
        description=row.get("description", ""),
        motivation=row.get("motivation", ""),
        confidence=row.get("confidence", 0.5),
        first_seen=datetime.fromisoformat(row["first_seen"]),
        last_seen=datetime.fromisoformat(row["last_seen"]),
    )
