"""Generate Sigma detection rules from LLM artifacts and composite IOC patterns."""

from __future__ import annotations
import logging
import re
import uuid
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from threats.models import DailyBriefing, EnrichedIntelItem
from threats.models.briefing import SigmaRule
from threats.models.ioc import IOC, IOCType
from threats.processors.ioc_extractor import _load_fp_config
from threats.storage import Repository

log = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parents[2] / "config" / "sigma_templates"

# Minimum item severity to generate a composite IOC rule
_MIN_SEVERITY_FOR_COMPOSITE = 0.5
# Minimum number of context-dependent IOCs to form a composite rule
_MIN_COMPOSITE_IOC_COUNT = 2
_HASH_TYPES = {IOCType.MD5, IOCType.SHA1, IOCType.SHA256}


def generate_sigma_rules(
    briefing: DailyBriefing,
    output_dir: Path,
    repo: Repository | None = None,
) -> list[SigmaRule]:
    """
    Generate Sigma rules in two passes — behavioral only.

    Pass 1 — LLM artifact rules (behavioral, high fidelity):
      One rule per technique+logsource combination where the LLM extracted
      concrete detection artifacts (process names, command lines, file paths, etc.).
      Versioned: if the same technique+logsource+cluster was seen before, the rule
      is updated with incremented version rather than recreated.

    Pass 2 — Composite IOC rules (context-dependent bundles):
      When 2+ context-dependent IOCs (Tor, Discord, AnyDesk, etc.) appear in the
      same campaign item, generate a single DNS/network rule listing them all.
      These are meaningfully higher-fidelity than any single context-dependent IOC.

    Single high-fidelity IOCs (hashes, dedicated IPs/domains) go to the IOC export,
    not to Sigma rules.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    env = _build_jinja_env()
    rules: list[SigmaRule] = []
    date_str = briefing.briefing_date.strftime("%Y/%m/%d")
    slug_date = briefing.briefing_date.strftime("%Y-%m-%d")

    # Build a cluster_id lookup: item content_hash → cluster_id + source_count
    item_cluster: dict[str, tuple[int, int]] = {}  # hash → (cluster_id, source_count)
    for cluster in briefing.clusters:
        for item in cluster.items:
            item_cluster[item.content_hash] = (cluster.cluster_id, cluster.source_count)

    # ── Pass 1: Artifact-based behavioral rules ───────────────────────────────
    seen_rule_keys: set[str] = set()

    for item in briefing.items:
        cluster_id, source_count = item_cluster.get(item.content_hash, (None, 1))

        for artifact in item.detection_artifacts:
            if not isinstance(artifact, dict):
                continue
            technique_id = artifact.get("technique_id", "unknown").upper()
            logsource_cat = artifact.get("logsource_category", "process_creation")

            # Stable key: ties rule identity to cluster (or item) + technique + logsource
            cluster_tag = f"c{cluster_id}" if cluster_id else f"i{item.content_hash[:12]}"
            stable_key = f"beh:{technique_id}:{logsource_cat}:{cluster_tag}"

            # Check for existing version in registry
            existing = repo.get_rule_version(stable_key) if repo else None
            if existing:
                # Rule already exists — check if this item brings new artifacts
                # If the rule_key was already processed in THIS run, skip
                if stable_key in seen_rule_keys:
                    continue
                # Otherwise update: re-render with same rule_id, bump version
            else:
                if stable_key in seen_rule_keys:
                    continue

            seen_rule_keys.add(stable_key)

            try:
                rule_id = existing["rule_id"] if existing else str(uuid.uuid4())
                rule = _render_artifact_rule(
                    env, artifact, item, date_str, slug_date,
                    rule_id=rule_id,
                    source_count=source_count,
                    stable_key=stable_key,
                )
                if rule:
                    slug = re.sub(r"[^a-z0-9]", "-", f"{technique_id}-{logsource_cat}".lower())
                    filename = f"{slug_date}-{slug}.yaml"
                    _write_rule(rule, output_dir, filename)

                    if repo:
                        version = repo.upsert_rule_version(
                            stable_key=stable_key,
                            rule_id=rule.rule_id,
                            title=rule.title,
                            source_count=source_count,
                            cluster_id=cluster_id,
                            output_path=rule.output_path,
                        )
                        rule.version = version
                        rule.modified = date_str if version > 1 else ""
                        rule.source_count = source_count
                        # Re-write the file with updated version metadata
                        _write_rule(rule, output_dir, filename)

                    rules.append(rule)
            except Exception as exc:
                log.warning("Artifact rule failed for %s: %s", technique_id, exc)

    # ── Pass 2: Composite context-dependent IOC rules ─────────────────────────
    new_ioc_set = {f"{i.type.value}:{i.value.lower()}" for i in briefing.new_iocs}

    for item in briefing.items:
        if item.severity < _MIN_SEVERITY_FOR_COMPOSITE:
            continue
        if not item.iocs:
            continue

        cluster_id, source_count = item_cluster.get(item.content_hash, (None, 1))

        # Collect context-dependent IOCs that are new this run and not likely FP
        ctx_domains = [
            i for i in item.iocs
            if i.type == IOCType.DOMAIN
            and i.context_dependent
            and not i.likely_fp
            and f"{i.type.value}:{i.value.lower()}" in new_ioc_set
        ]

        if len(ctx_domains) < _MIN_COMPOSITE_IOC_COUNT:
            continue

        cluster_tag = f"c{cluster_id}" if cluster_id else f"i{item.content_hash[:12]}"
        stable_key = f"comp-ioc:{cluster_tag}"

        if stable_key in seen_rule_keys:
            continue
        seen_rule_keys.add(stable_key)

        existing = repo.get_rule_version(stable_key) if repo else None

        try:
            rule_id = existing["rule_id"] if existing else str(uuid.uuid4())
            level = _level_from_severity(item.severity, source_count)
            mitre_tags, mitre_urls = _tags_from_item(item)

            rule = _render_composite_ioc_rule(
                env, ctx_domains, item, date_str, slug_date,
                rule_id=rule_id,
                level=level,
                mitre_tags=mitre_tags,
                mitre_urls=mitre_urls,
                source_count=source_count,
                stable_key=stable_key,
            )
            if rule:
                item_slug = re.sub(r"[^a-z0-9]", "-", item.title[:40].lower()).strip("-")
                filename = f"{slug_date}-composite-ioc-{item_slug}.yaml"
                _write_rule(rule, output_dir, filename)

                if repo:
                    version = repo.upsert_rule_version(
                        stable_key=stable_key,
                        rule_id=rule.rule_id,
                        title=rule.title,
                        source_count=source_count,
                        cluster_id=cluster_id,
                        output_path=rule.output_path,
                    )
                    rule.version = version
                    rule.modified = date_str if version > 1 else ""
                    rule.source_count = source_count
                    _write_rule(rule, output_dir, filename)

                rules.append(rule)
        except Exception as exc:
            log.warning("Composite IOC rule failed for '%s': %s", item.title[:40], exc)

    log.info("Generated %d Sigma rules in %s", len(rules), output_dir)
    briefing.sigma_rules = rules
    return rules


def _render_artifact_rule(
    env: Environment,
    artifact: dict,
    item: EnrichedIntelItem,
    date_str: str,
    slug_date: str,
    rule_id: str,
    source_count: int = 1,
    stable_key: str = "",
) -> SigmaRule | None:
    # Scrub FP-prone IOC fields based on behavioral strength before rendering
    artifact = _scrub_fp_iocs_from_artifact(artifact)
    if artifact is None:
        return None

    technique_id     = artifact.get("technique_id", "unknown").upper()
    logsource_cat    = artifact.get("logsource_category", "process_creation")
    logsource_product = artifact.get("logsource_product", "")

    process_name     = artifact.get("process_name")   or []
    command_line     = artifact.get("command_line")    or []
    file_path        = artifact.get("file_path")       or []
    registry_key     = artifact.get("registry_key")    or []
    network_dst_ip   = artifact.get("network_dst_ip")  or []
    network_dst_port = [str(p) for p in (artifact.get("network_dst_port") or [])]
    dns_query        = artifact.get("dns_query")       or []
    parent_process   = artifact.get("parent_process")  or []
    event_id         = [str(e) for e in (artifact.get("event_id") or [])]

    _required = {
        "process_creation":   process_name or command_line,
        "file_event":         file_path,
        "registry_event":     registry_key,
        "network_connection": network_dst_ip or network_dst_port,
        "firewall":           network_dst_ip or network_dst_port,
        "dns_query":          dns_query,
    }
    if not _required.get(logsource_cat, process_name or command_line or file_path):
        return None

    tactic_tag    = _tactic_for_technique(technique_id)
    technique_tag = technique_id.lower().replace(".", "_")
    level         = _level_from_severity(item.severity, source_count)
    title = (
        artifact.get("title")
        or f"{technique_id} - {logsource_cat.replace('_', ' ').title()}"
    )
    description = (
        artifact.get("description")
        or f"Detects {technique_id} behavior observed in threat intelligence"
    )

    context = dict(
        rule_id=rule_id, title=title, description=description,
        technique_id=technique_id, tactic_tag=tactic_tag, technique_tag=technique_tag,
        date=date_str, source_url=item.source_url, source_name=item.source_name,
        logsource_category=logsource_cat, logsource_product=logsource_product, level=level,
        process_name=process_name, command_line=command_line, file_path=file_path,
        registry_key=registry_key, network_dst_ip=network_dst_ip,
        network_dst_port=network_dst_port, dns_query=dns_query,
        parent_process=parent_process, event_id=event_id,
        source_count=source_count,
    )
    yaml_content = env.get_template("behavior_artifact.yaml.j2").render(**context)
    return SigmaRule(
        rule_id=rule_id, title=title, description=description,
        date=date_str, level=level,
        tags=[f"attack.{tactic_tag}", f"attack.{technique_tag}"],
        related_source_url=item.source_url, yaml_content=yaml_content,
        source_count=source_count, stable_key=stable_key,
    )


def _render_composite_ioc_rule(
    env: Environment,
    iocs: list[IOC],
    item: EnrichedIntelItem,
    date_str: str,
    slug_date: str,
    rule_id: str,
    level: str,
    mitre_tags: list[str],
    mitre_urls: list[str],
    source_count: int = 1,
    stable_key: str = "",
) -> SigmaRule | None:
    values = [i.value for i in iocs]
    title = f"{item.title[:55]} — Multi-Indicator Bundle"
    description = (
        f"Composite detection: {len(iocs)} context-dependent indicators observed together "
        f"in the same campaign ({item.source_name}). Each indicator is FP-prone in isolation "
        f"but their co-occurrence within a short timeframe raises confidence significantly. "
        f"Source: {item.source_name}."
    )
    context = dict(
        rule_id=rule_id, title=title, description=description,
        date=date_str, source_url=item.source_url, source_name=item.source_name,
        mitre_tags=mitre_tags, mitre_urls=mitre_urls, level=level,
        values=values, ioc_count=len(values),
        source_count=source_count,
    )
    yaml_content = env.get_template("composite_ioc.yaml.j2").render(**context)
    return SigmaRule(
        rule_id=rule_id, title=title, description=description,
        date=date_str, level=level, tags=mitre_tags,
        related_source_url=item.source_url, yaml_content=yaml_content,
        source_count=source_count, stable_key=stable_key,
    )


def _scrub_fp_iocs_from_artifact(artifact: dict) -> dict | None:
    """
    Evaluate IOC fields (dns_query, network_dst_ip) in a behavioral artifact and
    decide whether to keep, strip, or reject them based on behavioral strength.

    The guiding principle: a FP-prone IOC is only valuable in a Sigma rule when it
    is ANDed with other conditions that it meaningfully tightens. If the behavioral
    conditions are already highly specific, a FP-prone domain/IP adds suppression
    risk without improving precision. If the behavioral conditions are broad, the
    FP-prone IOC is doing real filtering work and should be kept.

    Behavioral strength:
      STRONG  — (process_name OR parent_process) AND (command_line OR file_path)
      MODERATE — any single behavioral field (process_name, cmdline, file_path,
                 registry_key) but not meeting the STRONG threshold
      NONE    — only network/DNS conditions

    Returns:
      Modified artifact dict with FP-prone IOC fields stripped (STRONG behavioral),
      unmodified artifact (MODERATE or NONE with clean IOCs),
      or None if the rule should be skipped entirely (NONE behavioral + only FP IOCs).
    """
    fp_domains, fp_ips, fp_suffixes, ctx_domains, ctx_suffixes = _load_fp_config()

    dns_queries   = list(artifact.get("dns_query")      or [])
    network_ips   = list(artifact.get("network_dst_ip") or [])

    def _is_fp_domain(d: str) -> bool:
        d = d.lower()
        return (d in fp_domains or any(d.endswith(s) for s in fp_suffixes)
                or d in ctx_domains or any(d.endswith(s) for s in ctx_suffixes))

    def _is_fp_ip(ip: str) -> bool:
        return ip in fp_ips

    fp_dns    = [d for d in dns_queries if _is_fp_domain(d)]
    fp_ips_l  = [ip for ip in network_ips if _is_fp_ip(ip)]
    clean_dns = [d for d in dns_queries  if not _is_fp_domain(d)]
    clean_ips = [ip for ip in network_ips if not _is_fp_ip(ip)]

    # Nothing FP-prone — return as-is
    if not fp_dns and not fp_ips_l:
        return artifact

    # Assess behavioral strength
    has_process  = bool(artifact.get("process_name") or artifact.get("parent_process"))
    has_cmdline  = bool(artifact.get("command_line") or artifact.get("file_path"))
    has_registry = bool(artifact.get("registry_key"))
    strong   = has_process and has_cmdline
    moderate = has_process or has_cmdline or has_registry

    result = dict(artifact)

    if strong:
        # STRONG behavioral: FP-prone IOCs add suppression risk without improving
        # precision — strip them. The behavior alone is the detection signal.
        result["dns_query"]     = clean_dns
        result["network_dst_ip"] = clean_ips
        if fp_dns or fp_ips_l:
            log.debug(
                "Stripped FP-prone IOCs %s from strong behavioral rule [%s]",
                fp_dns + fp_ips_l, artifact.get("technique_id"),
            )

    elif moderate:
        # MODERATE behavioral: FP-prone IOC tightens an otherwise broad rule.
        # Keep the FP-prone IOC — this is the AND-anchoring case the user described.
        # Only strip if clean alternatives exist (don't drop all IOC diversity).
        if clean_dns or clean_ips:
            # Clean IOCs exist — prefer them, drop FP-prone ones
            result["dns_query"]      = clean_dns
            result["network_dst_ip"] = clean_ips
        # else: only FP-prone IOCs exist — keep them, they're doing real work here

    else:
        # NO behavioral conditions — pure IOC rule
        # Keep only clean IOCs; if nothing clean remains, skip the rule
        result["dns_query"]      = clean_dns
        result["network_dst_ip"] = clean_ips
        logsource = artifact.get("logsource_category", "")
        if logsource in ("dns_query", "firewall", "network_connection"):
            if not clean_dns and not clean_ips and not artifact.get("network_dst_port"):
                log.debug(
                    "Skipping pure-IOC rule [%s] — all IOCs are FP-prone",
                    artifact.get("technique_id"),
                )
                return None

    return result


def _tags_from_item(item: EnrichedIntelItem) -> tuple[list[str], list[str]]:
    tags, urls = [], []
    seen: set[str] = set()
    for ttp in item.ttps[:5]:
        tactic = _tactic_for_technique(ttp.technique_id)
        tactic_tag = f"attack.{tactic}"
        tech_tag = f"attack.{ttp.technique_id.lower().replace('.', '_')}"
        if tactic_tag not in seen:
            tags.append(tactic_tag)
            seen.add(tactic_tag)
        if tech_tag not in seen:
            tags.append(tech_tag)
            seen.add(tech_tag)
        urls.append(
            f"https://attack.mitre.org/techniques/{ttp.technique_id.replace('.', '/')}/"
        )
    return tags, urls


def _level_from_severity(severity: float, source_count: int = 1) -> str:
    """Compute Sigma level, boosting one step up for multi-source detections."""
    if severity >= 0.8:
        base = "high"
    elif severity >= 0.6:
        base = "medium"
    else:
        base = "low"
    if source_count >= 2:
        return {"low": "medium", "medium": "high", "high": "high"}[base]
    return base


_TACTIC_MAP = {
    "T1059": "execution",       "T1053": "persistence",     "T1547": "persistence",
    "T1055": "defense_evasion", "T1027": "defense_evasion", "T1036": "defense_evasion",
    "T1070": "defense_evasion", "T1112": "defense_evasion", "T1574": "defense_evasion",
    "T1110": "credential_access","T1003": "credential_access","T1550": "credential_access",
    "T1071": "command_and_control","T1090": "command_and_control","T1572": "command_and_control",
    "T1083": "discovery",       "T1082": "discovery",       "T1016": "discovery",
    "T1105": "command_and_control","T1041": "exfiltration",
    "T1486": "impact",          "T1498": "impact",          "T1490": "impact",
    "T1566": "initial_access",  "T1195": "initial_access",  "T1190": "initial_access",
    "T1133": "initial_access",  "T1595": "reconnaissance",  "T1068": "privilege_escalation",
    "T1203": "execution",       "T1210": "lateral_movement","T1218": "defense_evasion",
    "T1485": "impact",          "T1505": "persistence",     "T1552": "credential_access",
    "T1219": "command_and_control",
}


def _tactic_for_technique(technique_id: str) -> str:
    return _TACTIC_MAP.get(technique_id.split(".")[0], "unknown")


def _build_jinja_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape([]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _write_rule(rule: SigmaRule, output_dir: Path, filename: str) -> None:
    path = output_dir / filename
    path.write_text(rule.yaml_content)
    rule.output_path = str(path)
