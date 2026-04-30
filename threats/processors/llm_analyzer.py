"""LLM-based enrichment of intel items via Claude API."""

from __future__ import annotations
import json
import logging
import os
import re

import anthropic

_CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)

from threats.models import EnrichedIntelItem
from threats.models.threat_actor import ThreatActor
from threats.models.ttp import TTP, MITRETactic
from threats.utils.rate_limiter import RateLimiter

log = logging.getLogger(__name__)

_ARTIFACT_CONDITION_FIELDS = (
    "process_name", "command_line", "file_path", "registry_key",
    "network_dst_ip", "network_dst_port", "dns_query", "parent_process", "event_id",
)


def _artifact_has_conditions(artifact: dict) -> bool:
    """Return True only if the artifact has at least one non-empty detection field."""
    return any(artifact.get(f) for f in _ARTIFACT_CONDITION_FIELDS)

_SYSTEM_PROMPT = """\
You are a senior threat intelligence analyst and Sigma rule author. Extract structured \
data from the provided security blog post or advisory text.

Return ONLY a single valid JSON object — no markdown, no explanation, no commentary \
outside the JSON. Use this exact schema:

{
  "threat_actors": [
    {"name": "string", "aliases": ["string"], "confidence": 0.0}
  ],
  "summary": "string (2-3 sentences, analyst voice, plain text)",
  "severity": 0.0,
  "new_ttps": ["T1234.001"],
  "targeted_sectors": ["string"],
  "targeted_regions": ["string"],
  "motivation": "string (espionage|financial|hacktivism|sabotage|unknown)",
  "campaign_names": ["string"],
  "malware_families": ["string"],
  "detection_artifacts": [
    {
      "technique_id": "T1234.001",
      "title": "short descriptive title for the Sigma rule",
      "description": "what this detection catches, referencing the specific malware/campaign",
      "logsource_category": "process_creation",
      "logsource_product": "windows",
      "process_name": ["malware.exe", "loader.dll"],
      "command_line": ["-enc ", "FromBase64String", "/tmp/.hidden"],
      "file_path": ["\\AppData\\Roaming\\svchost.exe", "\\Temp\\.kadnap"],
      "registry_key": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"],
      "network_dst_ip": ["1.2.3.4"],
      "network_dst_port": [4444, 8080],
      "dns_query": ["evil.c2domain.com"],
      "parent_process": ["winword.exe", "excel.exe"],
      "event_id": []
    }
  ],
  "false_positive_iocs": ["value1", "value2"]
}

Rules:
- severity is 0.0-1.0 (0.8+ = critical, active exploitation; 0.6 = high; 0.4 = medium)
- confidence on threat_actors is 0.0-1.0 (only >0.7 if name is explicitly stated)
- new_ttps are MITRE ATT&CK technique IDs only (Txxxx or Txxxx.xxx format)
- Use empty arrays [] when data is absent — never null
- targeted_sectors: use industry verticals (finance, healthcare, energy, government, etc.)
- detection_artifacts: CRITICAL RULES:
  * Only include entries when you can extract CONCRETE artifacts from the article text
  * Do NOT invent generic placeholders — if the article doesn't mention specific process
    names, file paths, command lines, registry keys, or network indicators, omit that field
  * Do NOT add an entry if ALL detection arrays would be empty
  * logsource_category must be one of: process_creation, network_connection, file_event,
    registry_event, dns_query, firewall
  * logsource_product: windows, linux, macos — omit (empty string) for network/firewall rules
  * command_line values: exact substrings or distinctive patterns that appear in command logs
  * One entry per technique+logsource combination — combine related artifacts into one entry
  * If the article describes no specific technical artifacts, return detection_artifacts: []
  * FILENAMES AND SCRIPTS: always extract into detection fields, not just descriptions:
    - Shell scripts (e.g. aic.sh, fwr.sh, install.sh) → command_line AND file_path
    - Dropped/renamed binaries (e.g. renamed to 'kad', '.asusrouter') → process_name AND file_path
    - Scheduled tasks or cron entries referencing filenames → command_line
    - Any filename mentioned as downloaded, executed, or persisted must appear in a detection field
  * ALL confirmed C2/staging IPs mentioned in the article → network_dst_ip (not just the primary one)
  * Do not put artifact details only in description and leave detection arrays empty
- campaign_names: named operations or campaigns explicitly referenced (e.g. "Operation ShadowHammer",
  "Volt Typhoon"). Use exact names as stated. Empty array [] if none mentioned.
- malware_families: malware family or tool names (e.g. "LockBit 3.0", "Cobalt Strike", "SUNBURST",
  "Mimikatz"). Use exact names. Empty array [] if none identified.
- false_positive_iocs: list the exact values of any IOCs that were likely extracted from the \
  article text but are NOT genuine threat indicators. Include:
  * Reference URLs embedded in the article (documentation links, vendor blogs, MITRE pages)
  * Victim organization domains/IPs mentioned by name (not attacker infrastructure)
  * Legitimate services cited as context ("the attacker abused OneDrive") — include the \
    service domain (e.g. onedrive.com) since the service itself is not malicious
  * Example or placeholder values in the article text
  * The article's own source domain or related vendor domains
  Do NOT include confirmed C2 IPs, malware download URLs, attacker-registered domains, \
  phishing URLs, or file hashes of malicious samples — those are genuine IOCs.
  Return [] if all extracted IOCs appear to be genuine threat indicators.
"""


def _tag_iocs_from_item(item: "EnrichedIntelItem") -> None:
    """
    Populate ioc.tags for every non-FP IOC in the item.
    Tags are collected from: CVE IDs in article text, campaign names, malware families,
    and threat actor names. Applied in-place; existing tags are merged (not replaced).
    """
    text = f"{item.title} {item.body}"
    cve_tags = sorted({m.upper() for m in _CVE_RE.findall(text)})
    actor_tags = [a.name for a in item.actors if a.name]
    new_tags = sorted(set(
        cve_tags
        + item.campaign_names
        + item.malware_families
        + actor_tags
    ))
    if not new_tags:
        return
    for ioc in item.iocs:
        if not ioc.likely_fp:
            merged = sorted(set(ioc.tags) | set(new_tags))
            object.__setattr__(ioc, "tags", merged)


class LLMAnalyzer:
    """Enriches EnrichedIntelItems with Claude-generated analysis."""

    def __init__(self, model: str = "claude-opus-4-6", rpm_limit: int = 40, max_body_chars: int = 4000) -> None:
        self.model = model
        self.max_body_chars = max_body_chars
        self._client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        self._limiter = RateLimiter(rpm_limit)

    def enrich_batch(self, items: list[EnrichedIntelItem]) -> list[EnrichedIntelItem]:
        """Enrich each item in the list; skips on failure (non-blocking)."""
        enriched: list[EnrichedIntelItem] = []
        for item in items:
            try:
                enriched.append(self._enrich_one(item))
            except Exception as exc:
                log.warning("LLM enrichment failed for '%s': %s", item.title[:60], exc)
                enriched.append(item)
        return enriched

    def _enrich_one(self, item: EnrichedIntelItem) -> EnrichedIntelItem:
        self._limiter.acquire()
        body_snippet = (item.body or "")[:self.max_body_chars]
        user_content = f"Title: {item.title}\n\nContent:\n{body_snippet}"

        response = self._client.messages.create(
            model=self.model,
            max_tokens=2048,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_content}],
        )

        raw_text = response.content[0].text.strip()
        data = self._parse_json(raw_text, item.title)
        if not data:
            return item

        return self._apply_enrichment(item, data)

    def _apply_enrichment(self, item: EnrichedIntelItem, data: dict) -> EnrichedIntelItem:
        if summary := data.get("summary", "").strip():
            item.summary = summary
        if severity := data.get("severity"):
            item.severity = max(0.0, min(1.0, float(severity)))
        if sectors := data.get("targeted_sectors", []):
            item.targeted_sectors = sectors
        if regions := data.get("targeted_regions", []):
            item.targeted_regions = regions

        # Merge LLM-detected actors
        for actor_data in data.get("threat_actors", []):
            name = actor_data.get("name", "").strip()
            if name:
                actor = ThreatActor(
                    name=name,
                    aliases=actor_data.get("aliases", []),
                    confidence=float(actor_data.get("confidence", 0.5)),
                    motivation=data.get("motivation", "unknown"),
                    targeted_sectors=data.get("targeted_sectors", []),
                    targeted_regions=data.get("targeted_regions", []),
                )
                item.actors.append(actor)

        # Merge LLM-detected TTPs (avoid duplicates)
        existing_ids = {t.technique_id for t in item.ttps}
        for tid in data.get("new_ttps", []):
            tid = tid.strip().upper()
            if tid and tid not in existing_ids:
                item.ttps.append(TTP(technique_id=tid))
                existing_ids.add(tid)

        # Store detection artifacts for Sigma generation
        artifacts = data.get("detection_artifacts", [])
        if isinstance(artifacts, list):
            # Filter out artifacts with no actual detection conditions
            item.detection_artifacts = [
                a for a in artifacts
                if isinstance(a, dict) and _artifact_has_conditions(a)
            ]

        # Apply LLM-identified IOC false positive flags
        fp_values = {v.lower().strip() for v in data.get("false_positive_iocs", []) if v}
        if fp_values:
            fp_count = 0
            for ioc in item.iocs:
                if ioc.value.lower() in fp_values:
                    ioc.likely_fp = True
                    fp_count += 1
            if fp_count:
                log.debug("LLM flagged %d IOCs as likely FP for '%s'", fp_count, item.title[:60])

        # Store campaign names and malware families on the item
        item.campaign_names = [n.strip() for n in data.get("campaign_names", []) if n and n.strip()]
        item.malware_families = [f.strip() for f in data.get("malware_families", []) if f and f.strip()]

        # Tag all IOCs with context from this item (CVEs, campaign, malware, actors)
        _tag_iocs_from_item(item)

        item.llm_enriched = True
        return item

    def _parse_json(self, text: str, context: str) -> dict | None:
        # Strip markdown code fences if present
        if "```" in text:
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError as exc:
            log.warning("LLM returned invalid JSON for '%s': %s", context[:60], exc)
            return None

    def generate_executive_summary(
        self,
        items: list[EnrichedIntelItem],
        recent_titles: list[str] | None = None,
    ) -> str:
        """
        Generate an executive summary focused only on new and emerging threats.

        Returns an empty string when today's items are continuations of already-reported
        stories with no meaningful escalation, new TTPs, or new IOCs.

        Args:
            items: New intel items collected this run.
            recent_titles: Titles of items already reported in previous briefings
                           (used to detect duplicate coverage).
        """
        if not items:
            return ""

        self._limiter.acquire()

        today_bullets = "\n".join(
            f"- [{i.severity_label}] {i.title} ({i.source_name})"
            for i in sorted(items, key=lambda x: x.severity, reverse=True)[:20]
        )

        previously_reported_section = ""
        if recent_titles:
            recent_sample = "\n".join(f"- {t}" for t in recent_titles[:40])
            previously_reported_section = (
                f"\n\nPREVIOUSLY REPORTED (already covered in prior briefings — do not rehash):\n"
                f"{recent_sample}"
            )

        user_content = f"TODAY'S NEW ITEMS:\n{today_bullets}{previously_reported_section}"

        response = self._client.messages.create(
            model=self.model,
            max_tokens=512,
            system=(
                "You are a CISO-level threat intelligence analyst writing a daily briefing.\n\n"
                "Your task: Write a concise executive summary focused ONLY on what is genuinely "
                "new or materially escalating since the previous briefing. Be specific — name "
                "the threat actors, campaigns, or techniques. Plain text only, no bullet points.\n\n"
                "Rules:\n"
                "- If today's items are continued coverage of already-reported incidents with no "
                "new TTPs, no new IOCs, and no meaningful escalation, output exactly: NO_NEW_FINDINGS\n"
                "- If there are genuine new threats or significant developments, summarize them in "
                "3-5 sentences. Do not mention the previously-reported items unless they have "
                "materially escalated.\n"
                "- Prefer 'No new findings today' over duplicating prior summaries."
            ),
            messages=[{"role": "user", "content": user_content}],
        )
        result = response.content[0].text.strip()
        return "" if result == "NO_NEW_FINDINGS" else result
