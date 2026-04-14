"""Post-generation LLM review of Sigma rules for false positive risk and expiry."""

from __future__ import annotations
import json
import logging
from datetime import date, timedelta
from pathlib import Path

import anthropic

from threats.models import EnrichedIntelItem
from threats.models.briefing import SigmaRule
from threats.utils.rate_limiter import RateLimiter

log = logging.getLogger(__name__)

_REVIEW_SYSTEM_PROMPT = """\
You are a senior detection engineer reviewing auto-generated Sigma rules before production deployment.

Your job: assess false positive risk, tighten detection conditions where needed, and recommend \
expiry dates for IOC-based rules.

Return ONLY a single valid JSON object — no markdown, no commentary outside the JSON:

{
  "fp_risk": "low|medium|high",
  "fp_notes": "1-2 sentences: what legitimate activity triggers this rule and how common it is",
  "expiry_days": null,
  "falsepositives": ["specific FP scenario 1", "specific FP scenario 2"],
  "revised_yaml": null
}

expiry_days rules (null = no expiry for behavioral rules):
- Dedicated campaign IP (non-cloud): 90
- Cloud/CDN-hosted C2 IP: 30
- Bulletproof hosting IP: 180
- Attacker-controlled domain: 60
- CDN/platform subdomain (*.vercel.app, *.pages.dev, *.netlify.app, etc.): 14
- URL shortener domain: 7
- Pure behavioral rule (no IOCs): null

revised_yaml: return the FULL revised YAML string if you change detection conditions; \
null if the rule is already well-scoped. Keep all original fields (id, title, author, date, \
references, tags, logsource) unchanged — only modify the detection block and falsepositives list.

## IOC artifacts inside behavioral rules — the AND-anchoring principle

When a Sigma rule contains BOTH behavioral conditions (process_name, command_line,
file_path, registry_key, parent_process) AND network/DNS IOC conditions, apply this
decision framework:

**STRONG behavioral rule** (specific process + command line OR specific process + parent):
  The behavioral conditions already uniquely identify malicious activity. A FP-prone
  domain or IP (CDNs, anonymization tools, widely-used platforms like Discord/Telegram,
  government/financial sites) HURTS the rule — it may cause suppression in environments
  that legitimately use those services. Remove FP-prone IOC conditions from revised_yaml.
  Keep only attacker-controlled infrastructure (novel domains, bulletproof hosting IPs).

**MODERATE behavioral rule** (one behavioral field only — e.g. just a registry key or
  just a process name with no command line specifics):
  A FP-prone domain/IP is doing real filtering work here — it tightens an otherwise
  broad rule. Keep it as an AND condition. This is when a FP-prone IOC REDUCES the
  overall false positive rate by requiring multiple conditions to fire simultaneously.
  Example: `HKCU\Run` key write alone fires constantly; adding `dns_query: anydesk.com`
  makes it a meaningful detection for attacker remote-access persistence.

**Pure IOC rule** (only dns_query or network_dst_ip, no behavioral conditions):
  If the IOC is widely-used legitimate infrastructure (CDNs, anonymization tools,
  common platforms), set fp_risk: high and recommend deletion or restructuring as
  a behavioral rule. A standalone DNS rule for torproject.org, discord.com, or
  any.run is not deployable.

## Common HIGH false-positive patterns to know — flag and tighten when you see these:
- node.exe/npm spawning curl, wget, bash, sh — extremely common in npm postinstall scripts \
  (node-gyp, esbuild, Playwright, puppeteer download native binaries this way)
- cmd.exe or powershell.exe as ParentImage for python.exe — routine developer activity \
  (pip install, script execution, build tools)
- Code.exe (VS Code) or Cursor.exe spawning shells with curl/wget — VS Code integrated \
  terminal is used by every developer; this fires on every `curl` from a VS Code terminal
- HKCU/HKLM\\Run key writes with no Image restriction — Chrome, Slack, Teams, Zoom, \
  Dropbox, OneDrive, Discord, antivirus all write here routinely
- *.vercel.app, *.netlify.app, *.pages.dev, *.github.io, *.azurewebsites.net DNS queries — \
  major legitimate hosting platforms; standalone DNS rules for these are not deployable
- Generic *.azureedge.net, *.cloudfront.net, *.fastly.net — CDN infrastructure, \
  massive legitimate traffic
- curl/wget in CommandLine with no specific destination pattern — fires on every download

Tightening techniques:
- Replace broad parent (cmd.exe, powershell.exe) with the specific malicious parent from \
  the campaign (e.g. only node.exe for Contagious Interview)
- Add CommandLine|contains conditions for specific malicious flags/paths/destinations \
  mentioned in the article
- For registry Run key rules: add Image|endswith exclusions for known signed paths, \
  or require the specific malicious value name if the article names it
- For CDN/platform DNS rules: either delete them or restructure as a parent-process + \
  network correlation (require the request to originate from node.exe/npm)
- Combine with suspicious output path conditions (%TEMP%, /tmp/, %APPDATA% for dropped payloads)
"""


class SigmaReviewer:
    """Reviews generated Sigma rules for FP risk and tightens conditions via LLM."""

    def __init__(self, client: anthropic.Anthropic, model: str, limiter: RateLimiter) -> None:
        self._client = client
        self.model = model
        self._limiter = limiter

    def review_rules(
        self,
        rules: list[SigmaRule],
        items: list[EnrichedIntelItem],
        briefing_date: date | None = None,
    ) -> list[SigmaRule]:
        """
        Review each rule for FP risk. Updates rules in-place and returns the list.
        Re-writes the YAML file on disk if conditions are tightened.
        """
        if not rules:
            return rules

        if briefing_date is None:
            briefing_date = date.today()

        # Build url→item lookup for article context
        item_by_url = {i.source_url: i for i in items}

        revised_count = 0
        for rule in rules:
            try:
                self._review_one(rule, item_by_url, briefing_date)
                if rule.fp_risk in ("medium", "high"):
                    revised_count += 1
            except Exception as exc:
                log.warning("FP review failed for '%s': %s", rule.title[:60], exc)
                rule.reviewed = False

        log.info(
            "FP review complete: %d rules reviewed, %d medium/high FP risk",
            len(rules), revised_count,
        )
        return rules

    def _review_one(
        self,
        rule: SigmaRule,
        item_by_url: dict[str, EnrichedIntelItem],
        briefing_date: date,
    ) -> None:
        self._limiter.acquire()

        item = item_by_url.get(rule.related_source_url)
        article_context = ""
        if item:
            article_context = (
                f"Source article: {item.title}\n"
                f"Campaign/threat: {', '.join(a.name for a in item.actors) or 'Unknown'}\n"
                f"Summary: {item.summary or item.title}\n\n"
            )

        user_content = (
            f"{article_context}"
            f"Review this Sigma rule:\n\n"
            f"```yaml\n{rule.yaml_content}\n```"
        )

        response = self._client.messages.create(
            model=self.model,
            max_tokens=2048,
            system=_REVIEW_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_content}],
        )

        raw = response.content[0].text.strip()
        data = _parse_json(raw, rule.title)
        if not data:
            return

        rule.fp_risk = data.get("fp_risk", "medium")
        rule.fp_notes = data.get("fp_notes", "").strip()
        rule.expiry_days = data.get("expiry_days")  # None = no expiry
        rule.reviewed = True

        # Update falsepositives list if reviewer provided specific ones
        fp_list = data.get("falsepositives")
        if fp_list and isinstance(fp_list, list):
            rule.falsepositives = fp_list

        # Apply revised YAML if the reviewer tightened conditions
        revised = (data.get("revised_yaml") or "").strip()
        if revised and revised != rule.yaml_content.strip():
            rule.yaml_content = revised
            log.info("Tightened rule '%s' (FP risk: %s)", rule.title[:60], rule.fp_risk)
        else:
            log.debug("Rule '%s' unchanged (FP risk: %s)", rule.title[:60], rule.fp_risk)

        # Append custom metadata block to YAML
        rule.yaml_content = _append_custom_block(rule, briefing_date)

        # Re-write the YAML file on disk with updated content
        if rule.output_path:
            Path(rule.output_path).write_text(rule.yaml_content)


def _append_custom_block(rule: SigmaRule, briefing_date: date) -> str:
    """Append a custom: metadata block to the YAML string."""
    yaml = rule.yaml_content.rstrip()

    # Compute expiry_date if expiry_days is set
    expiry_line = ""
    if rule.expiry_days is not None:
        expiry_date = briefing_date + timedelta(days=rule.expiry_days)
        expiry_line = f"\n  expiry_date: '{expiry_date.isoformat()}'  # retire after {rule.expiry_days} days"

    # Use block scalar (|) so fp_notes content never needs escaping
    fp_notes_text = (rule.fp_notes or "No specific FP concerns identified.").replace("\n", " ")
    # Indent the note value for block scalar
    fp_notes_block = f"|\n    {fp_notes_text}"

    version_line = f"\n  version: {rule.version}" if rule.version > 1 else "\n  version: 1"
    modified_line = f"\n  modified: '{rule.modified}'" if rule.modified else ""
    source_line = f"\n  source_count: {rule.source_count}" if rule.source_count > 1 else ""

    custom_block = (
        f"\ncustom:"
        f"\n  fp_risk: {rule.fp_risk or 'unknown'}"
        f"{expiry_line}"
        f"\n  fp_notes: {fp_notes_block}"
        f"\n  reviewed: true"
        f"\n  reviewed_at: {briefing_date.isoformat()}"
        f"{version_line}"
        f"{modified_line}"
        f"{source_line}"
    )
    return yaml + custom_block + "\n"


def _parse_json(text: str, context: str) -> dict | None:
    if "```" in text:
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError as exc:
        log.warning("FP review returned invalid JSON for '%s': %s", context[:60], exc)
        return None
