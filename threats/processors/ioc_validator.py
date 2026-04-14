"""
Second-pass LLM validation of extracted IOCs.

The LLM enrichment prompt already asks for false_positive_iocs, but that's buried
in a large multi-task prompt and can miss obvious cases (e.g. irs.gov extracted from
a phishing article that's about IRS impersonation). This validator runs a focused,
single-purpose pass over each item's IOCs to catch what slips through.

Called after enrichment, before DB storage.

High-confidence FP verdicts (≥ 0.85) are automatically written back to
false_positives.yaml so the static list learns over time and avoids repeat LLM calls.
"""

from __future__ import annotations
import json
import logging
import re
from datetime import date
from pathlib import Path

import anthropic
import yaml

from threats.models import EnrichedIntelItem
from threats.models.ioc import IOC, IOCType
from threats.utils.rate_limiter import RateLimiter

log = logging.getLogger(__name__)

_FP_CONFIG_PATH = Path(__file__).parents[2] / "config" / "false_positives.yaml"
# Confidence threshold above which a verdict is written to the static FP list
_AUTO_LEARN_THRESHOLD = 0.85

_MAX_IOCS_PER_CALL = 25   # batch ceiling per API call
_HASH_TYPES = {IOCType.MD5, IOCType.SHA1, IOCType.SHA256}

_SYSTEM_PROMPT = """\
You are a threat intelligence IOC analyst performing a false-positive validation pass.

You will be given a security article (title + summary) and a list of IOC candidates \
that were automatically extracted from it. Your task is to determine, for each IOC, \
whether it is a GENUINE threat indicator or a FALSE POSITIVE.

## False positive categories — flag these as "fp":

1. **Impersonation targets** — legitimate domains/IPs mentioned because attackers are \
   *spoofing* them, not because they are attacker infrastructure.
   Examples: irs.gov in a tax-season phishing article, paypal.com in a credential \
   harvesting writeup, microsoft.com in a Teams vishing report.

2. **Legitimate services abused as staging** — the service itself is benign even if \
   attackers upload payloads there. Do NOT flag the specific attacker-controlled URL, \
   only the base service domain.
   Examples: onedrive.live.com, drive.google.com, dropbox.com, discord.com (as a \
   platform — flag the domain, not a specific CDN URL with an attacker payload).

3. **Victim organization domains** — organizations that were attacked, not attacker \
   infrastructure. Flag these if mentioned by name as victims.

4. **Reference and documentation links** — domains cited as sources, references, or \
   further reading. Examples: attack.mitre.org, nvd.nist.gov, cve.org.

5. **Security vendor / researcher domains** — vendors, threat intel platforms, or \
   researchers cited in the article. Examples: virustotal.com, shodan.io.

6. **Generic infrastructure that appears in article text as context** — e.g. \
   a CDN or cloud provider mentioned because attackers used it, but the base domain \
   itself (aws.amazon.com, cloudflare.com) is not a useful IOC.

7. **Article's own source domain or closely related domains**.

## Genuine IOCs — mark as "genuine":
- Attacker-registered domains (random strings, typosquats, newly registered)
- Confirmed C2 IP addresses
- Malware download URLs (specific paths, not just the hosting platform's base domain)
- File hashes of malicious samples
- Phishing kit infrastructure
- Bullet-proof hosting IPs

## Uncertain:
- Use "uncertain" only when you genuinely cannot determine from context.
- When uncertain, set confidence <= 0.5.

## Output format — return ONLY valid JSON, no commentary:
{
  "verdicts": [
    {
      "value": "<exact IOC value>",
      "verdict": "genuine" | "fp" | "uncertain",
      "confidence": 0.0-1.0,
      "reason": "one sentence"
    }
  ]
}

Be decisive. An IOC like irs.gov extracted from a tax-phishing article is obviously \
a false positive (confidence 0.99). Do not hedge on clear cases.
"""


class IOCValidator:
    """
    Dedicated LLM pass to validate IOC candidates for false positives.
    Complements the static `false_positives.yaml` list and the FP hints
    embedded in the enrichment prompt.
    """

    def __init__(self, client: anthropic.Anthropic, model: str, limiter: RateLimiter) -> None:
        self._client = client
        self.model = model
        self._limiter = limiter

    def validate_batch(self, items: list[EnrichedIntelItem]) -> int:
        """
        Validate IOCs across a batch of items. Mutates ioc.likely_fp and ioc.confidence
        in-place for any IOC that the LLM judges to be a false positive.

        Skips hashes (always high-fidelity) and IOCs already flagged as likely_fp.
        High-confidence FP verdicts (≥ 0.85) are written back to false_positives.yaml.
        Returns total count of IOCs newly flagged as FP.
        """
        total_flagged = 0
        # Collect (ioc, reason) pairs to auto-learn after all items processed
        auto_learn: list[tuple[IOC, str]] = []

        for item in items:
            candidates = [
                ioc for ioc in item.iocs
                if not ioc.likely_fp and ioc.type not in _HASH_TYPES
            ]
            if not candidates:
                continue

            try:
                flagged, learned = self._validate_item(item, candidates)
                total_flagged += flagged
                auto_learn.extend(learned)
            except Exception as exc:
                log.warning(
                    "IOC validation failed for '%s' — keeping IOCs as-is: %s",
                    item.title[:60], exc,
                )

        if auto_learn:
            _write_to_fp_config(auto_learn)

        return total_flagged

    def _validate_item(
        self, item: EnrichedIntelItem, candidates: list[IOC]
    ) -> tuple[int, list[tuple[IOC, str]]]:
        """Validate IOCs for a single item. Returns (count_flagged, auto_learn_list)."""
        flagged = 0
        auto_learn: list[tuple[IOC, str]] = []
        for chunk in _chunks(candidates, _MAX_IOCS_PER_CALL):
            f, l = self._call_llm(item, chunk)
            flagged += f
            auto_learn.extend(l)
        return flagged, auto_learn

    def _call_llm(
        self, item: EnrichedIntelItem, iocs: list[IOC]
    ) -> tuple[int, list[tuple[IOC, str]]]:
        """Returns (count_flagged, auto_learn_list)."""
        self._limiter.acquire()

        ioc_list = [{"value": i.value, "type": i.type.value} for i in iocs]
        user_content = (
            f"Article title: {item.title}\n"
            f"Source: {item.source_name}\n"
            f"Summary: {item.summary or item.title}\n\n"
            f"IOC candidates to validate:\n{json.dumps(ioc_list, indent=2)}"
        )

        response = self._client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_content}],
        )

        raw = response.content[0].text.strip()
        data = _parse_json(raw, item.title)
        if not data:
            return 0, []

        ioc_by_value = {i.value.lower(): i for i in iocs}
        flagged = 0
        auto_learn: list[tuple[IOC, str]] = []

        for verdict in data.get("verdicts", []):
            val = (verdict.get("value") or "").lower().strip()
            decision = verdict.get("verdict", "uncertain")
            confidence = float(verdict.get("confidence", 0.5))
            reason = verdict.get("reason", "")

            ioc = ioc_by_value.get(val)
            if ioc is None:
                continue

            if decision == "fp" and confidence >= 0.7:
                ioc.likely_fp = True
                ioc.confidence = max(0.0, 1.0 - confidence)
                flagged += 1
                log.info(
                    "IOC validator flagged '%s' (%s) as FP [conf=%.2f]: %s",
                    ioc.value, ioc.type.value, confidence, reason,
                )
                # Queue for static list write-back if confidence is high enough
                if confidence >= _AUTO_LEARN_THRESHOLD:
                    auto_learn.append((ioc, reason))
            elif decision == "genuine" and confidence >= 0.7:
                ioc.confidence = min(1.0, max(ioc.confidence, confidence * 0.85))
            elif decision == "uncertain" or confidence < 0.7:
                ioc.confidence = min(ioc.confidence, 0.4)
                log.debug(
                    "IOC validator uncertain about '%s' (%s) [conf=%.2f]: %s",
                    ioc.value, ioc.type.value, confidence, reason,
                )

        return flagged, auto_learn


def _write_to_fp_config(entries: list[tuple[IOC, str]]) -> None:
    """
    Append newly learned FP domains/IPs to false_positives.yaml.
    Only writes entries not already present in the file.
    Clears the _load_fp_config cache so the same run benefits immediately.
    """
    if not _FP_CONFIG_PATH.exists():
        return

    try:
        text = _FP_CONFIG_PATH.read_text(encoding="utf-8")
        cfg = yaml.safe_load(text) or {}

        existing_domains = {d.lower() for d in cfg.get("domains", [])}
        existing_ips = set(cfg.get("ips", []))

        new_domain_lines: list[str] = []
        new_ip_lines: list[str] = []
        today = date.today().isoformat()

        for ioc, reason in entries:
            if ioc.type == IOCType.DOMAIN:
                val = ioc.value.lower()
                if val not in existing_domains:
                    existing_domains.add(val)
                    # Sanitize reason for inline YAML comment (no newlines, limit length)
                    safe_reason = re.sub(r"[\r\n]+", " ", reason)[:120]
                    new_domain_lines.append(f"  - {val}  # auto-learned {today}: {safe_reason}")
                    log.info("Auto-learned FP domain '%s' → added to false_positives.yaml", val)
            elif ioc.type == IOCType.IP:
                if ioc.value not in existing_ips:
                    existing_ips.add(ioc.value)
                    safe_reason = re.sub(r"[\r\n]+", " ", reason)[:120]
                    new_ip_lines.append(f"  - {ioc.value}  # auto-learned {today}: {safe_reason}")
                    log.info("Auto-learned FP IP '%s' → added to false_positives.yaml", ioc.value)

        if not new_domain_lines and not new_ip_lines:
            return

        # Append new entries under clearly marked auto-learned sections
        additions = ""
        if new_domain_lines:
            additions += "\n  # Auto-learned by IOC validator\n"
            additions += "\n".join(new_domain_lines) + "\n"

        # Insert domain additions before the `ips:` line
        if new_domain_lines:
            text = re.sub(r"(\nips:)", additions + r"\1", text, count=1)

        if new_ip_lines:
            ip_addition = "\n  # Auto-learned by IOC validator\n"
            ip_addition += "\n".join(new_ip_lines) + "\n"
            # Append after the last IP entry (before domain_suffixes or end of ips block)
            text = re.sub(r"(\ndomain_suffixes:)", ip_addition + r"\1", text, count=1)

        _FP_CONFIG_PATH.write_text(text, encoding="utf-8")

        # Invalidate cache so subsequent items in this run use the updated list
        from threats.processors.ioc_extractor import _load_fp_config
        _load_fp_config.cache_clear()

    except Exception as exc:
        log.warning("Failed to write auto-learned FPs to false_positives.yaml: %s", exc)


def _chunks(lst: list, n: int):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def _parse_json(text: str, context: str) -> dict | None:
    if "```" in text:
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError as exc:
        log.warning("IOC validator returned invalid JSON for '%s': %s", context[:60], exc)
        return None
