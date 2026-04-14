"""
IOC Specificity Research Pass.

After IOC extraction and FP validation, this pass evaluates each non-hash IOC
to determine whether it represents attack-specific infrastructure/tooling or
could represent normal/legitimate activity.

This informs the fidelity score: a single-source IOC confirmed as attack-specific
(e.g. a DGA-pattern C2 domain, a lookalike process name, bulletproof hosting IP)
gets a higher fidelity rating than one that could plausibly be normal activity.

Called after ioc_validator, before DB storage.
"""

from __future__ import annotations
import json
import logging

import anthropic

from threats.models import EnrichedIntelItem
from threats.models.ioc import IOC, IOCType
from threats.utils.rate_limiter import RateLimiter

log = logging.getLogger(__name__)

_HASH_TYPES = {IOCType.MD5, IOCType.SHA1, IOCType.SHA256}
_MAX_IOCS_PER_CALL = 20

_SYSTEM_PROMPT = """\
You are a threat intelligence analyst assessing IOC attack-specificity.

Given a security article (title + summary) and a list of extracted IOCs, determine for each
IOC whether it is attack-specific or could represent normal/legitimate activity.

## Specificity levels:

**attack_specific** — The IOC is highly likely to be unique to attacker infrastructure or tooling:
- Newly registered domains (random strings, typosquats, unusual TLD combinations like .xyz/.top/.cc)
- Known bulletproof hosting providers, TOR exit nodes, or IP ranges explicitly described as C2
- Filenames that mimic legitimate processes (svchost32.exe, svch0st.exe, lsaas.exe)
- C2 domains with algorithmically generated names (DGA-like patterns)
- Non-standard registry persistence paths (HKCU run keys with suspicious names)
- URLs with specific malicious payload paths (not just a CDN base domain)
- IP addresses the article explicitly describes as C2, attacker-controlled, or confirmed malicious

**ambiguous** — Context is insufficient to determine with confidence:
- IP addresses that could be shared hosting, VPN exit nodes, or compromised machines
- Generic-looking domains where article context doesn't confirm attacker ownership
- Filenames that exist in both legitimate and malicious contexts

**normal** — The IOC represents normal or widely-shared infrastructure unlikely to be useful as a standalone indicator:
- Base domains of legitimate cloud/CDN services used as staging (onedrive.live.com, cdn.discordapp.com)
- IP addresses belonging to major cloud providers without specific malicious path context
- Standard Windows/Linux system files cited as injection *targets* (not the injector malware itself)
- Legitimate vendor domains referenced as impersonation targets, not actual attacker infrastructure

## Output format — return ONLY valid JSON, no commentary:
{
  "verdicts": [
    {
      "value": "<exact IOC value>",
      "specificity": "attack_specific" | "ambiguous" | "normal",
      "note": "one concise sentence (max 100 chars) explaining why"
    }
  ]
}

Be decisive on clear cases. A DGA-pattern domain like xn--fjq9a6e.xyz is obviously attack_specific.
A base domain like onedrive.live.com used for payload hosting is normal (the specific URL with the path would be attack_specific).
"""


class IOCResearcher:
    """
    LLM pass that assesses whether each IOC is attack-specific or normal activity.
    Sets ioc.specificity and ioc.specificity_note on each IOC in-place.
    Skips hashes (always attack-specific by definition) and already-flagged FPs.
    """

    def __init__(self, client: anthropic.Anthropic, model: str, limiter: RateLimiter) -> None:
        self._client = client
        self.model = model
        self._limiter = limiter

    def research_batch(self, items: list[EnrichedIntelItem]) -> int:
        """
        Research IOC specificity for all items. Mutates ioc.specificity and
        ioc.specificity_note in-place. Returns total count of IOCs assessed.
        """
        total_assessed = 0
        for item in items:
            candidates = [
                ioc for ioc in item.iocs
                if not ioc.likely_fp and ioc.type not in _HASH_TYPES
            ]
            if not candidates:
                continue
            try:
                assessed = self._research_item(item, candidates)
                total_assessed += assessed
            except Exception as exc:
                log.warning(
                    "IOC research failed for '%s' — leaving specificity as unknown: %s",
                    item.title[:60], exc,
                )
        return total_assessed

    def _research_item(self, item: EnrichedIntelItem, candidates: list[IOC]) -> int:
        assessed = 0
        for chunk in _chunks(candidates, _MAX_IOCS_PER_CALL):
            assessed += self._call_llm(item, chunk)
        return assessed

    def _call_llm(self, item: EnrichedIntelItem, iocs: list[IOC]) -> int:
        self._limiter.acquire()

        ioc_list = [{"value": i.value, "type": i.type.value} for i in iocs]
        user_content = (
            f"Article title: {item.title}\n"
            f"Source: {item.source_name}\n"
            f"Summary: {item.summary or item.title}\n\n"
            f"IOCs to assess:\n{json.dumps(ioc_list, indent=2)}"
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
            return 0

        ioc_by_value = {i.value.lower(): i for i in iocs}
        assessed = 0

        for verdict in data.get("verdicts", []):
            val = (verdict.get("value") or "").lower().strip()
            specificity = verdict.get("specificity", "ambiguous")
            note = (verdict.get("note") or "").strip()[:120]

            ioc = ioc_by_value.get(val)
            if ioc is None:
                continue

            if specificity in ("attack_specific", "ambiguous", "normal"):
                ioc.specificity = specificity
                ioc.specificity_note = note
                assessed += 1
                log.debug(
                    "IOC researcher: '%s' (%s) → %s",
                    ioc.value, ioc.type.value, specificity,
                )

        return assessed


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
        log.warning("IOC researcher returned invalid JSON for '%s': %s", context[:60], exc)
        return None
