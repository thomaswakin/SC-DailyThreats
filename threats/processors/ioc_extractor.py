"""Extract IOCs from free text using regex patterns."""

from __future__ import annotations
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

import yaml

from threats.models.ioc import IOC, IOCType

# ── Patterns ──────────────────────────────────────────────────────────────────

_IP = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:com|net|org|io|gov|edu|mil|int|co|uk|de|ru|cn|tk|xyz|top|info|biz|cc|onion)\b",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://[^\s\"'<>)\]]{8,}", re.IGNORECASE)
_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")
_SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")
_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")

# IPs to always exclude (RFC 1918, loopback, link-local)
_EXCLUDE_IP_PREFIXES = {
    "127.", "0.", "255.", "169.254.",
    "192.168.", "10.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
}

_FP_CONFIG_PATH = Path(__file__).parents[2] / "config" / "false_positives.yaml"


@lru_cache(maxsize=1)
def _load_fp_config() -> tuple[frozenset, frozenset, tuple, frozenset, tuple]:
    """Load false-positive lists from config. Cached after first load."""
    if not _FP_CONFIG_PATH.exists():
        return frozenset(), frozenset(), (), frozenset(), ()
    with open(_FP_CONFIG_PATH) as f:
        cfg = yaml.safe_load(f) or {}
    domains = frozenset(d.lower() for d in cfg.get("domains", []))
    ips = frozenset(cfg.get("ips", []))
    suffixes = tuple(s.lower() for s in cfg.get("domain_suffixes", []))
    ctx_domains = frozenset(d.lower() for d in cfg.get("context_dependent_domains", []))
    ctx_suffixes = tuple(s.lower() for s in cfg.get("context_dependent_domain_suffixes", []))
    return domains, ips, suffixes, ctx_domains, ctx_suffixes


def _is_fp_domain(domain: str) -> bool:
    fp_domains, _, fp_suffixes, _, _ = _load_fp_config()
    d = domain.lower()
    return d in fp_domains or any(d.endswith(s) for s in fp_suffixes)


def _is_context_dependent_domain(domain: str) -> bool:
    _, _, _, ctx_domains, ctx_suffixes = _load_fp_config()
    d = domain.lower()
    return d in ctx_domains or any(d.endswith(s) for s in ctx_suffixes)


def _is_fp_ip(ip: str) -> bool:
    _, fp_ips, _, _, _ = _load_fp_config()
    return ip in fp_ips or any(ip.startswith(p) for p in _EXCLUDE_IP_PREFIXES)


def extract_iocs(text: str) -> list[IOC]:
    """Extract and deduplicate IOCs from a text blob."""
    text = _normalize(text)
    found: dict[str, IOC] = {}

    def add(ioc: IOC) -> None:
        if ioc.uid not in found:
            found[ioc.uid] = ioc

    # Order matters: SHA256 → SHA1 → MD5 to avoid partial matches
    for m in _SHA256.finditer(text):
        add(IOC(type=IOCType.SHA256, value=m.group()))

    for m in _SHA1.finditer(text):
        v = m.group()
        if not any(v in sha.value for sha in found.values() if sha.type == IOCType.SHA256):
            add(IOC(type=IOCType.SHA1, value=v))

    for m in _MD5.finditer(text):
        v = m.group()
        if not any(v in sha.value for sha in found.values()):
            add(IOC(type=IOCType.MD5, value=v))

    for m in _URL.finditer(text):
        url = m.group().rstrip(".,;)")
        try:
            hostname = urlparse(url).hostname or ""
        except Exception:
            hostname = ""
        if hostname and _is_fp_domain(hostname):
            continue
        add(IOC(type=IOCType.URL, value=url,
                context_dependent=_is_context_dependent_domain(hostname) if hostname else False))

    for m in _IP.finditer(text):
        v = m.group()
        if not _is_fp_ip(v):
            add(IOC(type=IOCType.IP, value=v))

    for m in _EMAIL.finditer(text):
        add(IOC(type=IOCType.EMAIL, value=m.group().lower()))

    for m in _DOMAIN.finditer(text):
        v = m.group().lower()
        if _is_fp_domain(v) or _is_part_of_url(v, text):
            continue
        add(IOC(type=IOCType.DOMAIN, value=v,
                context_dependent=_is_context_dependent_domain(v)))

    return list(found.values())


def _normalize(text: str) -> str:
    """Re-fang defanged IOCs."""
    return (
        text.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[dot]", ".")
        .replace("[at]", "@")
        .replace("hxxp", "http")
        .replace("hXXp", "http")
        .replace("hxxps", "https")
    )


def _is_part_of_url(domain: str, text: str) -> bool:
    return f"://{domain}" in text or f"/{domain}" in text
