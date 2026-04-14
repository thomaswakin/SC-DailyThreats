"""
Source Discovery — runs at the start of each pipeline cycle.

Two signals:
  1. Curated lists  — diffs community-maintained GitHub lists against feeds.yaml
  2. Citation mining — finds domains that existing sources frequently cite in articles

New candidates pass through an LLM evaluation gate before anything is written.
Approved candidates with a discoverable RSS feed are appended to feeds.yaml and
are available to the collector stage of the same run.

Nothing in this module raises — all failures are logged and the pipeline continues.
"""

from __future__ import annotations
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import yaml

from threats.utils.http import get_session
from threats.utils.rate_limiter import RateLimiter

log = logging.getLogger(__name__)

# ── Curated list definitions ──────────────────────────────────────────────────
_CURATED_LISTS = [
    {
        "name": "awesome-threat-intelligence",
        "url": "https://raw.githubusercontent.com/hslatman/awesome-threat-intelligence/main/README.md",
        "format": "markdown",
    },
    {
        "name": "MISP default feeds",
        "url": "https://raw.githubusercontent.com/MISP/MISP/2.4/app/files/feed-metadata/defaults.json",
        "format": "misp_json",
    },
]

# Domains to skip without LLM evaluation — not threat intel research sources
_SKIP_DOMAINS = {
    "github.com", "twitter.com", "x.com", "linkedin.com", "youtube.com",
    "google.com", "wikipedia.org", "reddit.com", "medium.com",
    "attack.mitre.org", "nvd.nist.gov", "cve.org", "cve.mitre.org",
    "virustotal.com", "shodan.io", "censys.io", "urlscan.io",
    "docs.microsoft.com", "learn.microsoft.com", "support.microsoft.com",
    "arxiv.org", "doi.org", "ietf.org", "rfc-editor.org",
    "feedburner.com", "blogger.com", "wordpress.com", "substack.com",
}

# Feed URL patterns to probe in order during autodiscovery
_FEED_PROBES = [
    "/feed/",
    "/feed.xml",
    "/rss/",
    "/rss.xml",
    "/blog/feed/",
    "/blog/rss/",
    "/index.xml",
    "/atom.xml",
    "/feeds/posts/default",
]

_MARKDOWN_URL_RE = re.compile(r'\[(?:[^\]]*?)\]\((https?://[^\s\)]+)\)')
_BARE_URL_RE     = re.compile(r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s"\'<>]*)?')

_LLM_SYSTEM_PROMPT = """\
You are a threat intelligence programme manager evaluating candidate sources.

For each candidate URL below, assess whether it is a PRIMARY threat intelligence \
research source — meaning it publishes ORIGINAL content such as:
  - Malware reverse engineering
  - APT actor tracking and attribution
  - Novel TTP discovery and behavioral analysis
  - Incident reconstruction with technical artifacts
  - Vulnerability exploitation research

Do NOT recommend:
  - News or journalism sites (BleepingComputer, DarkReading, TheHackerNews)
  - Aggregators or commentary blogs
  - Vendor marketing / product announcement blogs
  - Government alert feeds with no technical depth (CISA advisories only, no research)
  - Sites already well-known to overlap completely with existing top-tier sources

Return ONLY valid JSON — an array, one object per candidate:
[
  {
    "url": "<exact URL from input>",
    "recommended": true | false,
    "name": "short display name (vendor/team name)",
    "reliability": "authoritative" | "high" | "medium",
    "tags": ["malware", "apt", ...],
    "reason": "one sentence"
  }
]

Be selective. Only recommend sources that would add genuine detection engineering value.
"""


class SourceDiscovery:
    """
    Discovers and vets new threat intelligence feed sources each pipeline run.
    Writes approved sources directly to feeds.yaml.
    """

    def __init__(
        self,
        repo,
        feeds_path: str | Path,
        llm_client,
        model: str,
        limiter: RateLimiter,
    ) -> None:
        self._repo = repo
        self._feeds_path = Path(feeds_path)
        self._client = llm_client
        self._model = model
        self._limiter = limiter
        self._session = get_session()

    def run(self) -> int:
        """
        Full discovery cycle. Returns the number of new sources added to feeds.yaml.
        Never raises — all errors are logged.
        """
        try:
            existing_domains = self._existing_feed_domains()
            known_urls       = self._repo.get_known_candidate_urls()

            candidates: list[dict] = []
            candidates += self._fetch_curated_candidates(existing_domains, known_urls)
            candidates += self._fetch_citation_candidates(existing_domains, known_urls)

            if not candidates:
                log.info("Source discovery: no new candidates found this run")
                return 0

            log.info("Source discovery: %d new candidates to evaluate", len(candidates))

            # Record all candidates as pending before LLM evaluation
            for c in candidates:
                self._repo.upsert_source_candidate(
                    url=c["url"], domain=c["domain"],
                    name=c.get("name", ""), status="pending",
                    discovered_via=c["discovered_via"],
                    citation_count=c.get("citation_count", 0),
                )

            approved = self._evaluate_candidates(candidates)
            if not approved:
                log.info("Source discovery: no candidates approved by LLM")
                return 0

            added = self._write_to_feeds(approved)
            log.info("Source discovery: %d new sources added to feeds.yaml", added)
            return added

        except Exception as exc:
            log.warning("Source discovery failed (pipeline will continue): %s", exc)
            return 0

    # ── Signal 1: Curated lists ───────────────────────────────────────────────

    def _fetch_curated_candidates(
        self, existing_domains: set[str], known_urls: set[str]
    ) -> list[dict]:
        candidates: list[dict] = []
        for source in _CURATED_LISTS:
            try:
                resp = self._session.get(source["url"], timeout=15)
                resp.raise_for_status()
                if source["format"] == "markdown":
                    urls = self._parse_markdown_urls(resp.text)
                elif source["format"] == "misp_json":
                    urls = self._parse_misp_json(resp.text)
                else:
                    continue

                for url in urls:
                    domain = _domain(url)
                    if not domain:
                        continue
                    if domain in _SKIP_DOMAINS or domain in existing_domains:
                        continue
                    # Normalise to domain-level key for dedup against known_urls
                    if any(domain in ku for ku in known_urls):
                        continue
                    candidates.append({
                        "url": url,
                        "domain": domain,
                        "discovered_via": "curated_list",
                        "list_name": source["name"],
                    })
                log.debug("Curated list '%s': %d new candidate URLs",
                          source["name"], len(candidates))
            except Exception as exc:
                log.warning("Failed to fetch curated list '%s': %s", source["name"], exc)

        return _dedup_by_domain(candidates)

    def _parse_markdown_urls(self, text: str) -> list[str]:
        urls = [m.group(1) for m in _MARKDOWN_URL_RE.finditer(text)]
        # Add bare URLs not inside markdown links
        urls += _BARE_URL_RE.findall(text)
        return list({u.rstrip("/.") for u in urls if u.startswith("http")})

    def _parse_misp_json(self, text: str) -> list[str]:
        try:
            feeds = json.loads(text)
            urls = []
            for feed in (feeds if isinstance(feeds, list) else []):
                if isinstance(feed, dict):
                    url = feed.get("url") or feed.get("source_format", "")
                    if url and url.startswith("http"):
                        urls.append(url)
            return urls
        except Exception:
            return []

    # ── Signal 2: Citation mining ─────────────────────────────────────────────

    def _fetch_citation_candidates(
        self, existing_domains: set[str], known_urls: set[str]
    ) -> list[dict]:
        try:
            cited = self._repo.get_cited_domains(min_sources=3, lookback_days=90)
        except Exception as exc:
            log.warning("Citation mining query failed: %s", exc)
            return []

        candidates = []
        for domain, count in cited:
            if domain in _SKIP_DOMAINS or domain in existing_domains:
                continue
            if any(domain in ku for ku in known_urls):
                continue
            # Use https://domain as the placeholder URL; feed autodiscovery runs later
            candidates.append({
                "url": f"https://{domain}",
                "domain": domain,
                "discovered_via": "citation",
                "citation_count": count,
            })

        log.debug("Citation mining: %d new candidate domains (min 3 sources)", len(candidates))
        return candidates

    # ── LLM evaluation gate ───────────────────────────────────────────────────

    def _evaluate_candidates(self, candidates: list[dict]) -> list[dict]:
        """
        Batch-evaluate all candidates in a single LLM call.
        Returns only those the LLM recommends.
        """
        self._limiter.acquire()

        url_list = "\n".join(
            f"- {c['url']}"
            + (f"  (cited by {c['citation_count']} sources)" if c.get("citation_count") else "")
            + (f"  [from: {c.get('list_name', '')}]" if c.get("list_name") else "")
            for c in candidates
        )

        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=2048,
                system=_LLM_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": url_list}],
            )
            raw = response.content[0].text.strip()
            verdicts = self._parse_json(raw)
        except Exception as exc:
            log.warning("LLM evaluation of source candidates failed: %s", exc)
            return []

        if not verdicts:
            return []

        now = datetime.now(timezone.utc).isoformat()
        approved = []
        candidate_by_url = {c["url"]: c for c in candidates}

        for v in verdicts:
            url = (v.get("url") or "").strip()
            if not url:
                continue
            recommended = bool(v.get("recommended", False))
            status = "approved" if recommended else "rejected"
            self._repo.upsert_source_candidate(
                url=url,
                domain=_domain(url),
                name=v.get("name", ""),
                status=status,
                discovered_via=candidate_by_url.get(url, {}).get("discovered_via", ""),
                citation_count=candidate_by_url.get(url, {}).get("citation_count", 0),
                llm_verdict=v.get("reason", ""),
                reliability=v.get("reliability", "high"),
                suggested_tags=v.get("tags", []),
                evaluated_at=now,
            )
            if recommended:
                c = candidate_by_url.get(url, {})
                approved.append({
                    "url": url,
                    "domain": _domain(url),
                    "name": v.get("name", _domain(url)),
                    "reliability": v.get("reliability", "high"),
                    "tags": v.get("tags", []),
                    "reason": v.get("reason", ""),
                    "discovered_via": c.get("discovered_via", ""),
                })
                log.info("Source discovery approved: %s — %s", url, v.get("reason", ""))
            else:
                log.debug("Source discovery rejected: %s — %s", url, v.get("reason", ""))

        return approved

    # ── Feed URL autodiscovery ────────────────────────────────────────────────

    def _find_feed_url(self, site_url: str) -> str | None:
        """
        Given a site URL, attempt to locate its RSS/Atom feed.
        First checks for <link rel="alternate"> in the HTML, then probes common paths.
        Returns the feed URL if found and parseable, else None.
        """
        import feedparser

        base = site_url.rstrip("/")
        parsed = urlparse(base)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Check for feed autodiscovery link in homepage HTML
        try:
            resp = self._session.get(origin, timeout=10)
            if resp.ok:
                link_re = re.compile(
                    r'<link[^>]+type=["\']application/(?:rss|atom)\+xml["\'][^>]*href=["\']([^"\']+)["\']',
                    re.IGNORECASE,
                )
                m = link_re.search(resp.text)
                if m:
                    feed_url = m.group(1)
                    if not feed_url.startswith("http"):
                        feed_url = origin + "/" + feed_url.lstrip("/")
                    fp = feedparser.parse(feed_url)
                    if fp.entries:
                        return feed_url
        except Exception:
            pass

        # 2. Probe common feed paths
        for path in _FEED_PROBES:
            candidate = origin + path
            try:
                fp = feedparser.parse(candidate)
                if fp.entries:
                    return candidate
            except Exception:
                pass

        return None

    # ── Write to feeds.yaml ───────────────────────────────────────────────────

    def _write_to_feeds(self, approved: list[dict]) -> int:
        """
        For each approved candidate, discover its feed URL then append to feeds.yaml.
        Returns count of sources actually added.
        """
        try:
            text = self._feeds_path.read_text(encoding="utf-8")
            cfg  = yaml.safe_load(text) or {}
        except Exception as exc:
            log.error("Cannot read feeds.yaml: %s", exc)
            return 0

        existing_urls = {f.get("url", "") for f in cfg.get("feeds", [])}
        added = 0

        for candidate in approved:
            site_url  = candidate["url"]
            domain    = candidate["domain"]

            feed_url = self._find_feed_url(site_url)
            if not feed_url:
                log.info("Source discovery: no RSS feed found for %s — skipping", domain)
                self._repo.upsert_source_candidate(
                    url=site_url, domain=domain, status="approved",
                    llm_verdict=candidate.get("reason", "") + " [no RSS feed found]",
                )
                continue

            if feed_url in existing_urls:
                log.debug("Feed already in feeds.yaml: %s", feed_url)
                continue

            tags_str = ", ".join(candidate.get("tags", []))
            block = (
                f"\n  - name: \"{candidate['name']}\"\n"
                f"    url: \"{feed_url}\"\n"
                f"    collector: rss\n"
                f"    reliability: {candidate.get('reliability', 'high')}\n"
                f"    tlp: white\n"
                f"    tags: [{tags_str}]\n"
                f"    notes: \"Auto-discovered. {candidate.get('reason', '')}\"\n"
                f"    discovered_via: \"{candidate['discovered_via']}\"\n"
            )

            # Append under an auto-discovered section comment if not present
            if "# Auto-discovered sources" not in text:
                text += "\n  # Auto-discovered sources\n"
            text += block

            existing_urls.add(feed_url)
            self._repo.upsert_source_candidate(
                url=site_url, domain=domain, status="approved",
                llm_verdict=candidate.get("reason", ""),
            )
            log.info("Source discovery: added '%s' (%s) to feeds.yaml",
                     candidate["name"], feed_url)
            added += 1

        if added:
            self._feeds_path.write_text(text, encoding="utf-8")

        return added

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _existing_feed_domains(self) -> set[str]:
        """Return the set of domains already present in feeds.yaml."""
        try:
            with open(self._feeds_path) as f:
                cfg = yaml.safe_load(f) or {}
            domains = set()
            for feed in cfg.get("feeds", []):
                d = _domain(feed.get("url", ""))
                if d:
                    domains.add(d)
            return domains
        except Exception:
            return set()

    def _parse_json(self, text: str) -> list:
        if "```" in text:
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        try:
            result = json.loads(text.strip())
            return result if isinstance(result, list) else []
        except json.JSONDecodeError as exc:
            log.warning("Source discovery LLM returned invalid JSON: %s", exc)
            return []


# ── Module-level helpers ──────────────────────────────────────────────────────

def _domain(url: str) -> str:
    """Extract bare domain (no www.) from a URL."""
    try:
        host = urlparse(url).netloc or ""
        return host.lstrip("www.").lower()
    except Exception:
        return ""


def _dedup_by_domain(candidates: list[dict]) -> list[dict]:
    """Keep one candidate per domain (first seen wins)."""
    seen: set[str] = set()
    result = []
    for c in candidates:
        d = c.get("domain", "")
        if d and d not in seen:
            seen.add(d)
            result.append(c)
    return result
