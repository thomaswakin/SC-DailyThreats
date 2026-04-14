"""Web scraper collector for non-RSS sources (CSV, JSON endpoints, HTML pages)."""

import csv
import io
import json
import logging
from datetime import datetime, timezone

from bs4 import BeautifulSoup

from threats.models import RawIntelItem
from threats.utils.http import get_session
from .base import BaseCollector

log = logging.getLogger(__name__)


class ScraperCollector(BaseCollector):
    """Handles scraper-type sources: raw HTML, JSON endpoints, and CSV feeds."""

    def collect(self) -> list[RawIntelItem]:
        if not self.source_url:
            log.warning("No URL for scraper source %s", self.source_name)
            return []

        fmt = self.config.get("format", "html")
        log.info("Collecting %s (%s): %s", fmt.upper(), self.source_name, self.source_url)

        try:
            session = get_session()
            resp = session.get(self.source_url)
            resp.raise_for_status()
        except Exception as exc:
            log.error("Failed to fetch %s: %s", self.source_name, exc)
            return []

        if fmt == "json":
            return self._parse_json(resp.text)
        elif fmt == "csv":
            return self._parse_csv(resp.text)
        else:
            return self._parse_html(resp.text)

    # ── Format parsers ────────────────────────────────────────────────────────

    def _parse_json(self, text: str) -> list[RawIntelItem]:
        """Generic JSON parser - handles CISA KEV and ThreatFox formats."""
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            log.error("JSON parse error for %s: %s", self.source_name, exc)
            return []

        items: list[RawIntelItem] = []
        # CISA KEV format
        if isinstance(data, dict) and "vulnerabilities" in data:
            for v in data["vulnerabilities"][:50]:  # cap at 50 per run
                items.append(RawIntelItem(
                    source_name=self.source_name,
                    source_url=self.source_url or "",
                    title=f"{v.get('cveID', 'CVE')} - {v.get('vulnerabilityName', '')}",
                    body=(
                        f"CVE: {v.get('cveID')} | Vendor: {v.get('vendorProject')} | "
                        f"Product: {v.get('product')} | Description: {v.get('shortDescription')} | "
                        f"Required Action: {v.get('requiredAction')} | Due: {v.get('dueDate')}"
                    ),
                    published_at=self._parse_iso(v.get("dateAdded")),
                    tags=self.tags + ["kev", "vulnerability"],
                ))
        # ThreatFox format: {"query_status": "ok", "data": [...]}
        elif isinstance(data, dict) and "data" in data:
            for ioc_entry in (data["data"] or [])[:100]:
                items.append(RawIntelItem(
                    source_name=self.source_name,
                    source_url=self.source_url or "",
                    title=f"[ThreatFox] {ioc_entry.get('malware', 'Unknown')} - {ioc_entry.get('ioc_type', '')}",
                    body=(
                        f"IOC: {ioc_entry.get('ioc')} | Type: {ioc_entry.get('ioc_type')} | "
                        f"Malware: {ioc_entry.get('malware')} | "
                        f"Confidence: {ioc_entry.get('confidence_level')}%"
                    ),
                    published_at=self._parse_iso(ioc_entry.get("first_seen")),
                    tags=self.tags,
                ))
        return items

    def _parse_csv(self, text: str) -> list[RawIntelItem]:
        """Parse URLhaus recent CSV feed."""
        items: list[RawIntelItem] = []
        reader = csv.DictReader(
            io.StringIO(text),
            fieldnames=["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"],
        )
        for row in reader:
            if row.get("id", "").startswith("#"):
                continue  # skip comment lines
            url_val = row.get("url", "").strip()
            if not url_val:
                continue
            items.append(RawIntelItem(
                source_name=self.source_name,
                source_url=row.get("urlhaus_link") or self.source_url or "",
                title=f"[URLhaus] {row.get('threat', 'malware')} - {url_val[:80]}",
                body=f"Malicious URL: {url_val} | Threat: {row.get('threat')} | Status: {row.get('url_status')}",
                published_at=self._parse_iso(row.get("dateadded")),
                tags=self.tags + [t.strip() for t in (row.get("tags") or "").split(",") if t.strip()],
            ))
            if len(items) >= 100:
                break
        return items

    def _parse_html(self, html: str) -> list[RawIntelItem]:
        """Generic HTML scraper using CSS selector from feed config."""
        selector = self.config.get("selector")
        if not selector:
            log.warning("No CSS selector for HTML scraper %s", self.source_name)
            return []

        soup = BeautifulSoup(html, "lxml")
        items: list[RawIntelItem] = []
        for link in soup.select(selector)[:20]:
            href = link.get("href", "")
            if not href.startswith("http"):
                from urllib.parse import urljoin
                href = urljoin(self.source_url or "", href)
            items.append(RawIntelItem(
                source_name=self.source_name,
                source_url=href,
                title=link.get_text(strip=True),
                body="",
                tags=self.tags,
            ))
        return items

    def _parse_iso(self, value: str | None) -> datetime | None:
        if not value:
            return None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        return None
