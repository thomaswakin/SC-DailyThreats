"""RSS/Atom feed collector using feedparser."""

import logging
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

import feedparser

from threats.models import RawIntelItem
from threats.utils.http import get_session
from .base import BaseCollector

log = logging.getLogger(__name__)

# Default: only collect items published within this window.
# Prevents ingesting years of blog archives on first run of a new feed.
_DEFAULT_LOOKBACK_HOURS = 72


class RSSCollector(BaseCollector):
    """Collects items from any RSS or Atom feed, filtered to recent entries only."""

    def __init__(self, config: dict, lookback_hours: int = _DEFAULT_LOOKBACK_HOURS) -> None:
        super().__init__(config)
        self._lookback_hours = lookback_hours

    def collect(self) -> list[RawIntelItem]:
        if not self.source_url:
            log.warning("No URL configured for %s", self.source_name)
            return []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=self._lookback_hours)

        log.info("Collecting RSS: %s (since %s)", self.source_name, cutoff.strftime("%Y-%m-%d %H:%M UTC"))
        try:
            session = get_session()
            resp = session.get(self.source_url)
            resp.raise_for_status()
        except Exception as exc:
            log.error("Failed to fetch %s: %s", self.source_name, exc)
            return []

        feed = feedparser.parse(resp.content)
        items: list[RawIntelItem] = []

        for entry in feed.entries:
            try:
                item = self._parse_entry(entry)
                # Skip items older than the lookback window.
                # Items with no date are included (some feeds omit dates).
                if item.published_at and item.published_at < cutoff:
                    continue
                items.append(item)
            except Exception as exc:
                log.debug("Failed to parse entry from %s: %s", self.source_name, exc)

        log.info("  -> %d items from %s", len(items), self.source_name)
        return items

    def _parse_entry(self, entry: feedparser.FeedParserDict) -> RawIntelItem:
        title = entry.get("title", "").strip()
        url = entry.get("link", "").strip()
        body = self._extract_body(entry)
        published_at = self._parse_date(entry)

        return RawIntelItem(
            source_name=self.source_name,
            source_url=url,
            title=title,
            body=body,
            published_at=published_at,
            tags=self.tags,
        )

    def _extract_body(self, entry: feedparser.FeedParserDict) -> str:
        # Try content first (full text), then summary
        if content := entry.get("content"):
            for c in content:
                if c.get("value"):
                    return self._strip_html(c["value"])
        if summary := entry.get("summary", ""):
            return self._strip_html(summary)
        return ""

    def _strip_html(self, html: str) -> str:
        from bs4 import BeautifulSoup
        return BeautifulSoup(html, "lxml").get_text(separator=" ", strip=True)

    def _parse_date(self, entry: feedparser.FeedParserDict) -> datetime | None:
        for field in ("published", "updated", "created"):
            raw = entry.get(f"{field}_parsed") or entry.get(field)
            if raw:
                try:
                    if isinstance(raw, str):
                        return parsedate_to_datetime(raw)
                    # feedparser returns time.struct_time
                    import time
                    return datetime.fromtimestamp(time.mktime(raw), tz=timezone.utc)
                except Exception:
                    pass
        return None
