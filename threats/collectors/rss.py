"""RSS/Atom feed collector using feedparser."""

import logging
import time
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

import feedparser
from bs4 import BeautifulSoup

from threats.models import RawIntelItem
from threats.utils.http import get_session
from .base import BaseCollector

log = logging.getLogger(__name__)

# Default: only collect items published within this window.
# Prevents ingesting years of blog archives on first run of a new feed.
_DEFAULT_LOOKBACK_HOURS = 72

# If the RSS entry body is shorter than this, fetch the full article page.
# Most teaser-only feeds deliver < 150 chars; real content is typically > 1000.
_MIN_BODY_CHARS = 300

# Candidate selectors tried in order when extracting article body from a page.
# Covers the blog platforms used by Wiz, Unit 42, ESET, Red Canary, Huntress, etc.
_ARTICLE_SELECTORS = [
    "article",
    "main",
    "[class*='post-content']",
    "[class*='entry-content']",
    "[class*='article-body']",
    "[class*='blog-content']",
    "[class*='content-body']",
    "[class*='prose']",
    "[role='main']",
]

# Tags to strip entirely (navigation, chrome, non-content)
_STRIP_TAGS = {"script", "style", "nav", "header", "footer", "aside",
               "form", "button", "noscript", "iframe", "svg"}


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

        # If the feed only delivered a teaser, fetch the full article page.
        if len(body) < _MIN_BODY_CHARS and url:
            full = self._fetch_full_article(url)
            if full:
                body = full

        return RawIntelItem(
            source_name=self.source_name,
            source_url=url,
            title=title,
            body=body,
            published_at=published_at,
            tags=self.tags,
        )

    def _extract_body(self, entry: feedparser.FeedParserDict) -> str:
        """Extract body text from the RSS entry itself (no network call)."""
        if content := entry.get("content"):
            for c in content:
                if c.get("value"):
                    return self._strip_html(c["value"])
        if summary := entry.get("summary", ""):
            return self._strip_html(summary)
        return ""

    def _fetch_full_article(self, url: str) -> str:
        """
        Fetch the article page at `url` and extract the main content text.
        Returns empty string on any failure so the caller can keep the short body.
        Respects a 1-second delay to avoid hammering source sites.
        """
        try:
            time.sleep(1)
            session = get_session()
            resp = session.get(url, timeout=20)
            resp.raise_for_status()
        except Exception as exc:
            log.debug("Full-article fetch failed for %s: %s", url, exc)
            return ""

        try:
            soup = BeautifulSoup(resp.text, "lxml")

            # Remove non-content elements in place
            for tag in soup.find_all(_STRIP_TAGS):
                tag.decompose()

            # Try candidate selectors in order; take the first substantial match
            for selector in _ARTICLE_SELECTORS:
                el = soup.select_one(selector)
                if el:
                    text = el.get_text(separator=" ", strip=True)
                    if len(text) >= _MIN_BODY_CHARS:
                        log.debug("Full article fetched via '%s' selector: %s (%d chars)",
                                  selector, url, len(text))
                        return text

            # Last resort: concatenate all <p> tags with meaningful text
            paragraphs = [
                p.get_text(separator=" ", strip=True)
                for p in soup.find_all("p")
                if len(p.get_text(strip=True)) > 60
            ]
            text = " ".join(paragraphs)
            if text:
                log.debug("Full article fetched via <p> fallback: %s (%d chars)", url, len(text))
            return text

        except Exception as exc:
            log.debug("Full-article parse failed for %s: %s", url, exc)
            return ""

    def _strip_html(self, html: str) -> str:
        return BeautifulSoup(html, "lxml").get_text(separator=" ", strip=True)

    def _parse_date(self, entry: feedparser.FeedParserDict) -> datetime | None:
        for field in ("published", "updated", "created"):
            raw = entry.get(f"{field}_parsed") or entry.get(field)
            if raw:
                try:
                    if isinstance(raw, str):
                        return parsedate_to_datetime(raw)
                    import time as _time
                    return datetime.fromtimestamp(_time.mktime(raw), tz=timezone.utc)
                except Exception:
                    pass
        return None
