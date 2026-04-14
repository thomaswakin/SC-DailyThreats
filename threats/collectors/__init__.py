"""Collector factory - instantiates collectors from feeds.yaml config."""

from __future__ import annotations
import yaml
from pathlib import Path
from .base import BaseCollector
from .rss import RSSCollector
from .scraper import ScraperCollector
from .otx import OTXCollector


def load_collectors(feeds_path: str | Path = "config/feeds.yaml", lookback_hours: int = 72) -> list[BaseCollector]:
    """Read feeds.yaml and return a list of ready-to-run collector instances."""
    with open(feeds_path) as f:
        config = yaml.safe_load(f)

    collectors: list[BaseCollector] = []
    for feed in config.get("feeds", []):
        ctype = feed.get("collector", "rss")
        if ctype == "rss":
            collectors.append(RSSCollector(feed, lookback_hours=lookback_hours))
        elif ctype == "scraper":
            collectors.append(ScraperCollector(feed))
        elif ctype == "otx":
            collectors.append(OTXCollector(feed))
        else:
            import logging
            logging.getLogger(__name__).warning("Unknown collector type: %s for %s", ctype, feed.get("name"))

    return collectors
