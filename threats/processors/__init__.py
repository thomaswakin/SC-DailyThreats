"""Processing pipeline: raw items → enriched items."""

from __future__ import annotations
import logging
from threats.models import RawIntelItem, EnrichedIntelItem
from .ioc_extractor import extract_iocs
from .ttp_mapper import map_ttps
from .deduplicator import Deduplicator
from .llm_analyzer import LLMAnalyzer

log = logging.getLogger(__name__)


def run_pipeline(
    raw_items: list[RawIntelItem],
    seen_urls: set[str],
    llm_analyzer: LLMAnalyzer | None = None,
) -> list[EnrichedIntelItem]:
    """Run all processing steps and return enriched items."""
    dedup = Deduplicator(seen_urls)
    unique = dedup.filter(raw_items)
    log.info("Dedup: %d/%d items remain", len(unique), len(raw_items))

    enriched: list[EnrichedIntelItem] = []
    for raw in unique:
        item = EnrichedIntelItem(**raw.model_dump())
        item.iocs = extract_iocs(raw.body + " " + raw.title)
        item.ttps = map_ttps(raw.body + " " + raw.title)
        enriched.append(item)

    if llm_analyzer:
        enriched = llm_analyzer.enrich_batch(enriched)

    return enriched
