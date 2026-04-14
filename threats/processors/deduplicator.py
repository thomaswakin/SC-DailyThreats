"""Within-run deduplication of raw intel items by source URL hash."""

from threats.models import RawIntelItem


class Deduplicator:
    """Filters items already seen in the DB or in the current batch."""

    def __init__(self, seen_urls: set[str]) -> None:
        # seed with hashes already stored in the DB (passed in by the caller)
        self._seen: set[str] = set(seen_urls)

    def filter(self, items: list[RawIntelItem]) -> list[RawIntelItem]:
        unique: list[RawIntelItem] = []
        for item in items:
            h = item.content_hash
            if h not in self._seen:
                self._seen.add(h)
                unique.append(item)
        return unique
