"""Abstract base collector interface."""

from abc import ABC, abstractmethod
from threats.models import RawIntelItem


class BaseCollector(ABC):
    def __init__(self, config: dict) -> None:
        self.config = config
        self.source_name: str = config.get("name", "unknown")
        self.source_url: str | None = config.get("url")
        self.reliability: str = config.get("reliability", "medium")
        self.tags: list[str] = config.get("tags", [])

    @abstractmethod
    def collect(self) -> list[RawIntelItem]:
        """Fetch and return raw intel items. Must not raise on network errors."""
        ...

    def _base_confidence(self) -> float:
        return {"authoritative": 0.9, "high": 0.75, "medium": 0.5, "low": 0.3}.get(
            self.reliability, 0.5
        )
