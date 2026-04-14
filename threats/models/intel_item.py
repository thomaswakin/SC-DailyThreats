from datetime import datetime, timezone
from pydantic import BaseModel
from .ioc import IOC
from .ttp import TTP
from .threat_actor import ThreatActor


class RawIntelItem(BaseModel):
    """Unprocessed item straight from a collector."""
    source_name: str
    source_url: str
    title: str
    body: str = ""
    published_at: datetime | None = None
    fetched_at: datetime = None  # type: ignore[assignment]
    tags: list[str] = []

    def model_post_init(self, __context: object) -> None:
        if self.fetched_at is None:
            object.__setattr__(self, "fetched_at", datetime.now(timezone.utc))

    @property
    def content_hash(self) -> str:
        """SHA-256 of URL for dedup (cheap, stable)."""
        import hashlib
        return hashlib.sha256(self.source_url.encode()).hexdigest()


class EnrichedIntelItem(RawIntelItem):
    """Processed item with extracted IOCs, TTPs, actors, and LLM summary."""
    iocs: list[IOC] = []
    ttps: list[TTP] = []
    actors: list[ThreatActor] = []
    summary: str = ""             # LLM-generated analyst summary
    severity: float = 0.0         # 0.0–1.0
    confidence: float = 0.5       # overall confidence in enrichment
    targeted_sectors: list[str] = []
    targeted_regions: list[str] = []
    llm_enriched: bool = False
    detection_artifacts: list[dict] = []  # LLM-extracted per-TTP detection conditions
    campaign_names: list[str] = []        # Operation/campaign identifiers (LLM-extracted)
    malware_families: list[str] = []      # Malware family names (LLM-extracted)

    @property
    def has_active_iocs(self) -> bool:
        return len(self.iocs) > 0

    @property
    def severity_label(self) -> str:
        if self.severity >= 0.8:
            return "CRITICAL"
        elif self.severity >= 0.6:
            return "HIGH"
        elif self.severity >= 0.4:
            return "MEDIUM"
        elif self.severity >= 0.2:
            return "LOW"
        return "INFORMATIONAL"
