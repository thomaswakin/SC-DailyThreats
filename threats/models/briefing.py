from datetime import date, datetime
from pydantic import BaseModel
from .intel_item import EnrichedIntelItem
from .ioc import IOC, IOCType
from .ttp import TTP
from .threat_actor import ThreatActor


class SigmaRule(BaseModel):
    """A generated Sigma detection rule."""
    rule_id: str               # UUID
    title: str
    description: str
    status: str = "experimental"
    author: str = "ThreatIntelBot"
    date: str = ""             # YYYY/MM/DD
    logsource: dict = {}
    detection: dict = {}
    falsepositives: list[str] = []
    level: str = "medium"      # low | medium | high | critical
    tags: list[str] = []       # MITRE tags e.g. attack.t1059.001
    related_source_url: str = ""
    yaml_content: str = ""     # Fully rendered YAML string
    # FP review fields (populated by SigmaReviewer after generation)
    fp_risk: str = ""          # low | medium | high
    fp_notes: str = ""         # 1-2 sentences on what legitimate activity triggers this
    expiry_days: int | None = None  # Recommended days to keep rule active (None = no expiry)
    reviewed: bool = False     # Whether the FP review pass ran
    output_path: str = ""      # Absolute path to the written YAML file
    # Versioning fields
    version: int = 1                   # Incremented when rule is updated with new source data
    modified: str = ""                 # YYYY/MM/DD of last update (empty if version==1)
    source_count: int = 1             # Number of distinct intel sources backing this rule
    stable_key: str = ""              # Stable identity key for versioning lookups


class IOCCounts(BaseModel):
    total: int = 0
    new: int = 0
    reobserved: int = 0
    by_type: dict[str, int] = {}


class IncidentCluster(BaseModel):
    """A group of intel items from multiple sources covering the same attack/campaign."""
    cluster_id: int
    name: str
    source_count: int
    sources: list[str] = []         # distinct source_name values
    items: list[EnrichedIntelItem] = []
    iocs: list[IOC] = []            # union of all IOCs across items
    ttps: list[TTP] = []            # union of all TTPs across items
    first_seen: datetime
    last_seen: datetime

    @property
    def is_multi_source(self) -> bool:
        return self.source_count > 1

    @property
    def severity(self) -> float:
        return max((i.severity for i in self.items), default=0.0)


class DailyBriefing(BaseModel):
    """Top-level container for a single day's threat intelligence output."""
    briefing_date: date
    generated_at: datetime
    # Clustered view — primary output
    clusters: list[IncidentCluster] = []
    # Raw items not yet in a multi-source cluster (singletons)
    items: list[EnrichedIntelItem] = []
    # Threat actors
    new_actors: list[ThreatActor] = []
    returning_actors: list[ThreatActor] = []
    # IOCs split by new vs re-observed across previous runs
    new_iocs: list[IOC] = []
    reobserved_iocs: list[IOC] = []
    # TTPs split by new vs re-observed
    new_ttps: list[TTP] = []
    reobserved_ttps: list[TTP] = []
    # Sigma rules generated only for NEW items this run
    sigma_rules: list[SigmaRule] = []
    ioc_export_path: str = ""         # Path to the generated IOC ZIP file
    ioc_counts: IOCCounts = IOCCounts()
    executive_summary: str = ""
    since_label: str = ""          # Human-readable "since" window e.g. "2026-03-11 14:00 UTC"
    llm_warning: str = ""          # Set when LLM is unavailable (e.g. depleted credits)

    @property
    def all_actors(self) -> list[ThreatActor]:
        return self.new_actors + self.returning_actors

    @property
    def multi_source_clusters(self) -> list[IncidentCluster]:
        return [c for c in self.clusters if c.is_multi_source]

    @property
    def singleton_clusters(self) -> list[IncidentCluster]:
        return [c for c in self.clusters if not c.is_multi_source]

    @property
    def critical_items(self) -> list[EnrichedIntelItem]:
        return [i for i in self.items if i.severity >= 0.8]

    @property
    def high_items(self) -> list[EnrichedIntelItem]:
        return [i for i in self.items if 0.6 <= i.severity < 0.8]

    @property
    def is_empty(self) -> bool:
        """True when no new data has been collected since the last run."""
        return not self.items and not self.new_iocs and not self.new_ttps and not self.new_actors

    def compute_ioc_counts(self) -> None:
        counts: dict[str, int] = {}
        for ioc in self.new_iocs + self.reobserved_iocs:
            counts[ioc.type.value] = counts.get(ioc.type.value, 0) + 1
        self.ioc_counts = IOCCounts(
            total=len(self.new_iocs) + len(self.reobserved_iocs),
            new=len(self.new_iocs),
            reobserved=len(self.reobserved_iocs),
            by_type=counts,
        )
