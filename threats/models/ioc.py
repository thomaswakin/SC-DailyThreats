from enum import Enum
from datetime import datetime, timezone
from pydantic import BaseModel, field_validator


class IOCType(str, Enum):
    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    EMAIL = "EMAIL"
    FILENAME = "FILENAME"
    REGISTRY = "REGISTRY"


_HASH_TYPES = {"MD5", "SHA1", "SHA256"}


class IOC(BaseModel):
    type: IOCType
    value: str
    confidence: float = 0.5  # 0.0 – 1.0
    source: str = ""
    first_seen: datetime = None  # type: ignore[assignment]
    last_seen: datetime = None   # type: ignore[assignment]
    tags: list[str] = []
    likely_fp: bool = False           # True if heuristics suggest false positive
    context_dependent: bool = False   # True if FP-prone alone; only useful combined with other indicators
    source_count: int = 1             # Number of distinct sources that reported this IOC
    specificity: str = "unknown"      # attack_specific | ambiguous | normal | unknown
    specificity_note: str = ""        # Brief LLM rationale for specificity verdict

    def model_post_init(self, __context: object) -> None:
        now = datetime.now(timezone.utc)
        if self.first_seen is None:
            object.__setattr__(self, "first_seen", now)
        if self.last_seen is None:
            object.__setattr__(self, "last_seen", now)

    @field_validator("value", mode="before")
    @classmethod
    def defang(cls, v: str) -> str:
        """Normalize defanged IOCs back to fanged form."""
        return (
            v.strip()
            .replace("[.]", ".")
            .replace("(.)", ".")
            .replace("[dot]", ".")
            .replace("hxxp", "http")
            .replace("hXXp", "http")
        )

    @field_validator("confidence", mode="before")
    @classmethod
    def clamp_confidence(cls, v: float) -> float:
        return max(0.0, min(1.0, float(v)))

    @property
    def uid(self) -> str:
        """Stable unique identifier for dedup."""
        return f"{self.type.value}:{self.value.lower()}"

    @property
    def fidelity(self) -> str:
        """
        Fidelity label: high | medium | low | fp

        Combines source_count, confidence, IOC type, and attack specificity:
        - Hashes are inherently attack-specific — fidelity driven by source count alone
        - context_dependent or LLM-confirmed normal activity → low regardless of source count
        - Research-confirmed attack_specific boosts single-source IOCs to medium
        - Multi-source (3+) or 2+ sources with high confidence → high
        """
        if self.likely_fp:
            return "fp"
        if self.context_dependent or self.specificity == "normal":
            return "low"
        # Hashes are always attack-specific by definition
        if self.type.value in _HASH_TYPES:
            if self.source_count >= 3:
                return "high"
            return "medium"
        # Multi-source consensus drives high fidelity
        if self.source_count >= 3 or (self.source_count >= 2 and self.confidence >= 0.7):
            return "high"
        # Two sources OR high confidence OR research-confirmed attack-specific → medium
        if self.source_count >= 2 or self.confidence >= 0.7 or self.specificity == "attack_specific":
            return "medium"
        return "low"
