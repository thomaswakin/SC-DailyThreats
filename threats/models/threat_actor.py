from datetime import datetime, timezone
from pydantic import BaseModel


class ThreatActor(BaseModel):
    name: str
    aliases: list[str] = []
    description: str = ""
    motivation: str = ""          # espionage, financial, hacktivism, etc.
    origin: str = ""              # country / region attribution
    targeted_sectors: list[str] = []
    targeted_regions: list[str] = []
    confidence: float = 0.5       # attribution confidence 0.0–1.0
    first_seen: datetime = None   # type: ignore[assignment]
    last_seen: datetime = None    # type: ignore[assignment]
    is_new: bool = False          # True if first seen today

    def model_post_init(self, __context: object) -> None:
        now = datetime.now(timezone.utc)
        if self.first_seen is None:
            object.__setattr__(self, "first_seen", now)
        if self.last_seen is None:
            object.__setattr__(self, "last_seen", now)

    @property
    def all_names(self) -> list[str]:
        return [self.name] + self.aliases
