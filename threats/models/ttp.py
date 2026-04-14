from enum import Enum
from pydantic import BaseModel, field_validator


class MITRETactic(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class TTP(BaseModel):
    technique_id: str          # e.g. T1059.001
    tactic: MITRETactic | None = None
    name: str = ""
    description: str = ""
    platforms: list[str] = []  # windows, linux, macos, cloud, etc.

    @field_validator("technique_id", mode="before")
    @classmethod
    def normalize_id(cls, v: str) -> str:
        return v.strip().upper()

    @property
    def is_subtechnique(self) -> bool:
        return "." in self.technique_id
