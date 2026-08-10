from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

Platform = Literal["hackerone", "bugcrowd", "yeswehack"]
FindingKind = Literal["new_program", "new_scope", "scope_change"]
JobStatus = Literal["queued", "running", "completed", "failed", "cancelled"]
AgentStatus = Literal["queued", "running", "finished", "error", "cancelled"]


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(slots=True)
class ProgramRecord:
    platform: Platform
    handle: str
    name: str = ""
    url: str = ""
    offers_bounties: bool = False


@dataclass(slots=True)
class ScopeRecord:
    platform: Platform
    program_handle: str
    asset_identifier: str
    asset_type: str = ""
    external_id: str = ""
    eligible_for_bounty: bool = False
    eligible_for_submission: bool = True
    in_scope: bool = True
    instruction: str = ""

    def fingerprint(self) -> str:
        parts = [
            self.platform,
            self.program_handle.lower(),
            self.asset_type.lower(),
            self.asset_identifier.strip().lower(),
            self.external_id,
        ]
        return "|".join(parts)


@dataclass(slots=True)
class Finding:
    id: str
    kind: FindingKind
    platform: Platform
    program_handle: str
    program_name: str = ""
    program_url: str = ""
    scope_id: int | None = None
    asset_identifier: str = ""
    asset_type: str = ""
    eligible_for_bounty: bool = False
    summary: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    alerted_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
