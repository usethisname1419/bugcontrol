from __future__ import annotations

from abc import ABC, abstractmethod

from bugcontrol.models import ProgramRecord, ScopeRecord


class PlatformClient(ABC):
    name: str

    @abstractmethod
    def list_programs(self) -> list[ProgramRecord]:
        raise NotImplementedError

    @abstractmethod
    def list_scopes(self, program: ProgramRecord) -> list[ScopeRecord]:
        raise NotImplementedError
