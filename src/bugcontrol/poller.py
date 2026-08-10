from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Awaitable

from bugcontrol.config import Settings
from bugcontrol.db.store import Store
from bugcontrol.models import Finding
from bugcontrol.platforms.base import PlatformClient
from bugcontrol.platforms.bugcrowd import BugcrowdClient
from bugcontrol.platforms.hackerone import HackerOneClient
from bugcontrol.platforms.yeswehack import YesWeHackClient

logger = logging.getLogger(__name__)

AlertCallback = Callable[[Finding], Awaitable[None] | None]


class Poller:
    def __init__(
        self,
        settings: Settings,
        store: Store,
        on_finding: AlertCallback | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.on_finding = on_finding
        self._clients: list[PlatformClient] = []

    def _build_clients(self) -> list[PlatformClient]:
        clients: list[PlatformClient] = []
        for name in self.settings.platforms():
            if name == "hackerone":
                clients.append(HackerOneClient(self.settings))
            elif name == "bugcrowd":
                clients.append(BugcrowdClient(self.settings))
            elif name == "yeswehack":
                clients.append(YesWeHackClient(self.settings))
        return clients

    def close(self) -> None:
        for client in self._clients:
            close = getattr(client, "close", None)
            if callable(close):
                close()
        self._clients.clear()

    def run_once(self) -> list[Finding]:
        findings: list[Finding] = []
        # First successful poll seeds the DB without Telegram spam.
        bootstrap = self.store.get_meta("bootstrap_complete") != "1"
        if bootstrap:
            logger.info("bootstrap poll: seeding programs/scopes without alerts")
        self._clients = self._build_clients()
        try:
            for client in self._clients:
                try:
                    findings.extend(
                        self._poll_platform(client, alert=not bootstrap)
                    )
                except Exception:
                    logger.exception("poll failed for platform %s", client.name)
            if bootstrap:
                self.store.set_meta("bootstrap_complete", "1")
                logger.info(
                    "bootstrap complete; seeded %s findings (no alerts)",
                    len(findings),
                )
            self.store.enforce_storage_budget()
        finally:
            self.close()
        return findings if not bootstrap else []

    def _poll_platform(
        self, client: PlatformClient, *, alert: bool = True
    ) -> list[Finding]:
        logger.info("polling %s", client.name)
        programs = client.list_programs()
        known = self.store.known_program_handles(client.name)  # type: ignore[arg-type]
        findings: list[Finding] = []

        for program in programs:
            is_new_program = program.handle not in known
            program_id = self.store.upsert_program(program)

            if is_new_program:
                finding = self.store.create_finding(
                    kind="new_program",
                    platform=program.platform,
                    program_handle=program.handle,
                    program_name=program.name,
                    program_url=program.url,
                    summary=f"New {program.platform} program: {program.name}",
                    details={"offers_bounties": program.offers_bounties},
                )
                findings.append(finding)
                if alert:
                    self._emit(finding)
                known.add(program.handle)

            try:
                scopes = client.list_scopes(program)
            except Exception:
                logger.exception(
                    "failed listing scopes for %s/%s",
                    program.platform,
                    program.handle,
                )
                continue

            for scope in scopes:
                if not scope.in_scope:
                    continue
                scope_id, is_new, changed = self.store.upsert_scope(program_id, scope)
                if is_new:
                    finding = self.store.create_finding(
                        kind="new_scope",
                        platform=program.platform,
                        program_handle=program.handle,
                        program_name=program.name,
                        program_url=program.url,
                        scope_id=scope_id,
                        asset_identifier=scope.asset_identifier,
                        asset_type=scope.asset_type,
                        eligible_for_bounty=scope.eligible_for_bounty,
                        summary=(
                            f"New scope on {program.handle}: {scope.asset_identifier}"
                        ),
                        details={
                            "instruction": scope.instruction,
                            "external_id": scope.external_id,
                        },
                    )
                    findings.append(finding)
                    if alert:
                        self._emit(finding)
                elif changed:
                    finding = self.store.create_finding(
                        kind="scope_change",
                        platform=program.platform,
                        program_handle=program.handle,
                        program_name=program.name,
                        program_url=program.url,
                        scope_id=scope_id,
                        asset_identifier=scope.asset_identifier,
                        asset_type=scope.asset_type,
                        eligible_for_bounty=scope.eligible_for_bounty,
                        summary=(
                            f"Scope changed on {program.handle}: "
                            f"{scope.asset_identifier}"
                        ),
                        details={
                            "instruction": scope.instruction,
                            "external_id": scope.external_id,
                        },
                    )
                    findings.append(finding)
                    if alert:
                        self._emit(finding)

        logger.info(
            "%s: %s programs, %s findings",
            client.name,
            len(programs),
            len(findings),
        )
        return findings

    def _emit(self, finding: Finding) -> None:
        if not self.on_finding:
            return
        try:
            result = self.on_finding(finding)
            # Support async callbacks scheduled by the app layer.
            if result is not None and hasattr(result, "__await__"):
                # Caller is responsible for awaiting; sync path ignores.
                pass
        except Exception:
            logger.exception("alert callback failed for %s", finding.id)
