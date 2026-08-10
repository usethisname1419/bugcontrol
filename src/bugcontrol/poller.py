from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from datetime import datetime, timezone
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
        self._lock = threading.Lock()

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

    @staticmethod
    def _close_clients(clients: list[PlatformClient]) -> None:
        for client in clients:
            close = getattr(client, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    logger.exception("failed closing client %s", getattr(client, "name", "?"))

    def run_once(self) -> list[Finding]:
        # Bugcrowd scope crawl is slow; overlapping polls close each other's httpx clients.
        if not self._lock.acquire(blocking=False):
            logger.warning("poll already in progress; skipping this run")
            return []

        clients = self._build_clients()
        findings: list[Finding] = []
        try:
            bootstrap = self.store.get_meta("bootstrap_complete") != "1"
            if bootstrap:
                logger.info("bootstrap poll: seeding programs/scopes without alerts")

            for client in clients:
                try:
                    findings.extend(
                        self._poll_platform(client, alert=not bootstrap, bootstrap=bootstrap)
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
            return findings if not bootstrap else []
        finally:
            self._close_clients(clients)
            self._lock.release()

    def _should_fetch_scopes(
        self, platform: str, handle: str, *, is_new_program: bool, bootstrap: bool
    ) -> bool:
        if bootstrap or is_new_program:
            return True
        key = f"scope_sync:{platform}:{handle}"
        last = self.store.get_meta(key)
        if not last:
            return True
        try:
            last_dt = datetime.fromisoformat(last)
            if last_dt.tzinfo is None:
                last_dt = last_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return True
        age = (datetime.now(timezone.utc) - last_dt).total_seconds()
        return age >= self.settings.scope_refresh_hours * 3600

    def _mark_scopes_synced(self, platform: str, handle: str) -> None:
        self.store.set_meta(
            f"scope_sync:{platform}:{handle}",
            datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        )

    def _poll_platform(
        self,
        client: PlatformClient,
        *,
        alert: bool = True,
        bootstrap: bool = False,
    ) -> list[Finding]:
        logger.info("polling %s", client.name)
        programs = client.list_programs()
        known = self.store.known_program_handles(client.name)  # type: ignore[arg-type]
        findings: list[Finding] = []
        scopes_fetched = 0
        scopes_skipped = 0

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

            if not self._should_fetch_scopes(
                program.platform,
                program.handle,
                is_new_program=is_new_program,
                bootstrap=bootstrap,
            ):
                scopes_skipped += 1
                continue

            try:
                scopes = client.list_scopes(program)
                scopes_fetched += 1
                self._mark_scopes_synced(program.platform, program.handle)
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
            "%s: %s programs, scopes_fetched=%s skipped=%s findings=%s",
            client.name,
            len(programs),
            scopes_fetched,
            scopes_skipped,
            len(findings),
        )
        return findings

    def _emit(self, finding: Finding) -> None:
        if not self.on_finding:
            return
        try:
            result = self.on_finding(finding)
            if result is not None and hasattr(result, "__await__"):
                pass
        except Exception:
            logger.exception("alert callback failed for %s", finding.id)
