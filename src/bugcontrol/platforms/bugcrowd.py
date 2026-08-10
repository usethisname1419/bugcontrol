from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from bugcontrol.config import Settings
from bugcontrol.models import ProgramRecord, ScopeRecord
from bugcontrol.platforms.base import PlatformClient

logger = logging.getLogger(__name__)

BC_BASE = "https://api.bugcrowd.com"


class BugcrowdClient(PlatformClient):
    name = "bugcrowd"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._client = httpx.Client(
            base_url=BC_BASE,
            headers={
                "Accept": "application/vnd.bugcrowd+json",
                "Authorization": f"Token {settings.bugcrowd_token}",
            },
            timeout=60.0,
        )

    def close(self) -> None:
        self._client.close()

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        for attempt in range(5):
            resp = self._client.get(path, params=params)
            if resp.status_code == 429:
                retry = float(resp.headers.get("Retry-After", 2 ** attempt))
                logger.warning("Bugcrowd rate limited; sleeping %.1fs", retry)
                time.sleep(retry)
                continue
            resp.raise_for_status()
            return resp.json()
        resp.raise_for_status()
        return {}

    def list_programs(self) -> list[ProgramRecord]:
        if not self.settings.bugcrowd_token:
            logger.warning("Bugcrowd token missing; skipping")
            return []

        try:
            programs = self._list_engagements()
            if programs:
                return programs
        except httpx.HTTPError as exc:
            logger.warning("Bugcrowd engagements fetch failed: %s; trying /programs", exc)

        return self._list_legacy_programs()

    def _list_engagements(self) -> list[ProgramRecord]:
        programs: list[ProgramRecord] = []
        offset = 0
        limit = 100
        while True:
            data = self._get(
                "/engagements",
                params={"page[offset]": offset, "page[limit]": limit},
            )
            items = data.get("data") or []
            if not items:
                break
            for item in items:
                attrs = item.get("attributes") or {}
                code = (
                    attrs.get("code")
                    or attrs.get("slug")
                    or attrs.get("name")
                    or item.get("id")
                    or ""
                )
                if not code:
                    continue
                handle = str(code)
                url = (
                    attrs.get("brief_url")
                    or attrs.get("url")
                    or f"https://bugcrowd.com/{handle}"
                )
                programs.append(
                    ProgramRecord(
                        platform="bugcrowd",
                        handle=handle,
                        name=str(attrs.get("name") or handle),
                        url=str(url),
                        offers_bounties=str(attrs.get("category") or "").lower()
                        in ("bug_bounty", "bounty"),
                    )
                )
            if len(items) < limit:
                break
            offset += limit
        return programs

    def _list_legacy_programs(self) -> list[ProgramRecord]:
        programs: list[ProgramRecord] = []
        offset = 0
        limit = 100
        while True:
            data = self._get(
                "/programs",
                params={
                    "page[offset]": offset,
                    "page[limit]": limit,
                    "include": "current_brief.target_groups.targets",
                },
            )
            items = data.get("data") or []
            if not items:
                break
            for item in items:
                attrs = item.get("attributes") or {}
                handle = str(attrs.get("code") or attrs.get("name") or item.get("id") or "")
                if not handle:
                    continue
                programs.append(
                    ProgramRecord(
                        platform="bugcrowd",
                        handle=handle,
                        name=str(attrs.get("name") or handle),
                        url=f"https://bugcrowd.com/{handle}",
                        offers_bounties=True,
                    )
                )
            if len(items) < limit:
                break
            offset += limit
        return programs

    def list_scopes(self, program: ProgramRecord) -> list[ScopeRecord]:
        scopes: list[ScopeRecord] = []
        try:
            scopes.extend(self._scopes_from_engagement(program))
        except httpx.HTTPError as exc:
            logger.debug("engagement scopes failed for %s: %s", program.handle, exc)

        if scopes:
            return scopes

        try:
            scopes.extend(self._scopes_from_program(program))
        except httpx.HTTPError as exc:
            logger.warning("program scopes failed for %s: %s", program.handle, exc)
        return scopes

    def _scopes_from_engagement(self, program: ProgramRecord) -> list[ScopeRecord]:
        scopes: list[ScopeRecord] = []
        data = self._get(
            f"/engagements/{program.handle}",
            params={"include": "targets,target_groups.targets"},
        )
        included = data.get("included") or []
        for item in included:
            if item.get("type") not in ("target", "targets"):
                continue
            attrs = item.get("attributes") or {}
            name = attrs.get("name") or attrs.get("uri") or attrs.get("identifier") or ""
            if not name:
                continue
            in_scope = attrs.get("in_scope")
            if in_scope is None:
                in_scope = True
            scopes.append(
                ScopeRecord(
                    platform="bugcrowd",
                    program_handle=program.handle,
                    asset_identifier=str(name),
                    asset_type=str(attrs.get("category") or attrs.get("type") or ""),
                    external_id=str(item.get("id") or ""),
                    eligible_for_bounty=bool(attrs.get("eligible_for_bounty", True)),
                    eligible_for_submission=bool(in_scope),
                    in_scope=bool(in_scope),
                    instruction=str(attrs.get("description") or ""),
                )
            )
        return scopes

    def _scopes_from_program(self, program: ProgramRecord) -> list[ScopeRecord]:
        scopes: list[ScopeRecord] = []
        data = self._get(
            f"/programs/{program.handle}",
            params={"include": "current_brief.target_groups.targets"},
        )
        included = data.get("included") or []
        for item in included:
            if item.get("type") not in ("target", "targets"):
                continue
            attrs = item.get("attributes") or {}
            name = attrs.get("name") or attrs.get("uri") or attrs.get("identifier") or ""
            if not name:
                continue
            scopes.append(
                ScopeRecord(
                    platform="bugcrowd",
                    program_handle=program.handle,
                    asset_identifier=str(name),
                    asset_type=str(attrs.get("category") or attrs.get("type") or ""),
                    external_id=str(item.get("id") or ""),
                    eligible_for_bounty=True,
                    eligible_for_submission=True,
                    in_scope=True,
                    instruction=str(attrs.get("description") or ""),
                )
            )
        return scopes
