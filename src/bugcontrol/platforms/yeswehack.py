from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from bugcontrol.config import Settings
from bugcontrol.models import ProgramRecord, ScopeRecord
from bugcontrol.platforms.base import PlatformClient

logger = logging.getLogger(__name__)

YWH_BASE = "https://api.yeswehack.com"


class YesWeHackClient(PlatformClient):
    name = "yeswehack"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._client = httpx.Client(
            base_url=YWH_BASE,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {settings.yeswehack_token}",
            },
            timeout=60.0,
        )

    def close(self) -> None:
        self._client.close()

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        for attempt in range(5):
            resp = self._client.get(path, params=params)
            if resp.status_code == 429:
                retry = float(resp.headers.get("Retry-After", 2 ** attempt))
                logger.warning("YesWeHack rate limited; sleeping %.1fs", retry)
                time.sleep(retry)
                continue
            resp.raise_for_status()
            return resp.json()
        resp.raise_for_status()
        return {}

    def list_programs(self) -> list[ProgramRecord]:
        if not self.settings.yeswehack_token:
            logger.warning("YesWeHack token missing; skipping")
            return []

        programs: list[ProgramRecord] = []
        page = 1
        while True:
            data = self._get("/programs", params={"page": page})
            items = data.get("items") if isinstance(data, dict) else None
            if items is None and isinstance(data, list):
                items = data
            items = items or []
            if not items:
                break
            for item in items:
                slug = (
                    item.get("slug")
                    or item.get("id")
                    or item.get("title")
                    or ""
                )
                if not slug:
                    continue
                handle = str(slug)
                bounty = item.get("bounty") or item.get("disabled") is False
                programs.append(
                    ProgramRecord(
                        platform="yeswehack",
                        handle=handle,
                        name=str(item.get("title") or handle),
                        url=f"https://yeswehack.com/programs/{handle}",
                        offers_bounties=bool(bounty),
                    )
                )
            # Pagination: stop when page empty or pagination says last
            pagination = data.get("pagination") if isinstance(data, dict) else None
            if pagination and page >= int(pagination.get("nb_pages") or page):
                break
            if len(items) < 20:
                break
            page += 1
        return programs

    def list_scopes(self, program: ProgramRecord) -> list[ScopeRecord]:
        data = self._get(f"/programs/{program.handle}")
        scopes: list[ScopeRecord] = []
        raw_scopes = []
        if isinstance(data, dict):
            raw_scopes = (
                data.get("scopes")
                or data.get("scope")
                or (data.get("program") or {}).get("scopes")
                or []
            )
        for item in raw_scopes:
            if not isinstance(item, dict):
                continue
            identifier = (
                item.get("scope")
                or item.get("asset_value")
                or item.get("value")
                or item.get("name")
                or ""
            )
            if not identifier:
                continue
            scope_type = str(
                item.get("scope_type")
                or item.get("type")
                or item.get("asset_type")
                or ""
            )
            scopes.append(
                ScopeRecord(
                    platform="yeswehack",
                    program_handle=program.handle,
                    asset_identifier=str(identifier),
                    asset_type=scope_type,
                    external_id=str(item.get("id") or ""),
                    eligible_for_bounty=bool(
                        item.get("bounty") is not False
                        and item.get("eligible_for_bounty", True)
                    ),
                    eligible_for_submission=True,
                    in_scope=True,
                    instruction=str(item.get("description") or ""),
                )
            )
        return scopes
