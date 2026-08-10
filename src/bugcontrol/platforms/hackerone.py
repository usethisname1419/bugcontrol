from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from bugcontrol.config import Settings
from bugcontrol.models import ProgramRecord, ScopeRecord
from bugcontrol.platforms.base import PlatformClient

logger = logging.getLogger(__name__)

H1_BASE = "https://api.hackerone.com/v1"


class HackerOneClient(PlatformClient):
    name = "hackerone"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._client = httpx.Client(
            base_url=H1_BASE,
            auth=(settings.h1_username, settings.h1_api_token),
            headers={"Accept": "application/json"},
            timeout=60.0,
        )
        self._last_scope_call = 0.0
        self._min_scope_interval = 60.0 / 45.0  # stay under 50 rpm

    def close(self) -> None:
        self._client.close()

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        for attempt in range(5):
            resp = self._client.get(path, params=params)
            if resp.status_code == 429:
                retry = float(resp.headers.get("Retry-After", 2 ** attempt))
                logger.warning("H1 rate limited; sleeping %.1fs", retry)
                time.sleep(retry)
                continue
            resp.raise_for_status()
            return resp.json()
        resp.raise_for_status()
        return {}

    def list_programs(self) -> list[ProgramRecord]:
        if not self.settings.h1_username or not self.settings.h1_api_token:
            logger.warning("HackerOne credentials missing; skipping")
            return []

        programs: list[ProgramRecord] = []
        page = 1
        while True:
            data = self._get(
                "/hackers/programs",
                params={"page[number]": page, "page[size]": 100},
            )
            items = data.get("data") or []
            if not items:
                break
            for item in items:
                attrs = item.get("attributes") or {}
                handle = attrs.get("handle") or item.get("id") or ""
                if not handle:
                    continue
                programs.append(
                    ProgramRecord(
                        platform="hackerone",
                        handle=str(handle),
                        name=str(attrs.get("name") or handle),
                        url=f"https://hackerone.com/{handle}",
                        offers_bounties=bool(attrs.get("offers_bounties")),
                    )
                )
            links = data.get("links") or {}
            if not links.get("next"):
                break
            page += 1
        return programs

    def _throttle_scopes(self) -> None:
        elapsed = time.monotonic() - self._last_scope_call
        if elapsed < self._min_scope_interval:
            time.sleep(self._min_scope_interval - elapsed)
        self._last_scope_call = time.monotonic()

    def list_scopes(self, program: ProgramRecord) -> list[ScopeRecord]:
        scopes: list[ScopeRecord] = []
        page = 1
        while True:
            self._throttle_scopes()
            data = self._get(
                f"/hackers/programs/{program.handle}/structured_scopes",
                params={"page[number]": page, "page[size]": 100},
            )
            items = data.get("data") or []
            if not items:
                break
            for item in items:
                attrs = item.get("attributes") or {}
                identifier = attrs.get("asset_identifier") or ""
                if not identifier:
                    continue
                scopes.append(
                    ScopeRecord(
                        platform="hackerone",
                        program_handle=program.handle,
                        asset_identifier=str(identifier),
                        asset_type=str(attrs.get("asset_type") or ""),
                        external_id=str(item.get("id") or ""),
                        eligible_for_bounty=bool(attrs.get("eligible_for_bounty")),
                        eligible_for_submission=bool(
                            attrs.get("eligible_for_submission", True)
                        ),
                        in_scope=True,
                        instruction=str(attrs.get("instruction") or ""),
                    )
                )
            links = data.get("links") or {}
            if not links.get("next"):
                break
            page += 1
        return scopes
