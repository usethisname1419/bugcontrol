from __future__ import annotations

import json
import logging
import re
import time
from typing import Any
from urllib.parse import urljoin

import httpx

from bugcontrol.config import Settings
from bugcontrol.models import ProgramRecord, ScopeRecord
from bugcontrol.platforms.base import PlatformClient

logger = logging.getLogger(__name__)

BC_WEB = "https://bugcrowd.com"
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)
MIN_REQUEST_INTERVAL = 1.05

API_ENDPOINTS_RE = re.compile(
    r'data-api-endpoints=(["\'])(?P<json>.*?)\1',
    re.IGNORECASE | re.DOTALL,
)


def _normalize_handle(brief: str) -> str:
    brief = brief.strip()
    if brief.startswith("http://") or brief.startswith("https://"):
        # https://bugcrowd.com/engagements/foo -> /engagements/foo
        parts = brief.split("bugcrowd.com", 1)
        path = parts[1] if len(parts) == 2 else brief
        return path if path.startswith("/") else f"/{path}"
    return brief if brief.startswith("/") else f"/{brief}"


class BugcrowdClient(PlatformClient):
    """Public Bugcrowd portal client — no login required for open programs/scopes."""

    name = "bugcrowd"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        # Optional: if set, may surface invite-only engagements too.
        session = (settings.bugcrowd_session or "").strip()
        if session.lower().startswith("_bugcrowd_session="):
            session = session.split("=", 1)[1].split(";", 1)[0].strip()
        self._session = session
        self._last_request = 0.0
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/html, */*",
        }
        if self._session:
            headers["Cookie"] = f"_bugcrowd_session={self._session}"
        self._client = httpx.Client(
            base_url=BC_WEB,
            headers=headers,
            timeout=60.0,
            follow_redirects=True,
        )

    def close(self) -> None:
        self._client.close()

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < MIN_REQUEST_INTERVAL:
            time.sleep(MIN_REQUEST_INTERVAL - elapsed)
        self._last_request = time.monotonic()

    def _get(self, path: str, *, accept: str | None = None) -> httpx.Response:
        headers = {"Accept": accept} if accept else None
        for attempt in range(5):
            self._throttle()
            resp = self._client.get(path, headers=headers)
            if resp.status_code in (403, 406):
                raise httpx.HTTPStatusError(
                    "Bugcrowd WAF blocked request (403/406). Wait or change IP.",
                    request=resp.request,
                    response=resp,
                )
            if resp.status_code == 429:
                time.sleep(float(resp.headers.get("Retry-After", 2 ** attempt)))
                continue
            return resp
        return resp

    def list_programs(self) -> list[ProgramRecord]:
        programs: list[ProgramRecord] = []
        seen: set[str] = set()
        for category in ("bug_bounty", "vdp"):
            try:
                for prog in self._list_engagements(category):
                    if prog.handle in seen:
                        continue
                    seen.add(prog.handle)
                    programs.append(prog)
            except Exception:
                logger.exception("Bugcrowd list failed for category=%s", category)
        return programs

    def _list_engagements(self, category: str) -> list[ProgramRecord]:
        programs: list[ProgramRecord] = []
        page = 1
        while page <= 200:
            resp = self._get(
                f"/engagements.json?category={category}"
                f"&sort_by=promoted&sort_direction=desc&page={page}"
            )
            resp.raise_for_status()
            data = resp.json()
            engagements = data.get("engagements") or []
            if not engagements:
                break
            for item in engagements:
                brief = str(item.get("briefUrl") or "").strip()
                if not brief:
                    continue
                handle = _normalize_handle(brief)
                name = str(
                    item.get("name")
                    or item.get("programName")
                    or item.get("code")
                    or handle
                )
                programs.append(
                    ProgramRecord(
                        platform="bugcrowd",
                        handle=handle,
                        name=name,
                        url=urljoin(BC_WEB, handle),
                        offers_bounties=category == "bug_bounty",
                    )
                )
            page += 1
        return programs

    def list_scopes(self, program: ProgramRecord) -> list[ScopeRecord]:
        handle = program.handle
        try:
            if "/engagements/" in handle:
                return self._scopes_from_engagement(program)
            return self._scopes_from_legacy_program(program)
        except Exception:
            logger.exception("Bugcrowd scope fetch failed for %s", handle)
            return []

    def _scopes_from_engagement(self, program: ProgramRecord) -> list[ScopeRecord]:
        handle = program.handle if program.handle.startswith("/") else f"/{program.handle}"
        resp = self._get(handle, accept="*/*")
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        html = resp.text
        m = API_ENDPOINTS_RE.search(html)
        if not m:
            logger.debug("no data-api-endpoints on %s", handle)
            return []
        endpoints_raw = (
            m.group("json")
            .replace("&quot;", '"')
            .replace("&#39;", "'")
            .replace("&amp;", "&")
        )
        try:
            endpoints = json.loads(endpoints_raw)
        except json.JSONDecodeError:
            logger.warning("bad data-api-endpoints JSON on %s", handle)
            return []

        brief_path = (
            (endpoints.get("engagementBriefApi") or {}).get("getBriefVersionDocument")
            or ""
        )
        if not brief_path:
            return []
        if not brief_path.endswith(".json"):
            brief_path = f"{brief_path}.json"

        brief_resp = self._get(brief_path, accept="*/*")
        if brief_resp.status_code == 404:
            return []
        brief_resp.raise_for_status()
        return self._parse_brief_scope(program, brief_resp.json())

    def _parse_brief_scope(
        self, program: ProgramRecord, payload: dict[str, Any]
    ) -> list[ScopeRecord]:
        scopes: list[ScopeRecord] = []
        data = payload.get("data") or payload
        for group in data.get("scope") or []:
            in_scope = bool(group.get("inScope", True))
            for target in group.get("targets") or []:
                uri = str(target.get("uri") or "").strip()
                name = str(target.get("name") or "").strip()
                identifier = uri or name
                if not identifier:
                    continue
                scopes.append(
                    ScopeRecord(
                        platform="bugcrowd",
                        program_handle=program.handle,
                        asset_identifier=identifier,
                        asset_type=str(target.get("category") or ""),
                        external_id=str(target.get("id") or ""),
                        eligible_for_bounty=program.offers_bounties and in_scope,
                        eligible_for_submission=in_scope,
                        in_scope=in_scope,
                        instruction=str(target.get("description") or ""),
                    )
                )
        return scopes

    def _scopes_from_legacy_program(self, program: ProgramRecord) -> list[ScopeRecord]:
        base = program.handle if program.handle.startswith("/") else f"/{program.handle}"
        path = base.rstrip("/")
        resp = self._get(f"{path}/target_groups", accept="*/*")
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        data = resp.json()
        scopes: list[ScopeRecord] = []
        for group in data.get("groups") or []:
            in_scope = bool(group.get("in_scope", True))
            targets_url = group.get("targets_url") or ""
            if not targets_url:
                continue
            t_resp = self._get(targets_url, accept="*/*")
            if t_resp.status_code >= 400:
                continue
            for target in (t_resp.json().get("targets") or []):
                uri = str(target.get("uri") or "").strip()
                name = str(target.get("name") or "").strip()
                identifier = uri or name
                if not identifier:
                    continue
                scopes.append(
                    ScopeRecord(
                        platform="bugcrowd",
                        program_handle=program.handle,
                        asset_identifier=identifier,
                        asset_type=str(target.get("category") or ""),
                        external_id=str(target.get("id") or ""),
                        eligible_for_bounty=program.offers_bounties and in_scope,
                        eligible_for_submission=in_scope,
                        in_scope=in_scope,
                        instruction=str(target.get("description") or ""),
                    )
                )
        return scopes
