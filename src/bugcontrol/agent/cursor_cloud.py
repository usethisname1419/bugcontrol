from __future__ import annotations

import asyncio
import logging
from typing import Any

from bugcontrol.config import Settings
from bugcontrol.db.store import Store
from bugcontrol.models import Finding, utcnow

logger = logging.getLogger(__name__)


def build_agent_prompt(store: Store, finding: Finding) -> str:
    scopes = store.in_scope_assets_for_program(finding.platform, finding.program_handle)
    scope_lines = []
    for row in scopes[:200]:
        bounty = "bounty" if row["eligible_for_bounty"] else "no-bounty"
        scope_lines.append(
            f"- [{row['asset_type']}] {row['asset_identifier']} ({bounty})"
        )
    jobs = store.list_jobs_for_finding(finding.id, limit=5)
    job_lines = []
    for j in jobs:
        job_lines.append(
            f"- {j['id']} {j['tool']} {j['status']}: {(j['summary'] or '')[:200]}"
        )

    return f"""You are assisting with authorized bug bounty reconnaissance only.

Program: {finding.program_name} ({finding.program_handle})
Platform: {finding.platform}
Program URL: {finding.program_url}
Finding ID: {finding.id}
Finding kind: {finding.kind}
Primary asset: {finding.asset_identifier or '(program-level)'}
Summary: {finding.summary}

In-scope assets:
{chr(10).join(scope_lines) or '(none stored yet)'}

Recent local scan jobs:
{chr(10).join(job_lines) or '(none)'}

Tasks:
1. Triage the attack surface from the in-scope list.
2. Propose a prioritized, policy-respecting test plan (recon → auth → injection → business logic).
3. Call out high-value assets and likely tech stack guesses.
4. Do NOT attack out-of-scope assets. Do NOT suggest illegal activity.
5. Write a short markdown note summarizing the plan (create `notes/{finding.id}.md` if the workspace allows).

Return a concise summary suitable to paste into Telegram.
"""


class CursorCloudAgent:
    def __init__(self, settings: Settings, store: Store) -> None:
        self.settings = settings
        self.store = store

    def enabled(self) -> bool:
        return bool(self.settings.cursor_api_key and self.settings.cursor_agent_repo)

    async def launch(self, finding_id: str) -> str:
        finding = self.store.get_finding(finding_id)
        if not finding:
            raise ValueError(f"unknown finding {finding_id}")
        if not self.enabled():
            raise RuntimeError(
                "CURSOR_API_KEY and CURSOR_AGENT_REPO must be set for /ai"
            )

        prompt = build_agent_prompt(self.store, finding)
        run_pk = self.store.create_agent_run(finding_id, prompt)
        self.store.update_agent_run(run_pk, status="running")

        try:
            summary, agent_id, run_id = await asyncio.to_thread(
                self._run_cloud_sync, prompt
            )
            dashboard = (
                f"https://cursor.com/agents?agentId={agent_id}" if agent_id else ""
            )
            self.store.update_agent_run(
                run_pk,
                status="finished",
                agent_id=agent_id,
                run_id=run_id,
                summary=summary[:8000],
                dashboard_url=dashboard,
                finished_at=utcnow(),
            )
            return run_pk
        except Exception as exc:
            logger.exception("cursor agent failed")
            self.store.update_agent_run(
                run_pk,
                status="error",
                error=str(exc),
                finished_at=utcnow(),
            )
            raise

    async def resume(self, finding_id: str, message: str) -> str:
        latest = self.store.latest_agent_run_for_finding(finding_id)
        if not latest or not latest["agent_id"]:
            raise ValueError("no prior agent run with agent_id for this finding")
        if not self.settings.cursor_api_key:
            raise RuntimeError("CURSOR_API_KEY required")

        run_pk = self.store.create_agent_run(finding_id, message)
        self.store.update_agent_run(
            run_pk, status="running", agent_id=latest["agent_id"]
        )
        try:
            summary, agent_id, run_id = await asyncio.to_thread(
                self._resume_cloud_sync, latest["agent_id"], message
            )
            dashboard = (
                f"https://cursor.com/agents?agentId={agent_id}" if agent_id else ""
            )
            self.store.update_agent_run(
                run_pk,
                status="finished",
                agent_id=agent_id,
                run_id=run_id,
                summary=summary[:8000],
                dashboard_url=dashboard,
                finished_at=utcnow(),
            )
            return run_pk
        except Exception as exc:
            self.store.update_agent_run(
                run_pk,
                status="error",
                error=str(exc),
                finished_at=utcnow(),
            )
            raise

    def _run_cloud_sync(self, prompt: str) -> tuple[str, str, str]:
        from cursor_sdk import Agent, CloudAgentOptions, CursorAgentError

        try:
            with Agent.create(
                api_key=self.settings.cursor_api_key,
                model=self.settings.cursor_model,
                cloud=CloudAgentOptions(
                    repos=[
                        {
                            "url": self.settings.cursor_agent_repo,
                            "starting_ref": self.settings.cursor_agent_ref,
                        }
                    ],
                    skip_reviewer_request=True,
                ),
            ) as agent:
                agent_id = str(getattr(agent, "agent_id", "") or "")
                run = agent.send(prompt)
                result = run.wait()
                return _result_tuple(result, agent_id)
        except CursorAgentError as err:
            raise RuntimeError(
                f"cursor startup failed: {err.message} retryable={err.is_retryable}"
            ) from err

    def _resume_cloud_sync(self, agent_id: str, message: str) -> tuple[str, str, str]:
        from cursor_sdk import Agent, AgentOptions, CursorAgentError

        try:
            with Agent.resume(
                agent_id,
                AgentOptions(api_key=self.settings.cursor_api_key),
            ) as agent:
                run = agent.send(message)
                result = run.wait()
                return _result_tuple(result, agent_id)
        except CursorAgentError as err:
            raise RuntimeError(
                f"cursor resume failed: {err.message} retryable={err.is_retryable}"
            ) from err


def _result_tuple(result: Any, fallback_agent_id: str) -> tuple[str, str, str]:
    status = getattr(result, "status", None)
    run_id = str(getattr(result, "id", "") or "")
    agent_id = str(getattr(result, "agent_id", "") or fallback_agent_id)
    text = str(getattr(result, "result", "") or "")
    if status == "error":
        raise RuntimeError(f"cursor run error: {run_id}")
    if not text:
        text = f"(finished with empty result; run_id={run_id})"
    return text, agent_id, run_id
