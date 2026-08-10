from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from bugcontrol.config import Settings
from bugcontrol.db.store import Store
from bugcontrol.models import Finding, utcnow

logger = logging.getLogger(__name__)

# Cap evidence so prompts stay within model context on a cheap VPS flow.
_MAX_JOBS = 8
_MAX_LOG_CHARS_PER_JOB = 3500
_MAX_SCOPE_LINES = 250


def _read_log_excerpt(path: str | None, limit: int = _MAX_LOG_CHARS_PER_JOB) -> str:
    if not path:
        return ""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[: limit // 2] + "\n...\n" + text[-limit // 2 :]


def build_evidence_pack(store: Store, finding: Finding) -> str:
    scopes = store.in_scope_assets_for_program(finding.platform, finding.program_handle)
    scope_lines = []
    for row in scopes[:_MAX_SCOPE_LINES]:
        bounty = "bounty" if row["eligible_for_bounty"] else "no-bounty"
        scope_lines.append(
            f"- [{row['asset_type']}] {row['asset_identifier']} ({bounty})"
            + (f" — {row['instruction'][:120]}" if row["instruction"] else "")
        )

    jobs = store.list_jobs_for_finding(finding.id, limit=_MAX_JOBS)
    evidence_blocks: list[str] = []
    for j in jobs:
        header = (
            f"### Job {j['id']} | tool={j['tool']} | status={j['status']} "
            f"| exit={j['exit_code']}"
        )
        summary = (j["summary"] or "").strip()
        log_excerpt = _read_log_excerpt(j["log_path"])
        body = summary
        if log_excerpt and log_excerpt not in summary:
            body = f"{summary}\n\nLOG EXCERPT:\n{log_excerpt}".strip()
        evidence_blocks.append(f"{header}\n{body or '(empty)'}")

    return f"""## Target program
- Platform: {finding.platform}
- Program: {finding.program_name} ({finding.program_handle})
- URL: {finding.program_url}
- Finding ID: {finding.id}
- Kind: {finding.kind}
- Primary asset: {finding.asset_identifier or '(program-level)'}
- Alert summary: {finding.summary}

## In-scope assets (authorized only)
{chr(10).join(scope_lines) or '(none stored yet)'}

## Local scanner evidence (from hunter VPS)
{chr(10).join(evidence_blocks) or '(no scans yet — reason from scope alone; call out which scans to run next)'}
"""


def build_agent_prompt(store: Store, finding: Finding) -> str:
    evidence = build_evidence_pack(store, finding)
    return f"""You are an expert bug-bounty hunter agent operating under authorized program rules only.

Your job is NOT to write a generic recon checklist. Your job is to **find plausible, high-signal vulnerabilities** (or clear leads with concrete next probes) for this program using the evidence below.

{evidence}

## Rules
1. Stay strictly in-scope. Never suggest attacking out-of-scope assets, third parties, or illegal activity.
2. Prefer concrete findings over vague advice. If evidence is thin, produce ranked hypotheses with exact requests/checks.
3. Treat secrets hits, open ports, interesting headers, and JS leaks as attack leads — chain them into exploit paths when possible.
4. Do not invent confirmed vulns without evidence; label confidence: CONFIRMED / LIKELY / HYPOTHESIS.
5. Respect common BB policy: no DoS, no destructive actions, no spam, no social engineering.

## Hunt priorities (work top-down)
1. Exposed secrets / API keys / tokens in JS (from /secrets evidence) → impact + abuse path
2. Authn/authz flaws: IDOR, BOLA, privilege escalation, broken session handling
3. Injection: SQLi, XSS, SSRF, command injection on in-scope inputs
4. Misconfig: debug endpoints, open admin, CORS, exposed .git/.env, verbose errors
5. Business logic: payment, invite, password reset, file upload, rate-limit bypasses

## Deliverable (required format)
Write `notes/{finding.id}-hunt.md` in the repo with:

# Hunt report — {finding.program_handle} ({finding.id})

## Executive summary
(2-5 sentences)

## Findings
For each finding:
### [CONFIDENCE] Title
- Asset:
- Type:
- Evidence:
- Impact:
- Reproduction steps: (numbered, specific)
- Remediation:

## Dead ends / ruled out
## Recommended next VPS commands
(e.g. `/nmap {finding.id}`, `/sqlmap {finding.id}`, `/secrets {finding.id}`, `/ai_resume {finding.id} ...`)

## Telegram brief
A short plain-text block (max ~1500 chars) summarizing the best findings for pasting into Telegram.

Return that Telegram brief as your final assistant message (keep it tight and actionable).
"""


def build_resume_prompt(finding_id: str, user_message: str) -> str:
    return f"""Continue the authorized bug hunt for finding `{finding_id}`.

Hunter follow-up instruction:
{user_message}

Update `notes/{finding_id}-hunt.md` if you refine findings.
Return an updated Telegram brief (max ~1500 chars) as your final message.
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

        prompt = build_resume_prompt(finding_id, message)
        run_pk = self.store.create_agent_run(finding_id, prompt)
        self.store.update_agent_run(
            run_pk, status="running", agent_id=latest["agent_id"]
        )
        try:
            summary, agent_id, run_id = await asyncio.to_thread(
                self._resume_cloud_sync, latest["agent_id"], prompt
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
