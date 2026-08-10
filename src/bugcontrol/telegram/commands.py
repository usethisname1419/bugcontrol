from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from telegram import Update
from telegram.ext import ContextTypes

from bugcontrol.telegram.alerts import format_finding_detail

if TYPE_CHECKING:
    from bugcontrol.app import AppContext

logger = logging.getLogger(__name__)

HELP = """\
*Bugcontrol commands*
`/help` — this message
`/finding <id>` — show finding + scopes
`/nmap <id>` `/sqlmap <id>` `/nikto <id>` `/secrets <id>`
`/ai <id>` — launch Cursor cloud agent
`/ai_resume <id> <message>` — continue agent
`/jobs` — recent jobs
`/job <job_id>` — job detail
`/cancel <job_id>` — cancel queued/running job
`/poll` — run platform poll now
"""


def _ctx(context: ContextTypes.DEFAULT_TYPE) -> "AppContext":
    return context.application.bot_data["app"]


async def require_auth(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    app = _ctx(context)
    user = update.effective_user
    if not user:
        return False
    allowed = app.settings.allowed_user_ids()
    if allowed and user.id not in allowed:
        if update.message:
            await update.message.reply_text("Unauthorized.")
        return False
    return True


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await require_auth(update, context):
        return
    assert update.message
    await update.message.reply_text(HELP, parse_mode="Markdown")


async def cmd_finding(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await require_auth(update, context):
        return
    assert update.message
    if not context.args:
        await update.message.reply_text("Usage: /finding <id>")
        return
    app = _ctx(context)
    finding = app.store.get_finding(context.args[0])
    if not finding:
        await update.message.reply_text("Finding not found.")
        return
    scopes = app.store.in_scope_assets_for_program(
        finding.platform, finding.program_handle
    )
    scope_lines = [
        f"`{r['asset_type']}` {r['asset_identifier']}" for r in scopes[:40]
    ]
    jobs = app.store.list_jobs_for_finding(finding.id)
    job_lines = [f"`{j['id']}` {j['tool']} {j['status']}" for j in jobs]
    await update.message.reply_text(
        format_finding_detail(finding, scope_lines, job_lines),
        parse_mode="Markdown",
        disable_web_page_preview=True,
    )


async def _enqueue_tool(
    update: Update, context: ContextTypes.DEFAULT_TYPE, tool: str
) -> None:
    if not await require_auth(update, context):
        return
    assert update.message
    if not context.args:
        await update.message.reply_text(f"Usage: /{tool} <finding_id>")
        return
    app = _ctx(context)
    finding_id = context.args[0]
    if not app.store.get_finding(finding_id):
        await update.message.reply_text("Finding not found.")
        return
    job_id = await app.jobs.enqueue(finding_id, tool)
    await update.message.reply_text(
        f"Queued `{tool}` as `{job_id}` for `{finding_id}`",
        parse_mode="Markdown",
    )


async def cmd_nmap(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _enqueue_tool(update, context, "nmap")


async def cmd_sqlmap(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _enqueue_tool(update, context, "sqlmap")


async def cmd_nikto(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _enqueue_tool(update, context, "nikto")


async def cmd_secrets(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _enqueue_tool(update, context, "secrets")


async def cmd_ai(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await require_auth(update, context):
        return
    assert update.message
    if not context.args:
        await update.message.reply_text("Usage: /ai <finding_id>")
        return
    app = _ctx(context)
    finding_id = context.args[0]
    if not app.store.get_finding(finding_id):
        await update.message.reply_text("Finding not found.")
        return
    await update.message.reply_text(
        f"Launching Cursor cloud agent for `{finding_id}`…",
        parse_mode="Markdown",
    )
    try:
        run_pk = await app.agent.launch(finding_id)
        run = app.store.get_agent_run(run_pk)
        summary = (run["summary"] if run else "") or ""
        dash = (run["dashboard_url"] if run else "") or ""
        text = f"Agent run `{run_pk}` finished.\n"
        if dash:
            text += f"Dashboard: {dash}\n"
        text += f"```\n{summary[:3000]}\n```"
        await update.message.reply_text(text, parse_mode="Markdown")
    except Exception as exc:
        await update.message.reply_text(f"AI launch failed: {exc}")


async def cmd_ai_resume(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await require_auth(update, context):
        return
    assert update.message
    if len(context.args) < 2:
        await update.message.reply_text("Usage: /ai_resume <finding_id> <message>")
        return
    app = _ctx(context)
    finding_id = context.args[0]
    message = " ".join(context.args[1:])
    try:
        run_pk = await app.agent.resume(finding_id, message)
        run = app.store.get_agent_run(run_pk)
        summary = (run["summary"] if run else "") or ""
        await update.message.reply_text(
            f"Resume `{run_pk}` done.\n```\n{summary[:3000]}\n```",
            parse_mode="Markdown",
        )
    except Exception as exc:
        await update.message.reply_text(f"AI resume failed: {exc}")


async def cmd_jobs(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await require_auth(update, context):
        return
    assert update.message
    app = _ctx(context)
    rows = app.store.list_jobs(20)
    if not rows:
        await update.message.reply_text("No jobs yet.")
        return
    lines = [
        f"`{r['id']}` {r['tool']} {r['status']} finding=`{r['finding_id']}`"
        for r in rows
    ]
    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")


async def cmd_job(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await require_auth(update, context):
        return
    assert update.message
    if not context.args:
        await update.message.reply_text("Usage: /job <job_id>")
        return
    app = _ctx(context)
    job = app.store.get_job(context.args[0])
    if not job:
        await update.message.reply_text("Job not found.")
        return
    text = (
        f"*Job* `{job['id']}`\n"
        f"Tool: `{job['tool']}` Status: `{job['status']}`\n"
        f"Finding: `{job['finding_id']}`\n"
        f"Log: `{job['log_path'] or '-'}`\n"
        f"Error: `{job['error'] or '-'}`\n"
        f"```\n{(job['summary'] or '')[:2500]}\n```"
    )
    await update.message.reply_text(text, parse_mode="Markdown")


async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await require_auth(update, context):
        return
    assert update.message
    if not context.args:
        await update.message.reply_text("Usage: /cancel <job_id>")
        return
    app = _ctx(context)
    ok = app.jobs.cancel(context.args[0])
    await update.message.reply_text("Cancelled." if ok else "Could not cancel.")


async def cmd_poll(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await require_auth(update, context):
        return
    assert update.message
    app = _ctx(context)
    await update.message.reply_text("Polling platforms…")
    findings = await app.poll_now()
    await update.message.reply_text(f"Poll done. New findings: {len(findings)}")
