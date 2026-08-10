from __future__ import annotations

import asyncio
import logging

from telegram.ext import Application, CommandHandler

from bugcontrol.telegram import commands as cmds
from bugcontrol.telegram.alerts import format_finding_alert

logger = logging.getLogger(__name__)


def build_telegram_app(token: str, app_context: object) -> Application:
    application = (
        Application.builder()
        .token(token)
        .post_init(_make_post_init(app_context))
        .build()
    )
    application.bot_data["app"] = app_context

    handlers = [
        ("help", cmds.cmd_help),
        ("start", cmds.cmd_help),
        ("finding", cmds.cmd_finding),
        ("nmap", cmds.cmd_nmap),
        ("sqlmap", cmds.cmd_sqlmap),
        ("nikto", cmds.cmd_nikto),
        ("secrets", cmds.cmd_secrets),
        ("nuclei", cmds.cmd_nuclei),
        ("ai", cmds.cmd_ai),
        ("ai_resume", cmds.cmd_ai_resume),
        ("jobs", cmds.cmd_jobs),
        ("job", cmds.cmd_job),
        ("cancel", cmds.cmd_cancel),
        ("poll", cmds.cmd_poll),
    ]
    for name, handler in handlers:
        application.add_handler(CommandHandler(name, handler))
    return application


def _make_post_init(app_context: object):
    async def post_init(application: Application) -> None:
        notify_q = getattr(app_context, "notify_queue", None)
        if notify_q is not None:
            asyncio.create_task(
                _notify_pump(application, app_context, notify_q),
                name="bugcontrol-notify",
            )

    return post_init


async def _notify_pump(
    application: Application, app_context: object, queue: asyncio.Queue
) -> None:
    chat_id = getattr(getattr(app_context, "settings", None), "telegram_chat_id", "")
    while True:
        text = await queue.get()
        try:
            if chat_id:
                await application.bot.send_message(
                    chat_id=chat_id,
                    text=text,
                    parse_mode="Markdown",
                    disable_web_page_preview=True,
                )
        except Exception:
            logger.exception("failed sending job notify")
        finally:
            queue.task_done()


async def send_finding_alert(application: Application, chat_id: str, finding) -> None:
    text = format_finding_alert(finding)
    await application.bot.send_message(
        chat_id=chat_id,
        text=text,
        parse_mode="Markdown",
        disable_web_page_preview=True,
    )
