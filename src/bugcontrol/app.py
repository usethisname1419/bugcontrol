from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from bugcontrol.agent.cursor_cloud import CursorCloudAgent
from bugcontrol.config import Settings, get_settings
from bugcontrol.db.store import Store
from bugcontrol.models import Finding
from bugcontrol.poller import Poller
from bugcontrol.scanners.runner import JobRunner
from bugcontrol.telegram.bot import build_telegram_app, send_finding_alert

logger = logging.getLogger(__name__)


@dataclass
class AppContext:
    settings: Settings
    store: Store
    jobs: JobRunner
    agent: CursorCloudAgent
    poller: Poller
    notify_queue: asyncio.Queue[str] = field(default_factory=asyncio.Queue)
    telegram_app: object | None = None
    scheduler: AsyncIOScheduler | None = None
    _loop: asyncio.AbstractEventLoop | None = None

    async def poll_now(self) -> list[Finding]:
        return await asyncio.to_thread(self.poller.run_once)

    def on_finding_sync(self, finding: Finding) -> None:
        """Called from poller thread; schedule alert on event loop."""
        if self._loop and self.telegram_app and self.settings.telegram_chat_id:
            asyncio.run_coroutine_threadsafe(
                self._alert(finding), self._loop
            )

    async def _alert(self, finding: Finding) -> None:
        try:
            await send_finding_alert(
                self.telegram_app,  # type: ignore[arg-type]
                self.settings.telegram_chat_id,
                finding,
            )
            self.store.mark_finding_alerted(finding.id)
        except Exception:
            logger.exception("failed to alert for %s", finding.id)


async def run_app() -> None:
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    settings.ensure_dirs()

    if not settings.telegram_bot_token:
        raise SystemExit("TELEGRAM_BOT_TOKEN is required")

    store = Store(settings)
    jobs = JobRunner(settings, store)
    agent = CursorCloudAgent(settings, store)
    ctx = AppContext(
        settings=settings,
        store=store,
        jobs=jobs,
        agent=agent,
        poller=Poller(settings, store, on_finding=None),
    )
    # Wire poller callback after ctx exists
    ctx.poller = Poller(settings, store, on_finding=ctx.on_finding_sync)
    jobs.set_notify_queue(ctx.notify_queue)

    telegram_app = build_telegram_app(settings.telegram_bot_token, ctx)
    ctx.telegram_app = telegram_app

    scheduler = AsyncIOScheduler()
    ctx.scheduler = scheduler

    async def scheduled_poll() -> None:
        logger.info("scheduled poll starting")
        findings = await ctx.poll_now()
        logger.info("scheduled poll finished: %s findings", len(findings))

    scheduler.add_job(
        scheduled_poll,
        "interval",
        minutes=max(1, settings.poll_interval_minutes),
        id="platform_poll",
        replace_existing=True,
    )

    await jobs.start()
    scheduler.start()
    ctx._loop = asyncio.get_running_loop()

    # Initial poll shortly after start (non-blocking)
    asyncio.create_task(scheduled_poll())

    logger.info(
        "bugcontrol starting; poll every %s minutes",
        settings.poll_interval_minutes,
    )
    try:
        await telegram_app.initialize()
        await telegram_app.start()
        assert telegram_app.updater is not None
        await telegram_app.updater.start_polling(drop_pending_updates=True)
        # Run forever
        await asyncio.Event().wait()
    finally:
        scheduler.shutdown(wait=False)
        await jobs.stop()
        if telegram_app.updater:
            await telegram_app.updater.stop()
        await telegram_app.stop()
        await telegram_app.shutdown()
        store.close()
