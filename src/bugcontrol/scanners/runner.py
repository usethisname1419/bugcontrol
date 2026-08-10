from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path
from urllib.parse import urlparse

from bugcontrol.config import Settings
from bugcontrol.db.store import Store
from bugcontrol.models import utcnow

logger = logging.getLogger(__name__)

WILDCARD_RE = re.compile(r"^\*\.")


def filter_scannable_targets(targets: list[str], tool: str) -> list[str]:
    """Keep concrete hosts/URLs; drop bare wildcards unless tool can use them."""
    out: list[str] = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        if WILDCARD_RE.match(t) and tool not in ("nuclei",):
            # nuclei may accept wildcard DNS in some setups; skip for other tools
            continue
        if tool == "nmap":
            host = _to_host(t)
            if host and not WILDCARD_RE.match(host):
                out.append(host)
        elif tool in ("sqlmap", "nikto", "nuclei"):
            if t.startswith("http://") or t.startswith("https://"):
                out.append(t)
            elif "." in t and not WILDCARD_RE.match(t):
                out.append(f"https://{t}")
        elif tool == "secrets":
            # secrets scanners need a path or URL; keep URLs/hosts as-is for remote fetchers
            out.append(t)
        else:
            out.append(t)
    # dedupe preserve order
    seen: set[str] = set()
    unique: list[str] = []
    for t in out:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


def _to_host(value: str) -> str:
    if "://" in value:
        return urlparse(value).hostname or ""
    return value.split("/")[0].split(":")[0]


class JobRunner:
    def __init__(self, settings: Settings, store: Store) -> None:
        self.settings = settings
        self.store = store
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._workers: list[asyncio.Task[None]] = []
        self._cancel: set[str] = set()
        self._notify: asyncio.Queue[str] | None = None

    def set_notify_queue(self, q: asyncio.Queue[str]) -> None:
        """Queue of Telegram-facing status messages."""
        self._notify = q

    async def start(self) -> None:
        n = max(1, self.settings.scan_concurrency)
        for i in range(n):
            self._workers.append(asyncio.create_task(self._worker(i), name=f"scan-{i}"))

    async def stop(self) -> None:
        for w in self._workers:
            w.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

    async def enqueue(self, finding_id: str, tool: str) -> str:
        targets = filter_scannable_targets(
            self.store.resolve_scan_targets(finding_id), tool
        )
        job_id = self.store.create_job(finding_id, tool, targets)
        await self._queue.put(job_id)
        return job_id

    def cancel(self, job_id: str) -> bool:
        job = self.store.get_job(job_id)
        if not job:
            return False
        if job["status"] == "queued":
            self._cancel.add(job_id)
            self.store.update_job(job_id, status="cancelled", finished_at=utcnow())
            return True
        if job["status"] == "running":
            self._cancel.add(job_id)
            return True
        return False

    async def _worker(self, worker_id: int) -> None:
        while True:
            job_id = await self._queue.get()
            try:
                if job_id in self._cancel:
                    self._cancel.discard(job_id)
                    continue
                await self._run_job(job_id)
            except Exception:
                logger.exception("worker %s failed on job %s", worker_id, job_id)
            finally:
                self._queue.task_done()

    async def _run_job(self, job_id: str) -> None:
        job = self.store.get_job(job_id)
        if not job or job["status"] in ("cancelled", "completed", "failed"):
            return

        import json

        targets = json.loads(job["targets_json"] or "[]")
        tool = job["tool"]
        finding_id = job["finding_id"]

        if not targets:
            self.store.update_job(
                job_id,
                status="failed",
                finished_at=utcnow(),
                error="no scannable in-scope targets",
                summary="No scannable targets",
            )
            await self._notify_msg(
                f"Job `{job_id}` ({tool}) failed: no scannable targets for `{finding_id}`"
            )
            return

        out_dir = self.settings.artifact_dir / finding_id
        out_dir.mkdir(parents=True, exist_ok=True)
        log_path = out_dir / f"{job_id}_{tool}.log"

        self.store.update_job(
            job_id, status="running", started_at=utcnow(), log_path=str(log_path)
        )
        await self._notify_msg(
            f"Job `{job_id}` running `{tool}` on {len(targets)} target(s) for `{finding_id}`"
        )

        cmd = self._build_command(tool, targets, out_dir)
        if not cmd:
            self.store.update_job(
                job_id,
                status="failed",
                finished_at=utcnow(),
                error=f"unknown tool {tool}",
            )
            return

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=str(out_dir),
            )
        except FileNotFoundError:
            self.store.update_job(
                job_id,
                status="failed",
                finished_at=utcnow(),
                error=f"binary not found for {tool}; check PATH / .env",
            )
            await self._notify_msg(
                f"Job `{job_id}` failed: `{tool}` binary not found on PATH"
            )
            return

        max_bytes = self.settings.artifact_max_bytes_per_job
        written = 0
        timed_out = False
        try:
            assert proc.stdout is not None
            with log_path.open("wb") as fh:
                while True:
                    if job_id in self._cancel:
                        proc.kill()
                        self._cancel.discard(job_id)
                        self.store.update_job(
                            job_id,
                            status="cancelled",
                            finished_at=utcnow(),
                            summary="cancelled",
                        )
                        await self._notify_msg(f"Job `{job_id}` cancelled")
                        return
                    try:
                        chunk = await asyncio.wait_for(
                            proc.stdout.read(8192),
                            timeout=self.settings.scan_timeout_seconds,
                        )
                    except asyncio.TimeoutError:
                        proc.kill()
                        timed_out = True
                        break
                    if not chunk:
                        break
                    remain = max_bytes - written
                    if remain <= 0:
                        fh.write(b"\n...truncated...\n")
                        proc.kill()
                        break
                    to_write = chunk[:remain]
                    fh.write(to_write)
                    written += len(to_write)
            exit_code = await proc.wait()
        except Exception as exc:
            self.store.update_job(
                job_id,
                status="failed",
                finished_at=utcnow(),
                error=str(exc),
            )
            await self._notify_msg(f"Job `{job_id}` failed: {exc}")
            return

        size = log_path.stat().st_size if log_path.exists() else 0
        self.store.add_artifact(finding_id, log_path, size, job_id=job_id)

        summary = self._summarize_log(log_path)
        if timed_out:
            status = "failed"
            error = "timeout"
            summary = f"TIMEOUT\n{summary}"
        else:
            status = "completed" if exit_code == 0 else "failed"
            error = "" if exit_code == 0 else f"exit {exit_code}"

        self.store.update_job(
            job_id,
            status=status,
            finished_at=utcnow(),
            exit_code=exit_code if not timed_out else -1,
            summary=summary[:3500],
            error=error,
        )
        await self._notify_msg(
            f"Job `{job_id}` {status} (`{tool}`)\n```\n{summary[:1500]}\n```"
        )
        self.store.enforce_storage_budget()

    def _build_command(
        self, tool: str, targets: list[str], out_dir: Path
    ) -> list[str] | None:
        s = self.settings
        if tool == "nmap":
            return [s.nmap_bin, "-sV", "-T4", "-oN", "-", *targets[:50]]
        if tool == "sqlmap":
            # Conservative: batch, crawl lightly, one URL at a time via -m list
            list_file = out_dir / "sqlmap_targets.txt"
            list_file.write_text("\n".join(targets[:20]), encoding="utf-8")
            return [
                s.sqlmap_bin,
                "-m",
                str(list_file),
                "--batch",
                "--crawl=1",
                "--level=1",
                "--risk=1",
                "--threads=2",
            ]
        if tool == "nikto":
            # Nikto takes one host; scan first target (multi-target via loop later if needed)
            return [s.nikto_bin, "-h", targets[0], "-output", "-", "-Format", "txt"]
        if tool == "nuclei":
            list_file = out_dir / "nuclei_targets.txt"
            list_file.write_text("\n".join(targets[:100]), encoding="utf-8")
            return [
                s.nuclei_bin,
                "-l",
                str(list_file),
                "-silent",
                "-nc",
            ]
        if tool == "secrets":
            if s.secrets_scanner == "trufflehog":
                # Prefer git URL or filesystem; for hosts, skip with message
                return [s.trufflehog_bin, "filesystem", str(out_dir)]
            return [s.gitleaks_bin, "dir", str(out_dir), "--no-banner"]
        return None

    def _summarize_log(self, log_path: Path, max_lines: int = 40) -> str:
        try:
            text = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return "(no log)"
        lines = [ln for ln in text.splitlines() if ln.strip()]
        if not lines:
            return "(empty output)"
        tail = lines[-max_lines:]
        return "\n".join(tail)

    async def _notify_msg(self, text: str) -> None:
        if self._notify is not None:
            await self._notify.put(text)
