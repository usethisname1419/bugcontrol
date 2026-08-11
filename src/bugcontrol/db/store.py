from __future__ import annotations

import json
import logging
import secrets
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from bugcontrol.config import Settings
from bugcontrol.models import Finding, FindingKind, Platform, ProgramRecord, ScopeRecord, utcnow

logger = logging.getLogger(__name__)

SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def new_finding_id() -> str:
    # No underscore: Telegram legacy Markdown treats _text_ as italic and corrupts cmds.
    return f"f{secrets.token_hex(3)}"


def new_job_id() -> str:
    return f"j_{secrets.token_hex(4)}"


def new_agent_run_id() -> str:
    return f"a_{secrets.token_hex(4)}"


class Store:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        settings.ensure_dirs()
        self.path = settings.db_path
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
        self._conn.executescript(schema)
        page_size = self._conn.execute("PRAGMA page_size").fetchone()[0]
        max_pages = max(1, self.settings.db_max_bytes // int(page_size))
        self._conn.execute(f"PRAGMA max_page_count = {max_pages}")
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def connection(self) -> sqlite3.Connection:
        return self._conn

    # --- programs / scopes -------------------------------------------------

    def upsert_program(self, program: ProgramRecord) -> int:
        now = utcnow()
        row = self._conn.execute(
            "SELECT id FROM programs WHERE platform = ? AND handle = ?",
            (program.platform, program.handle),
        ).fetchone()
        if row:
            self._conn.execute(
                """
                UPDATE programs
                SET name = ?, url = ?, offers_bounties = ?, last_seen_at = ?
                WHERE id = ?
                """,
                (
                    program.name,
                    program.url,
                    int(program.offers_bounties),
                    now,
                    row["id"],
                ),
            )
            self._conn.commit()
            return int(row["id"])

        cur = self._conn.execute(
            """
            INSERT INTO programs (
                platform, handle, name, url, offers_bounties, first_seen_at, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                program.platform,
                program.handle,
                program.name,
                program.url,
                int(program.offers_bounties),
                now,
                now,
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def get_program(self, platform: Platform, handle: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM programs WHERE platform = ? AND handle = ?",
            (platform, handle),
        ).fetchone()

    def known_program_handles(self, platform: Platform) -> set[str]:
        rows = self._conn.execute(
            "SELECT handle FROM programs WHERE platform = ?",
            (platform,),
        ).fetchall()
        return {str(r["handle"]) for r in rows}

    def upsert_scope(self, program_id: int, scope: ScopeRecord) -> tuple[int, bool, bool]:
        """Return (scope_id, is_new, changed)."""
        now = utcnow()
        fp = scope.fingerprint()
        row = self._conn.execute(
            "SELECT * FROM scopes WHERE program_id = ? AND fingerprint = ?",
            (program_id, fp),
        ).fetchone()
        if row:
            changed = (
                bool(row["eligible_for_bounty"]) != scope.eligible_for_bounty
                or bool(row["eligible_for_submission"]) != scope.eligible_for_submission
                or bool(row["in_scope"]) != scope.in_scope
                or str(row["instruction"]) != scope.instruction
                or str(row["asset_type"]) != scope.asset_type
            )
            self._conn.execute(
                """
                UPDATE scopes SET
                    asset_identifier = ?,
                    asset_type = ?,
                    eligible_for_bounty = ?,
                    eligible_for_submission = ?,
                    in_scope = ?,
                    instruction = ?,
                    last_seen_at = ?
                WHERE id = ?
                """,
                (
                    scope.asset_identifier,
                    scope.asset_type,
                    int(scope.eligible_for_bounty),
                    int(scope.eligible_for_submission),
                    int(scope.in_scope),
                    scope.instruction,
                    now,
                    row["id"],
                ),
            )
            self._conn.commit()
            return int(row["id"]), False, changed

        cur = self._conn.execute(
            """
            INSERT INTO scopes (
                program_id, platform, external_id, asset_identifier, asset_type,
                eligible_for_bounty, eligible_for_submission, in_scope, instruction,
                fingerprint, first_seen_at, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                program_id,
                scope.platform,
                scope.external_id,
                scope.asset_identifier,
                scope.asset_type,
                int(scope.eligible_for_bounty),
                int(scope.eligible_for_submission),
                int(scope.in_scope),
                scope.instruction,
                fp,
                now,
                now,
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid), True, False

    def in_scope_assets_for_program(
        self, platform: Platform, handle: str
    ) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                """
                SELECT s.* FROM scopes s
                JOIN programs p ON p.id = s.program_id
                WHERE p.platform = ? AND p.handle = ? AND s.in_scope = 1
                  AND s.eligible_for_submission = 1
                ORDER BY s.asset_identifier
                """,
                (platform, handle),
            ).fetchall()
        )

    # --- findings ----------------------------------------------------------

    def create_finding(
        self,
        *,
        kind: FindingKind,
        platform: Platform,
        program_handle: str,
        program_name: str = "",
        program_url: str = "",
        scope_id: int | None = None,
        asset_identifier: str = "",
        asset_type: str = "",
        eligible_for_bounty: bool = False,
        summary: str = "",
        details: dict[str, Any] | None = None,
    ) -> Finding:
        fid = new_finding_id()
        while self._conn.execute(
            "SELECT 1 FROM findings WHERE id = ?", (fid,)
        ).fetchone():
            fid = new_finding_id()
        created = utcnow()
        payload = json.dumps(details or {})
        self._conn.execute(
            """
            INSERT INTO findings (
                id, kind, platform, program_handle, program_name, program_url,
                scope_id, asset_identifier, asset_type, eligible_for_bounty,
                summary, details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                fid,
                kind,
                platform,
                program_handle,
                program_name,
                program_url,
                scope_id,
                asset_identifier,
                asset_type,
                int(eligible_for_bounty),
                summary,
                payload,
                created,
            ),
        )
        self._conn.commit()
        return Finding(
            id=fid,
            kind=kind,
            platform=platform,
            program_handle=program_handle,
            program_name=program_name,
            program_url=program_url,
            scope_id=scope_id,
            asset_identifier=asset_identifier,
            asset_type=asset_type,
            eligible_for_bounty=eligible_for_bounty,
            summary=summary,
            details=details or {},
            created_at=created,
        )

    def get_finding(self, finding_id: str) -> Finding | None:
        raw = (finding_id or "").strip()
        if not raw:
            return None
        for candidate in self._finding_id_candidates(raw):
            row = self._conn.execute(
                "SELECT * FROM findings WHERE id = ?", (candidate,)
            ).fetchone()
            if row:
                return Finding(
                    id=row["id"],
                    kind=row["kind"],
                    platform=row["platform"],
                    program_handle=row["program_handle"],
                    program_name=row["program_name"],
                    program_url=row["program_url"],
                    scope_id=row["scope_id"],
                    asset_identifier=row["asset_identifier"] or "",
                    asset_type=row["asset_type"] or "",
                    eligible_for_bounty=bool(row["eligible_for_bounty"]),
                    summary=row["summary"] or "",
                    details=json.loads(row["details_json"] or "{}"),
                    created_at=row["created_at"],
                    alerted_at=row["alerted_at"],
                )
        return None

    @staticmethod
    def _finding_id_candidates(raw: str) -> list[str]:
        """Accept f1a2b3c, f_1a2b3c, and accidental markdown-stripped forms."""
        out: list[str] = []
        for c in (raw, raw.lower()):
            if c and c not in out:
                out.append(c)
        if raw.startswith("f_") and len(raw) > 2:
            alt = "f" + raw[2:]
            if alt not in out:
                out.append(alt)
        elif raw.startswith("f") and not raw.startswith("f_") and len(raw) > 1:
            alt = "f_" + raw[1:]
            if alt not in out:
                out.append(alt)
        return out

    def mark_finding_alerted(self, finding_id: str) -> None:
        self._conn.execute(
            "UPDATE findings SET alerted_at = ? WHERE id = ?",
            (utcnow(), finding_id),
        )
        self._conn.commit()

    def resolve_scan_targets(self, finding_id: str) -> list[str]:
        finding = self.get_finding(finding_id)
        if not finding:
            return []
        if finding.asset_identifier and finding.kind in ("new_scope", "scope_change"):
            return [finding.asset_identifier]
        rows = self.in_scope_assets_for_program(finding.platform, finding.program_handle)
        return [str(r["asset_identifier"]) for r in rows if r["asset_identifier"]]

    # --- jobs --------------------------------------------------------------

    def create_job(
        self, finding_id: str, tool: str, targets: Iterable[str]
    ) -> str:
        job_id = new_job_id()
        self._conn.execute(
            """
            INSERT INTO jobs (
                id, finding_id, tool, status, targets_json, created_at
            ) VALUES (?, ?, ?, 'queued', ?, ?)
            """,
            (job_id, finding_id, tool, json.dumps(list(targets)), utcnow()),
        )
        self._conn.commit()
        return job_id

    def update_job(self, job_id: str, **fields: Any) -> None:
        if not fields:
            return
        cols = []
        vals: list[Any] = []
        for key, value in fields.items():
            cols.append(f"{key} = ?")
            vals.append(value)
        vals.append(job_id)
        self._conn.execute(
            f"UPDATE jobs SET {', '.join(cols)} WHERE id = ?",
            vals,
        )
        self._conn.commit()

    def get_job(self, job_id: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM jobs WHERE id = ?", (job_id,)
        ).fetchone()

    def list_jobs(self, limit: int = 20) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        )

    def list_jobs_for_finding(self, finding_id: str, limit: int = 10) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                """
                SELECT * FROM jobs WHERE finding_id = ?
                ORDER BY created_at DESC LIMIT ?
                """,
                (finding_id, limit),
            ).fetchall()
        )

    # --- agent runs --------------------------------------------------------

    def create_agent_run(self, finding_id: str, prompt: str) -> str:
        run_id = new_agent_run_id()
        self._conn.execute(
            """
            INSERT INTO agent_runs (
                id, finding_id, status, prompt, created_at
            ) VALUES (?, ?, 'queued', ?, ?)
            """,
            (run_id, finding_id, prompt, utcnow()),
        )
        self._conn.commit()
        return run_id

    def update_agent_run(self, run_pk: str, **fields: Any) -> None:
        if not fields:
            return
        cols = []
        vals: list[Any] = []
        for key, value in fields.items():
            cols.append(f"{key} = ?")
            vals.append(value)
        vals.append(run_pk)
        self._conn.execute(
            f"UPDATE agent_runs SET {', '.join(cols)} WHERE id = ?",
            vals,
        )
        self._conn.commit()

    def get_agent_run(self, run_pk: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM agent_runs WHERE id = ?", (run_pk,)
        ).fetchone()

    def latest_agent_run_for_finding(self, finding_id: str) -> sqlite3.Row | None:
        return self._conn.execute(
            """
            SELECT * FROM agent_runs WHERE finding_id = ?
            ORDER BY created_at DESC LIMIT 1
            """,
            (finding_id,),
        ).fetchone()

    # --- artifacts / retention ---------------------------------------------

    def add_artifact(
        self, finding_id: str, path: Path, size_bytes: int, job_id: str | None = None
    ) -> None:
        self._conn.execute(
            """
            INSERT INTO scan_artifacts (finding_id, job_id, path, size_bytes, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (finding_id, job_id, str(path), size_bytes, utcnow()),
        )
        self._conn.commit()

    def db_file_size(self) -> int:
        try:
            return self.path.stat().st_size
        except FileNotFoundError:
            return 0

    def get_meta(self, key: str) -> str | None:
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key = ?", (key,)
        ).fetchone()
        return str(row["value"]) if row else None

    def set_meta(self, key: str, value: str) -> None:
        self._conn.execute(
            """
            INSERT INTO meta (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )
        self._conn.commit()

    def enforce_storage_budget(self) -> None:
        """Delete oldest artifacts/job logs when soft limit exceeded; vacuum if needed."""
        soft = self.settings.db_soft_limit_bytes
        size = self.db_file_size()
        artifact_root = self.settings.artifact_dir
        if not artifact_root.exists():
            return

        # Always prune oversized disk artifacts first (outside SQLite size).
        artifacts = list(
            self._conn.execute(
                "SELECT id, path, size_bytes FROM scan_artifacts ORDER BY created_at ASC"
            ).fetchall()
        )
        disk_total = sum(int(a["size_bytes"] or 0) for a in artifacts)
        # Keep disk artifacts under soft limit as well.
        while disk_total > soft and artifacts:
            oldest = artifacts.pop(0)
            path = Path(oldest["path"])
            try:
                if path.exists():
                    path.unlink()
            except OSError as exc:
                logger.warning("failed to delete artifact %s: %s", path, exc)
            self._conn.execute(
                "DELETE FROM scan_artifacts WHERE id = ?", (oldest["id"],)
            )
            disk_total -= int(oldest["size_bytes"] or 0)
        self._conn.commit()

        size = self.db_file_size()
        if size <= soft:
            return

        # Trim old completed/failed jobs (keep findings).
        old_jobs = self._conn.execute(
            """
            SELECT id, log_path FROM jobs
            WHERE status IN ('completed', 'failed', 'cancelled')
            ORDER BY created_at ASC
            LIMIT 200
            """
        ).fetchall()
        for job in old_jobs:
            if self.db_file_size() <= soft:
                break
            if job["log_path"]:
                lp = Path(job["log_path"])
                try:
                    if lp.exists():
                        lp.unlink()
                except OSError:
                    pass
            self._conn.execute("DELETE FROM jobs WHERE id = ?", (job["id"],))
            self._conn.commit()

        if self.db_file_size() > soft:
            self._conn.execute("VACUUM")
            self._conn.commit()
            logger.info("vacuumed database; size now %s bytes", self.db_file_size())
