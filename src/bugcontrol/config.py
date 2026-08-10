from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PlatformName = Literal["hackerone", "bugcrowd", "yeswehack"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    telegram_allowed_user_ids: str = ""

    h1_username: str = ""
    h1_api_token: str = ""

    bugcrowd_token: str = ""  # unused; kept for backward compat
    bugcrowd_session: str = ""  # researcher _bugcrowd_session cookie

    yeswehack_token: str = ""
    yeswehack_totp_secret: str = ""

    poll_interval_minutes: int = 30
    enabled_platforms: str = "hackerone,bugcrowd,yeswehack"
    # Re-fetch scopes for known programs this often (hours). New programs always fetch.
    scope_refresh_hours: float = 6.0

    db_path: Path = Path("data/bugcontrol.db")
    db_max_bytes: int = 10 * 1024 * 1024 * 1024
    db_soft_limit_bytes: int = 8 * 1024 * 1024 * 1024
    artifact_dir: Path = Path("data/artifacts")
    artifact_max_bytes_per_job: int = 50 * 1024 * 1024

    scan_concurrency: int = 2
    scan_timeout_seconds: int = 1800
    secrets_crawl_max_pages: int = 80
    secrets_crawl_max_js: int = 500
    secrets_crawl_depth: int = 3
    secrets_crawl_timeout: float = 15.0
    # Cap per JS/HTML read (streamed); default 2 MiB keeps 4GB boxes safe
    secrets_max_js_bytes: int = 2 * 1024 * 1024
    secrets_chunk_bytes: int = 64 * 1024
    secrets_overlap_bytes: int = 2048
    secrets_max_concurrent: int = 2
    secrets_max_hits: int = 200
    nmap_bin: str = "nmap"
    sqlmap_bin: str = "sqlmap"
    nikto_bin: str = "nikto"
    gitleaks_bin: str = "gitleaks"
    trufflehog_bin: str = "trufflehog"

    cursor_api_key: str = ""
    cursor_agent_repo: str = ""
    cursor_model: str = "composer-2.5"
    cursor_agent_ref: str = "main"
    # After a successful /secrets job, auto-launch the Cursor bug-hunter agent
    ai_auto_after_secrets: bool = True

    log_level: str = "INFO"

    @field_validator("db_path", "artifact_dir", mode="before")
    @classmethod
    def _as_path(cls, value: object) -> Path:
        return Path(str(value))

    def allowed_user_ids(self) -> set[int]:
        ids: set[int] = set()
        for part in self.telegram_allowed_user_ids.split(","):
            part = part.strip()
            if part:
                ids.add(int(part))
        return ids

    def platforms(self) -> list[PlatformName]:
        out: list[PlatformName] = []
        for part in self.enabled_platforms.split(","):
            name = part.strip().lower()
            if name in ("hackerone", "bugcrowd", "yeswehack"):
                out.append(name)  # type: ignore[arg-type]
        return out

    def ensure_dirs(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.artifact_dir.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()
