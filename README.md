# Bugcontrol

Polls **HackerOne**, **Bugcrowd**, and **YesWeHack** every 30 minutes for new programs and scopes, stores them in a capped SQLite database, alerts via **Telegram**, and runs scanners or a **Cursor cloud agent** from Telegram commands keyed by finding ID.

Scanning is **manual only** (Telegram command). Only in-scope, submission-eligible assets are passed to tools.

## Features

- Platform adapters with rate-limit backoff
- First poll **bootstraps silently** (no alert flood), then alerts on real deltas
- Finding IDs like `f_a1b2c3`
- Telegram: `/nmap`, `/sqlmap`, `/nikto`, `/secrets`, `/nuclei`, `/ai`, `/ai_resume`
- SQLite hard-capped (~10 GiB via `PRAGMA max_page_count`) + artifact retention
- Cursor cloud agents via `cursor-sdk`

## Quick start

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux:   source .venv/bin/activate
pip install -e .

cp .env.example .env
# fill TELEGRAM_*, platform tokens, CURSOR_* 

python -m bugcontrol
```

## Telegram setup

1. Create a bot with [@BotFather](https://t.me/BotFather) → `TELEGRAM_BOT_TOKEN`
2. Message the bot, then get your chat id → `TELEGRAM_CHAT_ID`
3. Set `TELEGRAM_ALLOWED_USER_IDS` to your numeric user id(s)

### Commands

| Command | Action |
|---------|--------|
| `/finding <id>` | Show finding + scopes |
| `/nmap <id>` | Queue nmap |
| `/sqlmap <id>` | Queue sqlmap |
| `/nikto <id>` | Queue nikto |
| `/secrets <id>` | Live-crawl all JS (streamed) + in-memory regex secrets (22 patterns) |
| `/nuclei <id>` | Queue nuclei |
| `/ai <id>` | Launch Cursor cloud agent |
| `/ai_resume <id> <msg>` | Continue agent |
| `/jobs` `/job <id>` `/cancel <id>` | Job ops |
| `/poll` | Force platform poll |

## Platform API tokens

- **HackerOne:** Hacker API username + token → `H1_USERNAME`, `H1_API_TOKEN`
- **Bugcrowd:** API token → `BUGCROWD_TOKEN`
- **YesWeHack:** Bearer/PAT → `YESWEHACK_TOKEN`

Disable platforms with `ENABLED_PLATFORMS=hackerone,bugcrowd` (comma-separated).

## Cursor cloud agent

1. Create an API key at [Cursor Dashboard → Integrations](https://cursor.com/dashboard/integrations)
2. Set `CURSOR_API_KEY`
3. Set `CURSOR_AGENT_REPO` to this private repo’s HTTPS URL (account must have access)
4. Optional: `CURSOR_MODEL=composer-2.5`, `CURSOR_AGENT_REF=main`

`/ai` clones the repo in Cursor cloud and runs a triage/test-plan prompt with in-scope assets. Local nmap/sqlmap/etc. still run on the VPS.

## VPS tools

Install on the host PATH (or set `*_BIN` in `.env`):

- `nmap`, `sqlmap`, `nikto`, `nuclei`
- `/secrets` needs **no extra binary** (built-in crawler + regex scanner; streams JS in memory)
## systemd (Linux)

```ini
# /etc/systemd/system/bugcontrol.service
[Unit]
Description=Bugcontrol watcher
After=network-online.target

[Service]
Type=simple
User=bugcontrol
WorkingDirectory=/opt/bugcontrol
EnvironmentFile=/opt/bugcontrol/.env
ExecStart=/opt/bugcontrol/.venv/bin/python -m bugcontrol
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now bugcontrol
```

## Storage

- DB: `data/bugcontrol.db` (default), max ~10 GiB (`DB_MAX_BYTES`)
- Artifacts: `data/artifacts/{finding_id}/`
- Soft limit (~8 GiB) triggers artifact/job pruning and `VACUUM`

## Safety

- Authorized bug bounty use only
- No auto-scan on alert
- Wildcards skipped for most tools
- Keep `.env`, `data/`, and secrets out of git
