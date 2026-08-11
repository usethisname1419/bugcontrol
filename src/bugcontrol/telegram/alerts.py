from __future__ import annotations

from bugcontrol.models import Finding


def format_finding_alert(finding: Finding) -> str:
    bounty = "yes" if finding.eligible_for_bounty else "no"
    asset = finding.asset_identifier or "(program)"
    fid = finding.id
    # Put commands in backticks so Telegram Markdown cannot eat underscores
    # (legacy Markdown: _text_ = italic).
    lines = [
        f"Bugcontrol finding `{fid}`",
        f"Kind: `{finding.kind}`",
        f"Platform: `{finding.platform}`",
        f"Program: {finding.program_name or finding.program_handle}",
        f"Handle: `{finding.program_handle}`",
        f"Asset: `{asset}`",
        f"Type: `{finding.asset_type or '-'}`",
        f"Bounty eligible: `{bounty}`",
    ]
    if finding.program_url:
        lines.append(f"URL: {finding.program_url}")
    if finding.summary:
        lines.append(f"Summary: {finding.summary}")
    lines.append("")
    lines.append("Commands (copy/paste):")
    lines.append(f"`/finding {fid}`")
    lines.append(f"`/secrets {fid}`")
    lines.append(f"`/nmap {fid}`")
    lines.append(f"`/nikto {fid}`")
    lines.append(f"`/sqlmap {fid}`")
    lines.append(f"`/ai {fid}`")
    return "\n".join(lines)


def format_finding_detail(finding: Finding, scopes: list[str], jobs: list[str]) -> str:
    lines = [
        f"Finding `{finding.id}`",
        f"`{finding.kind}` · `{finding.platform}` · `{finding.program_handle}`",
        finding.summary or "",
        "",
        "In-scope (sample):",
        *(scopes[:30] or ["(none)"]),
        "",
        "Recent jobs:",
        *(jobs[:10] or ["(none)"]),
    ]
    return "\n".join(lines)
