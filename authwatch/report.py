"""Render findings as a console summary, a Markdown incident report or JSON."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from typing import Dict, List, Sequence

from .detect import SEVERITY_ORDER, Finding
from .parser import SUCCESS, Event

SEVERITY_BADGE = {
    "critical": "[CRITICAL]",
    "high": "[HIGH]    ",
    "medium": "[MEDIUM]  ",
    "low": "[LOW]     ",
}


def build_stats(events: Sequence[Event]) -> Dict[str, object]:
    """Aggregate figures used in the report header."""
    if not events:
        return {
            "total": 0, "failures": 0, "successes": 0, "unique_ips": 0,
            "unique_users": 0, "start": None, "end": None, "top_ips": [],
        }
    ordered = sorted(events, key=lambda e: e.ts)
    return {
        "total": len(events),
        "failures": sum(1 for e in events if e.is_failure),
        "successes": sum(1 for e in events if e.kind == SUCCESS),
        "unique_ips": len({e.ip for e in events}),
        "unique_users": len({e.user for e in events}),
        "start": ordered[0].ts,
        "end": ordered[-1].ts,
        "top_ips": Counter(e.ip for e in events if e.is_failure).most_common(5),
    }


def _severity_counts(findings: Sequence[Finding]) -> Counter:
    return Counter(f.severity for f in findings)


# --------------------------------------------------------------------- console
def render_console(findings: Sequence[Finding], stats: Dict[str, object]) -> str:
    """Human-readable triage summary for the terminal."""
    lines: List[str] = []
    lines.append("authwatch - authentication log triage")
    lines.append("=" * 62)

    if stats["total"]:
        lines.append(
            f"Window   : {stats['start']:%Y-%m-%d %H:%M} -> {stats['end']:%Y-%m-%d %H:%M}"
        )
        lines.append(
            f"Events   : {stats['total']} parsed | {stats['failures']} failures | "
            f"{stats['successes']} successes"
        )
        lines.append(
            f"Entities : {stats['unique_ips']} source IPs | {stats['unique_users']} accounts"
        )
    else:
        lines.append("No relevant authentication events found.")

    counts = _severity_counts(findings)
    summary = ", ".join(
        f"{counts[sev]} {sev}" for sev in SEVERITY_ORDER if counts.get(sev)
    ) or "none"
    lines.append(f"Findings : {len(findings)} ({summary})")
    lines.append("")

    if not findings:
        lines.append("No detection rules fired. Nothing to escalate.")
        return "\n".join(lines)

    lines.append(f"{'SEVERITY':<11}{'IP':<18}{'COUNT':>6}  RULE / TARGET")
    lines.append("-" * 62)
    for finding in findings:
        users = ", ".join(finding.users[:3])
        if len(finding.users) > 3:
            users += f" (+{len(finding.users) - 3})"
        lines.append(
            f"{SEVERITY_BADGE.get(finding.severity, finding.severity):<11}"
            f"{finding.ip:<18}{finding.count:>6}  {finding.rule} -> {users}"
        )

    lines.append("")
    lines.append("Top offending sources:")
    for ip, hits in stats["top_ips"]:
        lines.append(f"  {ip:<18} {hits} failed authentications")
    lines.append("")
    lines.append("Next step: triage the CRITICAL/HIGH findings first, confirm whether the")
    lines.append("source is internal, and escalate with the evidence attached.")
    return "\n".join(lines)


# -------------------------------------------------------------------- markdown
def render_markdown(
    findings: Sequence[Finding], stats: Dict[str, object], source: str = "auth.log"
) -> str:
    """Full incident-style report, the artefact you attach to a ticket."""
    counts = _severity_counts(findings)
    out: List[str] = []

    out.append("# Authentication log triage report")
    out.append("")
    out.append(f"- **Source file:** `{source}`")
    out.append(f"- **Generated:** {datetime.now():%Y-%m-%d %H:%M}")
    if stats["total"]:
        out.append(
            f"- **Log window:** {stats['start']:%Y-%m-%d %H:%M} to {stats['end']:%Y-%m-%d %H:%M}"
        )
    out.append(f"- **Events parsed:** {stats['total']} "
               f"({stats['failures']} failures, {stats['successes']} successful logins)")
    out.append(f"- **Source IPs:** {stats['unique_ips']} | **Accounts touched:** {stats['unique_users']}")
    out.append(
        "- **Findings:** " + (", ".join(f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts.get(s))
                               or "none")
    )
    out.append("")

    out.append("## Summary of findings")
    out.append("")
    if findings:
        out.append("| Severity | Rule | Source IP | Events | Accounts | Window |")
        out.append("|---|---|---|---|---|---|")
        for f in findings:
            out.append(
                f"| {f.severity.upper()} | {f.rule} | `{f.ip}` | {f.count} | "
                f"{len(f.users)} | {f.start:%m-%d %H:%M} -> {f.end:%m-%d %H:%M} |"
            )
    else:
        out.append("No detection rules fired against this log.")
    out.append("")

    if findings:
        out.append("## Detail")
        out.append("")
        for f in findings:
            out.append(f"### {f.severity.upper()} - {f.title}")
            out.append("")
            out.append(f"- **Source IP:** `{f.ip}`")
            out.append(f"- **Accounts involved:** {', '.join(f.users[:8])}"
                       + (" ..." if len(f.users) > 8 else ""))
            out.append(f"- **Events:** {f.count} over {f.duration_minutes} minutes")
            out.append(f"- **Window:** {f.start:%Y-%m-%d %H:%M:%S} to {f.end:%Y-%m-%d %H:%M:%S}")
            if f.attack:
                out.append(f"- **MITRE ATT&CK:** {f.attack}")
            if f.nist:
                out.append(f"- **NIST CSF:** {f.nist}")
            out.append("")
            out.append(f.detail)
            out.append("")
            if f.evidence:
                out.append("Evidence (latest lines):")
                out.append("")
                out.append("```")
                for event in f.evidence[-4:]:
                    out.append(event.raw.strip()[:160])
                out.append("```")
                out.append("")

    out.append("## Recommended actions")
    out.append("")
    rules = {f.rule for f in findings}
    actions: List[str] = []
    if "success_after_failure" in rules:
        actions.append(
            "Treat the affected account as compromised: reset credentials, revoke sessions "
            "and review what happened after the successful login."
        )
    if "brute_force" in rules or "spraying" in rules:
        actions.append(
            "Block or rate-limit the source addresses at the firewall and enable fail2ban-style "
            "lockouts for the targeted accounts."
        )
    if "root_targeting" in rules:
        actions.append(
            "Confirm that direct root login over SSH is disabled (PermitRootLogin no) and that "
            "only key-based authentication is accepted."
        )
    if "off_hours" in rules:
        actions.append(
            "Validate off-hours logins with the account owners before closing the ticket; "
            "silent agreement from the user is a weak but useful signal."
        )
    if not actions:
        actions.append("No action required beyond routine monitoring.")
    for action in actions:
        out.append(f"1. {action}")
    out.append("")
    out.append("---")
    out.append("")
    out.append("*Generated by [authwatch](https://github.com/NicoLucian/authwatch) - "
               "detection rules, thresholds and mapping are documented in `docs/detections.md`.*")
    return "\n".join(out)


# ------------------------------------------------------------------------ json
def render_json(findings: Sequence[Finding], stats: Dict[str, object]) -> str:
    """Machine-readable output for pipelines and SIEM ingestion tests."""
    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "stats": {
            "events": stats["total"],
            "failures": stats["failures"],
            "successes": stats["successes"],
            "unique_ips": stats["unique_ips"],
            "unique_users": stats["unique_users"],
            "start": stats["start"].isoformat() if stats["start"] else None,
            "end": stats["end"].isoformat() if stats["end"] else None,
        },
        "findings": [
            {
                "rule": f.rule,
                "title": f.title,
                "severity": f.severity,
                "source_ip": f.ip,
                "count": f.count,
                "users": f.users,
                "start": f.start.isoformat(),
                "end": f.end.isoformat(),
                "mitre_attack": f.attack,
                "nist_csf": f.nist,
                "detail": f.detail,
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
