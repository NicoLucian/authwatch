"""authwatch - lightweight Linux authentication log triage for SOC L1 work.

Parses ``/var/log/auth.log`` (Debian/Ubuntu) and ``/var/log/secure``
(RHEL/CentOS) style logs, applies a small set of detection rules and emits a
console summary, a Markdown incident report or JSON findings.
"""

__version__ = "1.0.0"
__all__ = ["parser", "detect", "report", "cli"]
