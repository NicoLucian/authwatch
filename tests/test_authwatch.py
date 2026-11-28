"""Test suite. Run with: python -m unittest discover -s tests -v"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authwatch.cli import main  # noqa: E402
from authwatch.detect import (  # noqa: E402
    detect_brute_force,
    detect_off_hours,
    detect_root_targeting,
    detect_spraying,
    detect_success_after_failure,
    run_all,
)
from authwatch.parser import (  # noqa: E402
    FAILED,
    INVALID,
    SUCCESS,
    Event,
    count_time_bases,
    parse_line,
    parse_lines,
)
from authwatch.report import build_stats, render_console, render_json, render_markdown  # noqa: E402

BASE = datetime(2026, 1, 6, 8, 0, 0)


def ev(user: str, ip: str, minutes: int = 0, kind: str = FAILED,
       invalid: bool = False, hour: int = 8) -> Event:
    return Event(
        ts=datetime(2026, 1, 6, hour, 0, 0) + timedelta(minutes=minutes),
        host="web01", user=user, ip=ip, kind=kind, invalid_user=invalid,
    )


class ParserTests(unittest.TestCase):
    def test_failed_password(self):
        line = ("Jan  6 08:00:01 web01 sshd[1234]: Failed password for root "
                "from 203.0.113.45 port 51234 ssh2")
        event = parse_line(line, year=2026)
        self.assertIsNotNone(event)
        self.assertEqual(event.kind, FAILED)
        self.assertEqual(event.user, "root")
        self.assertEqual(event.ip, "203.0.113.45")
        self.assertEqual(event.port, 51234)
        self.assertEqual(event.ts, datetime(2026, 1, 6, 8, 0, 1))

    def test_invalid_user_is_flagged(self):
        line = ("Jan  6 08:05:00 web01 sshd[1235]: Failed password for invalid user admin "
                "from 198.51.100.7 port 33000 ssh2")
        event = parse_line(line, year=2026)
        self.assertEqual(event.kind, INVALID)
        self.assertTrue(event.invalid_user)

    def test_accepted_password(self):
        line = ("Jan  6 09:00:00 web01 sshd[1240]: Accepted password for ncancino "
                "from 10.0.0.12 port 47011 ssh2")
        event = parse_line(line, year=2026)
        self.assertEqual(event.kind, SUCCESS)
        self.assertEqual(event.method, "password")

    def test_pam_unix_failure(self):
        line = ("Jan  6 22:03:00 web01 pam_unix[2200]: pam_unix(sshd:auth): authentication "
                "failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.45  user=ncancino")
        event = parse_line(line, year=2026)
        self.assertEqual(event.kind, FAILED)
        self.assertEqual(event.ip, "203.0.113.45")
        self.assertEqual(event.user, "ncancino")

    def test_iso_timestamp(self):
        line = ("2026-01-06T08:00:01+0000 web01 sshd[1234]: Failed password for root "
                "from 203.0.113.45 port 51234 ssh2")
        event = parse_line(line)
        self.assertEqual(event.ts, datetime(2026, 1, 6, 8, 0, 1))

    def test_iso_timestamp_with_offset_is_normalised_to_utc(self):
        line = ("2026-01-06T08:00:01+0300 web01 sshd[1234]: Failed password for root "
                "from 203.0.113.45 port 51234 ssh2")
        event = parse_line(line)
        self.assertEqual(event.ts, datetime(2026, 1, 6, 5, 0, 1))

    def test_mixed_formats_keep_their_own_convention(self):
        """Contrato: syslog = hora de pared del host, ISO = UTC.

        Un archivo que mezcle formatos compara convenciones distintas (desfase = offset
        local). Queda fijado aquí para que sea una decisión visible y no un silencio.
        """
        syslog = parse_line(
            "Jan  6 08:00:01 web01 sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2",
            year=2026,
        )
        iso = parse_line(
            "2026-01-06T08:00:01+0300 web01 sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2"
        )
        self.assertEqual(syslog.ts, datetime(2026, 1, 6, 8, 0, 1))
        self.assertEqual(iso.ts, datetime(2026, 1, 6, 5, 0, 1))

    def test_noise_is_ignored(self):
        self.assertIsNone(parse_line("Jan  6 08:00:00 web01 CRON[900]: (root) CMD (backup)"))
        self.assertIsNone(parse_line("Jan  6 08:00:00 web01 sshd[900]: Connection closed "
                                     "by 10.0.0.12 port 41000 [preauth]"))
        self.assertIsNone(parse_line(""))
        self.assertIsNone(parse_line("garbage line without structure"))

    def test_parse_lines_filters(self):
        lines = [
            "Jan  6 08:00:01 web01 sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2",
            "Jan  6 08:00:02 web01 CRON[2]: (root) CMD (true)",
        ]
        self.assertEqual(len(parse_lines(lines, year=2026)), 1)


class BruteForceTests(unittest.TestCase):
    def test_detects_repeated_failures(self):
        events = [ev("root", "203.0.113.45", minutes=i) for i in range(6)]
        findings = detect_brute_force(events, threshold=5, window_minutes=10)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].ip, "203.0.113.45")
        self.assertEqual(findings[0].count, 6)

    def test_below_threshold_is_silent(self):
        events = [ev("root", "203.0.113.45", minutes=i) for i in range(4)]
        self.assertEqual(detect_brute_force(events, threshold=5), [])

    def test_failures_outside_window_are_silent(self):
        events = [ev("root", "203.0.113.45", minutes=i * 30) for i in range(6)]
        self.assertEqual(detect_brute_force(events, threshold=5, window_minutes=10), [])

    def test_separate_accounts_are_reported_separately(self):
        events = ([ev("root", "203.0.113.45", minutes=i) for i in range(5)]
                  + [ev("admin", "203.0.113.45", minutes=i) for i in range(5)])
        findings = detect_brute_force(events, threshold=5, window_minutes=10)
        self.assertEqual(len(findings), 2)
        self.assertEqual({f.users[0] for f in findings}, {"root", "admin"})


class SprayingTests(unittest.TestCase):
    def test_detects_many_accounts_from_one_source(self):
        events = [ev(user, "198.51.100.7", minutes=4 * i)
                  for i, user in enumerate(["admin", "a", "b", "c", "d"])]
        findings = detect_spraying(events, threshold=5, min_users=3, window_minutes=30)
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(findings[0].users), 5)

    def test_single_account_is_not_spraying(self):
        events = [ev("admin", "198.51.100.7", minutes=i) for i in range(6)]
        self.assertEqual(detect_spraying(events, threshold=5, min_users=3), [])


class CompromiseTests(unittest.TestCase):
    def test_success_after_failures_is_critical(self):
        events = [ev("ncancino", "203.0.113.45", minutes=i) for i in range(4)]
        events.append(ev("ncancino", "203.0.113.45", minutes=5, kind=SUCCESS))
        findings = detect_success_after_failure(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")

    def test_clean_success_is_silent(self):
        events = [ev("ncancino", "10.0.0.12", minutes=1, kind=SUCCESS)]
        self.assertEqual(detect_success_after_failure(events), [])


class OtherRuleTests(unittest.TestCase):
    def test_root_targeting(self):
        events = [ev("root", "192.0.2.99", minutes=i) for i in range(4)]
        findings = detect_root_targeting(events, threshold=3)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "medium")

    def test_off_hours_login(self):
        events = [ev("svc_deploy", "10.0.0.42", kind=SUCCESS, hour=3)]
        findings = detect_off_hours(events, start_hour=7, end_hour=20)
        self.assertEqual(len(findings), 1)

    def test_business_hours_login_is_silent(self):
        events = [ev("ncancino", "10.0.0.12", kind=SUCCESS, hour=11)]
        self.assertEqual(detect_off_hours(events, start_hour=7, end_hour=20), [])

    def test_run_all_sorts_by_severity(self):
        events = [ev("root", "192.0.2.99", minutes=i) for i in range(4)]
        events += [ev("ncancino", "203.0.113.45", minutes=i) for i in range(5)]
        events.append(ev("ncancino", "203.0.113.45", minutes=6, kind=SUCCESS))
        findings = run_all(events)
        severities = [f.severity for f in findings]
        self.assertEqual(severities[0], "critical")
        self.assertIn("high", severities)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.events = ([ev("ncancino", "203.0.113.45", minutes=i) for i in range(6)]
                       + [ev("ncancino", "203.0.113.45", minutes=6, kind=SUCCESS)])
        self.findings = run_all(self.events)
        self.stats = build_stats(self.events)

    def test_stats(self):
        self.assertEqual(self.stats["total"], 7)
        self.assertEqual(self.stats["failures"], 6)
        self.assertEqual(self.stats["successes"], 1)

    def test_markdown_has_sections(self):
        report = render_markdown(self.findings, self.stats, source="sample.log")
        self.assertIn("## Summary of findings", report)
        self.assertIn("## Recommended actions", report)
        self.assertIn("MITRE ATT&CK", report)

    def test_console_is_readable(self):
        report = render_console(self.findings, self.stats)
        self.assertIn("authentication log triage", report)
        self.assertIn("Findings", report)

    def test_json_is_serialisable(self):
        payload = render_json(self.findings, self.stats)
        self.assertIn('"findings"', payload)
        self.assertIn('"severity"', payload)

    def test_empty_log_does_not_crash(self):
        stats = build_stats([])
        self.assertEqual(render_console([], stats).strip().splitlines()[-1],
                         "No detection rules fired. Nothing to escalate.")


class CliTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(os.path.dirname(__file__), "tmp_chatty.log")
        lines = [
            f"Jan  6 0{8 + i // 6}:{i * 2 % 60:02d}:00 web01 sshd[{1000 + i}]: "
            f"Failed password for root from 203.0.113.45 port {50000 + i} ssh2"
            for i in range(6)
        ]
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")

    def tearDown(self):
        for path in (self.path, self.path + ".json"):
            if os.path.exists(path):
                os.remove(path)

    def test_exit_code_when_findings_reach_threshold(self):
        self.assertEqual(main([self.path, "--fail-on", "high", "--format", "json",
                               "--year", "2026", "--out", self.path + ".json"]), 1)

    def test_exit_code_with_fail_on_none(self):
        self.assertEqual(main([self.path, "--fail-on", "none", "--format", "json",
                               "--year", "2026", "--out", self.path + ".json"]), 0)
        os.remove(self.path + ".json")

    def test_missing_file_returns_two(self):
        self.assertEqual(main(["does_not_exist.log"], ), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TimeAxisTests(unittest.TestCase):
    """El eje temporal: syslog es hora de pared, ISO es UTC. Se declara o se avisa."""

    SYSLOG = ("Jan  6 08:00:01 web01 sshd[1]: Failed password for root "
              "from 203.0.113.45 port 1 ssh2")

    def test_syslog_stays_wall_clock_without_an_offset(self):
        event = parse_line(self.SYSLOG, year=2026)
        self.assertEqual(event.ts, datetime(2026, 1, 6, 8, 0, 1))

    def test_syslog_offset_moves_the_event_to_utc(self):
        # Chile en verano es UTC-3: 08:00 local son 11:00 UTC.
        event = parse_line(self.SYSLOG, year=2026, syslog_offset=-3)
        self.assertEqual(event.ts, datetime(2026, 1, 6, 11, 0, 1))

    def test_iso_and_offset_syslog_land_on_the_same_axis(self):
        iso = parse_line(
            "2026-01-06T11:00:01+0000 web01 sshd[1]: Failed password for root "
            "from 203.0.113.45 port 1 ssh2"
        )
        syslog = parse_line(self.SYSLOG, year=2026, syslog_offset=-3)
        self.assertEqual(iso.ts, syslog.ts)

    def test_count_time_bases_flags_a_mixed_file(self):
        lines = [
            self.SYSLOG,
            "2026-01-06T08:00:01+0000 web01 sshd[1]: Failed password for root "
            "from 203.0.113.45 port 1 ssh2",
        ]
        bases = count_time_bases(lines)
        self.assertEqual(bases["syslog"], 1)
        self.assertEqual(bases["iso"], 1)
        self.assertTrue(bases["mixed"])

    def test_count_time_bases_reports_a_single_base(self):
        bases = count_time_bases([self.SYSLOG, self.SYSLOG])
        self.assertEqual(bases["syslog"], 2)
        self.assertEqual(bases["iso"], 0)
        self.assertFalse(bases["mixed"])
