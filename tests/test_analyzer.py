from pathlib import Path

from log_guard.analyzer import analyze

SAMPLE = Path(__file__).parent.parent / "samples" / "auth.log"


def test_counts_failed_attempts_per_ip():
    report = analyze(SAMPLE.read_text().splitlines())
    assert report.failed_by_ip["203.0.113.5"] == 6
    assert report.failed_by_ip["198.51.100.23"] == 1


def test_flags_ips_over_threshold():
    report = analyze(SAMPLE.read_text().splitlines(), threshold=5)
    assert report.suspicious_ips == ["192.0.2.77", "203.0.113.5"]


def test_detects_login_after_bruteforce():
    report = analyze(SAMPLE.read_text().splitlines())
    assert report.compromised == [("203.0.113.5", "deploy")]


def test_ignores_unrelated_lines():
    report = analyze(["Oct 19 10:00:00 server CRON[1]: session opened for user root"])
    assert not report.failed_by_ip
    assert report.suspicious_ips == []
