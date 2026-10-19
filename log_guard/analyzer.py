"""Поиск попыток подбора пароля (brute-force) в SSH-логах."""

import re
from collections import Counter
from dataclasses import dataclass

# Пример строки: "Oct 19 10:15:01 server sshd[1234]: Failed password for root from 203.0.113.5 port 52211 ssh2"
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)
ACCEPTED_RE = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>[\d.]+)")


@dataclass
class Report:
    failed_by_ip: Counter
    suspicious_ips: list
    compromised: list  # IP, с которых был подбор и затем успешный вход


def analyze(lines, threshold=5):
    """Считает неудачные входы по IP и помечает подозрительные адреса."""
    failed_by_ip = Counter()
    accepted = []

    for line in lines:
        if m := FAILED_RE.search(line):
            failed_by_ip[m["ip"]] += 1
        elif m := ACCEPTED_RE.search(line):
            accepted.append((m["ip"], m["user"]))

    suspicious = sorted(ip for ip, n in failed_by_ip.items() if n >= threshold)
    compromised = sorted({(ip, user) for ip, user in accepted if ip in suspicious})
    return Report(failed_by_ip, suspicious, compromised)
