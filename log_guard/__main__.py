"""CLI: python -m log_guard auth.log --threshold 5"""

import argparse
import sys

from log_guard.analyzer import analyze


def main(argv=None):
    parser = argparse.ArgumentParser(description="Поиск brute-force атак в SSH-логах")
    parser.add_argument("logfile", help="путь к auth.log")
    parser.add_argument("--threshold", type=int, default=5,
                        help="сколько неудачных входов считать атакой (по умолчанию 5)")
    args = parser.parse_args(argv)

    with open(args.logfile, encoding="utf-8", errors="replace") as f:
        report = analyze(f, args.threshold)

    print(f"Неудачных попыток входа: {sum(report.failed_by_ip.values())}")
    if not report.suspicious_ips:
        print("Подозрительных IP не найдено.")
        return 0

    print(f"\nПодозрительные IP (>= {args.threshold} неудачных попыток):")
    for ip in report.suspicious_ips:
        print(f"  {ip:<16} {report.failed_by_ip[ip]} попыток")

    if report.compromised:
        print("\n[!] После подбора был успешный вход:")
        for ip, user in report.compromised:
            print(f"  {ip} -> пользователь {user}")
        return 2  # ненулевой код, чтобы скрипт можно было встроить в автоматизацию
    return 1


if __name__ == "__main__":
    sys.exit(main())
