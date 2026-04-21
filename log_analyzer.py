import argparse
import json
import re
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Optional

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
APACHE_TS_RE = re.compile(r"\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}")
ISO_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")
SYSLOG_TS_RE = re.compile(r"\b[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}\b")
HTTP_STATUS_RE = re.compile(r"\s(\d{3})\s")
HTTP_REQ_RE = re.compile(r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ([^\s\"]+)')
PORT_RE = re.compile(r"\bport\s+(\d{1,5})\b", re.IGNORECASE)

SUSPICIOUS_URL_PATTERNS = [
    r"\.\./",
    r"/etc/passwd",
    r"/wp-admin",
    r"/phpmyadmin",
    r"/cgi-bin/",
    r"/admin",
    r"/\.git",
    r"/\.env",
    r"select\b",
]
SUSPICIOUS_URL_RE = re.compile("|".join(SUSPICIOUS_URL_PATTERNS), re.IGNORECASE)

FAILED_LOGIN_RE = re.compile(r"failed (password|login|authentication)", re.IGNORECASE)


@dataclass
class ParsedLine:
    line_no: int
    raw: str
    ip: Optional[str]
    timestamp: Optional[datetime]
    status: Optional[int]
    url: Optional[str]
    port: Optional[int]
    failed_login: bool


@dataclass
class Alert:
    kind: str
    ip: Optional[str]
    timestamp: Optional[datetime]
    line_no: int
    detail: str


def parse_timestamp(line: str) -> Optional[datetime]:
    m = APACHE_TS_RE.search(line)
    if m:
        return datetime.strptime(m.group(0), "%d/%b/%Y:%H:%M:%S %z")
    m = ISO_TS_RE.search(line)
    if m:
        ts = m.group(0)
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(ts)
        except ValueError:
            return None
    m = SYSLOG_TS_RE.search(line)
    if m:
        # Syslog timestamps omit year; assume current year
        ts = m.group(0)
        try:
            return datetime.strptime(f"{datetime.now().year} {ts}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
    return None


def parse_line(line: str, line_no: int) -> ParsedLine:
    ip_match = IP_RE.search(line)
    ip = ip_match.group(0) if ip_match else None

    ts = parse_timestamp(line)

    status_match = HTTP_STATUS_RE.search(line)
    status = int(status_match.group(1)) if status_match else None

    req_match = HTTP_REQ_RE.search(line)
    url = req_match.group(2) if req_match else None

    port_match = PORT_RE.search(line)
    port = int(port_match.group(1)) if port_match else None

    failed_login = bool(FAILED_LOGIN_RE.search(line)) or (status == 401)

    return ParsedLine(
        line_no=line_no,
        raw=line.rstrip("\n"),
        ip=ip,
        timestamp=ts,
        status=status,
        url=url,
        port=port,
        failed_login=failed_login,
    )


def load_blacklist(path: Optional[str]) -> set[str]:
    if not path:
        return set()
    ips: set[str] = set()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            ips.add(s)
    return ips


def analyze(lines: Iterable[str], blacklist: set[str], min_fails: int, fail_window: int,
            port_threshold: int, port_window: int) -> tuple[list[Alert], dict]:
    alerts: list[Alert] = []
    stats = {
        "total_lines": 0,
        "failed_logins": 0,
        "unique_ips": set(),
        "suspicious_events": 0,
    }

    fail_windows: dict[str, deque[datetime]] = defaultdict(deque)
    port_windows: dict[str, deque[tuple[datetime, int]]] = defaultdict(deque)

    for idx, raw in enumerate(lines, start=1):
        stats["total_lines"] += 1
        pl = parse_line(raw, idx)
        if pl.ip:
            stats["unique_ips"].add(pl.ip)

        # Blacklist check
        if pl.ip and pl.ip in blacklist:
            alerts.append(Alert(
                kind="BLACKLISTED_IP",
                ip=pl.ip,
                timestamp=pl.timestamp,
                line_no=pl.line_no,
                detail="Access from blacklisted IP",
            ))

        # Failed login / brute force detection
        if pl.failed_login and pl.ip:
            stats["failed_logins"] += 1
            if pl.timestamp:
                dq = fail_windows[pl.ip]
                dq.append(pl.timestamp)
                cutoff = pl.timestamp - timedelta(seconds=fail_window)
                while dq and dq[0] < cutoff:
                    dq.popleft()
                if len(dq) >= min_fails:
                    alerts.append(Alert(
                        kind="BRUTE_FORCE",
                        ip=pl.ip,
                        timestamp=pl.timestamp,
                        line_no=pl.line_no,
                        detail=f"{len(dq)} failed logins within {fail_window}s",
                    ))
                    dq.clear()
            else:
                # No timestamp; use line-based heuristic
                alerts.append(Alert(
                    kind="FAILED_LOGIN",
                    ip=pl.ip,
                    timestamp=None,
                    line_no=pl.line_no,
                    detail="Failed login detected (no timestamp)",
                ))

        # Suspicious URLs
        if pl.url and SUSPICIOUS_URL_RE.search(pl.url):
            alerts.append(Alert(
                kind="SUSPICIOUS_URL",
                ip=pl.ip,
                timestamp=pl.timestamp,
                line_no=pl.line_no,
                detail=f"Suspicious URL: {pl.url}",
            ))

        # Port scan heuristic
        if pl.ip and pl.port is not None and pl.timestamp:
            dq = port_windows[pl.ip]
            dq.append((pl.timestamp, pl.port))
            cutoff = pl.timestamp - timedelta(seconds=port_window)
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            unique_ports = {p for _, p in dq}
            if len(unique_ports) >= port_threshold:
                alerts.append(Alert(
                    kind="PORT_SCAN",
                    ip=pl.ip,
                    timestamp=pl.timestamp,
                    line_no=pl.line_no,
                    detail=f"{len(unique_ports)} unique ports in {port_window}s",
                ))
                dq.clear()

    stats["suspicious_events"] = len(alerts)
    stats["unique_ips"] = len(stats["unique_ips"])
    return alerts, stats


def build_report(alerts: list[Alert], stats: dict, top_n: int) -> dict:
    ip_counts = Counter(a.ip for a in alerts if a.ip)

    def alert_ts(a: Alert) -> str:
        if a.timestamp:
            return a.timestamp.isoformat()
        return f"line {a.line_no}"

    def sort_key(a: Alert):
        if a.timestamp:
            return (0, a.timestamp, a.line_no)
        return (1, datetime.min, a.line_no)

    return {
        "summary": {
            "total_lines": stats["total_lines"],
            "failed_logins": stats["failed_logins"],
            "unique_ips": stats["unique_ips"],
            "suspicious_events": stats["suspicious_events"],
        },
        "top_ips": [
            {"ip": ip, "count": count} for ip, count in ip_counts.most_common(top_n)
        ],
        "alerts": [
            {
                "kind": a.kind,
                "ip": a.ip or "unknown",
                "timestamp": alert_ts(a),
                "detail": a.detail,
                "line_no": a.line_no,
            }
            for a in alerts
        ],
        "timeline": [
            {
                "timestamp": alert_ts(a),
                "ip": a.ip or "unknown",
                "kind": a.kind,
                "detail": a.detail,
                "line_no": a.line_no,
            }
            for a in sorted(alerts, key=sort_key)
        ],
    }


def format_report(alerts: list[Alert], stats: dict, top_n: int) -> str:
    report = build_report(alerts, stats, top_n)
    lines: list[str] = []
    lines.append("Summary")
    lines.append(f"Total lines: {report['summary']['total_lines']}")
    lines.append(f"Failed logins: {report['summary']['failed_logins']}")
    lines.append(f"Unique IPs: {report['summary']['unique_ips']}")
    lines.append(f"Suspicious events: {report['summary']['suspicious_events']}")

    lines.append("")
    lines.append("Top attacker IPs")
    if report["top_ips"]:
        for entry in report["top_ips"]:
            lines.append(f"- {entry['ip']}: {entry['count']}")
    else:
        lines.append("- None")

    lines.append("")
    lines.append("Alerts")
    if report["alerts"]:
        for a in report["alerts"]:
            lines.append(
                f"- [{a['kind']}] {a['timestamp']} {a['ip']} - {a['detail']}"
            )
    else:
        lines.append("- None")

    lines.append("")
    lines.append("Timeline")
    if report["timeline"]:
        for a in report["timeline"]:
            lines.append(
                f"- {a['timestamp']} {a['ip']} {a['kind']}: {a['detail']}"
            )
    else:
        lines.append("- None")

    return "\n".join(lines)


def read_lines_from_file(path: str) -> Iterable[str]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            yield line


def read_lines_from_stdin() -> Iterable[str]:
    for line in sys.stdin:
        yield line


def main() -> int:
    parser = argparse.ArgumentParser(description="Log Analyzer")
    parser.add_argument("--file", help="Path to log file")
    parser.add_argument("--stdin", action="store_true", help="Read logs from stdin")
    parser.add_argument("--blacklist", help="Path to blacklist file")
    parser.add_argument("--min-fails", type=int, default=3, help="Failed login threshold")
    parser.add_argument("--fail-window", type=int, default=60, help="Failed login window in seconds")
    parser.add_argument("--port-threshold", type=int, default=10, help="Unique ports threshold")
    parser.add_argument("--port-window", type=int, default=300, help="Port scan window in seconds")
    parser.add_argument("--top", type=int, default=3, help="Top attacker IPs to show")
    parser.add_argument("--json", action="store_true", help="Output JSON report")

    args = parser.parse_args()

    if not args.file and not args.stdin:
        print("Error: Provide --file or --stdin", file=sys.stderr)
        return 2

    blacklist = load_blacklist(args.blacklist)

    if args.stdin:
        lines = read_lines_from_stdin()
    else:
        lines = read_lines_from_file(args.file)

    alerts, stats = analyze(
        lines,
        blacklist,
        min_fails=args.min_fails,
        fail_window=args.fail_window,
        port_threshold=args.port_threshold,
        port_window=args.port_window,
    )

    if args.json:
        report = build_report(alerts, stats, args.top)
        print(json.dumps(report, indent=2))
    else:
        report = format_report(alerts, stats, args.top)
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
