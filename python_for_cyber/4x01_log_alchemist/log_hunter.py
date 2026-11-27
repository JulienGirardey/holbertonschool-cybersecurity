#!/usr/bin/env python3
"""LogHunter: a log analysis engine for Apache and Syslog files."""
import argparse
import json
import logging
import multiprocessing
import sys
from datetime import datetime
from itertools import islice
from collections import Counter, defaultdict, deque
from collections.abc import Iterable, Iterator
import re
from urllib.parse import unquote_plus
from typing import Optional


APACHE_PATTERN = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) \S+ \S+ '
    r'\[(?P<date>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: [^"]*)?" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)
SYSLOG_PATTERN = re.compile(
    r'^(?P<date>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) '
    r'(?P<host>\S+) '
    r'(?P<process>[^:\s]+): '
    r'(?P<message>.*)$'
)
IP_PATTERN = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')

GEOIP_DB = {'1.2.3.4': 'US', '5.6.7.8': 'RU'}
BOT_SIGNATURES = ['sqlmap', 'nikto', 'curl', 'python']
BLACKLIST = {'10.0.0.1', '192.168.1.66'}
SQLI_SIGNATURES = [
    re.compile(r"union(?:\s|/\*.*?\*/)+(?:all\s+)?select", re.IGNORECASE),
    re.compile(r"'\s*or\s+'?\w+'?\s*=\s*'?\w+", re.IGNORECASE),
    re.compile(r"\bor\s+1\s*=\s*1\b", re.IGNORECASE),
    re.compile(r"'\s*(?:--|#)", re.IGNORECASE),
    re.compile(r";\s*(?:drop|delete|insert|update)\s", re.IGNORECASE),
    re.compile(r"\b(?:sleep|benchmark)\s*\(", re.IGNORECASE),
    re.compile(r"information_schema", re.IGNORECASE),
]
XSS_SIGNATURES = [
    re.compile(r"<\s*script\b", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"\bon(?:load|error|click|mouseover|focus)\s*=",
               re.IGNORECASE),
    re.compile(r"<\s*(?:img|svg|iframe|body)\b[^>]*\bon\w+\s*=",
               re.IGNORECASE),
    re.compile(r"\b(?:alert|prompt|confirm)\s*\(", re.IGNORECASE),
    re.compile(r"document\.cookie", re.IGNORECASE),
]


# define logger
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# define logger format
formatter = logging.Formatter("[%(levelname)s] %(message)s")

# display debug logger on console
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(formatter)

# plug handlers to the logger
logger.addHandler(console)


class LogEntry:
    """A log event in a common format, whatever its source."""

    def __init__(self, ip: str = '', timestamp: str = '',
                 service: str = '', message: str = '', raw_line: str = '',
                 method: Optional[str] = None, path: Optional[str] = None,
                 status: Optional[int] = None,
                 user_agent: Optional[str] = None, **extra) -> None:
        """Store the common fields, the HTTP fields and any extra one."""
        self.ip = ip
        self.timestamp = timestamp
        self.service = service
        self.message = message
        self.raw_line = raw_line
        self.method = method
        self.path = path
        self.status = int(status) if status is not None else None
        self.user_agent = user_agent
        for name, value in extra.items():
            setattr(self, name, value)


def clean_data(lines: Iterable[str]) -> Iterator[str]:
    """Yield stripped lines, skipping blank lines and comments."""
    result1 = (x.strip() for x in lines if x.strip()
               and not x.strip().startswith("#"))
    return result1


def read_stream(file_path: str) -> Iterator[str]:
    """Yield the lines of a log file one at a time."""
    print(f"[*] LogHunter - Log Analysis Engine")
    try:
        print(f"[*] Reading: {file_path}")
        count = 0
        with open(file_path) as f:
            for line in clean_data(f):
                count += 1
                yield line
        print(f"[*] Lines read: {count}")
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        print("[!] No data to process. Exiting.")
        sys.exit(1)
    except PermissionError:
        logging.error(f"Permission denied: {file_path}")
        print("[!] No data to process. Exiting.")
        sys.exit(1)


def parse_apache_line(line: str) -> Optional[dict]:
    """Parse an Apache access log line into a dict, or None."""
    match = APACHE_PATTERN.search(line)
    if match:
        return match.groupdict()
    return None


def parse_syslog_line(line: str) -> Optional[dict]:
    """Parse a Syslog line into a dict, or None."""
    match = SYSLOG_PATTERN.search(line)
    if match:
        return match.groupdict()
    return None


def normalize_entry(parsed_dict: dict, log_type: str,
                    raw_line: str = '') -> LogEntry:
    """Turn an Apache or Syslog dict into a LogEntry."""
    if log_type == 'apache':
        entry = LogEntry(
            ip=parsed_dict['ip'],
            timestamp=parsed_dict['date'],
            service='http',
            message=f"{parsed_dict['method']} {parsed_dict['path']}",
            raw_line=raw_line,
        )
        entry.method = parsed_dict['method']
        entry.path = parsed_dict['path']
        entry.status = int(parsed_dict['status'])
        entry.user_agent = parsed_dict.get('user_agent') or ''
        return entry
    found_ip = IP_PATTERN.search(parsed_dict['message'])
    return LogEntry(
        ip=found_ip.group() if found_ip else '',
        timestamp=parsed_dict['date'],
        service='ssh',
        message=parsed_dict['message'],
        raw_line=raw_line,
    )


def filter_logs(stream: Iterable[LogEntry],
                status_codes: list = [404, 500]) -> Iterator[LogEntry]:
    """Yield only the entries whose HTTP status is in status_codes."""
    for entry in stream:
        if getattr(entry, 'status', None) in status_codes:
            yield entry


def enrich_ip(log_entry: LogEntry) -> LogEntry:
    """Add a country attribute to the entry from GEOIP_DB."""
    log_entry.country = GEOIP_DB.get(log_entry.ip, 'UNKNOWN')
    return log_entry


def analyze_user_agent(log_entry: LogEntry) -> LogEntry:
    """Flag the entry as a bot if it carries a known tool signature."""
    searched_text = ' '.join([
        getattr(log_entry, 'user_agent', None) or '',
        getattr(log_entry, 'message', None) or '',
        getattr(log_entry, 'raw_line', None) or '',
    ]).lower()
    log_entry.is_bot = any(signature in searched_text
                           for signature in BOT_SIGNATURES)
    return log_entry


def check_threat_intel(log_entry: LogEntry) -> LogEntry:
    """Set alert_level to HIGH for blacklisted IPs, LOW otherwise."""
    if getattr(log_entry, 'ip', '') in BLACKLIST:
        log_entry.alert_level = 'HIGH'
    else:
        log_entry.alert_level = 'LOW'
    return log_entry


def detect_sqli(log_entry: LogEntry) -> LogEntry:
    """Set attack_type to 'SQLi' if the path matches a SQLi signature."""
    path = unquote_plus(getattr(log_entry, 'path', None) or '')
    if any(signature.search(path) for signature in SQLI_SIGNATURES):
        log_entry.attack_type = 'SQLi'
    return log_entry


def detect_xss(log_entry: LogEntry) -> LogEntry:
    """Set attack_type to 'XSS' if the path matches an XSS signature."""
    if getattr(log_entry, 'attack_type', None) == 'SQLi':
        return log_entry
    path = unquote_plus(getattr(log_entry, 'path', None) or '')
    if any(signature.search(path) for signature in XSS_SIGNATURES):
        log_entry.attack_type = 'XSS'
    return log_entry


def detect_bruteforce(entries: Iterable[LogEntry],
                      threshold: int = 5) -> Iterator[dict]:
    """Yield a BRUTE_FORCE alert for each IP with too many failed logins."""
    failures = Counter()
    for entry in entries:
        ip_address = getattr(entry, 'ip', '')
        if not ip_address:
            continue
        failed_http = getattr(entry, 'status', None) == 401
        failed_ssh = 'Failed password' in (getattr(entry, 'message', None)
                                           or '')
        if failed_http or failed_ssh:
            failures[ip_address] += 1
    for ip_address, count in failures.most_common():
        if count > threshold:
            yield {'ip': ip_address, 'count': count,
                   'alert_type': 'BRUTE_FORCE'}


def parse_timestamp(timestamp: str) -> Optional[datetime]:
    """Turn an Apache or Syslog timestamp into a naive datetime, or None."""
    apache_formats = ('%d/%b/%Y:%H:%M:%S %z', '%d/%b/%Y:%H:%M:%S')
    for time_format in apache_formats:
        try:
            parsed = datetime.strptime(timestamp, time_format)
            return parsed.replace(tzinfo=None)
        except (TypeError, ValueError):
            continue
    try:
        # Syslog has no year: add a leap year so that Feb 29 parses too.
        return datetime.strptime(f"2000 {timestamp}", '%Y %b %d %H:%M:%S')
    except (TypeError, ValueError):
        return None


def detect_burst(entries: Iterable[LogEntry], window_seconds: int = 60,
                 threshold: int = 10) -> Iterator[dict]:
    """Yield a BURST alert when an IP sends threshold requests in a window."""
    windows = defaultdict(deque)
    alerted_ips = set()
    for entry in entries:
        ip_address = getattr(entry, 'ip', '')
        event_time = parse_timestamp(getattr(entry, 'timestamp', ''))
        if not ip_address or event_time is None:
            continue
        if ip_address in alerted_ips:
            continue
        window = windows[ip_address]
        window.append(event_time)
        while (event_time - window[0]).total_seconds() > window_seconds:
            window.popleft()
        if len(window) >= threshold:
            alerted_ips.add(ip_address)
            yield {'ip': ip_address, 'count': len(window),
                   'window': window_seconds, 'alert_type': 'BURST'}


def correlate_events(entries: Iterable[LogEntry]) -> Iterator[dict]:
    """Yield a CRITICAL INCIDENT when an IP both scans and tries SQLi."""
    ip_states = defaultdict(set)
    for entry in entries:
        ip_address = getattr(entry, 'ip', '')
        if not ip_address:
            continue
        if getattr(entry, 'status', None) == 404:
            ip_states[ip_address].add('scanner')
        if getattr(entry, 'attack_type', None) == 'SQLi':
            ip_states[ip_address].add('sqli')
        if {'scanner', 'sqli'} <= ip_states[ip_address]:
            yield {'ip': ip_address, 'stages': ['scanner', 'sqli'],
                   'alert_type': 'CRITICAL INCIDENT'}
            ip_states[ip_address].clear()


def export_report(alerts: list, filename: str, format: str = 'json') -> bool:
    """Write the alerts (dicts or LogEntry objects) to a JSON file."""
    if format != 'json':
        logging.error(f"Unsupported report format: {format}")
        return False
    report = [alert if isinstance(alert, dict) else vars(alert)
              for alert in alerts]
    try:
        with open(filename, 'w') as report_file:
            json.dump(report, report_file, indent=2, default=str)
            report_file.write('\n')
    except OSError as error:
        logging.error(f"Cannot write report {filename}: {error}")
        return False
    return True


def analyze_entry(entry: LogEntry) -> LogEntry:
    """Run every per-line enrichment and detection on one entry."""
    enrich_ip(entry)
    analyze_user_agent(entry)
    check_threat_intel(entry)
    detect_sqli(entry)
    detect_xss(entry)
    return entry


def process_line(line: str) -> Optional[LogEntry]:
    """Parse, normalize and analyze one raw line, or return None."""
    parsed = parse_apache_line(line)
    if parsed is not None:
        return analyze_entry(normalize_entry(parsed, 'apache', line))
    parsed = parse_syslog_line(line)
    if parsed is not None:
        return analyze_entry(normalize_entry(parsed, 'syslog', line))
    return None


def process_chunk(lines: list) -> list:
    """Worker: turn a list of raw lines into analyzed LogEntry objects."""
    results = []
    for line in lines:
        entry = process_line(line)
        if entry is not None:
            results.append(entry)
    return results


def read_chunks(file_path: str, chunk_size: int) -> Iterator[list]:
    """Yield lists of at most chunk_size cleaned lines from the file."""
    with open(file_path) as log_file:
        lines = clean_data(log_file)
        while True:
            chunk = list(islice(lines, chunk_size))
            if not chunk:
                return
            yield chunk


def parallel_analyze(file_path: str, num_workers: int,
                     chunk_size: int = 10000) -> list:
    """Analyze the file with a pool of workers and merge the results."""
    try:
        with multiprocessing.Pool(num_workers) as pool:
            chunk_results = pool.map(process_chunk,
                                     read_chunks(file_path, chunk_size))
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        print("[!] No data to process. Exiting.")
        sys.exit(1)
    except PermissionError:
        logging.error(f"Permission denied: {file_path}")
        print("[!] No data to process. Exiting.")
        sys.exit(1)
    return [entry for chunk in chunk_results for entry in chunk]


def main() -> None:
    """Parse the command line and run the LogHunter pipeline."""
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    parser.add_argument("--report", metavar="FILE",
                        help="export the alerts to a JSON file")
    parser.add_argument("--workers", type=int, default=0,
                        help="number of worker processes (0 = sequential)")
    args = parser.parse_args()

    if args.workers > 0:
        print("[*] LogHunter - Log Analysis Engine")
        print(f"[*] Reading: {args.file} (parallel: {args.workers} workers)")
        entries = parallel_analyze(args.file, args.workers)
    else:
        entries = process_chunk(read_stream(args.file))

    apache = sum(1 for entry in entries if entry.service == 'http')
    syslog = sum(1 for entry in entries if entry.service == 'ssh')
    print("--- Parsing ---")
    print(f"[*] Apache lines:  {apache}")
    print(f"[*] Syslog lines:  {syslog}")
    print(f"[*] Total parsed:  {apache + syslog}")
    if entries:
        sample = entries[0]
        print("[*] Sample entry:")
        print(f"    ip={sample.ip} | service={sample.service} | "
              f"status={sample.status} | path={sample.path}")

    print("--- Filtering ---")
    suspicious = list(filter_logs(entries))
    print(f"[*] Suspicious (404, 500): {len(suspicious)}")

    print("--- Enrichment ---")
    known_ips = sum(1 for entry in entries if entry.country != 'UNKNOWN')
    bots = sum(1 for entry in entries if entry.is_bot)
    print(f"[*] GeoIP: {len(entries)} entries enriched "
          f"({known_ips} known IPs)")
    print(f"[*] Bots detected: {bots}")

    print("--- Threat Intelligence ---")
    high_alerts = sum(1 for entry in entries if entry.alert_level == 'HIGH')
    print(f"[*] HIGH alerts: {high_alerts} entries from blacklisted IPs")

    print("--- Attack Detection ---")
    attack_types = [getattr(entry, 'attack_type', None) for entry in entries]
    print(f"[*] SQLi attempts: {attack_types.count('SQLi')}")
    print(f"[*] XSS attempts:  {attack_types.count('XSS')}")

    print("--- Brute Force ---")
    bruteforce_alerts = list(detect_bruteforce(entries))
    print(f"[*] BRUTE_FORCE alerts: {len(bruteforce_alerts)}")
    for alert in bruteforce_alerts:
        print(f"    {alert['ip']}: {alert['count']} failures")

    print("--- Burst Detection ---")
    burst_alerts = list(detect_burst(entries))
    print(f"[*] BURST alerts: {len(burst_alerts)}")
    for alert in burst_alerts:
        print(f"    {alert['ip']}: {alert['count']} requests "
              f"in {alert['window']}s window")

    print("--- Correlation ---")
    correlation_alerts = list(correlate_events(entries))
    print("[*] CRITICAL INCIDENTS:")
    for alert in correlation_alerts:
        print(f"    {alert['ip']}: {' -> '.join(alert['stages'])}")

    all_alerts = bruteforce_alerts + burst_alerts + correlation_alerts
    print()
    if args.report:
        if export_report(all_alerts, args.report):
            print(f"[*] Report exported: {args.report} "
                  f"({len(all_alerts)} alerts)")
    else:
        print(f"[*] Total alerts: {len(all_alerts)}")
        print("[*] Use --report <file> to export.")


if __name__ == '__main__':
    main()
