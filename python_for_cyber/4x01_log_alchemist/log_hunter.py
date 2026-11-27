#!/usr/bin/env python3
"""LogHunter: a log analysis engine for Apache and Syslog files."""
import argparse
import logging
import sys
from datetime import datetime
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


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    args = parser.parse_args()
    apache = 0
    syslog = 0
    entries = []
    for line in read_stream(args.file):
        parsed = parse_apache_line(line)
        if parsed is not None:
            apache += 1
            entries.append(normalize_entry(parsed, 'apache', line))
            continue
        parsed = parse_syslog_line(line)
        if parsed is not None:
            syslog += 1
            entries.append(normalize_entry(parsed, 'syslog', line))
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
    known_ips = 0
    bots = 0
    for entry in entries:
        enrich_ip(entry)
        if entry.country != 'UNKNOWN':
            known_ips += 1
        analyze_user_agent(entry)
        if entry.is_bot:
            bots += 1
    print(f"[*] GeoIP: {len(entries)} entries enriched "
          f"({known_ips} known IPs)")
    print(f"[*] Bots detected: {bots}")
    print("--- Threat Intelligence ---")
    high_alerts = 0
    for entry in entries:
        check_threat_intel(entry)
        if entry.alert_level == 'HIGH':
            high_alerts += 1
    print(f"[*] HIGH alerts: {high_alerts} entries from blacklisted IPs")
    print("--- Attack Detection ---")
    sqli_attempts = 0
    xss_attempts = 0
    for entry in entries:
        detect_sqli(entry)
        detect_xss(entry)
        attack_type = getattr(entry, 'attack_type', None)
        if attack_type == 'SQLi':
            sqli_attempts += 1
        elif attack_type == 'XSS':
            xss_attempts += 1
    print(f"[*] SQLi attempts: {sqli_attempts}")
    print(f"[*] XSS attempts:  {xss_attempts}")
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
