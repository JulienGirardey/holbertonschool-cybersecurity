#!/usr/bin/env python3
import argparse
import logging
import sys
from collections.abc import Iterator
import re
from typing import Optional


APACHE_PATTERN = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) \S+ \S+ '
    r'\[(?P<date>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: [^"]*)?" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)
IP_PATTERN = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')


# define logger
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# define logger format
formatter = logging.Formatter("%(levelname)s %(message)s")

# display debug logger on console
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(formatter)

# plug handlers to the logger
logger.addHandler(console)


class LogEntry:
    """A log event in a common format, whatever its source"""
    def __init__(self, ip: str, timestamp: str, service: str,
                 message: str, raw_line: str = '') -> None:
        """Store the fields shared by every log type"""
        self.ip = ip
        self.timestamp = timestamp
        self.service = service
        self.message = message
        self.raw_line = raw_line
        self.method: Optional[str] = None
        self.path: Optional[str] = None
        self.status: Optional[str] = None
        self.user_agent: Optional[str] = None


def clean_data(lines: list) -> list:
    result1 = (x.strip() for x in lines if x.strip()
               and not x.strip().startswith("#"))
    return result1


def read_stream(file_path: str) -> Iterator[str]:
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
        print(f"[!] No data to process. Exiting.")
        return
    except PermissionError:
        logging.error(f"Permmission denied: {file_path}")
        return


def parse_apache_line(line: str) -> dict:
    pattern = (
        r'^(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
        r'\S+ \S+ '
        r'\[(?P<date>[^\]]+)\] '
        r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<protocol>[^"]+)" '
        r'(?P<status>\d{3}) '
        r'(?P<size>\d+|-)'
    )
    m = re.search(pattern, line)
    if (m):
        return m.groupdict()
    else:
        return None


def parse_syslog_line(line: str) -> dict:
    pattern = (
        r'^(?P<date>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) '
        r'(?P<host>\S+) '
        r'(?P<process>[^:\s]+): '
        r'(?P<message>.*)$'
    )
    m = re.search(pattern, line)
    if (m):
        return m.groupdict()
    else:
        return None


def normalize_entry(parsed_dict, log_type, raw_line='') -> LogEntry:
    """Turn an Apache or Syslog dict into a LogEntry"""
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
    print(f"[*] Apache lines: {apache}")
    print(f"[*] Syslog lines: 0")
    print(f"[*] Total parsed: {apache + syslog}")
    if entries:
        sample = entries[0]
        print("[*] Sample entry:")
        print(f"    ip={sample.ip} | service={sample.service} | "
              f"status={sample.status} | path={sample.path}")
