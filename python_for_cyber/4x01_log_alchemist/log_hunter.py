#!/usr/bin/env python3
import argparse
import logging
import sys
from collections.abc import Iterator
import re


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


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    args = parser.parse_args()
    apache = 0
    syslog = 0
    for line in read_stream(args.file):
        if (parse_apache_line(line) is not None):
            apache += 1
    print("--- Parsing ---")
    print(f"[*] Apache lines: {apache}")
    print(f"[*] Syslog lines: 0")
    print(f"[*] Total parsed: {apache + syslog}")
