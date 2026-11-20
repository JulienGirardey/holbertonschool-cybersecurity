#!/usr/bin/env python3
import argparse
import logging
import sys
from collections.abc import Iterator


def clean_data(lines: list) -> list:
    result1 = (x.strip() for x in lines if x.strip()
               and not x.strip().startswith("#"))
    return result1


def read_stream(file_path: str) -> Iterator[str]:
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
        sys.exit(1)
    except PermissionError:
        logging.error(f"Permmission denied: {file_path}")
        sys.exit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    args = parser.parse_args()
    print(f"[*] LogHunter - Log Analysis Engine")
    for file in read_stream(args.file):
        pass
