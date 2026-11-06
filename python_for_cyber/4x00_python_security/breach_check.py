#!/usr/bin/env python3
import argparse
import sys

def read_file(filename: str) -> list:
    try:
        with open(filename) as f:
            return f.read().splitlines()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filename}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"[ERROR] Permission denied: {filename}", file=sys.stderr)
        sys.exit(1)
    

def main():
    parser = argparse.ArgumentParser(description="Description of my program")
    parser.add_argument("-f", "--file", required=True, type=str, help="A mandatory string (Input file path).")
    parser.add_argument("-v", "--verbose", action="store_true", help="increase output verbosity")
    parser.add_argument("-o", "--output", type=str,help="An optional string (Output report file path).")
    args = parser.parse_args()
    result = read_file(args.file)
    print(result)

if __name__ == "__main__":
    main()
