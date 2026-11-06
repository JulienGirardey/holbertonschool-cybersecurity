#!/usr/bin/env python3
import argparse

def main():
    parser = argparse.ArgumentParser(description="Description of my program")
    parser.add_argument("-f", "--file", required=True, type=str, help="A mandatory string (Input file path).")
    parser.add_argument("-v", "--verbose", action="store_true", help="increase output verbosity")
    parser.add_argument("-o", "--output", type=str,help="An optional string (Output report file path).")
    args = parser.parse_args()

if __name__ == "__main__":
    main()
