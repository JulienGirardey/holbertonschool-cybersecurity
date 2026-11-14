#!/usr/bin/env python3
import argparse
import sys
import re
import logging
import hashlib

# define logger
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# define logger format
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

# display debug logger on console
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(formatter)

# display others logger on log file
file = logging.FileHandler("breach_check.log")
file.setLevel(logging.DEBUG)
file.setFormatter(formatter)

# plug handlers to the logger
logger.addHandler(console)
logger.addHandler(file)

def hash_password(password: str, salt: str) -> str:
    data = password.encode()
    encode_salt = salt.encode()
    data_salt = data + encode_salt
    h = hashlib.sha256(data_salt)
    return h

def check_policy(password: str) -> str:
    common_psw = ["password", "123456"]

    if len(password) < 8:
        return "WEAK"
    elif password.isalpha():
        return "WEAK"
    elif password.isdigit():
        return "WEAK"
    elif password in common_psw:
        return "WEAK"
    else:
        return "COMPLIANT"

def validate_line(line: str) -> bool:
    return bool(re.fullmatch(r"[\w.-]+@\w+\.\w+:.+", line))

def clean_data(lines: list) -> list:
    result1 = [x.strip() for x in lines if x.strip() and not x.strip().startswith("#")]
    return result1

def read_file(filename: str) -> list:
    logging.info(f"Processing file...")
    try:
        logging.debug("Starting readinf file on line 21...")
        with open(filename) as f:
            return f.read().splitlines()
    except FileNotFoundError:
        logging.error(f"File not found: {filename}")
        sys.exit(1)
    except PermissionError:
        logging.error(f"Permmission denied: {filename}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Description of my program")
    parser.add_argument("-f", "--file", required=True, type=str, help="A mandatory string (Input file path).")
    parser.add_argument("-v", "--verbose", action="store_true", help="increase output verbosity")
    parser.add_argument("-o", "--output", type=str,help="An optional string (Output report file path).")
    password = "password"
    print(check_policy(password))
    hash_password(password, "salt")
    result = read_file("test.txt")
    print(result)

if __name__ == "__main__":
    main()
