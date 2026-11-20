#!/usr/bin/env python3
import argparse
import sys
import logging
import configparser
from utils import  hash_password, clean_data, validate_line

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

config = configparser.ConfigParser()
found = config.read("config.ini")

if not found:
    print("[ERROR] config file missing")
    sys.exit(1)

salt_conf = config["SECURITY"]["salt"]
minLength = config.getint("SECURITY", "MinLength")

def check_policy(password: str) -> str:
    common_psw = ["password", "123456"]

    if len(password) < minLength:
        return "WEAK"
    elif password.isalpha():
        return "WEAK"
    elif password.isdigit():
        return "WEAK"
    elif password in common_psw:
        return "WEAK"
    else:
        return "COMPLIANT"

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
