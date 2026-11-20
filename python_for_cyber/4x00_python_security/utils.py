#!/usr/bin/env python3
import hashlib
import re


def hash_password(password: str, salt_conf: str) -> str:
    data = password.encode()
    encode_salt = salt_conf.encode()
    data_salt = data + encode_salt
    h = hashlib.sha256(data_salt)
    return h.hexdigest()


def clean_data(lines: list) -> list:
    result1 = [x.strip() for x in lines if x.strip()
               and not x.strip().startswith("#")]
    return result1


def validate_line(line: str) -> bool:
    return bool(re.fullmatch(r"[\w.-]+@\w+\.\w+:.+", line))
