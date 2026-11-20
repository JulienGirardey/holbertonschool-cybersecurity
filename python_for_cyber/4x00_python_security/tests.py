#!/usr/bin/env python3
import unittest
from utils import hash_password, validate_line
from breach_check import check_policy


class TestValidateLine(unittest.TestCase):
    def test_valid_line(self):
        self.assertTrue(validate_line("alice@example.com:secret"))

    def test_invalid_format(self):
        self.assertFalse(validate_line("alice.example.com:secret"))
        self.assertFalse(validate_line("not a valid line"))

    def test_missing_parts(self):
        self.assertFalse(validate_line("alice@example.com"))
        self.assertFalse(validate_line("alice@example.com:"))
        self.assertFalse(validate_line(":secret"))
        self.assertFalse(validate_line(""))


class TestCheckPolicy(unittest.TestCase):
    def test_short_password(self):
        self.assertEqual(check_policy("Ab1"), "WEAK")

    def test_numeric_password(self):
        self.assertEqual(check_policy("12345678"), "WEAK")

    def test_compliant_password(self):
        self.assertEqual(check_policy("Secure123"), "COMPLIANT")


class TestHashPassword(unittest.TestCase):
    def test_same_input_same_hash(self):
        first = hash_password("Secure123", "salt")
        second = hash_password("Secure123", "salt")
        self.assertEqual(first, second)

    def test_different_salt_different_hash(self):
        first = hash_password("Secure123", "salt1")
        second = hash_password("Secure123", "salt2")
        self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
