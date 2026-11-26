"""Unit tests for SHA-256 hash function.
All test vectors are hardcoded constants (NIST FIPS 180-4 and project specification).
NO forbidden crypto libraries (hashlib, etc.) are imported.
"""

import unittest
from src.sha256 import sha256_hex, sha256_bytes


class TestSHA256(unittest.TestCase):
    def test_empty_string(self):
        """Test vector for empty string: SHA-256('')"""
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertEqual(sha256_hex(b""), expected)

    def test_nist_abc(self):
        """Mandatory test vector 1: SHA-256('abc')"""
        expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        self.assertEqual(sha256_hex(b"abc"), expected)

    def test_student_name(self):
        """Mandatory test vector 2: SHA-256('Nguyen Thi Nhu Y')"""
        expected = "f5db6c7e3f6d978c01b2409cd300d3c551209137b1ada810c6323122acb47d4d"
        self.assertEqual(sha256_hex("Nguyen Thi Nhu Y"), expected)

    def test_nist_multi_block(self):
        """Test vector spanning across multiple blocks (56-byte message boundary)."""
        msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        self.assertEqual(sha256_hex(msg), expected)

    def test_avalanche_effect(self):
        """Test that altering 1 bit in the input flips roughly 50% (+/- 15%) of the hash bits."""
        msg1 = b"Information Security 2026 - Nguyen Thi Nhu Y"
        # Flip the lowest bit of the last character
        msg2 = bytearray(msg1)
        msg2[-1] ^= 0x01

        hash1 = sha256_bytes(bytes(msg1))
        hash2 = sha256_bytes(bytes(msg2))

        # Count bit differences (Hamming distance)
        diff_bits = sum(bin(b1 ^ b2).count("1") for b1, b2 in zip(hash1, hash2))
        total_bits = 256
        diff_percentage = (diff_bits / total_bits) * 100

        # Good cryptographic hash functions exhibit strict avalanche criterion (~40% to 60%)
        self.assertGreater(diff_percentage, 35.0)
        self.assertLess(diff_percentage, 65.0)


if __name__ == "__main__":
    unittest.main()
