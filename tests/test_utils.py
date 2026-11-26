"""Unit tests for utility functions including PKCS#7 padding and bitwise operations."""

import unittest
from src.utils import (
    rotr32,
    rotl32,
    bytes_to_int,
    int_to_bytes,
    pkcs7_pad,
    pkcs7_unpad,
    bytes_to_matrix,
    matrix_to_bytes,
)


class TestUtils(unittest.TestCase):
    def test_pkcs7_pad_unpad_lengths(self):
        """Test PKCS#7 pad and unpad roundtrips for lengths 0..33."""
        for length in range(34):
            data = bytes([i % 256 for i in range(length)])
            padded = pkcs7_pad(data, 16)
            self.assertEqual(len(padded) % 16, 0)
            self.assertGreater(len(padded), len(data))
            self.assertEqual(pkcs7_unpad(padded, 16), data)

    def test_pkcs7_16_byte_input_full_block(self):
        """Test that a 16-byte input gets a full 16-byte padding block."""
        data = b"0123456789abcdef"
        padded = pkcs7_pad(data, 16)
        self.assertEqual(len(padded), 32)
        self.assertEqual(padded[16:], bytes([16] * 16))
        self.assertEqual(pkcs7_unpad(padded, 16), data)

    def test_pkcs7_invalid_padding_rejected(self):
        """Test that invalid padding bytes and lengths are properly rejected."""
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"", 16)
        with self.assertRaises(ValueError):
            pkcs7_unpad(bytes(15), 16)
        with self.assertRaises(ValueError):
            pkcs7_unpad(bytes(15) + b"\x00", 16)
        with self.assertRaises(ValueError):
            pkcs7_unpad(bytes(15) + b"\x11", 16)
        with self.assertRaises(ValueError):
            pkcs7_unpad(bytes(14) + b"\x01\x02", 16)


if __name__ == "__main__":
    unittest.main()
