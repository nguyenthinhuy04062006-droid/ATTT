"""Unit tests for ElGamal Digital Signature.
Tests parameter generation, signing, verification, and tamper detection.
NO forbidden crypto libraries are imported.
"""

import secrets
import unittest
from src.elgamal import (
    generate_elgamal_params,
    generate_elgamal_keypair,
    elgamal_sign,
    elgamal_verify,
)
from src.sha256 import sha256_bytes
from src.rsa import is_probable_prime


def _is_prime_trial(n: int) -> bool:
    """Trial division primality test for small numbers (test-only helper)."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


class TestElGamal(unittest.TestCase):
    def setUp(self):
        # Predefined safe prime p and generator g for fast test execution
        # p is a 256-bit safe prime: p = 2*q + 1
        self.p = int(
            "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
            "FFFFFFFFFFFFFFFF", 16
        )
        self.g = 2

    def test_elgamal_sign_verify_valid(self):
        """Test standard signing and verification with valid keys and message."""
        x, y = generate_elgamal_keypair(self.p, self.g)
        message = b"Nguyen Thi Nhu Y - Digital Signature ElGamal"

        signature = elgamal_sign(message, x, self.p, self.g)
        is_valid = elgamal_verify(message, signature, y, self.p, self.g)
        self.assertTrue(is_valid, "Valid signature failed to verify")

    def test_elgamal_tampered_message_fails(self):
        """Test that altering 1 bit in the message invalidates the signature."""
        x, y = generate_elgamal_keypair(self.p, self.g)
        message = b"Original transaction: Transfer 100 USD"
        signature = elgamal_sign(message, x, self.p, self.g)

        # Alter 1 bit in message
        tampered_message = b"Original transaction: Transfer 900 USD"
        is_valid = elgamal_verify(tampered_message, signature, y, self.p, self.g)
        self.assertFalse(is_valid, "Tampered message unexpectedly verified as valid")

    def test_elgamal_tampered_signature_fails(self):
        """Test that altering 1 bit in signature components (r or s) invalidates verification."""
        x, y = generate_elgamal_keypair(self.p, self.g)
        message = b"Important document to sign"
        r, s = elgamal_sign(message, x, self.p, self.g)

        # Tamper r
        bad_sig_r = ((r ^ 1) % self.p, s)
        self.assertFalse(elgamal_verify(message, bad_sig_r, y, self.p, self.g))

        # Tamper s
        bad_sig_s = (r, (s ^ 1) % (self.p - 1))
        self.assertFalse(elgamal_verify(message, bad_sig_s, y, self.p, self.g))

    def test_elgamal_full_flow_with_generated_params(self):
        """Test full generation of parameters, keys, and signing."""
        p, g = generate_elgamal_params(bits=256)
        x, y = generate_elgamal_keypair(p, g)
        message = b"Full parameter generation test"

        signature = elgamal_sign(message, x, p, g)
        self.assertTrue(elgamal_verify(message, signature, y, p, g))

    def test_params_various_bit_lengths(self):
        """Test parameter generation across bits=8, 10, 16, 32, 64, 128 and error for bits=7."""
        with self.assertRaises(ValueError):
            generate_elgamal_params(7)

        for b in (8, 10, 16, 32, 64, 128):
            p, g = generate_elgamal_params(b)
            self.assertEqual(p.bit_length(), b)
            q = (p - 1) // 2

            if b in (8, 10, 16, 32):
                self.assertTrue(_is_prime_trial(p))
                self.assertTrue(_is_prime_trial(q))
            else:
                self.assertTrue(is_probable_prime(p, 40))
                self.assertTrue(is_probable_prime(q, 40))

            self.assertNotEqual(pow(g, 2, p), 1)
            self.assertNotEqual(pow(g, q, p), 1)

            if b in (8, 10, 16):
                # Brute-force order of g == p - 1
                generated = set(pow(g, i, p) for i in range(1, p))
                self.assertEqual(len(generated), p - 1)

    def test_params_512_bits(self):
        """Single test for 512-bit safe prime parameter generation and sign/verify roundtrip."""
        p, g = generate_elgamal_params(bits=512)
        self.assertEqual(p.bit_length(), 512)
        q = (p - 1) // 2
        self.assertTrue(is_probable_prime(p, 40))
        self.assertTrue(is_probable_prime(q, 40))

        x, y = generate_elgamal_keypair(p, g)
        msg = b"512-bit ElGamal test message"
        sig = elgamal_sign(msg, x, p, g)
        self.assertTrue(elgamal_verify(msg, sig, y, p, g))

    def test_keypair_ranges(self):
        """Test keypair adheres to 2 <= x <= p - 2 and y == g^x mod p."""
        x, y = generate_elgamal_keypair(self.p, self.g)
        self.assertTrue(2 <= x <= self.p - 2)
        self.assertEqual(y, pow(self.g, x, self.p))

    def test_textbook_fixed_params_467(self):
        """Test textbook fixed parameters p=467, g=2, x=127 with reference verification and signing."""
        p = 467
        g = 2
        x = 127
        y = pow(g, x, p)
        self.assertEqual(y, 132)

        # Find first i where int(SHA-256(f"msg{i}")) % 466 == 100
        target_i = None
        for i in range(1000):
            h_val = int.from_bytes(sha256_bytes(f"msg{i}".encode("utf-8")), byteorder="big")
            if h_val % 466 == 100:
                target_i = i
                break
        self.assertIsNotNone(target_i)

        # With k=213: r=29, s=51
        self.assertEqual((pow(y, 29, p) * pow(29, 51, p)) % p, pow(g, 100, p))
        self.assertTrue(elgamal_verify(f"msg{target_i}", (29, 51), y, p, g))

        # Full round trip with elgamal_sign
        sig = elgamal_sign(b"Textbook message", x, p, g)
        self.assertTrue(elgamal_verify(b"Textbook message", sig, y, p, g))

    def test_roundtrip_128_bit_params_20_signatures(self):
        """Test round trip with 128-bit params across 20 diverse messages."""
        p, g = generate_elgamal_params(128)
        x, y = generate_elgamal_keypair(p, g)

        messages = [
            "",
            "abc",
            "Nguyễn Thị Như Ý",
            "x" * 10240,  # 10 KB string
        ] + [f"Message payload #{i}" for i in range(16)]

        for msg in messages:
            sig = elgamal_sign(msg, x, p, g)
            self.assertTrue(elgamal_verify(msg, sig, y, p, g))

    def test_randomized_signatures_different(self):
        """Test same message signed twice produces distinct (r, s) due to fresh k."""
        p, g = generate_elgamal_params(128)
        x, y = generate_elgamal_keypair(p, g)
        msg = b"Signature randomness test"

        sig1 = elgamal_sign(msg, x, p, g)
        sig2 = elgamal_sign(msg, x, p, g)
        if sig1 == sig2:
            sig2 = elgamal_sign(msg, x, p, g)
        self.assertNotEqual(sig1, sig2)
        self.assertTrue(elgamal_verify(msg, sig1, y, p, g))
        self.assertTrue(elgamal_verify(msg, sig2, y, p, g))

    def test_negative_verification_cases(self):
        """Test that tampered signatures, keys, and malformed inputs return False without raising."""
        p, g = generate_elgamal_params(128)
        x, y = generate_elgamal_keypair(p, g)
        msg = b"Original message for negative testing"
        r, s = elgamal_sign(msg, x, p, g)

        # Altered message
        self.assertFalse(elgamal_verify(b"Altered message", (r, s), y, p, g))

        # r + 1 and s + 1
        self.assertFalse(elgamal_verify(msg, (r + 1, s), y, p, g))
        self.assertFalse(elgamal_verify(msg, (r, s + 1), y, p, g))

        # Wrong public key
        wrong_y = (y + 1) if y + 1 < p else (y - 1)
        self.assertFalse(elgamal_verify(msg, (r, s), wrong_y, p, g))

        # Boundary checks for r
        self.assertFalse(elgamal_verify(msg, (0, s), y, p, g))
        self.assertFalse(elgamal_verify(msg, (p, s), y, p, g))
        self.assertFalse(elgamal_verify(msg, (p + 1, s), y, p, g))

        # Boundary checks for s
        self.assertFalse(elgamal_verify(msg, (r, 0), y, p, g))
        self.assertFalse(elgamal_verify(msg, (r, p - 1), y, p, g))

        # Malformed signatures
        self.assertFalse(elgamal_verify(msg, None, y, p, g))
        self.assertFalse(elgamal_verify(msg, (1,), y, p, g))
        self.assertFalse(elgamal_verify(msg, (1, 2, 3), y, p, g))
        self.assertFalse(elgamal_verify(msg, ("a", "b"), y, p, g))
        self.assertFalse(elgamal_verify(msg, (secrets.randbelow(p), secrets.randbelow(p)), y, p, g))

    def test_wrong_private_key_signature_fails(self):
        """Test signature with wrong private key does not verify under original public key."""
        p, g = generate_elgamal_params(128)
        x, y = generate_elgamal_keypair(p, g)
        wrong_x = (x + 1) if x + 1 < p - 1 else (x - 1)
        msg = b"Test wrong private key"

        sig = elgamal_sign(msg, wrong_x, p, g)
        self.assertFalse(elgamal_verify(msg, sig, y, p, g))


if __name__ == "__main__":
    unittest.main()
