"""Unit tests for RSA cryptosystem.
Tests primality testing, key generation, and encrypt/decrypt roundtrips.
NO forbidden crypto libraries are imported.
"""

import secrets
import unittest
from src.rsa import (
    is_probable_prime,
    extended_gcd,
    mod_inverse,
    generate_prime,
    generate_rsa_keypair,
    rsa_encrypt,
    rsa_decrypt,
    rsa_encrypt_bytes,
    rsa_decrypt_bytes,
)


def _is_prime_trial_division(n: int) -> bool:
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


class TestRSA(unittest.TestCase):
    def test_miller_rabin_known_values(self):
        """Test Miller-Rabin on known primes and composites."""
        known_primes = [
            2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
            65537,
            2147483647,  # 2^31 - 1 (Mersenne prime M31)
            (1 << 61) - 1, # Mersenne prime M61
        ]
        for p in known_primes:
            self.assertTrue(is_probable_prime(p), f"Failed to identify prime: {p}")

        known_composites = [
            0, 1, 4, 6, 8, 9, 15, 25, 27, 49,
            561,    # Carmichael number (3 * 11 * 17)
            1105,   # Carmichael number (5 * 13 * 17)
            1729,   # Carmichael number (7 * 13 * 19)
            2821,   # Carmichael number
            65535,
        ]
        for c in known_composites:
            self.assertFalse(is_probable_prime(c), f"False positive on composite: {c}")

    def test_mod_inverse(self):
        """Test Extended Euclidean algorithm mod_inverse."""
        e = 65537
        phi = (61 - 1) * (53 - 1)  # small example
        # gcd(65537, 3120) = 1
        d = mod_inverse(e, phi)
        self.assertEqual((e * d) % phi, 1)

    def test_extended_gcd(self):
        """Test extended_gcd on specified pairs."""
        g1, x1, y1 = extended_gcd(240, 46)
        self.assertEqual(g1, 2)
        self.assertEqual(240 * x1 + 46 * y1, 2)

        g2, x2, y2 = extended_gcd(17, 3120)
        self.assertEqual(g2, 1)
        self.assertEqual(17 * x2 + 3120 * y2, 1)

    def test_mod_inverse_vectors(self):
        """Test modular inverse with specific test vectors and non-coprime error."""
        self.assertEqual(mod_inverse(3, 11), 4)
        self.assertEqual(mod_inverse(17, 3120), 2753)
        self.assertEqual(mod_inverse(7, 40), 23)

        with self.assertRaises(ValueError):
            mod_inverse(4, 8)
        with self.assertRaises(ValueError):
            mod_inverse(6, 9)

    def test_is_probable_prime_primes(self):
        """Test is_probable_prime with k=40 on known primes."""
        primes = [
            2, 3, 5, 7, 97, 7919, 104729, 1000000007,
            2147483647,
            2305843009213693951,
        ]
        for p in primes:
            self.assertTrue(is_probable_prime(p, 40), f"Expected prime for {p}")

    def test_is_probable_prime_composites(self):
        """Test is_probable_prime with k=40 on composites including Carmichael numbers."""
        composites = [
            0, 1, 4, 100, 561, 41041, 825265, 321197185, 3215031751
        ]
        for c in composites:
            self.assertFalse(is_probable_prime(c, 40), f"Expected composite for {c}")

    def test_rsa_roundtrip_512_bits(self):
        """Test RSA keypair generation and roundtrip encryption/decryption (512-bit)."""
        pub_key, priv_key = generate_rsa_keypair(bits=512)
        e, n = pub_key
        d, _ = priv_key
        self.assertEqual(n.bit_length(), 512)

        # Byte roundtrip
        message = b"Nguyen Thi Nhu Y - RSA test 512"
        ciphertext = rsa_encrypt_bytes(message, pub_key)
        self.assertNotEqual(ciphertext, message)
        decrypted = rsa_decrypt_bytes(ciphertext, priv_key)
        self.assertEqual(decrypted, message)

        # Integer roundtrips for m = 2, 65, n - 1 and random m < n
        random_m = secrets.randbelow(n - 2) + 2
        for m in (2, 65, n - 1, random_m):
            c = rsa_encrypt(m, pub_key)
            self.assertEqual(rsa_decrypt(c, priv_key), m)

    def test_rsa_roundtrip_1024_bits(self):
        """Test RSA roundtrip with 1024-bit key."""
        pub_key, priv_key = generate_rsa_keypair(bits=1024)
        e, n = pub_key
        d, _ = priv_key
        self.assertEqual(n.bit_length(), 1024)

        # Byte roundtrip
        message = b"Information Security Assignment 2026 - RSA 1024 bit"
        ciphertext = rsa_encrypt_bytes(message, pub_key)
        decrypted = rsa_decrypt_bytes(ciphertext, priv_key)
        self.assertEqual(decrypted, message)

        # Integer roundtrips for m = 2, 65, n - 1 and random m < n
        random_m = secrets.randbelow(n - 2) + 2
        for m in (2, 65, n - 1, random_m):
            c = rsa_encrypt(m, pub_key)
            self.assertEqual(rsa_decrypt(c, priv_key), m)

    def test_generate_prime_bit_lengths_and_uniqueness(self):
        """Test generate_prime for exact bit length, primality by trial division, and uniqueness."""
        p16 = generate_prime(16)
        self.assertEqual(p16.bit_length(), 16)
        self.assertTrue(_is_prime_trial_division(p16))

        p32 = generate_prime(32)
        self.assertEqual(p32.bit_length(), 32)
        self.assertTrue(_is_prime_trial_division(p32))

        p64 = generate_prime(64)
        self.assertEqual(p64.bit_length(), 64)

        # Two calls give different values (allow one retry)
        a = generate_prime(64)
        b = generate_prime(64)
        if a == b:
            b = generate_prime(64)
        self.assertNotEqual(a, b)

    def test_fixed_textbook_key(self):
        """Test fixed textbook key p=61, q=53, n=3233, e=17, d=2753."""
        pub_key = (17, 3233)
        priv_key = (2753, 3233)
        phi = (61 - 1) * (53 - 1)
        self.assertEqual((17 * 2753) % phi, 1)

        vectors = [
            (65, 2790),
            (2, 1752),
            (123, 855),
            (1000, 175),
            (3232, 3232),
            (0, 0),
            (1, 1),
        ]
        for m, expected_c in vectors:
            c = rsa_encrypt(m, pub_key)
            self.assertEqual(c, expected_c)
            self.assertEqual(rsa_decrypt(c, priv_key), m)

    def test_rsa_value_errors(self):
        """Test ValueError for out-of-range message and ciphertext."""
        pub_key = (17, 3233)
        priv_key = (2753, 3233)
        with self.assertRaises(ValueError):
            rsa_encrypt(3233, pub_key)
        with self.assertRaises(ValueError):
            rsa_encrypt(-1, pub_key)
        with self.assertRaises(ValueError):
            rsa_decrypt(3233, priv_key)

    def test_wrong_private_key_fails(self):
        """Test that wrong private key (d + 1) does not decrypt to original m."""
        pub_key = (17, 3233)
        wrong_priv_key = (2754, 3233)  # d + 1
        m = 65
        c = rsa_encrypt(m, pub_key)
        self.assertNotEqual(rsa_decrypt(c, wrong_priv_key), m)


if __name__ == "__main__":
    unittest.main()
