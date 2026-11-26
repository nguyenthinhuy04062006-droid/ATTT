"""RSA Asymmetric Cryptosystem (PKCS #1 / RFC 8017).
Implemented from scratch without external cryptographic libraries.

Student: Nguyen Thi Nhu Y
SID ends with: 0 (0 mod 3 = 0 -> RSA)
Reference: RFC 8017 (PKCS #1 v2.2)
"""

import secrets
from typing import Tuple
from src.utils import bytes_to_int, int_to_bytes


def is_probable_prime(n: int, k: int = 40) -> bool:
    """Miller-Rabin Probabilistic Primality Test.
    
    Determines whether odd integer n is composite or probable prime with error <= 4^(-k).
    
    Algorithm:
    1. Handle small primes and even numbers (n <= 3, n % 2 == 0).
    2. Write n - 1 = 2^s * d, where d is odd.
    3. Loop k times:
       - Pick random witness a in range [2, n - 2].
       - Compute x = pow(a, d, n).
       - If x == 1 or x == n - 1, continue next round.
       - Repeat s - 1 times:
           x = pow(x, 2, n)
           If x == n - 1, break to next witness.
       - If loop completes without break, return False (composite).
    4. Return True (probable prime).
    
    Args:
        n: Integer to test for primality.
        k: Number of iterations (security parameter, default 40).
        
    Returns:
        True if n is probably prime, False if n is definitely composite.
    """
    # Miller-Rabin Primality Test (Miller 1976, Rabin 1980)
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Decompose n - 1 = 2^s * d with d odd
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # Test with k random witness bases in range [2, n - 2]
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits: int) -> int:
    """Generate a random prime number with the specified bit length.
    
    Uses secrets.randbits(bits), sets top bit and bottom bit to ensure
    exact bit length and oddness, then tests with is_probable_prime.
    """
    if bits < 2:
        raise ValueError("Prime bit length must be at least 2")
    if bits == 2:
        return secrets.choice([2, 3])
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate, 40):
            return candidate


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean Algorithm.
    
    Returns (g, x, y) such that a*x + b*y = g = gcd(a, b).
    """
    x0, x1 = 1, 0
    y0, y1 = 0, 1
    while b != 0:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def mod_inverse(e: int, phi: int) -> int:
    """Compute modular inverse d such that (d * e) % phi == 1 (Rivest-Shamir-Adleman 1978).
    
    Raises ValueError if gcd(e, phi) != 1.
    """
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist: gcd({e}, {phi}) = {g} != 1")
    return x % phi


def generate_rsa_keypair(bits: int = 1024, e: int = 65537) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """Generate an RSA key pair ((e, n), (d, n)) (Rivest-Shamir-Adleman 1978).
    
    Textbook RSA (no padding) is deterministic and malleable, so not secure alone in production.
    """
    half_bits = bits // 2
    while True:
        while True:
            p_cand = secrets.randbits(half_bits) | (1 << (half_bits - 1)) | (1 << (half_bits - 2)) | 1
            if is_probable_prime(p_cand, 40):
                p = p_cand
                break
        while True:
            q_cand = secrets.randbits(half_bits) | (1 << (half_bits - 1)) | (1 << (half_bits - 2)) | 1
            if q_cand != p and is_probable_prime(q_cand, 40):
                q = q_cand
                break

        n = p * q
        if n.bit_length() != bits:
            continue

        phi = (p - 1) * (q - 1)
        g, _, _ = extended_gcd(e, phi)
        if g == 1:
            d = mod_inverse(e, phi)
            return (e, n), (d, n)


def rsa_encrypt(message_int: int, public_key: Tuple[int, int]) -> int:
    """Encrypt an integer message using RSA public key (e, n) (Rivest-Shamir-Adleman 1978).
    
    Formula: c = (m^e) mod n
    Textbook RSA is deterministic and malleable, not secure alone.
    """
    e, n = public_key
    if message_int < 0 or message_int >= n:
        raise ValueError(f"Message representative out of range [0, {n - 1}]")
    return pow(message_int, e, n)


def rsa_decrypt(ciphertext_int: int, private_key: Tuple[int, int]) -> int:
    """Decrypt an integer ciphertext using RSA private key (d, n) (Rivest-Shamir-Adleman 1978).
    
    Formula: m = (c^d) mod n
    Textbook RSA is deterministic and malleable, not secure alone.
    """
    d, n = private_key
    if ciphertext_int < 0 or ciphertext_int >= n:
        raise ValueError(f"Ciphertext representative out of range [0, {n - 1}]")
    return pow(ciphertext_int, d, n)


def rsa_encrypt_bytes(data: bytes, public_key: Tuple[int, int]) -> bytes:
    """Encrypt byte string by converting to integer and applying RSA."""
    m_int = bytes_to_int(data)
    _, n = public_key
    if m_int >= n:
        raise ValueError("Message size is too large for modulus n")
    c_int = rsa_encrypt(m_int, public_key)
    # Output byte length is modulus byte length
    mod_len = (n.bit_length() + 7) // 8
    return int_to_bytes(c_int, mod_len)


def rsa_decrypt_bytes(ciphertext_bytes: bytes, private_key: Tuple[int, int]) -> bytes:
    """Decrypt ciphertext bytes back to original message bytes."""
    c_int = bytes_to_int(ciphertext_bytes)
    m_int = rsa_decrypt(c_int, private_key)
    return int_to_bytes(m_int)
