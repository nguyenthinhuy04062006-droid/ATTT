"""ElGamal Digital Signature Scheme.
Implemented from scratch without external cryptographic libraries.
Uses custom SHA-256 implementation for message hashing.

Student: Nguyen Thi Nhu Y
SID ends with: 0 (0 mod 4 = 0 -> ElGamal Digital Signature)
Reference: Taher Elgamal, "A Public Key Cryptosystem and a Signature Scheme Based on Discrete Logarithms" (1985)
"""

import secrets
from typing import Tuple, Union, List
from src.sha256 import sha256_bytes
from src.rsa import is_probable_prime, mod_inverse, extended_gcd
from src.utils import bytes_to_int


def _small_primes_sieve(limit: int = 1000) -> List[int]:
    """Generate list of small primes up to limit for early composite rejection."""
    primes = []
    sieve = [True] * limit
    for i in range(2, limit):
        if sieve[i]:
            primes.append(i)
            for j in range(i * i, limit, i):
                sieve[j] = False
    return primes


_SMALL_PRIMES = _small_primes_sieve(1000)


def find_primitive_root(p: int) -> int:
    """Find a primitive root (generator) g modulo safe prime p = 2*q + 1 (ElGamal 1985).
    
    If p = 2*q + 1 (safe prime where q is prime), the only proper divisors of p - 1 are 2 and q.
    g in [2, p - 2] is a generator iff:
        pow(g, 2, p) != 1 and pow(g, q, p) != 1.
    """
    q = (p - 1) // 2
    while True:
        g = secrets.randbelow(p - 3) + 2  # Random candidate in [2, p - 2]
        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            return g


def generate_elgamal_params(bits: int = 512) -> Tuple[int, int]:
    """Generate ElGamal domain parameters (p, g) (ElGamal 1985).
    
    p is a safe prime of length `bits` (i.e. p = 2*q + 1 where q is a prime of length bits - 1).
    g is a generator of the cyclic group Z_p^*.
    
    Returns:
        (p, g) tuple.
    """
    if bits < 8:
        raise ValueError("ElGamal parameter bit length must be at least 8")

    half_bits = bits - 1
    while True:
        # q is an odd integer of length bits - 1 with top bit set
        q_cand = secrets.randbits(half_bits) | (1 << (half_bits - 1)) | 1
        p_cand = 2 * q_cand + 1

        # Reject early if divisible by small prime s < 1000 and s < candidate
        early_reject = False
        for s in _SMALL_PRIMES:
            if s < q_cand and q_cand % s == 0:
                early_reject = True
                break
            if s < p_cand and p_cand % s == 0:
                early_reject = True
                break
        if early_reject:
            continue

        # Primality verification via Miller-Rabin (k=40)
        if is_probable_prime(q_cand, 40) and is_probable_prime(p_cand, 40):
            p = p_cand
            break

    g = find_primitive_root(p)
    return p, g


def generate_elgamal_keypair(p: int, g: int) -> Tuple[int, int]:
    """Generate ElGamal private key x and public key y (ElGamal 1985).
    
    1. Select random private key x in range [2, p - 2].
    2. Compute public key y = (g^x) mod p.
    
    Returns:
        (private_key_x, public_key_y)
    """
    x = secrets.randbelow(p - 3) + 2
    y = pow(g, x, p)
    return x, y


def elgamal_sign(message: Union[bytes, str], x: int, p: int, g: int) -> Tuple[int, int]:
    """Generate ElGamal digital signature (r, s) for a message (ElGamal 1985).
    
    Security requirements:
    - Fresh random ephemeral key k per signature (reused k exposes private key x).
    - Hash needed before signing (prevents existential forgery without knowing private key).
    - Exponents and s computed modulo p - 1 (Euler's totient theorem in Z_p^*).
    """
    if isinstance(message, str):
        message = message.encode("utf-8")

    h = int.from_bytes(sha256_bytes(message), byteorder="big")
    p_minus_1 = p - 1

    while True:
        k = secrets.randbelow(p - 3) + 2  # New random k in [2, p - 2]
        gcd_val, _, _ = extended_gcd(k, p_minus_1)
        if gcd_val != 1:
            continue
        r = pow(g, k, p)
        k_inv = mod_inverse(k, p_minus_1)
        s = (k_inv * (h - x * r)) % p_minus_1
        if s != 0:
            return r, s


def elgamal_verify(message: Union[bytes, str], signature: Tuple[int, int], y: int, p: int, g: int) -> bool:
    """Verify an ElGamal digital signature (r, s) for a message (ElGamal 1985).
    
    Verification rules:
    - Never raises exception on malformed signatures; returns False.
    - Strict range checks: 0 < r < p and 0 < s < p - 1 (prevents trivial forgery).
    - Verification equation: (y^r * r^s) mod p == (g^h) mod p.
    """
    try:
        if not (isinstance(signature, (tuple, list)) and len(signature) == 2):
            return False
        r, s = signature
        if not (isinstance(r, int) and isinstance(s, int) and not isinstance(r, bool) and not isinstance(s, bool)):
            return False
        if not (0 < r < p and 0 < s < p - 1):
            return False

        if isinstance(message, str):
            message = message.encode("utf-8")

        h = int.from_bytes(sha256_bytes(message), byteorder="big")
        left = (pow(y, r, p) * pow(r, s, p)) % p
        right = pow(g, h, p)
        return left == right
    except Exception:
        return False
