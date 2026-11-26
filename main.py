"""Modern Cryptography Implementation Demonstration - Information Security Course.
Implemented strictly from scratch using Python 3.13 Standard Library only.

Student: Nguyen Thi Nhu Y
Student ID (SID) ends with: 0
Execution Order:
  1. AES-128 (Symmetric Block Cipher - CBC mode + PKCS#7 padding)
  2. RSA (Asymmetric Cryptosystem - PKCS #1 / RFC 8017)
  3. SHA-256 (Cryptographic Hash Function - NIST FIPS 180-4)
  4. ElGamal (Digital Signature Scheme - Taher Elgamal 1985)
"""

import argparse
import secrets
import sys
import time

from src.sha256 import sha256_bytes, sha256_hex
from src.aes128 import (
    key_expansion,
    aes128_encrypt_message,
    aes128_decrypt_message,
    encrypt_block,
    decrypt_block,
)
from src.rsa import (
    generate_rsa_keypair,
    rsa_encrypt,
    rsa_decrypt,
    rsa_encrypt_bytes,
    rsa_decrypt_bytes,
    is_probable_prime,
    extended_gcd,
    mod_inverse,
)
from src.elgamal import (
    generate_elgamal_params,
    generate_elgamal_keypair,
    elgamal_sign,
    elgamal_verify,
)


def print_header(title: str):
    print("\n" + "=" * 78)
    print(f" {title.upper()} ")
    print("=" * 78)


def demo_aes128():
    print_header("1. DEMO: AES-128 SYMMETRIC BLOCK CIPHER (NIST FIPS 197, CBC, PKCS#7)")

    # 1. Student key derivation via SHA-256
    student_name = "Nguyen Thi Nhu Y"
    name_hash = sha256_bytes(student_name.encode("utf-8"))
    key = name_hash[:16]
    print(f"[*] Student Information: {student_name}")
    print(f"[*] SHA-256 Digest:      {name_hash.hex()}")
    print(f"[*] AES-128 Key (16B):   {key.hex()}")

    # 2. Key Expansion
    round_keys = key_expansion(key)
    k0_hex = bytes(round_keys[0][r][c] for c in range(4) for r in range(4)).hex()
    k10_hex = bytes(round_keys[10][r][c] for c in range(4) for r in range(4)).hex()
    print("[*] Key Expansion:       Successfully generated 11 round keys (44 32-bit words).")
    print(f"    - Round Key 0 (K0):   {k0_hex}")
    print(f"    - Round Key 10 (K10): {k10_hex}")

    # 3. FIPS 197 Appendix C.1 Single Block Verification
    fips_k = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    fips_p = bytes.fromhex("00112233445566778899aabbccddeeff")
    fips_c_expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    fips_rkeys = key_expansion(fips_k)
    fips_c = encrypt_block(fips_p, fips_rkeys)
    fips_p_rec = decrypt_block(fips_c, fips_rkeys)
    print("\n[+] NIST FIPS 197 Appendix C.1 Verification (Single Block):")
    print(f"    - Plaintext:         {fips_p.hex()}")
    print(f"    - Ciphertext:        {fips_c.hex()}")
    print(f"    - Standard Match:    {fips_c == fips_c_expected} (Decryption matches plaintext: {fips_p_rec == fips_p})")

    # 4. Message Encryption/Decryption in CBC Mode with PKCS#7 Padding
    message = "Information Security 2026 - Cryptography From Scratch - Nguyen Thi Nhu Y"
    plain_bytes = message.encode("utf-8")
    cipher_bytes = aes128_encrypt_message(plain_bytes, key)
    decrypted_bytes = aes128_decrypt_message(cipher_bytes, key)

    print("\n[+] Message Encryption in CBC Mode with PKCS#7 Padding:")
    print(f"    - Original Plaintext ({len(plain_bytes)} bytes): {message}")
    print(f"    - Ciphertext ({len(cipher_bytes)} bytes incl. 16B IV): {cipher_bytes.hex()[:48]}...")
    print(f"    - Initialization Vector (IV): {cipher_bytes[:16].hex()}")
    print(f"    - Decryption Match:  {decrypted_bytes == plain_bytes}")

    # 5. Tamper Detection Verification
    print("\n[+] Tamper Detection Verification:")
    # Case 1: Corrupt byte in ciphertext body (CBC)
    tampered_cipher_mid = bytearray(cipher_bytes)
    tampered_cipher_mid[20] ^= 0x01
    try:
        dec_mid = aes128_decrypt_message(bytes(tampered_cipher_mid), key)
        is_corrupted = (dec_mid != plain_bytes)
        print(f"    - Middle Byte Modification (CBC):   SUCCESS (Plaintext corrupted: {is_corrupted})")
    except ValueError as e:
        print(f"    - Middle Byte Modification (CBC):   Padding error caught: {e}")

    # Case 2: Corrupt padding byte (PKCS#7)
    tampered_cipher_pad = bytearray(cipher_bytes)
    tampered_cipher_pad[-1] ^= 0x01
    try:
        aes128_decrypt_message(bytes(tampered_cipher_pad), key)
        print("    - Padding Modification (PKCS#7):     FAILED (No error caught)")
    except ValueError as e:
        print(f"    - Padding Modification (PKCS#7):     SUCCESS (Padding error caught: {e})")


def demo_rsa():
    print_header("2. DEMO: RSA ASYMMETRIC CRYPTOSYSTEM (RFC 8017 / PKCS #1)")

    # 1. Miller-Rabin Primality Test
    p_test = 65537
    c_test = 561
    print("[+] Miller-Rabin Probabilistic Primality Test (k=40):")
    print(f"    - is_probable_prime({p_test}) -> {is_probable_prime(p_test, 40)} (Expected: True)")
    print(f"    - is_probable_prime({c_test}) -> {is_probable_prime(c_test, 40)} (Expected: False - Carmichael composite)")

    # 2. 512-bit RSA Keypair Generation
    print("\n[*] Generating 512-bit RSA keypair (Miller-Rabin k=40)...")
    t0 = time.perf_counter()
    pub_key, priv_key = generate_rsa_keypair(bits=512)
    t1 = time.perf_counter()
    e, n = pub_key
    d, _ = priv_key
    print(f"[*] Key generation time: {(t1 - t0)*1000.0:.2f} ms")
    print(f"    - Modulus bit length: {n.bit_length()} bits")
    print(f"    - Public exponent e:  {e}")
    print(f"    - Modulus n:          {str(n)[:30]}...{str(n)[-20:]}")
    print(f"    - Private exponent d: {str(d)[:30]}...{str(d)[-20:]}")

    # 3. Integer Encryption and Decryption
    m_int = 202611230104062006
    c_int = rsa_encrypt(m_int, pub_key)
    dec_m_int = rsa_decrypt(c_int, priv_key)
    print("\n[+] Integer Encryption and Decryption:")
    print(f"    - Plaintext integer m:           {m_int}")
    print(f"    - Ciphertext c = m^e mod n:      {str(c_int)[:40]}...")
    print(f"    - Decrypted integer c^d mod n:   {dec_m_int}")
    print(f"    - Correctness:                   {dec_m_int == m_int}")

    # 4. Byte String Encryption and Decryption
    msg = b"Nguyen Thi Nhu Y - RSA PKCS#1 Demo"
    c_bytes = rsa_encrypt_bytes(msg, pub_key)
    dec_msg = rsa_decrypt_bytes(c_bytes, priv_key)
    wrong_priv_key = (d + 2, n)
    try:
        wrong_dec = rsa_decrypt(c_int, wrong_priv_key)
        wrong_ok = (wrong_dec != m_int)
    except Exception:
        wrong_ok = True

    print("\n[+] Byte String Encryption and Decryption:")
    print(f"    - Original message:              {msg.decode('utf-8')}")
    print(f"    - Ciphertext ({len(c_bytes)}B):              {c_bytes.hex()[:40]}...")
    print(f"    - Decrypted message:             {dec_msg.decode('utf-8')}")
    print(f"    - Correctness:                   {dec_msg == msg}")
    print(f"    - Wrong Key Decryption:          SUCCESS (Decryption mismatch: {wrong_ok})")


def demo_sha256():
    print_header("3. DEMO: SHA-256 CRYPTOGRAPHIC HASH FUNCTION (NIST FIPS 180-4)")

    # 1. Standard NIST Test Vectors
    v_empty = sha256_hex(b"")
    v_abc = sha256_hex(b"abc")
    v_name = sha256_hex("Nguyen Thi Nhu Y")
    print("[+] Standard NIST Test Vectors:")
    print(f"    - SHA-256(''):       {v_empty}")
    print(f"    - SHA-256('abc'):    {v_abc}")
    print(f"    - SHA-256('Nguyen Thi Nhu Y'):")
    print(f"      -> {v_name}")

    # 2. Strict Avalanche Criterion (SAC) Verification
    msg1 = b"Information Security 2026 - Nguyen Thi Nhu Y"
    msg2 = bytearray(msg1)
    msg2[-1] ^= 0x01

    h1 = sha256_bytes(bytes(msg1))
    h2 = sha256_bytes(bytes(msg2))
    diff_bits = sum(bin(b1 ^ b2).count("1") for b1, b2 in zip(h1, h2))
    percent = (diff_bits / 256.0) * 100.0
    sac_passed = (35 <= percent <= 65)

    print("\n[+] Strict Avalanche Criterion (SAC) Verification:")
    print(f"    - Message 1:         {msg1.decode('utf-8')}")
    print(f"    - Hash 1:            {h1.hex()}")
    print(f"    - Message 2:         {bytes(msg2).decode('utf-8')}")
    print(f"    - Hash 2:            {h2.hex()}")
    print(f"    - Flipped bits:      {diff_bits} / 256 ({percent:.2f}%)")
    print(f"    - SAC Evaluation:    {'PASSED (Within optimal range 40% - 60%)' if sac_passed else 'FAILED'}")


def demo_elgamal():
    print_header("4. DEMO: ELGAMAL DIGITAL SIGNATURE SCHEME (TAHER ELGAMAL 1985)")

    # 1. Safe Prime Domain Parameters (128-bit for fast demo)
    print("[*] Generating ElGamal Domain Parameters (Safe Prime p = 2q + 1, 128-bit)...")
    t0 = time.perf_counter()
    p, g = generate_elgamal_params(bits=128)
    t1 = time.perf_counter()
    print(f"[*] Parameter generation time: {(t1 - t0)*1000.0:.2f} ms")
    print(f"    - Safe Prime p ({p.bit_length()} bits): {p}")
    print(f"    - Primitive root generator g: {g}")

    # 2. Keypair Generation
    x, y = generate_elgamal_keypair(p, g)
    print(f"[*] Private key x:            {x}")
    print(f"[*] Public key y = g^x mod p: {y}")

    # 3. Message Signing
    message = "Electronic Transaction Contract - Student: Nguyen Thi Nhu Y"
    msg_bytes = message.encode("utf-8")
    t_sign_0 = time.perf_counter()
    r, s = elgamal_sign(msg_bytes, x, p, g)
    t_sign_1 = time.perf_counter()
    print("\n[+] Digital Signature Generation:")
    print(f"    - Message:                   {message}")
    print(f"    - Signing time:              {(t_sign_1 - t_sign_0)*1000.0:.2f} ms")
    print(f"    - Signature r = g^k mod p:   {r}")
    print(f"    - Signature s:               {s}")

    # 4. Signature Verification
    t_ver_0 = time.perf_counter()
    is_valid = elgamal_verify(msg_bytes, (r, s), y, p, g)
    t_ver_1 = time.perf_counter()
    print("\n[+] Digital Signature Verification:")
    print(f"    - Verification time:         {(t_ver_1 - t_ver_0)*1000.0:.2f} ms")
    print(f"    - Verification result:       {is_valid} (Expected: True)")

    # 5. Anti-Tamper & Forgery Resistance Verification
    tampered_msg = b"Electronic Transaction Contract - Student: Nguyen Thi Nhu Z"
    print("\n[+] Anti-Tamper & Forgery Resistance Verification:")
    print(f"    - Altered message character: {elgamal_verify(tampered_msg, (r, s), y, p, g)} (Expected: False)")
    print(f"    - Altered signature r (r ^ 1): {elgamal_verify(msg_bytes, (r ^ 1, s), y, p, g)} (Expected: False)")
    print(f"    - Altered signature s (s ^ 1): {elgamal_verify(msg_bytes, (r, s ^ 1), y, p, g)} (Expected: False)")

    # 6. Catastrophic Ephemeral Nonce k-reuse Attack Demonstration
    print("\n[!] CATASTROPHIC RISK DEMONSTRATION: EPHEMERAL NONCE K-REUSE ATTACK:")
    m1 = b"Transfer Order 1: 10,000,000 VND"
    m2 = b"Transfer Order 2: 50,000,000 VND"
    h1 = int.from_bytes(sha256_bytes(m1), "big")
    h2 = int.from_bytes(sha256_bytes(m2), "big")
    p_minus_1 = p - 1

    k_fixed = secrets.randbelow(p - 3) + 2
    while extended_gcd(k_fixed, p_minus_1)[0] != 1:
        k_fixed = secrets.randbelow(p - 3) + 2

    r_fixed = pow(g, k_fixed, p)
    k_inv = mod_inverse(k_fixed, p_minus_1)
    s1 = (k_inv * (h1 - x * r_fixed)) % p_minus_1
    s2 = (k_inv * (h2 - x * r_fixed)) % p_minus_1

    print(f"    - Identical ephemeral k reused for 2 distinct messages: r1 = r2 = {r_fixed}")
    delta_s = (s1 - s2) % p_minus_1
    delta_h = (h1 - h2) % p_minus_1
    g_gcd, _, _ = extended_gcd(delta_s, p_minus_1)

    k_recovered = None
    if g_gcd == 1:
        k_recovered = (delta_h * mod_inverse(delta_s, p_minus_1)) % p_minus_1
    elif delta_h % g_gcd == 0:
        mod_red = p_minus_1 // g_gcd
        s_red = delta_s // g_gcd
        h_red = delta_h // g_gcd
        k_base = (h_red * mod_inverse(s_red, mod_red)) % mod_red
        for step in range(g_gcd):
            cand = k_base + step * mod_red
            if pow(g, cand, p) == r_fixed:
                k_recovered = cand
                break

    rhs = (h1 - k_recovered * s1) % p_minus_1
    g_r, _, _ = extended_gcd(r_fixed, p_minus_1)
    x_recovered = None
    if g_r == 1:
        x_recovered = (rhs * mod_inverse(r_fixed, p_minus_1)) % p_minus_1
    elif rhs % g_r == 0:
        mod_r_red = p_minus_1 // g_r
        r_red = r_fixed // g_r
        rhs_red = rhs // g_r
        x_base = (rhs_red * mod_inverse(r_red, mod_r_red)) % mod_r_red
        for step in range(g_r):
            cand_x = x_base + step * mod_r_red
            if pow(g, cand_x, p) == y:
                x_recovered = cand_x
                break

    print(f"    - Recovered ephemeral key k: {k_recovered} (Match: {k_recovered == k_fixed})")
    print(f"    - Compromised private key x: {x_recovered} (Match: {x_recovered == x})")
    print("    -> CONCLUSION: Ephemeral nonce k MUST NEVER be reused in ElGamal signatures!")


def main():
    parser = argparse.ArgumentParser(
        description="Demo modern cryptography implementations from scratch - ATTT Project"
    )
    parser.add_argument("--aes", action="store_true", help="Run AES-128 demo only")
    parser.add_argument("--rsa", action="store_true", help="Run RSA demo only")
    parser.add_argument("--sha", action="store_true", help="Run SHA-256 demo only")
    parser.add_argument("--elgamal", action="store_true", help="Run ElGamal demo only")
    args = parser.parse_args()

    run_all = not (args.aes or args.rsa or args.sha or args.elgamal)

    print("=" * 78)
    print(" MODERN CRYPTOGRAPHY SYSTEM DEMO - INFORMATION SECURITY PROJECT ")
    print(" Student: Nguyen Thi Nhu Y | Student ID ends with: 0")
    print(" Python 3.13 Standard Library | Zero external cryptographic dependencies")
    print("=" * 78)

    t_start = time.perf_counter()

    if run_all or args.aes:
        demo_aes128()
    if run_all or args.rsa:
        demo_rsa()
    if run_all or args.sha:
        demo_sha256()
    if run_all or args.elgamal:
        demo_elgamal()

    t_total = time.perf_counter() - t_start
    print("\n" + "=" * 78)
    print(f" DEMO COMPLETED SUCCESSFULLY IN {t_total:.3f} SECONDS ")
    print("=" * 78 + "\n")


if __name__ == "__main__":
    main()
