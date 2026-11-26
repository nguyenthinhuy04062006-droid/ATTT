# INFORMATION SECURITY COURSE PROJECT
## MODERN CRYPTOGRAPHIC ALGORITHMS IMPLEMENTED FROM SCRATCH

[![Python](https://img.shields.io/badge/Python-3.13-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20External%20(Standard%20Library%20Only)-success)](requirements.txt)
[![Unit Tests](https://img.shields.io/badge/Unit%20Tests-65%2F65%20Passed-brightgreen)](tests/)
[![AST Audit](https://img.shields.io/badge/AST%20Audit-Zero%20Forbidden%20Imports-blue)](tools/check_forbidden_imports.py)
[![Standards](https://img.shields.io/badge/Standards-NIST%20FIPS%20%7C%20RFC%208017-orange)](IS.ipynb)

* **Student Name:** Nguyen Thi Nhu Y
* **Student ID (SID):** Ends with `0`
* **Runtime Environment:** Python 3.13 (Python Standard Library only, strictly zero third-party crypto dependencies)

### Technology Stack & Standard Modules

| Category | Specification | Primary Modules / Standards |
| :--- | :--- | :--- |
| **Language Runtime** | Python 3.13 (Pure Python) | Standard Library only, zero pip packages |
| **Secure Randomness** | `secrets` module | CSPRNG for cryptographic keys and nonces |
| **Benchmarking** | `time.perf_counter()` | Sub-microsecond timing precision across 28 operations |
| **Testing Framework** | `unittest` module | 65 automated test vectors & regression suites |
| **Integrity Auditor** | `ast` module | Static syntax tree scanner forbidding third-party crypto |
| **System Utilities** | `argparse`, `csv`, `os`, `sys`, `typing` | CLI arguments, CSV export, type annotations |
| **Crypto Primitives** | Implemented From Scratch | AES-128 (FIPS 197), RSA (RFC 8017), SHA-256 (FIPS 180-4), ElGamal (1985) |

---

## 1. Algorithm Allocation

1. **Symmetric Block Cipher:** AES-128 (NIST FIPS 197), 128-bit key derived from the first 16 bytes of `SHA-256("Nguyen Thi Nhu Y")`. Cipher Block Chaining (CBC) mode with PKCS#7 padding.
2. **Asymmetric Public-Key Cryptosystem:** RSA (PKCS #1 v2.2 / RFC 8017), Miller-Rabin probabilistic primality test ($k=40$), 512/1024-bit keypair generation.
3. **Cryptographic Hash Function:** SHA-256 (NIST FIPS 180-4).
4. **Digital Signature Scheme:** ElGamal Digital Signature (Taher Elgamal 1985), signing digests produced by custom SHA-256.

---

## 2. Academic Integrity & Security Scope

- **Strict Prohibition:** Absolute zero use of third-party cryptographic libraries (`cryptography`, `pycryptodome`, `hashlib`, `hmac`, `ssl`, `gmpy2`, `rsa`, etc.) or dynamic execution primitives (`eval`, `exec`, `__import__`).
- **Pedagogical Scope:** Implementation is designed for educational exploration of mathematical foundations. It is non-constant-time, lacks side-channel resistance, and is NOT intended for production deployment. RSA is implemented as Textbook RSA without OAEP/PSS padding.
- **Performance Characteristics:** AES-128 and SHA-256 are pure Python implementations, whereas RSA and ElGamal utilize CPython's native C-accelerated `pow(base, exp, mod)`.
- **Automated AST Import Audit:** Run the static analyzer across all 15 Python files:
  ```powershell
  python tools/check_forbidden_imports.py
  ```

---

## 3. Repository Architecture

```text
d:\ATTT/
├── src/
│   ├── __init__.py
│   ├── utils.py                 # Bitwise helpers, byte/int conversions, PKCS#7 padding
│   ├── aes128.py                # 1. AES-128 block cipher and CBC mode
│   ├── rsa.py                   # 2. RSA public-key cryptosystem & Miller-Rabin test
│   ├── sha256.py                # 3. SHA-256 cryptographic hash function
│   └── elgamal.py               # 4. ElGamal digital signature scheme
├── tests/
│   ├── __init__.py
│   ├── test_aes128.py           # 1. AES-128 unit tests (FIPS-197 C.1 & student key)
│   ├── test_rsa.py              # 2. RSA unit tests (roundtrips & Miller-Rabin)
│   ├── test_sha256.py           # 3. SHA-256 unit tests (NIST test vectors & Avalanche)
│   ├── test_elgamal.py          # 4. ElGamal unit tests (signing, verification, tamper)
│   └── test_utils.py            # Utility & PKCS#7 padding unit tests
├── tools/
│   └── check_forbidden_imports.py # Static AST analyzer forbidding external crypto
├── docs/
│   ├── AI_Usage.md              # AI tool disclosure statement
│   ├── AI_Usage_log.md          # Academic integrity and code review session history
│   └── algorithms/              # Mathematical analysis documents
│       ├── aes128.md            # 1. AES-128 mathematical specification
│       ├── rsa.md               # 2. RSA mathematical specification
│       ├── sha256.md            # 3. SHA-256 mathematical specification
│       └── elgamal.md           # 4. ElGamal mathematical specification
├── evidence/                    # Benchmark data, CSV/TXT logs, and terminal screenshots
├── benchmark.py                 # High-resolution benchmark suite using time.perf_counter()
├── main.py                      # Interactive demonstration script for all 4 algorithms
├── IS.ipynb                     # Comprehensive Jupyter Notebook report with visual evidence
└── README.md                    # Project overview and execution instructions
```

---

## 4. Execution Instructions

1. **Verify Academic Integrity (Forbidden Import Scanner):**
   ```powershell
   python tools/check_forbidden_imports.py
   ```

2. **Execute Complete Unit Test Suite (65 tests):**
   ```powershell
   python -m unittest discover -s tests -v
   ```

3. **Run Interactive Demonstration Script:**
   ```powershell
   python main.py
   # Or run individual algorithms:
   python main.py --aes
   python main.py --rsa
   python main.py --sha
   python main.py --elgamal
   ```

4. **Execute Performance Benchmarks:**
   ```powershell
   python benchmark.py --quick   # Fast evaluation (~30 seconds)
   python benchmark.py --full    # Full benchmark with large iterations (~5.4 minutes)
   ```
