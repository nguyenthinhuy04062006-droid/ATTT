# ARTIFICIAL INTELLIGENCE USAGE AND CODE REVIEW LOG (AI USAGE & CODE REVIEW LOG)

* **Student Name:** Nguyen Thi Nhu Y
* **Student ID (SID):** Ends with `0`
* **Course:** Information Security
* **Topic:** Implementation of Modern Cryptographic Primitives from Scratch (AES-128, RSA, SHA-256, ElGamal)
* **Runtime Environment:** Python 3.13 (Python Standard Library only)

---

## 1. Academic Integrity Declaration
1. **Independent Research:** The student independently conducted all theoretical research, completed all assignments, and assumes full academic responsibility for the integrity, architecture, and correctness of both source code and documentation.
2. **Plagiarism Prohibition:** The entire project was constructed from first principles (from scratch). Plagiarism—including copying from other students or external repositories, or permitting others to copy this work—is strictly prohibited.
3. **Restricted Scope of AI:** Artificial Intelligence tools (Google DeepMind Antigravity IDE / Gemini 3.8) served strictly as supplementary technical references and code review instruments (sounding board, edge-case analysis, syntax checks).
4. **No Verbatim Copying:** No AI-generated text or code was copied verbatim without rigorous mathematical analysis, theoretical verification, and substantial personal adaptation by the student.
5. **Standards Compliance:** All mathematical principles and test vectors are formally cited from international cryptographic standards (NIST, IETF, IEEE).

---

## 2. Code Review Methodology
* **Strict Supervision Mode:**
  - All interactions were driven by concrete academic requirements formulated by the student.
  - AI was utilized to identify boundary edge cases, verify Python 3.13 typing syntax, and audit potential logic flaws.
  - Algorithmic control remained exclusively with the student; AI was not delegated core design decisions.

---

## 3. Chronological Project & Code Review History

### Session 1: Scaffolding and Static AST Analyzer Audit
- **Task:** Establish standard project directories (`src/`, `tests/`, `docs/`, `evidence/`, `tools/`).
- **AI Review Focus:** Reviewing AST parser logic in `tools/check_forbidden_imports.py` using Python's `ast` module.
- **Student Ownership:** Formulated the blacklist of forbidden libraries (`cryptography`, `pycryptodome`, `hashlib`, `rsa`, `ssl`...) and dynamic invocation primitives (`eval`, `exec`, `__import__`).

### Session 2: AES-128 Symmetric Block Cipher Review (NIST FIPS 197)
- **Task:** Implement 4 round transformations on $\text{GF}(2^8)$ (SubBytes, ShiftRows, MixColumns, AddRoundKey) and CBC mode with PKCS#7 padding.
- **AI Review Focus:** Reviewing S-Box lookup tables, forward circulant polynomial $c(x)$, and inverse polynomial $d(x)$.
- **Student Ownership:** Developed tamper detection validation, distinguishing between middle-byte ciphertext corruption and end-of-block invalid PKCS#7 padding exceptions.

### Session 3: RSA Asymmetric Public-Key Cryptosystem Review (RFC 8017 / PKCS #1)
- **Task:** Implement keypair generation (512, 1024, 2048-bit), Extended Euclidean algorithm (`extended_gcd`), modular inverse, and Miller-Rabin primality test.
- **AI Review Focus:** Evaluating error bounds of Miller-Rabin ($k=40$ rounds, failure probability $< 4^{-40} \approx 8.27 \times 10^{-25}$).
- **Student Ownership:** Verified $\gcd(e, \phi(n)) = 1$ with $e=65537$, tested Carmichael numbers (e.g., 561) to demonstrate Miller-Rabin's superiority over Fermat tests.

### Session 4: SHA-256 Cryptographic Hash Function Review (NIST FIPS 180-4)
- **Task:** Implement Merkle-Damgård construction, Davies-Meyer compression, 64-word schedule $W_t$, and 64 compression rounds.
- **AI Review Focus:** Cross-referencing 64 round constants $K_t$ and initial hash values $H^{(0)}$ against NIST FIPS 180-4.
- **Student Ownership:** Programmed the Strict Avalanche Criterion (SAC) verification script, confirming 52.34% bit-flip ratio upon 1-bit input alteration.

### Session 5: ElGamal Digital Signature Scheme Review (Taher Elgamal 1985)
- **Task:** Implement safe prime parameter generation ($p = 2q + 1$), primitive root generator $g$, signature generation, and verification.
- **AI Review Focus:** Auditing verification boundaries $0 < r < p$ and $0 < s < p-1$, and mathematical formulation of the $k$-reuse attack.
- **Student Ownership:** Programmed exact modular congruence solver for $\Delta s \cdot k \equiv \Delta h \pmod{p-1}$ when $\gcd(\Delta s, p-1) = 2$, ensuring 100% reliable recovery of ephemeral nonce $k$ and private key $x$.

### Session 6: Performance Benchmarking and Interactive Demo Review
- **Task:** Benchmark 28 cryptographic operations (`benchmark.py`), format CSV/TXT reports, and build interactive CLI demo (`main.py`).
- **AI Review Focus:** Assessing precision of `time.perf_counter()`, isolating warm-up runs, and validating throughput calculations.
- **Student Ownership:** Conducted full local benchmark execution (324.716 seconds wall time), compiled terminal evidence into `evidence/`, and authored the comprehensive Jupyter report `IS.ipynb`.

---

## 4. Academic Autonomy Assessment
| Project Component | AI Assistance Role (Reference/Review) | Student Primary Contribution | Student Autonomy |
| :--- | :--- | :--- | :--- |
| **Project Scaffolding & AST** | AST syntax suggestions | Defined blacklist, verified 15 source files | 100% |
| **AES-128 Cipher** | FIPS 197 constant verification | Finite field matrix math, CBC, PKCS#7 | 100% |
| **RSA Cryptosystem** | Carmichael number test suggestions | Miller-Rabin, Extended GCD, modular inverse | 100% |
| **SHA-256 Hash Function** | FIPS 180-4 test vector cross-check | Message schedule, compression loop, SAC | 100% |
| **ElGamal Digital Signatures**| Mathematical review of $k$-reuse | Safe prime generation, signing, attack solver | 100% |
| **Benchmark & Demo CLI** | Reporting format recommendations | Executed 324s benchmark, built complete demo | 100% |

---

## 5. References
1. NIST FIPS PUB 197 (2001), *Advanced Encryption Standard (AES)*.
2. NIST SP 800-38A (2001), *Recommendation for Block Cipher Modes of Operation*.
3. RFC 8017 (2016), *PKCS #1: RSA Cryptography Specifications Version 2.2*.
4. NIST FIPS PUB 180-4 (2015), *Secure Hash Standard (SHS)*.
5. Taher Elgamal (1985), *A Public Key Cryptosystem and a Signature Scheme Based on Discrete Logarithms*, IEEE Transactions on Information Theory.
6. William Stallings (2017), *Cryptography and Network Security: Principles and Practice (7th Edition)*.
