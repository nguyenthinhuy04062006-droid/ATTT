# ARTIFICIAL INTELLIGENCE USAGE REPORT (AI USAGE REPORT)

* **Student Name:** Nguyen Thi Nhu Y
* **Student ID (SID):** Ends with `0`
* **Course:** Information Security
* **Topic:** Implementation of Modern Cryptographic Primitives from Scratch (AES-128, RSA, SHA-256, ElGamal)
* **Runtime Environment:** Python 3.13 (Standard Library only)

---

## 1. Tools Used
- **Primary Tool:** Google DeepMind Antigravity IDE (Gemini 3.8 model / Assistant).
- **Interaction Model:** Technical sounding board and code reviewer (AI Assistant / Pair Programmer) under strict step-by-step student approval.

---

## 2. Main Purposes of AI Assistance
1. **Repository Scaffolding:** Automated generation of standard project directory structures (`src/`, `tests/`, `docs/`, `evidence/`, `tools/`).
2. **Test Suite Construction:** Encoding international reference test vectors from NIST (FIPS 197, FIPS 180-4, SP 800-38A) and RFC 8017 for automated verification.
3. **Academic Integrity Enforcement:** Establishing the AST static analyzer `tools/check_forbidden_imports.py` to ensure zero forbidden cryptographic dependencies.
4. **Empirical Benchmarking Framework:** Designing `benchmark.py` utilizing high-resolution `time.perf_counter()` to collect timing statistics (min, median, mean, stdev, ops/s).

---

## 3. Student Contributions
1. **Theoretical Mastery:** Independent research and mathematical analysis of all 4 cryptographic primitives:
   - AES-128: Finite field $\text{GF}(2^8)$, S-Box non-linear mapping, MixColumns matrix multiplication, Key Expansion, CBC mode, and PKCS#7 padding.
   - RSA: Modular arithmetic, Euler's totient theorem, Extended Euclidean algorithm (`extended_gcd`), modular multiplicative inverse (`mod_inverse`), Miller-Rabin probabilistic primality test ($k=40$).
   - SHA-256: Merkle-Damgård construction, Davies-Meyer compression, 64-word message schedule $W_t$, non-linear bitwise functions $\text{Ch}, \text{Maj}, \Sigma_0, \Sigma_1, \sigma_0, \sigma_1$.
   - ElGamal: Discrete Logarithm Problem (DLP) over cyclic group $\mathbb{Z}_p^*$, safe primes $p = 2q+1$, primitive roots $g$, randomized ephemeral nonces $k$, and the catastrophic $k$-reuse attack.
2. **Code Auditing & Mathematical Refinement:** In-depth review of every line of source code, edge-case debugging (e.g., small prime sieve loop termination, boundary checks $0 < r < p$ to prevent forgery).
3. **Empirical Execution & Artifact Collection:** Local execution of 65 unit test cases, running performance benchmarks (`--quick` and `--full`), recording terminal logs in `evidence/`, and synchronizing with remote Git.
4. **Oral Defense Readiness:** Complete preparation to explain all algorithmic nuances and mathematical proofs before the academic committee.

---

## 4. Important AI-Generated Scaffolding
1. **AST Static Analysis Template (`tools/check_forbidden_imports.py`):** Syntax tree parsing of `Import`, `ImportFrom`, and `Call` nodes to intercept external crypto modules.
2. **Initial Function Signatures & Stubs:** Initial structural stubs subsequently reviewed, audited, and mathematically corrected by the student.
3. **Automated Benchmark Scaffolding (`benchmark.py`):** Timing harness isolating warm-up runs, calculating throughput in MB/s, and exporting `.txt` and `.csv` reports.
4. **Documentation Outlines (`docs/`):** Structural skeleton adhering to the required 8 mandatory project criteria.

---

## 5. Prompting Methodology
- **Strict Direction & Supervision:**
  - Every prompt specified explicit boundaries (editing only target files without collateral modifications).
  - Concise, keyword-oriented communication without decorative elements.
  - Prohibition of automated `git push` without explicit student authorization.
  - Requirement for strict grounding in scientific standards (NIST, RFC, IEEE).

---

## 6. Student Modifications & Refinements
1. **ElGamal Parameter Generation:** Corrected small-prime sieve logic to prevent infinite loops when handling small bit lengths ($8 \le \text{bits} \le 16$).
2. **Exception Safety in ElGamal Verification:** Enforced that `elgamal_verify` returns `False` rather than raising unhandled exceptions upon malformed signatures.
3. **Standardized Global Execution Order:** Enforced uniform ordering across source code, test suites, benchmark tables, and reports: **1. AES-128 -> 2. RSA -> 3. SHA-256 -> 4. ElGamal**.
4. **Large-scale Benchmark Expansion:** Configured comprehensive loop counts ($n=30$ to $n=100$) in `--full` mode to measure heavy operations (RSA-2048, ElGamal-1024).

---

## 7. Verification & Independent Validation
1. **Automated Unit Testing:** 65 independent tests passing 100% (`OK`), verifying bit-level conformity with NIST FIPS 197, FIPS 180-4, and RFC 8017.
2. **Academic Integrity Audit:** AST scanner inspecting all 15 Python files, confirming zero forbidden imports.
3. **Tamper Detection:** Verifying that 1-bit corruption in ciphertext or signatures triggers immediate rejection.
4. **Empirical Grounding:** All figures in reports and tables originate from actual hardware execution on local machines without synthetic data.

---

### Student Declaration:
*I hereby declare that this report truthfully reflects my independent research and implementation process. I thoroughly understand the underlying mathematics and architecture, and I am fully prepared to defend all aspects of this project before the examination committee.*
