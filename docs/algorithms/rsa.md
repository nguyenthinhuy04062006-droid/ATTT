# MATHEMATICAL SPECIFICATION AND IMPLEMENTATION GUIDE: RSA ASYMMETRIC CRYPTOSYSTEM

* **Student Name:** Nguyen Thi Nhu Y | **SID:** Ends with `0`
* **Reference Standards:** RFC 8017 (PKCS #1 v2.2) & Rivest-Shamir-Adleman (1978)
* **Source Module:** `src/rsa.py` | **Unit Test Suite:** `tests/test_rsa.py`
* **Runtime Environment:** Python 3.13 (Python Standard Library only)

---

## 1. Number Theoretic Foundations
The security of RSA rests on the computational intractability of the Integer Factorization Problem (IFP) for composite modulus $n = p \cdot q$:

### 1.1. Euler's Totient Function and Euler's Theorem
- For distinct large primes $p$ and $q$, the number of positive integers less than $n$ that are coprime to $n$ is:
  $$\phi(n) = \phi(p) \cdot \phi(q) = (p - 1)(q - 1)$$
- Euler's Theorem states that for any integer $m$ where $\gcd(m, n) = 1$:
  $$m^{\phi(n)} \equiv 1 \pmod n$$

### 1.2. Mathematical Proof of Correctness
Choose public exponent $e$ such that $\gcd(e, \phi(n)) = 1$. The unique modular inverse $d$ satisfies:
$$e \cdot d \equiv 1 \pmod{\phi(n)} \implies e \cdot d = 1 + k \cdot \phi(n) \quad (k \in \mathbb{Z}^+)$$
For plaintext $m < n$, ciphertext $c = m^e \bmod n$. Decryption via private exponent $d$ yields:
$$c^d \equiv (m^e)^d \equiv m^{e \cdot d} \equiv m^{1 + k \cdot \phi(n)} \equiv m \cdot (m^{\phi(n)})^k \equiv m \cdot 1^k \equiv m \pmod n$$
By the Chinese Remainder Theorem (CRT), this congruence holds for all $m \in [0, n-1]$ even when $\gcd(m, n) > 1$.

---

## 2. Miller-Rabin Probabilistic Primality Test
To generate cryptographically strong primes, the Miller-Rabin algorithm is implemented from first principles:
1. **Factor Powers of 2:** Given candidate odd integer $n > 3$, write $n - 1 = 2^s \cdot d$ where $d$ is odd and $s \ge 1$.
2. **Witness Loop:**
   Execute $k = 40$ independent rounds with random bases $a \in [2, n - 2]$:
   - Compute $x = a^d \bmod n$.
   - If $x = 1$ or $x = n - 1$, $n$ passes the test for base $a$.
   - Repeat $s - 1$ times: $x = x^2 \bmod n$. If $x = n - 1$, break the inner loop and proceed to the next base.
   - If $n - 1$ is never encountered, $n$ is composite (`False`).
3. **Error Bound:** With $k = 40$ independent trials, the probability that a composite integer (including Carmichael numbers) passes is strictly bounded by:
   $$P_{\text{error}} \le \left(\frac{1}{4}\right)^{40} = 2^{-80} \approx 8.27 \times 10^{-25}$$

---

## 3. Operational Workflow

### 3.1. Keypair Generation (`generate_rsa_keypair`)
1. Generate two distinct primes $p, q$ of bit-length $\text{bits} / 2$.
   - **Bit-Length Preservation:** Set the two most significant bits to 1:
     $$\text{cand} = \text{randbits}(half\_bits) \mid (1 \ll (half\_bits - 1)) \mid (1 \ll (half\_bits - 2)) \mid 1$$
     This guarantees both primes $\ge 1.5 \times 2^{half\_bits - 1}$, ensuring product $n = p \cdot q$ possesses the exact target bit-length.
2. Compute $n = p \cdot q$ and $\phi(n) = (p - 1)(q - 1)$.
3. Fix public exponent $e = 65537 = 2^{16} + 1$, verifying $\gcd(e, \phi(n)) == 1$.
4. Employ the Extended Euclidean algorithm (`extended_gcd`) to find $d = e^{-1} \bmod \phi(n)$.
5. Output public key $(e, n)$ and private key $(d, n)$.

### 3.2. Encryption (`rsa_encrypt`) and Decryption (`rsa_decrypt`)
- **Integer Encryption:** Check $0 \le m < n$, compute $c = m^e \bmod n$.
- **Integer Decryption:** Check $0 \le c < n$, compute $m = c^d \bmod n$.
- **Byte String Encryption:** Convert byte sequences to big-endian integers via `bytes_to_int`, apply RSA, and convert back using `int_to_bytes`.

---

## 4. Security Analysis and Vulnerabilities
1. **Multiplicative Homomorphic Malleability:**
   $$(m_1 \cdot m_2)^e \equiv m_1^e \cdot m_2^e \equiv c_1 \cdot c_2 \pmod n$$
   Attackers can forge valid ciphertexts without knowing $d$. Production systems must employ OAEP (Optimal Asymmetric Encryption Padding).
2. **Wiener's Small Private Exponent Attack:** If $d < \frac{1}{3} n^{1/4}$, $d$ can be recovered efficiently via continued fractions.
3. **Fermat Factorization:** If $|p - q| < n^{1/4}$, Fermat's algorithm rapidly factors $n$.
4. **Timing Attacks:** The implementation uses Python's built-in `pow()`, which is non-constant-time. Designed strictly for educational exploration.

---

## 5. Empirical Performance Findings
Extracted from `benchmark_results.csv`:
- **Key Generation:** 512-bit requires 18.23 ms ($n=30$); 1024-bit requires 166.79 ms ($n=30$); 2048-bit requires 1,202.88 ms ($n=10$).
- **Encryption:** Extremely fast (0.012 ms for 512-bit; 0.040 ms for 1024-bit; 0.120 ms for 2048-bit) due to low Hamming weight of $e = 65537$.
- **Decryption:** 38x to 150x slower than encryption (0.47 ms for 512-bit; 2.80 ms for 1024-bit; 18.06 ms for 2048-bit) as private exponent $d$ has ~1024 set bits.
