# MATHEMATICAL SPECIFICATION AND IMPLEMENTATION GUIDE: ELGAMAL DIGITAL SIGNATURE SCHEME

* **Student Name:** Nguyen Thi Nhu Y | **SID:** Ends with `0`
* **Reference Standards:** Taher Elgamal (1985) & NIST FIPS PUB 186 (Digital Signature Standard)
* **Source Module:** `src/elgamal.py` | **Unit Test Suite:** `tests/test_elgamal.py`
* **Runtime Environment:** Python 3.13 (Python Standard Library only)

---

## 1. Mathematical Foundations and the Discrete Logarithm Problem (DLP)
The ElGamal digital signature scheme operates over the multiplicative cyclic group $\mathbb{Z}_p^*$ with group order $p - 1$:
- **Discrete Logarithm Problem (DLP):** Given large prime $p$, generator $g$, and $y \equiv g^x \pmod p$, modular exponentiation computes $y$ rapidly. Conversely, recovering the private exponent $x = \log_g(y) \bmod p$ is computationally intractable for $p \ge 2048$ bits.

---

## 2. Safe Primes and Primitive Root Generators

### 2.1. Safe Primes
- The implementation selects safe primes $p = 2q + 1$ where $q$ is an odd Sophie Germain prime.
- **Defensive Significance:** The group order is $p - 1 = 2q$. Because the prime factors of $p - 1$ are strictly limited to $2$ and large prime $q$, the Pohlig-Hellman algorithm cannot decompose the DLP into trivial prime-power subgroups.
- **1-bit Parity Leakage via Legendre Symbol:**
  The Legendre symbol $\left(\frac{y}{p}\right) \equiv y^{(p-1)/2} \equiv (g^x)^q \equiv (-1)^x \pmod p$ exposes the single parity bit (even/odd) of private key $x$.

### 2.2. Generator Verification
In cyclic group $\mathbb{Z}_p^*$ of order $p - 1 = 2q$:
- An integer $g \in [2, p - 2]$ is a primitive root generator iff its multiplicative order equals $2q$.
- Because proper divisors of $2q$ are strictly $\{1, 2, q\}$, verification requires only two conditions:
  $$g^2 \not\equiv 1 \pmod p \quad \text{and} \quad g^q \not\equiv 1 \pmod p$$

---

## 3. Operational Workflow

### 3.1. Parameter and Keypair Generation
1. **Domain Parameters:** Generate safe prime $p$ of length `bits` and find generator $g$ satisfying both order conditions.
2. **Key Generation:**
   - Draw private key $x \in_R [2, p - 2]$.
   - Compute public key $y = g^x \bmod p$.
   - Public Parameters: $(p, g, y)$; Private Key: $x$.

### 3.2. Digital Signature Generation (`elgamal_sign`)
To sign message $M$:
1. Compute message digest using SHA-256:
   $$h = \text{bytes\_to\_int}(\text{SHA-256}(M))$$
2. Select ephemeral nonce $k \in_R [2, p - 2]$ such that:
   $$\gcd(k, p - 1) = 1$$
3. Compute first signature component:
   $$r = g^k \bmod p$$
4. Compute modular inverse $k^{-1} \bmod (p - 1)$ via Extended GCD.
5. Compute second signature component:
   $$s = k^{-1} \cdot (h - x \cdot r) \bmod (p - 1)$$
   *(If $s = 0$, a fresh random nonce $k$ must be chosen).*
6. The signature is the pair $(r, s)$.

### 3.3. Digital Signature Verification (`elgamal_verify`)
Given message $M$, public key $(p, g, y)$, and signature $(r, s)$:
1. **Mandatory Boundary Checks:**
   $$0 < r < p \quad \text{and} \quad 0 < s < p - 1$$
   Return `False` immediately upon violation.
2. **Verification Equation:**
   Compute $h = \text{bytes\_to\_int}(\text{SHA-256}(M))$ and evaluate:
   $$v_1 = g^h \bmod p, \quad v_2 = (y^r \cdot r^s) \bmod p$$
   Valid iff $v_1 == v_2$.
3. **Exception Safety:** The verifier catches malformed structures (`None`, strings, invalid tuples) and returns `False` without crashing.

---

## 4. Mathematical Proof of Correctness
From the definition of $s$:
$$s \equiv k^{-1}(h - xr) \pmod{p - 1} \implies k \cdot s \equiv h - xr \pmod{p - 1} \implies h \equiv xr + ks \pmod{p - 1}$$
Exponentiating base $g$ modulo $p$ (by Fermat's Little Theorem since $g^{p-1} \equiv 1 \pmod p$):
$$g^h \equiv g^{xr + ks} \equiv (g^x)^r \cdot (g^k)^s \equiv y^r \cdot r^s \pmod p$$

---

## 5. Security Vulnerabilities and Attack Scenarios

### 5.1. Catastrophic Ephemeral Nonce $k$-Reuse Attack
Reusing $k$ for two distinct messages $M_1, M_2$ ($h_1 \ne h_2$) produces identical $r = g^k \bmod p$:
$$s_1 - s_2 \equiv k^{-1}(h_1 - xr) - k^{-1}(h_2 - xr) \equiv k^{-1}(h_1 - h_2) \pmod{p - 1}$$
The attacker immediately recovers $k$:
$$k \equiv (h_1 - h_2)(s_1 - s_2)^{-1} \pmod{p - 1}$$
Private key $x$ is then directly exposed:
$$x \equiv (h_1 - k \cdot s_1) \cdot r^{-1} \pmod{p - 1}$$

### 5.2. No-Hash Existential Forgery
Signing raw unhashed messages $m$ allows constructing valid signatures without knowing $x$:
1. Choose random $a, b \in \mathbb{Z}_{p-1}^*$ with $\gcd(b, p - 1) = 1$.
2. Compute $r = g^a \cdot y^b \bmod p$.
3. Compute $s = -r \cdot b^{-1} \bmod (p - 1)$.
4. Compute forged message $m = -r \cdot a \cdot b^{-1} \bmod (p - 1)$.
5. Verifying: $y^r \cdot r^s \equiv y^r \cdot (g^a y^b)^{-r b^{-1}} \equiv g^m \pmod p$.
Message hashing with SHA-256 prevents existential forgery.

---

## 6. Empirical Performance Findings
Extracted from `benchmark_results.csv`:
- **Domain Generation (`params_gen`):** 512-bit requires 881.67 ms ($n=30$); 1024-bit requires 21,248.60 ms ($n=5$).
- **Signing (`sign`):** 512-bit achieves 0.82 ms (1,161.5 ops/s); 1024-bit achieves 3.37 ms (287.1 ops/s). Signature size: 128 bytes (512-bit), 256 bytes (1024-bit).
- **Verification (`verify`):** 512-bit achieves 1.29 ms (748.2 ops/s); 1024-bit achieves 6.23 ms (157.6 ops/s).
- Verification is ~2x slower than signing due to computing 3 modular exponentiations ($g^h, y^r, r^s$).
