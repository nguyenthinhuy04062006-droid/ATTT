"""Cryptographic Benchmark Suite - ATTT Project.
Measures execution time, latency statistics, and throughput for AES-128, RSA, SHA-256, and ElGamal.
Standard library only.

Student: Nguyen Thi Nhu Y
SID ends with: 0
"""

import argparse
import csv
from datetime import datetime
import os
import platform
import secrets
import statistics
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.sha256 import sha256_bytes
from src.aes128 import (
    key_expansion,
    aes128_encrypt_message,
    aes128_decrypt_message,
)
from src.rsa import (
    generate_rsa_keypair,
    rsa_encrypt,
    rsa_decrypt,
)
from src.elgamal import (
    generate_elgamal_params,
    generate_elgamal_keypair,
    elgamal_sign,
    elgamal_verify,
)


def measure_metric(
    func: Callable,
    *args,
    runs: int = 5,
    warmup: int = 1,
    **kwargs,
) -> Dict[str, float]:
    """Execute warm-up run then measure `runs` executions using time.perf_counter().
    
    Returns statistical metrics: n, median_ms, mean_ms, stdev_ms, min_ms, max_ms, ops_per_s.
    """
    for _ in range(warmup):
        func(*args, **kwargs)

    times_ms: List[float] = []
    for _ in range(runs):
        t0 = time.perf_counter()
        func(*args, **kwargs)
        t1 = time.perf_counter()
        times_ms.append((t1 - t0) * 1000.0)

    mean_ms = statistics.mean(times_ms)
    stdev_ms = statistics.stdev(times_ms) if len(times_ms) > 1 else 0.0
    median_ms = statistics.median(times_ms)
    min_ms = min(times_ms)
    max_ms = max(times_ms)
    ops_per_s = (1000.0 / mean_ms) if mean_ms > 0 else 0.0

    return {
        "n": len(times_ms),
        "median_ms": median_ms,
        "mean_ms": mean_ms,
        "stdev_ms": stdev_ms,
        "min_ms": min_ms,
        "max_ms": max_ms,
        "ops_per_s": ops_per_s,
    }


def get_system_metadata() -> Dict[str, str]:
    """Gather hardware and environment metadata."""
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "processor": platform.processor() or platform.machine(),
        "python": platform.python_version(),
    }


def run_benchmarks(is_full: bool = False) -> Tuple[List[Dict[str, Any]], str]:
    """Execute all benchmarks and format results in order: AES-128, RSA, SHA-256, ElGamal."""
    records: List[Dict[str, Any]] = []
    text_lines: List[str] = []

    def log(msg: str = ""):
        print(msg)
        text_lines.append(msg)

    mode_label = "full" if is_full else "quick"
    meta = get_system_metadata()

    log("=" * 80)
    log("CRYPTOGRAPHIC BENCHMARK REPORT - ATTT PROJECT")
    log("=" * 80)
    log(f"Timestamp:        {meta['timestamp']}")
    log(f"Operating System: {meta['os']}")
    log(f"Processor:        {meta['processor']}")
    log(f"Python Version:   {meta['python']}")
    log(f"Benchmark Mode:   {mode_label.upper()}")
    log("=" * 80)

    # --------------------------------------------------------------------------
    # 1. AES-128 Benchmark (CBC + PKCS#7)
    # --------------------------------------------------------------------------
    log("\n1. BENCHMARK: AES-128 Symmetric Cipher (NIST FIPS 197, CBC mode, PKCS#7)")
    log("-" * 80)
    log(f"{'Operation':<16} | {'Size':<8} | {'n':<4} | {'Median(ms)':<10} | {'Mean(ms)':<10} | {'Throughput(MB/s)':<18} | {'Status'}")
    log("-" * 80)

    # Student key: first 16 bytes of SHA-256("Nguyen Thi Nhu Y")
    student_key = sha256_bytes(b"Nguyen Thi Nhu Y")[:16]

    # Key Expansion
    ke_runs = 20 if not is_full else 50
    ke_stats = measure_metric(key_expansion, student_key, runs=ke_runs, warmup=1)
    records.append({
        "algorithm": "AES-128",
        "operation": "key_expansion",
        "size": "16 bytes",
        "n": ke_stats["n"],
        "median_ms": ke_stats["median_ms"],
        "mean_ms": ke_stats["mean_ms"],
        "stdev_ms": ke_stats["stdev_ms"],
        "min_ms": ke_stats["min_ms"],
        "max_ms": ke_stats["max_ms"],
        "ops_per_s": ke_stats["ops_per_s"],
    })
    log(f"{'key_expansion':<16} | {'16 bytes':<8} | {ke_stats['n']:<4} | {ke_stats['median_ms']:<10.4f} | {ke_stats['mean_ms']:<10.4f} | {ke_stats['ops_per_s']:<18.1f} ops/s | PASS")

    aes_sizes = [
        (1024, "1 KB", 5 if not is_full else 10),
        (16 * 1024, "16 KB", 3 if not is_full else 10),
        (64 * 1024, "64 KB", 2 if not is_full else 10),
    ]

    for size_bytes, label, runs in aes_sizes:
        plain = b"B" * size_bytes
        # Correctness check outside timed loop
        cipher = aes128_encrypt_message(plain, student_key)
        recovered = aes128_decrypt_message(cipher, student_key)
        if recovered != plain:
            raise RuntimeError(f"AES-128 roundtrip correctness check failed on {label}")

        # Encrypt
        enc_stats = measure_metric(aes128_encrypt_message, plain, student_key, runs=runs, warmup=1)
        mean_enc_sec = enc_stats["mean_ms"] / 1000.0
        enc_mb_s = ((size_bytes / (1024 * 1024)) / mean_enc_sec) if mean_enc_sec > 0 else 0.0
        records.append({
            "algorithm": "AES-128",
            "operation": "encrypt_cbc",
            "size": label,
            "n": enc_stats["n"],
            "median_ms": enc_stats["median_ms"],
            "mean_ms": enc_stats["mean_ms"],
            "stdev_ms": enc_stats["stdev_ms"],
            "min_ms": enc_stats["min_ms"],
            "max_ms": enc_stats["max_ms"],
            "ops_per_s": enc_stats["ops_per_s"],
        })
        log(f"{'encrypt':<16} | {label:<8} | {enc_stats['n']:<4} | {enc_stats['median_ms']:<10.4f} | {enc_stats['mean_ms']:<10.4f} | {enc_mb_s:<18.3f} | PASS")

        # Decrypt
        dec_stats = measure_metric(aes128_decrypt_message, cipher, student_key, runs=runs, warmup=1)
        mean_dec_sec = dec_stats["mean_ms"] / 1000.0
        dec_mb_s = ((size_bytes / (1024 * 1024)) / mean_dec_sec) if mean_dec_sec > 0 else 0.0
        records.append({
            "algorithm": "AES-128",
            "operation": "decrypt_cbc",
            "size": label,
            "n": dec_stats["n"],
            "median_ms": dec_stats["median_ms"],
            "mean_ms": dec_stats["mean_ms"],
            "stdev_ms": dec_stats["stdev_ms"],
            "min_ms": dec_stats["min_ms"],
            "max_ms": dec_stats["max_ms"],
            "ops_per_s": dec_stats["ops_per_s"],
        })
        log(f"{'decrypt':<16} | {label:<8} | {dec_stats['n']:<4} | {dec_stats['median_ms']:<10.4f} | {dec_stats['mean_ms']:<10.4f} | {dec_mb_s:<18.3f} | PASS")

    # --------------------------------------------------------------------------
    # 2. RSA Benchmark
    # --------------------------------------------------------------------------
    log("\n2. BENCHMARK: RSA Asymmetric Cryptosystem (RFC 8017 / PKCS #1)")
    log("-" * 80)
    log(f"{'Operation':<14} | {'Key Size':<10} | {'n':<4} | {'Median(ms)':<10} | {'Mean(ms)':<10} | {'Throughput(ops/s)':<18} | {'Status'}")
    log("-" * 80)

    rsa_bits_list = [512, 1024]
    if is_full:
        rsa_bits_list.append(2048)

    rsa_random_time_stats = []

    for bits in rsa_bits_list:
        label = f"{bits} bits"
        # Quick: 512->3, 1024->2. Full: 512->30, 1024->30, 2048->10
        if not is_full:
            kg_runs = 3 if bits == 512 else 2
        else:
            kg_runs = 30 if bits in (512, 1024) else 10

        kg_stats = measure_metric(generate_rsa_keypair, bits, runs=kg_runs, warmup=1)
        records.append({
            "algorithm": "RSA",
            "operation": "keygen",
            "size": label,
            "n": kg_stats["n"],
            "median_ms": kg_stats["median_ms"],
            "mean_ms": kg_stats["mean_ms"],
            "stdev_ms": kg_stats["stdev_ms"],
            "min_ms": kg_stats["min_ms"],
            "max_ms": kg_stats["max_ms"],
            "ops_per_s": kg_stats["ops_per_s"],
        })
        rsa_random_time_stats.append((f"RSA keygen ({label})", kg_stats))
        log(f"{'keygen':<14} | {label:<10} | {kg_stats['n']:<4} | {kg_stats['median_ms']:<10.4f} | {kg_stats['mean_ms']:<10.4f} | {kg_stats['ops_per_s']:<18.2f} | PASS")

        # Generate a pair for encrypt/decrypt benchmark
        pub_key, priv_key = generate_rsa_keypair(bits)
        _, n = pub_key
        m = secrets.randbelow(n - 2) + 1

        # Correctness check
        c = rsa_encrypt(m, pub_key)
        dec_m = rsa_decrypt(c, priv_key)
        if dec_m != m:
            raise RuntimeError(f"RSA roundtrip correctness check failed for {label}")

        enc_runs = 10 if not is_full else (30 if bits <= 1024 else 10)
        enc_stats = measure_metric(rsa_encrypt, m, pub_key, runs=enc_runs, warmup=1)
        records.append({
            "algorithm": "RSA",
            "operation": "encrypt",
            "size": label,
            "n": enc_stats["n"],
            "median_ms": enc_stats["median_ms"],
            "mean_ms": enc_stats["mean_ms"],
            "stdev_ms": enc_stats["stdev_ms"],
            "min_ms": enc_stats["min_ms"],
            "max_ms": enc_stats["max_ms"],
            "ops_per_s": enc_stats["ops_per_s"],
        })
        log(f"{'encrypt':<14} | {label:<10} | {enc_stats['n']:<4} | {enc_stats['median_ms']:<10.4f} | {enc_stats['mean_ms']:<10.4f} | {enc_stats['ops_per_s']:<18.2f} | PASS")

        dec_runs = 10 if not is_full else (30 if bits <= 1024 else 10)
        dec_stats = measure_metric(rsa_decrypt, c, priv_key, runs=dec_runs, warmup=1)
        records.append({
            "algorithm": "RSA",
            "operation": "decrypt",
            "size": label,
            "n": dec_stats["n"],
            "median_ms": dec_stats["median_ms"],
            "mean_ms": dec_stats["mean_ms"],
            "stdev_ms": dec_stats["stdev_ms"],
            "min_ms": dec_stats["min_ms"],
            "max_ms": dec_stats["max_ms"],
            "ops_per_s": dec_stats["ops_per_s"],
        })
        log(f"{'decrypt':<14} | {label:<10} | {dec_stats['n']:<4} | {dec_stats['median_ms']:<10.4f} | {dec_stats['mean_ms']:<10.4f} | {dec_stats['ops_per_s']:<18.2f} | PASS")

    # One line per random-time operation after the algorithm table
    for name, st in rsa_random_time_stats:
        log(f"[Random-time] {name}: min = {st['min_ms']:.4f} ms / median = {st['median_ms']:.4f} ms / max = {st['max_ms']:.4f} ms (n = {st['n']})")

    # --------------------------------------------------------------------------
    # 3. SHA-256 Benchmark
    # --------------------------------------------------------------------------
    log("\n3. BENCHMARK: SHA-256 Cryptographic Hash Function (FIPS 180-4)")
    log("-" * 80)
    log(f"{'Size':<10} | {'n':<4} | {'Median(ms)':<10} | {'Mean(ms)':<10} | {'Stdev(ms)':<10} | {'Throughput(MB/s)':<18} | {'Status'}")
    log("-" * 80)

    sha_sizes = [
        (1024, "1 KB", 10 if not is_full else 20),
        (10 * 1024, "10 KB", 10 if not is_full else 20),
        (100 * 1024, "100 KB", 5 if not is_full else 10),
        (1024 * 1024, "1 MB", 2 if not is_full else 10),
    ]

    for size_bytes, label, runs in sha_sizes:
        payload = b"A" * size_bytes
        # Correctness check outside timed loop
        digest = sha256_bytes(payload)
        if len(digest) != 32:
            raise RuntimeError(f"SHA-256 correctness failure on {label}")

        stats = measure_metric(sha256_bytes, payload, runs=runs, warmup=1)
        mean_sec = stats["mean_ms"] / 1000.0
        mb_per_s = ((size_bytes / (1024 * 1024)) / mean_sec) if mean_sec > 0 else 0.0

        records.append({
            "algorithm": "SHA-256",
            "operation": "hash",
            "size": label,
            "n": stats["n"],
            "median_ms": stats["median_ms"],
            "mean_ms": stats["mean_ms"],
            "stdev_ms": stats["stdev_ms"],
            "min_ms": stats["min_ms"],
            "max_ms": stats["max_ms"],
            "ops_per_s": stats["ops_per_s"],
        })
        log(f"{label:<10} | {stats['n']:<4} | {stats['median_ms']:<10.4f} | {stats['mean_ms']:<10.4f} | {stats['stdev_ms']:<10.4f} | {mb_per_s:<18.3f} | PASS")

    # --------------------------------------------------------------------------
    # 4. ElGamal Benchmark
    # --------------------------------------------------------------------------
    log("\n4. BENCHMARK: ElGamal Digital Signature Scheme (ElGamal 1985)")
    log("-" * 80)
    log(f"{'Operation':<14} | {'Domain/Key':<10} | {'n':<4} | {'Median(ms)':<10} | {'Mean(ms)':<10} | {'Throughput(ops/s)':<18} | {'Sig Size'} | {'Status'}")
    log("-" * 80)

    elg_bits_list = [512]
    if is_full:
        elg_bits_list.append(1024)

    # Fixed 32-byte message
    test_message = b"Nguyen Thi Nhu Y - 32-byte msg!"
    elg_random_time_stats = []

    for bits in elg_bits_list:
        label = f"{bits} bits"
        # Params generation: Quick: 512->2. Full: 512->30, 1024->5
        if not is_full:
            p_runs = 2 if bits == 512 else 1
        else:
            p_runs = 30 if bits == 512 else 5

        p_stats = measure_metric(generate_elgamal_params, bits, runs=p_runs, warmup=1)
        records.append({
            "algorithm": "ElGamal",
            "operation": "params_gen",
            "size": label,
            "n": p_stats["n"],
            "median_ms": p_stats["median_ms"],
            "mean_ms": p_stats["mean_ms"],
            "stdev_ms": p_stats["stdev_ms"],
            "min_ms": p_stats["min_ms"],
            "max_ms": p_stats["max_ms"],
            "ops_per_s": p_stats["ops_per_s"],
        })
        elg_random_time_stats.append((f"ElGamal params_gen ({label})", p_stats))
        log(f"{'params_gen':<14} | {label:<10} | {p_stats['n']:<4} | {p_stats['median_ms']:<10.4f} | {p_stats['mean_ms']:<10.4f} | {p_stats['ops_per_s']:<18.2f} | {'N/A':<8} | PASS")

        # Generate domain parameters once for keygen/sign/verify
        p, g = generate_elgamal_params(bits)
        sig_size_bytes = 2 * ((p.bit_length() + 7) // 8)

        # Keygen: Quick: 10. Full: >= 30
        kg_runs = 10 if not is_full else 30
        kg_stats = measure_metric(generate_elgamal_keypair, p, g, runs=kg_runs, warmup=1)
        records.append({
            "algorithm": "ElGamal",
            "operation": "keygen",
            "size": label,
            "n": kg_stats["n"],
            "median_ms": kg_stats["median_ms"],
            "mean_ms": kg_stats["mean_ms"],
            "stdev_ms": kg_stats["stdev_ms"],
            "min_ms": kg_stats["min_ms"],
            "max_ms": kg_stats["max_ms"],
            "ops_per_s": kg_stats["ops_per_s"],
        })
        elg_random_time_stats.append((f"ElGamal keygen ({label})", kg_stats))
        log(f"{'keygen':<14} | {label:<10} | {kg_stats['n']:<4} | {kg_stats['median_ms']:<10.4f} | {kg_stats['mean_ms']:<10.4f} | {kg_stats['ops_per_s']:<18.2f} | {'N/A':<8} | PASS")

        # Keypair & Correctness check
        x, y = generate_elgamal_keypair(p, g)
        sample_sig = elgamal_sign(test_message, x, p, g)
        if not elgamal_verify(test_message, sample_sig, y, p, g):
            raise RuntimeError(f"ElGamal correctness failure for {label}")

        # Sign: Quick: 5. Full: 100
        sign_runs = 5 if not is_full else 100
        sign_stats = measure_metric(elgamal_sign, test_message, x, p, g, runs=sign_runs, warmup=1)
        records.append({
            "algorithm": "ElGamal",
            "operation": "sign",
            "size": label,
            "n": sign_stats["n"],
            "median_ms": sign_stats["median_ms"],
            "mean_ms": sign_stats["mean_ms"],
            "stdev_ms": sign_stats["stdev_ms"],
            "min_ms": sign_stats["min_ms"],
            "max_ms": sign_stats["max_ms"],
            "ops_per_s": sign_stats["ops_per_s"],
        })
        log(f"{'sign':<14} | {label:<10} | {sign_stats['n']:<4} | {sign_stats['median_ms']:<10.4f} | {sign_stats['mean_ms']:<10.4f} | {sign_stats['ops_per_s']:<18.2f} | {f'{sig_size_bytes} B':<8} | PASS")

        # Verify: Quick: 5. Full: 100
        ver_runs = 5 if not is_full else 100
        ver_stats = measure_metric(elgamal_verify, test_message, sample_sig, y, p, g, runs=ver_runs, warmup=1)
        records.append({
            "algorithm": "ElGamal",
            "operation": "verify",
            "size": label,
            "n": ver_stats["n"],
            "median_ms": ver_stats["median_ms"],
            "mean_ms": ver_stats["mean_ms"],
            "stdev_ms": ver_stats["stdev_ms"],
            "min_ms": ver_stats["min_ms"],
            "max_ms": ver_stats["max_ms"],
            "ops_per_s": ver_stats["ops_per_s"],
        })
        log(f"{'verify':<14} | {label:<10} | {ver_stats['n']:<4} | {ver_stats['median_ms']:<10.4f} | {ver_stats['mean_ms']:<10.4f} | {ver_stats['ops_per_s']:<18.2f} | {f'{sig_size_bytes} B':<8} | PASS")

    # One line per random-time operation after the algorithm table
    for name, st in elg_random_time_stats:
        log(f"[Random-time] {name}: min = {st['min_ms']:.4f} ms / median = {st['median_ms']:.4f} ms / max = {st['max_ms']:.4f} ms (n = {st['n']})")

    log("\n" + "=" * 80)
    log("BENCHMARK COMPLETED SUCCESSFULLY.")
    log("=" * 80)

    return records, "\n".join(text_lines)


def export_csv(records: List[Dict[str, Any]], filepath: str):
    """Write benchmark metrics to CSV file."""
    fieldnames = [
        "algorithm",
        "operation",
        "size",
        "n",
        "median_ms",
        "mean_ms",
        "stdev_ms",
        "min_ms",
        "max_ms",
        "ops_per_s",
    ]
    with open(filepath, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow({
                "algorithm": r["algorithm"],
                "operation": r["operation"],
                "size": r["size"],
                "n": r["n"],
                "median_ms": f"{r['median_ms']:.4f}",
                "mean_ms": f"{r['mean_ms']:.4f}",
                "stdev_ms": f"{r['stdev_ms']:.4f}",
                "min_ms": f"{r['min_ms']:.4f}",
                "max_ms": f"{r['max_ms']:.4f}",
                "ops_per_s": f"{r['ops_per_s']:.2f}",
            })


def main():
    parser = argparse.ArgumentParser(description="Cryptographic Benchmark Suite - ATTT Project")
    parser.add_argument("--full", action="store_true", help="Run full benchmark suite (includes 2048-bit RSA, 1024-bit ElGamal)")
    parser.add_argument("--quick", action="store_true", help="Run quick benchmark suite (default)")
    args = parser.parse_args()

    is_full = bool(args.full)
    start_total = time.perf_counter()
    records, text_summary = run_benchmarks(is_full=is_full)
    end_total = time.perf_counter()

    total_duration = end_total - start_total
    duration_str = f"\nTotal Execution Wall Time: {total_duration:.3f} seconds\n"
    print(duration_str)
    text_summary += duration_str

    # Write output files
    txt_path = "benchmark_results.txt"
    csv_path = "benchmark_results.csv"

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(text_summary)

    export_csv(records, csv_path)
    print(f"Artifacts successfully generated:\n- {txt_path}\n- {csv_path}")


if __name__ == "__main__":
    main()
