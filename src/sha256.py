"""SHA-256 Cryptographic Hash Function (FIPS 180-4).
Implemented from scratch without external cryptographic libraries.

Student: Nguyen Thi Nhu Y
SID ends with: 0
Reference: NIST FIPS PUB 180-4 Secure Hash Standard (SHS)
"""

from typing import List, Union
from src.utils import rotr32

# Initial Hash Values H^(0) (Section 5.3.3 of FIPS 180-4)
# First thirty-two bits of the fractional parts of the square roots of the first eight prime numbers
INITIAL_H: List[int] = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
]

# Round Constants K_0 to K_63 (Section 4.2.2 of FIPS 180-4)
# First thirty-two bits of the fractional parts of the cube roots of the first sixty-four prime numbers
K_CONSTANTS: List[int] = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]


def _ch(x: int, y: int, z: int) -> int:
    """Ch(x, y, z) = (x AND y) XOR ((NOT x) AND z)"""
    return (x & y) ^ (~x & z)


def _maj(x: int, y: int, z: int) -> int:
    """Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)"""
    return (x & y) ^ (x & z) ^ (y & z)


def _sigma0(x: int) -> int:
    """SIGMA_0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)"""
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22)


def _sigma1(x: int) -> int:
    """SIGMA_1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)"""
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25)


def _gamma0(x: int) -> int:
    """gamma_0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)"""
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3)


def _gamma1(x: int) -> int:
    """gamma_1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)"""
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10)


def pad_message(message: bytes) -> bytes:
    """Pad message according to FIPS 180-4 Section 5.1.1."""
    # 1. Tính độ dài chuỗi ban đầu theo số bit
    orig_len_bits = len(message) * 8
    
    # 2. Thêm bit '1' (byte 0x80)
    padded = bytearray(message)
    padded.append(0x80)
    
    # 3. Thêm các byte 0x00 cho đến khi chiều dài chia 64 dư 56 byte (448 bits)
    while len(padded) % 64 != 56:
        padded.append(0x00)
        
    # 4. Thêm 8 byte (64 bits) biểu diễn độ dài gốc ban đầu theo Big-Endian
    padded.extend(orig_len_bits.to_bytes(8, byteorder="big"))
    
    return bytes(padded)


def prepare_message_schedule(chunk: bytes) -> List[int]:
    """Prepare the 64-word message schedule W from a 64-byte chunk (FIPS 180-4 Section 6.2.2)."""
    w = [0] * 64
    
    # 1. 16 từ đầu tiên lấy trực tiếp từ khối 64 bytes (mỗi từ 4 bytes Big-Endian)
    for t in range(16):
        w[t] = int.from_bytes(chunk[t * 4 : (t + 1) * 4], byteorder="big")
        
    # 2. 48 từ tiếp theo tính toán bằng các hàm gamma0 và gamma1
    for t in range(16, 64):
        s0 = _gamma0(w[t - 15])
        s1 = _gamma1(w[t - 2])
        w[t] = (s1 + w[t - 7] + s0 + w[t - 16]) & 0xFFFFFFFF
        
    return w


def compress_chunk(chunk: bytes, current_h: List[int]) -> List[int]:
    """Execute the 64-round compression loop on a 512-bit chunk (FIPS 180-4 Section 6.2.2)."""
    w = prepare_message_schedule(chunk)
    a, b, c, d, e, f, g, h = current_h
    
    # Vòng lặp nén 64 bước
    for t in range(64):
        t1 = (h + _sigma1(e) + _ch(e, f, g) + K_CONSTANTS[t] + w[t]) & 0xFFFFFFFF
        t2 = (_sigma0(a) + _maj(a, b, c)) & 0xFFFFFFFF
        
        h = g
        g = f
        f = e
        e = (d + t1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (t1 + t2) & 0xFFFFFFFF
        
    # Cộng dồn trạng thái sau 64 vòng với modulo 2^32
    return [
        (current_h[0] + a) & 0xFFFFFFFF,
        (current_h[1] + b) & 0xFFFFFFFF,
        (current_h[2] + c) & 0xFFFFFFFF,
        (current_h[3] + d) & 0xFFFFFFFF,
        (current_h[4] + e) & 0xFFFFFFFF,
        (current_h[5] + f) & 0xFFFFFFFF,
        (current_h[6] + g) & 0xFFFFFFFF,
        (current_h[7] + h) & 0xFFFFFFFF,
    ]


def sha256_bytes(data: bytes) -> bytes:
    """Compute 32-byte SHA-256 hash of input data.
    
    Orchestration:
    1. Padded data = pad_message(data)
    2. H = list(INITIAL_H)
    3. For each 64-byte chunk in padded data:
          H = compress_chunk(chunk, H)
    4. Pack H (8 32-bit ints) into 32 big-endian bytes.
    """
    padded = pad_message(data)
    h_state = list(INITIAL_H)
    for i in range(0, len(padded), 64):
        chunk = padded[i : i + 64]
        h_state = compress_chunk(chunk, h_state)
    
    out = bytearray(32)
    for i, val in enumerate(h_state):
        out[i * 4 : (i + 1) * 4] = val.to_bytes(4, byteorder="big")
    return bytes(out)


def sha256_hex(data: Union[bytes, str]) -> str:
    """Compute SHA-256 hash and return as lowercase hexadecimal string."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return sha256_bytes(data).hex()
