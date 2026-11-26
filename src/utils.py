"""General utility functions for data formatting, bitwise operations, and PKCS#7 padding.
Does not import any cryptographic library.
"""

from typing import List, Tuple


def rotr32(x: int, n: int) -> int:
    """Rotate right 32-bit integer x by n bits.
    
    Formula: ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
    """
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def rotl32(x: int, n: int) -> int:
    """Rotate left 32-bit integer x by n bits.
    
    Formula: ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    """
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def bytes_to_int(b: bytes) -> int:
    """Convert big-endian bytes to integer."""
    return int.from_bytes(b, byteorder="big")


def int_to_bytes(n: int, length: int = None) -> bytes:
    """Convert integer to big-endian bytes."""
    if length is None:
        length = (n.bit_length() + 7) // 8 or 1
    return n.to_bytes(length, byteorder="big")


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Apply PKCS#7 padding (RFC 5652 Section 6.3) to align data to block_size."""
    if not (1 <= block_size <= 255):
        raise ValueError("Block size must be between 1 and 255")
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """Remove and validate PKCS#7 padding (RFC 5652 Section 6.3)."""
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length: must be non-empty multiple of block_size")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid PKCS#7 padding byte value")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS#7 padding bytes: mismatch in padding block")
    return data[:-pad_len]


def bytes_to_matrix(b: bytes) -> List[List[int]]:
    """Convert 16 bytes into a 4x4 column-major state matrix for AES."""
    if len(b) != 16:
        raise ValueError("AES state requires exactly 16 bytes")
    # Column-major order: state[r][c] = b[r + 4*c]
    return [[b[r + 4 * c] for c in range(4)] for r in range(4)]


def matrix_to_bytes(matrix: List[List[int]]) -> bytes:
    """Convert 4x4 column-major AES state matrix back to 16 bytes."""
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[r + 4 * c] = matrix[r][c] & 0xFF
    return bytes(out)
