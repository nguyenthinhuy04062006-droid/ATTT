"""AES-128 Symmetric Block Cipher (FIPS 197).
Implemented from scratch without external cryptographic libraries.

Student: Nguyen Thi Nhu Y
SID ends with: 0
Reference: NIST FIPS PUB 197 Advanced Encryption Standard (AES)
"""

from typing import List

# AES S-Box (Substitution box, FIPS 197 Figure 7)
S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

# Inverse AES S-Box (FIPS 197 Figure 14)
INV_S_BOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
]

# Round Constant Rcon (FIPS 197 Section 5.2)
RCON = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
]


def xtime(a: int) -> int:
    """Multiplication by 0x02 in GF(2^8) modulo irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b)."""
    return ((a << 1) ^ 0x1b) & 0xff if (a & 0x80) else (a << 1) & 0xff


def gf_mul(a: int, b: int) -> int:
    """Multiply two polynomials a and b in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1 (FIPS 197 Section 4.2.1)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = xtime(a)
        b >>= 1
    return p


def key_expansion(key: bytes) -> List[List[List[int]]]:
    """Expand a 16-byte key into 11 round keys (FIPS 197 Section 5.2).
    
    Input:
        key: 16-byte key.
        
    Returns:
        round_keys: list of 11 matrices (4x4).
        round_keys[i][r][c] = byte r of word 4*i + c (column-major, same as bytes_to_matrix).
    """
    # Input validation (FIPS 197 Section 5.2: Nk = 4 words = 16 bytes for AES-128)
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")

    # Step 1: Initialize first Nk=4 words directly from input key (FIPS 197 Figure 11, line 1-4)
    w: List[List[int]] = []
    for i in range(4):
        w.append([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])

    # Step 2: Generate remaining 40 words w_4 to w_43 (FIPS 197 Figure 11, line 5-11, Nr=10)
    for i in range(4, 44):
        temp = list(w[i - 1])
        if i % 4 == 0:
            # RotWord: cyclical left shift of 4-byte word (FIPS 197 Section 5.2)
            temp = temp[1:] + temp[:1]
            # SubWord: byte substitution using S_BOX (FIPS 197 Section 5.2)
            temp = [S_BOX[b] for b in temp]
            # XOR with Round Constant Rcon[i/Nk] on first byte (FIPS 197 Section 5.2)
            temp[0] ^= RCON[i // 4]
        # w[i] = w[i - 4] XOR temp (FIPS 197 Figure 11, line 11)
        w.append([w[i - 4][j] ^ temp[j] for j in range(4)])

    # Step 3: Pack 44 words into 11 4x4 round keys in column-major order (FIPS 197 Section 5.2)
    round_keys: List[List[List[int]]] = []
    for round_idx in range(11):
        round_key = [[0] * 4 for _ in range(4)]
        for col in range(4):
            word = w[4 * round_idx + col]
            for row in range(4):
                round_key[row][col] = word[row]
        round_keys.append(round_key)

    return round_keys


def sub_bytes(state: List[List[int]]) -> None:
    """Substitute each byte in state matrix using S_BOX (in-place)."""
    # FIPS 197 Section 5.1.1: SubBytes() non-linear byte substitution operating independently on each state byte
    for r in range(4):
        for c in range(4):
            state[r][c] = S_BOX[state[r][c]]


def inv_sub_bytes(state: List[List[int]]) -> None:
    """Substitute each byte in state matrix using INV_S_BOX (in-place)."""
    # FIPS 197 Section 5.3.2: InvSubBytes() byte substitution using inverse S-box
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_S_BOX[state[r][c]]


def shift_rows(state: List[List[int]]) -> None:
    """Cyclically shift rows to the left: row 0 by 0, row 1 by 1, row 2 by 2, row 3 by 3 (in-place)."""
    # FIPS 197 Section 5.1.2: ShiftRows() cyclical left shift of row r by r bytes
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]


def inv_shift_rows(state: List[List[int]]) -> None:
    """Cyclically shift rows to the right: row 0 by 0, row 1 by 1, row 2 by 2, row 3 by 3 (in-place)."""
    # FIPS 197 Section 5.3.1: InvShiftRows() cyclical right shift of row r by r bytes
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]


def mix_columns(state: List[List[int]]) -> None:
    """Mix columns using multiplication in GF(2^8) (in-place)."""
    # FIPS 197 Section 5.1.3: MixColumns() transformation operates on state column-by-column
    # FIPS 197 Section 4.2: Multiplication by {02} via xtime and {03} via xtime(x) ^ x in GF(2^8)
    for c in range(4):
        a0 = state[0][c]
        a1 = state[1][c]
        a2 = state[2][c]
        a3 = state[3][c]

        state[0][c] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3
        state[1][c] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3
        state[2][c] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3)
        state[3][c] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3)


def inv_mix_columns(state: List[List[int]]) -> None:
    """Inverse mix columns using inverse polynomial in GF(2^8) (in-place)."""
    # FIPS 197 Section 5.3.3: InvMixColumns() transformation operating column-by-column
    # Matrix polynomial coefficients: {0e}=14, {0b}=11, {0d}=13, {09}=9 in GF(2^8)
    for c in range(4):
        a0 = state[0][c]
        a1 = state[1][c]
        a2 = state[2][c]
        a3 = state[3][c]

        state[0][c] = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9)
        state[1][c] = gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13)
        state[2][c] = gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11)
        state[3][c] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14)


def add_round_key(state: List[List[int]], round_key: List[List[int]]) -> None:
    """XOR each byte of state with corresponding round_key byte (in-place)."""
    # FIPS 197 Section 5.1.4: AddRoundKey() bitwise XOR of state matrix with round key matrix
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key[r][c]


def encrypt_block(block: bytes, round_keys: List[List[List[int]]]) -> bytes:
    """Encrypt a single 16-byte block with AES-128 (10 rounds, FIPS 197 Section 5.1)."""
    # FIPS 197 Section 5.1: Cipher(in, out, w) algorithm
    if len(block) != 16:
        raise ValueError("AES-128 block size must be exactly 16 bytes")
    if len(round_keys) != 11:
        raise ValueError("AES-128 requires exactly 11 round keys")

    from src.utils import bytes_to_matrix, matrix_to_bytes

    # FIPS 197 Section 5.1 Figure 5: Initial round key addition
    state = bytes_to_matrix(block)
    add_round_key(state, round_keys[0])

    # FIPS 197 Section 5.1 Figure 5: Rounds 1 to 9 (Nr - 1 rounds)
    for r in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[r])

    # FIPS 197 Section 5.1 Figure 5: Final round 10 (without MixColumns)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10])

    return matrix_to_bytes(state)


def decrypt_block(block: bytes, round_keys: List[List[List[int]]]) -> bytes:
    """Decrypt a single 16-byte block with AES-128 (FIPS 197 Section 5.3)."""
    # FIPS 197 Section 5.3: InvCipher(in, out, w) algorithm (Figure 12)
    if len(block) != 16:
        raise ValueError("AES-128 block size must be exactly 16 bytes")
    if len(round_keys) != 11:
        raise ValueError("AES-128 requires exactly 11 round keys")

    from src.utils import bytes_to_matrix, matrix_to_bytes

    # FIPS 197 Section 5.3 Figure 12: Initial round key addition with round_keys[Nr] (Nr=10)
    state = bytes_to_matrix(block)
    add_round_key(state, round_keys[10])

    # FIPS 197 Section 5.3 Figure 12: Rounds 9 down to 1
    for r in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[r])
        inv_mix_columns(state)

    # FIPS 197 Section 5.3 Figure 12: Final round 0 (without InvMixColumns)
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])

    return matrix_to_bytes(state)


# ==============================================================================
# TODO (Student Design Decision):
# Select and implement a block cipher mode of operation (e.g. ECB or CBC)
# and a padding scheme (e.g. PKCS#7) for encrypting arbitrary-length messages.
# Document your design decision and rationale in the report.
# ==============================================================================

def aes128_encrypt_message(plaintext: bytes, key: bytes, iv: bytes = None, **kwargs) -> bytes:
    """Encrypt arbitrary-length message using AES-128 CBC mode with PKCS#7 padding (NIST SP 800-38A)."""
    # NIST SP 800-38A Section 6.2: Cipher Block Chaining (CBC) mode
    if len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes")
    import secrets
    from src.utils import pkcs7_pad

    if iv is None:
        iv = secrets.token_bytes(16)
    elif len(iv) != 16:
        raise ValueError("IV must be exactly 16 bytes")

    padded = pkcs7_pad(plaintext, 16)
    round_keys = key_expansion(key)

    ciphertext_blocks = bytearray()
    prev = iv
    for i in range(0, len(padded), 16):
        block = padded[i : i + 16]
        xored = bytes(a ^ b for a, b in zip(block, prev))
        ct_block = encrypt_block(xored, round_keys)
        ciphertext_blocks.extend(ct_block)
        prev = ct_block

    return iv + bytes(ciphertext_blocks)


def aes128_decrypt_message(ciphertext: bytes, key: bytes, **kwargs) -> bytes:
    """Decrypt message using AES-128 CBC mode with PKCS#7 unpadding (NIST SP 800-38A)."""
    # NIST SP 800-38A Section 6.2: CBC decryption
    if len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes")
    if len(ciphertext) < 32 or len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext must be at least 32 bytes and a multiple of 16 bytes")

    from src.utils import pkcs7_unpad

    iv = ciphertext[:16]
    ct_data = ciphertext[16:]
    round_keys = key_expansion(key)

    plaintext_blocks = bytearray()
    prev = iv
    for i in range(0, len(ct_data), 16):
        ct_block = ct_data[i : i + 16]
        decrypted_block = decrypt_block(ct_block, round_keys)
        pt_block = bytes(a ^ b for a, b in zip(decrypted_block, prev))
        plaintext_blocks.extend(pt_block)
        prev = ct_block

    return pkcs7_unpad(bytes(plaintext_blocks), 16)
