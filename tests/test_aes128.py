"""Unit tests for AES-128 block cipher.
All test vectors are hardcoded constants (NIST FIPS 197 Appendix C.1 and project requirements).
NO forbidden crypto libraries are imported.
"""

import unittest
from src.aes128 import (
    key_expansion,
    sub_bytes,
    inv_sub_bytes,
    shift_rows,
    inv_shift_rows,
    mix_columns,
    inv_mix_columns,
    add_round_key,
    xtime,
    gf_mul,
    encrypt_block,
    decrypt_block,
    aes128_encrypt_message,
    aes128_decrypt_message,
)
from src.utils import bytes_to_matrix, matrix_to_bytes, pkcs7_pad, pkcs7_unpad


class TestAES128(unittest.TestCase):
    def test_key_expansion_shape_and_initial_key(self):
        """Test C: Shape 11x4x4, byte range 0..255, and round_keys[0] equals key bytes."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        round_keys = key_expansion(key)

        self.assertEqual(len(round_keys), 11)
        for i, rk in enumerate(round_keys):
            self.assertEqual(len(rk), 4)
            for r in range(4):
                self.assertEqual(len(rk[r]), 4)
                for c in range(4):
                    self.assertIsInstance(rk[r][c], int)
                    self.assertTrue(0 <= rk[r][c] <= 255)

        # round_keys[0] in column-major order must equal the original key
        rk0_bytes = bytes(round_keys[0][r][c] for c in range(4) for r in range(4))
        self.assertEqual(rk0_bytes, key)

    def test_key_expansion_fips197_appendix_a1(self):
        """Test A: FIPS 197 Appendix A.1 test vectors for w4..w7 and w40..w43."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        round_keys = key_expansion(key)

        # Helper to extract word as hex string: column c of round_keys[i]
        def get_word_hex(rk_idx, col_idx):
            return bytes(round_keys[rk_idx][r][col_idx] for r in range(4)).hex()

        # w4..w7 is round_keys[1] columns 0..3
        self.assertEqual(get_word_hex(1, 0), "a0fafe17")
        self.assertEqual(get_word_hex(1, 1), "88542cb1")
        self.assertEqual(get_word_hex(1, 2), "23a33939")
        self.assertEqual(get_word_hex(1, 3), "2a6c7605")

        # w40..w43 is round_keys[10] columns 0..3
        self.assertEqual(get_word_hex(10, 0), "d014f9a8")
        self.assertEqual(get_word_hex(10, 1), "c9ee2589")
        self.assertEqual(get_word_hex(10, 2), "e13f0cc8")
        self.assertEqual(get_word_hex(10, 3), "b6630ca6")

    def test_key_expansion_fips197_appendix_c1(self):
        """Test B: FIPS 197 Appendix C.1 test vectors for w4..w7 and round key 10."""
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        round_keys = key_expansion(key)

        def get_word_hex(rk_idx, col_idx):
            return bytes(round_keys[rk_idx][r][col_idx] for r in range(4)).hex()

        # w4..w7 is round_keys[1] columns 0..3
        self.assertEqual(get_word_hex(1, 0), "d6aa74fd")
        self.assertEqual(get_word_hex(1, 1), "d2af72fa")
        self.assertEqual(get_word_hex(1, 2), "daa678f1")
        self.assertEqual(get_word_hex(1, 3), "d6ab76fe")

        # round key 10 bytes (column-major)
        rk10_bytes = bytes(round_keys[10][r][c] for c in range(4) for r in range(4)).hex()
        self.assertEqual(rk10_bytes, "13111d7fe3944a17f307a78b4d2b30c5")

    def test_fips197_appendix_c1(self):
        """Mandatory NIST FIPS-197 Appendix C.1 test vector."""
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected_ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

        round_keys = key_expansion(key)
        ciphertext = encrypt_block(plaintext, round_keys)
        self.assertEqual(ciphertext, expected_ciphertext)

        decrypted = decrypt_block(ciphertext, round_keys)
        self.assertEqual(decrypted, plaintext)

    def test_student_derived_key_single_block(self):
        """Test AES-128 single block roundtrip with student key derived from SHA-256('Nguyen Thi Nhu Y').
        First 16 bytes = f5db6c7e3f6d978c01b2409cd300d3c5.
        """
        key = bytes.fromhex("f5db6c7e3f6d978c01b2409cd300d3c5")
        block = bytes.fromhex("00112233445566778899aabbccddeeff")

        round_keys = key_expansion(key)
        ciphertext = encrypt_block(block, round_keys)
        self.assertEqual(len(ciphertext), 16)

        decrypted = decrypt_block(ciphertext, round_keys)
        self.assertEqual(decrypted, block)

    def test_student_mode_message_roundtrip(self):
        """Test arbitrary-length message encryption using student's chosen mode and padding."""
        key = bytes.fromhex("f5db6c7e3f6d978c01b2409cd300d3c5")
        message = b"Do an An toan thong tin - Sinh vien: Nguyen Thi Nhu Y - SID: 0"

        ciphertext = aes128_encrypt_message(message, key)
        self.assertNotEqual(ciphertext, message)

        decrypted = aes128_decrypt_message(ciphertext, key)
        self.assertEqual(decrypted, message)

    def test_sub_bytes_fips197_appendix_b(self):
        """Test SubBytes against FIPS 197 Appendix B Round 1."""
        state = bytes_to_matrix(bytes.fromhex("193de3bea0f4e22b9ac68d2ae9f84808"))
        sub_bytes(state)
        self.assertEqual(matrix_to_bytes(state).hex(), "d42711aee0bf98f1b8b45de51e415230")

    def test_shift_rows_fips197_appendix_b(self):
        """Test ShiftRows against FIPS 197 Appendix B Round 1."""
        state = bytes_to_matrix(bytes.fromhex("d42711aee0bf98f1b8b45de51e415230"))
        shift_rows(state)
        self.assertEqual(matrix_to_bytes(state).hex(), "d4bf5d30e0b452aeb84111f11e2798e5")

    def test_add_round_key_fips197_appendix_b(self):
        """Test AddRoundKey with round key 1 against FIPS 197 Appendix B Round 1."""
        state = bytes_to_matrix(bytes.fromhex("046681e5e0cb199a48f8d37a2806264c"))
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        round_keys = key_expansion(key)
        add_round_key(state, round_keys[1])
        self.assertEqual(matrix_to_bytes(state).hex(), "a49c7ff2689f352b6b5bea43026a5049")

    def test_add_round_key_twice_returns_original(self):
        """Edge test: Applying AddRoundKey twice with the same key returns original state."""
        original_bytes = bytes.fromhex("046681e5e0cb199a48f8d37a2806264c")
        state = bytes_to_matrix(original_bytes)
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        round_keys = key_expansion(key)
        add_round_key(state, round_keys[1])
        add_round_key(state, round_keys[1])
        self.assertEqual(matrix_to_bytes(state), original_bytes)

    def test_gf_xtime_fips197_sec4_2_1(self):
        """Test xtime in GF(2^8) against FIPS 197 Section 4.2.1."""
        self.assertEqual(xtime(0x57), 0xae)
        self.assertEqual(xtime(0xae), 0x47)

    def test_mix_columns_single_columns(self):
        """Test MixColumns on single column test vectors placed in column 0."""
        vectors = [
            ("db135345", "8e4da1bc"),
            ("f20a225c", "9fdc589d"),
            ("01010101", "01010101"),
            ("c6c6c6c6", "c6c6c6c6"),
            ("d4d4d4d5", "d5d5d7d6"),
            ("2d26314c", "4d7ebdf8"),
        ]
        for in_col_hex, out_col_hex in vectors:
            # Place 4 bytes in column 0, remaining 12 bytes can be zeros
            in_bytes = bytes.fromhex(in_col_hex) + bytes(12)
            state = bytes_to_matrix(in_bytes)
            mix_columns(state)
            out_bytes = matrix_to_bytes(state)
            self.assertEqual(out_bytes[:4].hex(), out_col_hex)

    def test_mix_columns_fips197_appendix_b(self):
        """Test MixColumns against FIPS 197 Appendix B full 16-byte states."""
        # Round 1
        state_r1 = bytes_to_matrix(bytes.fromhex("d4bf5d30e0b452aeb84111f11e2798e5"))
        mix_columns(state_r1)
        self.assertEqual(matrix_to_bytes(state_r1).hex(), "046681e5e0cb199a48f8d37a2806264c")

        # Round 2
        state_r2 = bytes_to_matrix(bytes.fromhex("49db873b453953897f02d2f177de961a"))
        mix_columns(state_r2)
        self.assertEqual(matrix_to_bytes(state_r2).hex(), "584dcaf11b4b5aacdbe7caa81b6bb0e5")

    def test_encrypt_block_fips197_appendix_b(self):
        """Test encrypt_block against FIPS 197 Appendix B."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        plaintext = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        expected_ciphertext = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
        round_keys = key_expansion(key)
        ciphertext = encrypt_block(plaintext, round_keys)
        self.assertEqual(ciphertext, expected_ciphertext)

    def test_encrypt_block_fips197_appendix_c1(self):
        """Test encrypt_block against FIPS 197 Appendix C.1."""
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected_ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        round_keys = key_expansion(key)
        ciphertext = encrypt_block(plaintext, round_keys)
        self.assertEqual(ciphertext, expected_ciphertext)

    def test_encrypt_block_value_error(self):
        """Test encrypt_block raises ValueError on invalid block size or round key count."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        round_keys = key_expansion(key)
        with self.assertRaises(ValueError):
            encrypt_block(bytes(15), round_keys)
        with self.assertRaises(ValueError):
            encrypt_block(bytes(17), round_keys)
        with self.assertRaises(ValueError):
            encrypt_block(bytes(16), round_keys[:10])

    def test_inv_sub_bytes_fips197(self):
        """Test InvSubBytes against FIPS 197 test vector."""
        state = bytes_to_matrix(bytes.fromhex("d42711aee0bf98f1b8b45de51e415230"))
        inv_sub_bytes(state)
        self.assertEqual(matrix_to_bytes(state).hex(), "193de3bea0f4e22b9ac68d2ae9f84808")

    def test_inv_shift_rows_fips197(self):
        """Test InvShiftRows against FIPS 197 test vector."""
        state = bytes_to_matrix(bytes.fromhex("d4bf5d30e0b452aeb84111f11e2798e5"))
        inv_shift_rows(state)
        self.assertEqual(matrix_to_bytes(state).hex(), "d42711aee0bf98f1b8b45de51e415230")

    def test_inv_mix_columns_fips197(self):
        """Test InvMixColumns against FIPS 197 Appendix B Round 1 state."""
        state = bytes_to_matrix(bytes.fromhex("046681e5e0cb199a48f8d37a2806264c"))
        inv_mix_columns(state)
        self.assertEqual(matrix_to_bytes(state).hex(), "d4bf5d30e0b452aeb84111f11e2798e5")

    def test_inv_mix_columns_single_columns(self):
        """Test InvMixColumns on single column test vectors placed in column 0."""
        vectors = [
            ("8e4da1bc", "db135345"),
            ("9fdc589d", "f20a225c"),
            ("01010101", "01010101"),
            ("c6c6c6c6", "c6c6c6c6"),
            ("d5d5d7d6", "d4d4d4d5"),
            ("4d7ebdf8", "2d26314c"),
        ]
        for in_col_hex, out_col_hex in vectors:
            in_bytes = bytes.fromhex(in_col_hex) + bytes(12)
            state = bytes_to_matrix(in_bytes)
            inv_mix_columns(state)
            out_bytes = matrix_to_bytes(state)
            self.assertEqual(out_bytes[:4].hex(), out_col_hex)

    def test_gf_mul_fips197_sec4_2_1(self):
        """Test gf_mul against FIPS 197 Section 4.2.1."""
        self.assertEqual(gf_mul(0x57, 0x83), 0xc1)
        self.assertEqual(gf_mul(0x57, 0x13), 0xfe)

    def test_aes_transformations_roundtrip(self):
        """Test roundtrips for SubBytes, ShiftRows, and MixColumns."""
        test_states_bytes = [
            bytes.fromhex("00112233445566778899aabbccddeeff"),
            bytes.fromhex("3243f6a8885a308d313198a2e0370734"),
            bytes(16),
            bytes([0xFF] * 16),
        ]
        for b in test_states_bytes:
            # SubBytes roundtrip
            s1 = bytes_to_matrix(b)
            sub_bytes(s1)
            inv_sub_bytes(s1)
            self.assertEqual(matrix_to_bytes(s1), b)

            # ShiftRows roundtrip
            s2 = bytes_to_matrix(b)
            shift_rows(s2)
            inv_shift_rows(s2)
            self.assertEqual(matrix_to_bytes(s2), b)

            # MixColumns roundtrip
            s3 = bytes_to_matrix(b)
            mix_columns(s3)
            inv_mix_columns(s3)
            self.assertEqual(matrix_to_bytes(s3), b)

    def test_decrypt_block_fips197_appendix_b(self):
        """Test decrypt_block against FIPS 197 Appendix B."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        ciphertext = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
        expected_plaintext = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        round_keys = key_expansion(key)
        plaintext = decrypt_block(ciphertext, round_keys)
        self.assertEqual(plaintext, expected_plaintext)

    def test_decrypt_block_fips197_appendix_c1(self):
        """Test decrypt_block against FIPS 197 Appendix C.1."""
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        expected_plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        round_keys = key_expansion(key)
        plaintext = decrypt_block(ciphertext, round_keys)
        self.assertEqual(plaintext, expected_plaintext)

    def test_regression_vector_student_key(self):
        """Test regression vector under student derived key in both encrypt and decrypt directions."""
        key = bytes.fromhex("f5db6c7e3f6d978c01b2409cd300d3c5")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected_ciphertext = bytes.fromhex("335f5bad6b7093aec191666fc2a0cbb3")
        round_keys = key_expansion(key)

        # Encrypt direction
        ct = encrypt_block(plaintext, round_keys)
        self.assertEqual(ct, expected_ciphertext)

        # Decrypt direction
        pt = decrypt_block(expected_ciphertext, round_keys)
        self.assertEqual(pt, plaintext)

    def test_decrypt_block_roundtrips(self):
        """Test decrypt_block(encrypt_block(x)) == x for 5 fixed blocks under 2 keys."""
        blocks = [
            bytes(16),
            bytes([0xFF] * 16),
            bytes.fromhex("00112233445566778899aabbccddeeff"),
            bytes.fromhex("0123456789abcdef0123456789abcdef"),
            bytes.fromhex("fedcba9876543210fedcba9876543210"),
        ]
        keys = [
            bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
            bytes.fromhex("f5db6c7e3f6d978c01b2409cd300d3c5"),
        ]
        for key in keys:
            round_keys = key_expansion(key)
            for block in blocks:
                ct = encrypt_block(block, round_keys)
                decrypted = decrypt_block(ct, round_keys)
                self.assertEqual(decrypted, block)

    def test_decrypt_block_value_error(self):
        """Test decrypt_block raises ValueError on invalid block size or round key count."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        round_keys = key_expansion(key)
        with self.assertRaises(ValueError):
            decrypt_block(bytes(15), round_keys)
        with self.assertRaises(ValueError):
            decrypt_block(bytes(17), round_keys)
        with self.assertRaises(ValueError):
            decrypt_block(bytes(16), round_keys[:10])

    def test_nist_sp800_38a_f21_cbc(self):
        """Test AES-128 CBC mode against NIST SP 800-38A Section F.2.1 with prepended IV and PKCS#7."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        )
        expected_ct = bytes.fromhex(
            "7649abac8119b246cee98e9b12e9197d"
            "5086cb9b507219ee95db113a917678b2"
            "73bed6b8e3c1743b7116e69e22229516"
            "3ff1caa1681fac09120eca307586e1a7"
        )
        output = aes128_encrypt_message(pt, key, iv=iv)
        self.assertEqual(len(output), 96)
        self.assertEqual(output[:16], iv)
        self.assertEqual(output[16:80], expected_ct)
        decrypted = aes128_decrypt_message(output, key)
        self.assertEqual(decrypted, pt)

    def test_cbc_pkcs7_regression_vectors(self):
        """Test CBC encryption with PKCS#7 against regression vectors with student key."""
        key = bytes.fromhex("f5db6c7e3f6d978c01b2409cd300d3c5")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        vectors = [
            (b"", "aa4eb3619300af841ba496a375656132"),
            (b"Hello AES", "5e5e0cbadc20ce57cffd0e60e497f432"),
            (b"0123456789abcdef", "e0cfad6f08bdf82c2619753ed32871106e7468d882bd3aa8efdfb982e148bcb4"),
        ]
        for plaintext, expected_ct_hex in vectors:
            full_ct = aes128_encrypt_message(plaintext, key, iv=iv)
            # Pre-pended IV is first 16 bytes, ciphertext blocks follow
            self.assertEqual(full_ct[:16], iv)
            self.assertEqual(full_ct[16:].hex(), expected_ct_hex)
            # Decrypt roundtrip
            decrypted = aes128_decrypt_message(full_ct, key)
            self.assertEqual(decrypted, plaintext)

    def test_cbc_pkcs7_roundtrips_variable_lengths(self):
        """Test roundtrip for lengths 0, 1, 15, 16, 17, 31, 32, 100 bytes."""
        key = bytes.fromhex("f5db6c7e3f6d978c01b2409cd300d3c5")
        lengths = [0, 1, 15, 16, 17, 31, 32, 100]
        for l in lengths:
            plaintext = bytes(range(256))[:l] if l > 0 else b""
            ct = aes128_encrypt_message(plaintext, key)
            self.assertEqual(aes128_decrypt_message(ct, key), plaintext)

    def test_random_iv_produces_different_ciphertexts(self):
        """Test encrypting same plaintext twice without fixed IV produces distinct ciphertexts."""
        key = bytes.fromhex("f5db6c7e3f6d978c01b2409cd300d3c5")
        pt = b"Deterministic Plaintext Test"
        ct1 = aes128_encrypt_message(pt, key)
        ct2 = aes128_encrypt_message(pt, key)
        self.assertNotEqual(ct1, ct2)
        self.assertEqual(aes128_decrypt_message(ct1, key), pt)
        self.assertEqual(aes128_decrypt_message(ct2, key), pt)

    def test_decrypt_message_value_errors(self):
        """Test ValueError on bad ciphertext length and tampered padding."""
        key = bytes.fromhex("f5db6c7e3f6d978c01b2409cd300d3c5")
        with self.assertRaises(ValueError):
            aes128_decrypt_message(bytes(15), key)  # < 32 bytes
        with self.assertRaises(ValueError):
            aes128_decrypt_message(bytes(33), key)  # Not multiple of 16

        # Valid ciphertext then tamper padding byte
        valid_ct = bytearray(aes128_encrypt_message(b"Valid message", key))
        valid_ct[-1] ^= 0x01  # Tamper last padding byte
        with self.assertRaises(ValueError):
            aes128_decrypt_message(bytes(valid_ct), key)

    def test_pkcs7_pad_unpad(self):
        """Test PKCS#7 pad and unpad roundtrips for lengths 0..33 and invalid padding detection."""
        for length in range(34):
            data = bytes([i % 256 for i in range(length)])
            padded = pkcs7_pad(data, 16)
            self.assertEqual(len(padded) % 16, 0)
            self.assertGreater(len(padded), len(data))
            self.assertEqual(pkcs7_unpad(padded, 16), data)

        # A 16-byte input gets a full 16-byte pad block
        input_16 = bytes(16)
        padded_16 = pkcs7_pad(input_16, 16)
        self.assertEqual(len(padded_16), 32)
        self.assertEqual(padded_16[16:], bytes([16] * 16))
        self.assertEqual(pkcs7_unpad(padded_16, 16), input_16)

        # Invalid padding tests
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"", 16)
        with self.assertRaises(ValueError):
            pkcs7_unpad(bytes(15), 16)
        with self.assertRaises(ValueError):
            pkcs7_unpad(bytes(15) + b"\x00", 16)
        with self.assertRaises(ValueError):
            pkcs7_unpad(bytes(15) + b"\x11", 16)
        with self.assertRaises(ValueError):
            pkcs7_unpad(bytes(14) + b"\x01\x02", 16)


if __name__ == "__main__":
    unittest.main()
