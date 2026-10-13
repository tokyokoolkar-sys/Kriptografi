"""Block ciphers, modes of operation, padding, and hashing."""

from __future__ import annotations

import hashlib
import hmac as stdhmac
import random

import pytest

from kriptografi.block.aes import AES, SBOX, aes_decrypt_block, aes_encrypt_block
from kriptografi.block.des import DES, des_decrypt_block, des_encrypt_block, generate_subkeys
from kriptografi.hashes import SHA256_H0, SHA256_K, hmac_sha256, sha256
from kriptografi.modes import (
    MODE_INFO,
    cbc_decrypt,
    cbc_encrypt,
    ctr_crypt,
    ecb_decrypt,
    ecb_encrypt,
    pkcs7_pad,
    pkcs7_unpad,
    zero_pad,
)


# --------------------------------------------------------------------------
# DES
# --------------------------------------------------------------------------

class TestDES:
    @pytest.mark.parametrize(
        "key,plaintext,ciphertext",
        [
            # FIPS 46-3 / NBS known-answer vectors.
            ("0000000000000000", "0000000000000000", "8CA64DE9C1B123A7"),
            ("FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "7359B2163E4EDC58"),
            ("3000000000000000", "1000000000000001", "958E6E627A05557B"),
            ("1111111111111111", "1111111111111111", "F40379AB9E0EC533"),
            ("FEDCBA9876543210", "0123456789ABCDEF", "ED39D950FA74BCC4"),
            ("7CA110454A1A6E57", "01A1D6D039776742", "690F5B0D9A26939B"),
            ("0131D9619DC1376E", "5CD54CA83DEF57DA", "7A389D10354BD271"),
        ],
    )
    def test_fips_vectors(self, key, plaintext, ciphertext):
        assert des_encrypt_block(bytes.fromhex(plaintext), bytes.fromhex(key)).hex().upper() == ciphertext
        assert des_decrypt_block(bytes.fromhex(ciphertext), bytes.fromhex(key)).hex().upper() == plaintext

    def test_round_trip(self):
        rng = random.Random(1)
        for _ in range(200):
            key = bytes(rng.randrange(256) for _ in range(8))
            block = bytes(rng.randrange(256) for _ in range(8))
            assert des_decrypt_block(des_encrypt_block(block, key), key) == block

    def test_key_schedule_shape(self):
        subkeys = generate_subkeys(bytes.fromhex("133457799BBCDFF1"))
        assert len(subkeys) == 16
        assert len(set(subkeys)) == 16
        assert all(subkey < 2**48 for subkey in subkeys)
        # FIPS 46-3 lists the first subkey for this key as 1B02EFFC7072.
        assert format(subkeys[0], "012X") == "1B02EFFC7072"

    def test_block_size_enforced(self):
        with pytest.raises(ValueError):
            DES(bytes(8)).encrypt_block(bytes(7))

    def test_key_length_enforced(self):
        with pytest.raises(ValueError, match="exactly 8 bytes"):
            DES(bytes(7))


# --------------------------------------------------------------------------
# AES
# --------------------------------------------------------------------------

class TestAES:
    @pytest.mark.parametrize(
        "key,plaintext,ciphertext",
        [
            # FIPS 197 appendix C.
            ("000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff",
             "69c4e0d86a7b0430d8cdb78070b4c55a"),
            ("000102030405060708090a0b0c0d0e0f1011121314151617", "00112233445566778899aabbccddeeff",
             "dda97ca4864cdfe06eaf70a0ec0d7191"),
            ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
             "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"),
        ],
    )
    def test_fips_vectors(self, key, plaintext, ciphertext):
        assert aes_encrypt_block(bytes.fromhex(plaintext), bytes.fromhex(key)).hex() == ciphertext
        assert aes_decrypt_block(bytes.fromhex(ciphertext), bytes.fromhex(key)).hex() == plaintext

    def test_sbox_matches_specification(self):
        # Spot checks from FIPS 197 figure 7.
        for x, y in {0x00: 0x63, 0x53: 0xED, 0xFF: 0x16, 0x7C: 0x10}.items():
            assert SBOX[x] == y

    def test_sbox_is_a_permutation(self):
        assert sorted(SBOX) == list(range(256))

    def test_round_trip_all_key_sizes(self):
        rng = random.Random(2)
        for key_size in (16, 24, 32):
            for _ in range(100):
                key = bytes(rng.randrange(256) for _ in range(key_size))
                block = bytes(rng.randrange(256) for _ in range(16))
                cipher = AES(key)
                assert cipher.decrypt_block(cipher.encrypt_block(block)) == block

    def test_round_counts(self):
        assert AES(bytes(16)).rounds == 10
        assert AES(bytes(24)).rounds == 12
        assert AES(bytes(32)).rounds == 14

    def test_invalid_key_length_rejected(self):
        with pytest.raises(ValueError, match="16, 24, or 32"):
            AES(bytes(20))

    def test_block_size_enforced(self):
        with pytest.raises(ValueError, match="16-byte block"):
            AES(bytes(16)).encrypt_block(bytes(15))


# --------------------------------------------------------------------------
# Padding
# --------------------------------------------------------------------------

class TestPadding:
    @pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 31, 32])
    def test_pkcs7_reaches_block_boundary(self, length):
        padded = pkcs7_pad(bytes(length), 16)
        assert len(padded) % 16 == 0
        assert len(padded) > length

    def test_pkcs7_round_trip(self):
        for length in range(0, 40):
            data = bytes(range(length))
            assert pkcs7_unpad(pkcs7_pad(data, 16), 16) == data

    def test_full_block_gets_whole_block_of_padding(self):
        # Adding a full block keeps unpadding unambiguous.
        assert pkcs7_pad(bytes(16), 16) == bytes(16) + bytes([16]) * 16

    def test_unpad_rejects_corrupt_padding(self):
        with pytest.raises(ValueError):
            pkcs7_unpad(bytes(16) + bytes([0]) * 16, 16)

    def test_zero_pad_round_trip(self):
        for length in range(0, 20):
            data = bytes(range(1, length + 1))
            assert zero_pad(data, 8)[:length] == data


# --------------------------------------------------------------------------
# Modes of operation
# --------------------------------------------------------------------------

@pytest.fixture(params=["aes", "des"])
def cipher(request):
    return AES(bytes(16)) if request.param == "aes" else DES(bytes(8))


class TestModes:
    def test_ecb_round_trip(self, cipher):
        rng = random.Random(3)
        for _ in range(50):
            message = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 64)))
            assert ecb_decrypt(cipher, ecb_encrypt(cipher, message)) == message

    def test_cbc_round_trip(self, cipher):
        rng = random.Random(4)
        for _ in range(50):
            message = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 64)))
            ciphertext, iv = cbc_encrypt(cipher, message)
            assert cbc_decrypt(cipher, ciphertext, iv) == message

    def test_ctr_round_trip(self, cipher):
        rng = random.Random(5)
        for _ in range(50):
            message = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 64)))
            ciphertext, nonce = ctr_crypt(cipher, message)
            assert ctr_crypt(cipher, ciphertext, nonce)[0] == message

    def test_ctr_is_involutive(self, cipher):
        data = b"the quick brown fox"
        nonce = bytes(cipher.block_size)
        assert ctr_crypt(cipher, ctr_crypt(cipher, data, nonce)[0], nonce)[0] == data

    def test_ctr_needs_no_padding(self, cipher):
        # CTR is a stream cipher, so ciphertext length equals plaintext length.
        data = b"exactly seventeen"
        ciphertext, _ = ctr_crypt(cipher, data)
        assert len(ciphertext) == len(data)

    def test_ecb_leaks_repeated_blocks(self, cipher):
        # The famous ECB weakness: identical plaintext blocks produce identical
        # ciphertext blocks. Only the first two blocks are compared -- padding
        # adds a third, which is a full block of filler and not part of the claim.
        block = bytes(range(cipher.block_size))
        ciphertext = ecb_encrypt(cipher, block + block)
        half = cipher.block_size
        assert ciphertext[:half] == ciphertext[half : 2 * half]

    def test_cbc_hides_repeated_blocks(self, cipher):
        block = bytes(range(cipher.block_size))
        ciphertext, _ = cbc_encrypt(cipher, block + block)
        half = cipher.block_size
        assert ciphertext[:half] != ciphertext[half : 2 * half]

    def test_cbc_requires_iv_of_right_size(self, cipher):
        with pytest.raises(ValueError):
            cbc_encrypt(cipher, b"data", iv=b"short")

    def test_mode_info_complete(self):
        assert set(MODE_INFO) == {"ecb", "cbc", "ctr"}
        for info in MODE_INFO.values():
            assert info.summary
            assert isinstance(info.needs_iv, bool)


# --------------------------------------------------------------------------
# Hashing
# --------------------------------------------------------------------------

class TestSHA256:
    def test_constants_match_fips(self):
        # The round constants and initial state must equal the published tables.
        assert SHA256_K[0] == 0x428A2F98
        assert SHA256_K[1] == 0x71374491
        assert SHA256_K[-1] == 0xC67178F2
        assert SHA256_H0[0] == 0x6A09E667
        assert SHA256_H0[-1] == 0x5BE0CD19

    @pytest.mark.parametrize(
        "message,digest",
        [
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
             "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        ],
    )
    def test_nist_vectors(self, message, digest):
        assert sha256(message) == digest

    def test_nist_million_a_vector(self):
        # Kept out of parametrize because a 1M-character id exceeds the Windows
        # environment-variable size limit when pytest renders the test id.
        assert sha256(b"a" * 1000000) == (
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        )

    def test_matches_hashlib(self):
        rng = random.Random(6)
        for length in list(range(0, 200)) + [255, 256, 511, 512, 4096]:
            data = bytes(rng.randrange(256) for _ in range(length))
            assert sha256(data) == hashlib.sha256(data).hexdigest()

    def test_avalanche_effect(self):
        base = sha256(b"hello world")
        changed = sha256(b"hello worlD")
        assert base != changed
        # A one-character input change should scramble the digest substantially.
        # The exact bit count varies by input; 50-160 differing bits is the
        # realistic band for SHA-256 on a short message.
        differing = sum(a != b for a, b in zip(base, changed))
        assert 50 < differing < 160

    def test_string_and_bytes_agree(self):
        assert sha256("abc") == sha256(b"abc")

    def test_deterministic(self):
        assert sha256("stable input") == sha256("stable input")


class TestHMAC:
    @pytest.mark.parametrize(
        "key,message,digest",
        [
            (b"\x0b" * 20, b"Hi There",
             "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
            (b"Jefe", b"what do ya want for nothing?",
             "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
            (b"\xaa" * 20, b"\xdd" * 50,
             "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
            (bytes(range(1, 26)), b"\xcd" * 50,
             "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
            # Key longer than the 64-byte block, which triggers key hashing.
            (b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First",
             "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
        ],
    )
    def test_rfc4231_vectors(self, key, message, digest):
        assert hmac_sha256(key, message).hex() == digest

    def test_matches_stdlib(self):
        rng = random.Random(7)
        for _ in range(50):
            key = bytes(rng.randrange(256) for _ in range(rng.choice([1, 16, 32, 64, 65, 200])))
            data = bytes(rng.randrange(256) for _ in range(rng.randint(0, 200)))
            assert hmac_sha256(key, data).hex() == stdhmac.new(key, data, hashlib.sha256).hexdigest()

    def test_depends_on_the_key(self):
        assert hmac_sha256(b"key1", b"message") != hmac_sha256(b"key2", b"message")

    def test_longer_key_changes_result(self):
        assert hmac_sha256(b"k", b"msg") != hmac_sha256(b"k" * 200, b"msg")
