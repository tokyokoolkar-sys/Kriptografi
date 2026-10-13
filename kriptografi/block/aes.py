"""Advanced Encryption Standard (FIPS 197), implemented from scratch.

AES is a substitution-permutation network, not a Feistel cipher. The 128-bit
block is held as a 4x4 column-major matrix of bytes; each round applies
SubBytes, ShiftRows, MixColumns, and AddRoundKey in that order, and the final
round omits MixColumns.

Key sizes are 128, 192, or 256 bits, giving 10, 12, or 14 rounds respectively.
"""

from __future__ import annotations

from ..modes import BlockCipher

__all__ = ["AES", "aes_encrypt_block", "aes_decrypt_block", "SBOX", "INV_SBOX"]


# --------------------------------------------------------------------------
# Lookup tables
# --------------------------------------------------------------------------

def _build_sbox() -> tuple[list[int], list[int]]:
    """Generate the AES S-box from its algebraic definition.

    The S-box is the composition of the multiplicative inverse in GF(2^8) with an
    affine transformation over GF(2). Building it from the definition rather than
    pasting the table means every entry is provably consistent with FIPS 197
    section 5.1.1, and it doubles as a check that the field arithmetic is right.

    Inverses are found by brute-force multiplication in GF(2^8), which is fast
    enough for a table this small and happens exactly once at import.
    """
    sbox = [0] * 256

    for x in range(256):
        inverse = 0
        if x != 0:
            for candidate in range(1, 256):
                if _gf_mul(x, candidate) == 1:
                    inverse = candidate
                    break

        y = inverse
        for k in range(1, 5):
            # y = y XOR rotl(inverse, k), for k = 1, 2, 3, 4, folding at 8 bits.
            y ^= ((inverse << k) | (inverse >> (8 - k))) & 0xFF

        sbox[x] = y ^ 0x63  # the constant 0x63

    inv_sbox = [0] * 256
    for i, value in enumerate(sbox):
        inv_sbox[value] = i

    return sbox, inv_sbox


def _gf_mul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) modulo the AES polynomial x^8+x^4+x^3+x+1."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high_bit = a & 0x80
        a = (a << 1) & 0xFF
        if high_bit:
            a ^= 0x1B
        b >>= 1
    return result


SBOX, INV_SBOX = _build_sbox()


# Round constants for the AddRoundKey step: powers of x in GF(2^8).
RCON = [0x01]
for _ in range(1, 14):
    RCON.append(_gf_mul(RCON[-1], 2))


# --------------------------------------------------------------------------
# Byte and state helpers
# --------------------------------------------------------------------------

def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _sub_bytes(state: list[list[int]], box: list[int]) -> list[list[int]]:
    """SubBytes: substitute every byte through the S-box."""
    return [[box[byte] for byte in row] for row in state]


def _shift_rows(state: list[list[int]]) -> list[list[int]]:
    """ShiftRows: rotate row ``r`` left by ``r`` positions.

    AES stores the state column-major, so a left row rotation moves byte
    ``(r, c)`` to ``(r, c + r)``. This is the step that breaks a cipher's
    symmetry across the four rounds.
    """
    return [
        [state[r][(c + r) % 4] for c in range(4)]
        for r in range(4)
    ]


def _inv_shift_rows(state: list[list[int]]) -> list[list[int]]:
    """Inverse ShiftRows: rotate row ``r`` right by ``r``."""
    return [
        [state[r][(c - r) % 4] for c in range(4)]
        for r in range(4)
    ]


def _mix_columns(state: list[list[int]]) -> list[list[int]]:
    """MixColumns: multiply each column by the fixed MDS matrix.

    Each column is an independent 4-byte vector multiplied by::

        [2 3 1 1]      [14 11 13  9]
        [1 2 3 1]  *   [11 14 10 15]
        [1 1 2 3]      [ 9 15  6  3]
        [3 1 1 2]      [13  9 15  7]

    with all arithmetic in GF(2^8). This is the only place AES introduces
    dependence between the bytes of a column.
    """
    out = [[0] * 4 for _ in range(4)]
    for c in range(4):
        a0, a1, a2, a3 = (state[r][c] for r in range(4))
        out[0][c] = _xtime(a0) ^ _xtime(a1) ^ a1 ^ a2 ^ a3
        out[1][c] = a0 ^ _xtime(a1) ^ _xtime(a2) ^ a2 ^ a3
        out[2][c] = a0 ^ a1 ^ _xtime(a2) ^ _xtime(a3) ^ a3
        out[3][c] = _xtime(a0) ^ a0 ^ a1 ^ a2 ^ _xtime(a3)
    return out


def _inv_mix_columns(state: list[list[int]]) -> list[list[int]]:
    """Inverse MixColumns.

    The inverse MDS matrix is::

        [0e 0b 0d 09]      [14 11 13  9]
        [09 0e 0b 0d]  *   [11 14 10 15]
        [0d 09 0e 0b]      [ 9 15  6  3]
        [0b 0d 09 0e]      [13  9 15  7]

    Multiplying the two matrices gives the identity over GF(2^8), which is the
    property the tests assert.
    """
    out = [[0] * 4 for _ in range(4)]
    for c in range(4):
        a0, a1, a2, a3 = (state[r][c] for r in range(4))
        out[0][c] = (_gf_mul(0x0E, a0) ^ _gf_mul(0x0B, a1) ^ _gf_mul(0x0D, a2) ^ _gf_mul(0x09, a3))
        out[1][c] = (_gf_mul(0x09, a0) ^ _gf_mul(0x0E, a1) ^ _gf_mul(0x0B, a2) ^ _gf_mul(0x0D, a3))
        out[2][c] = (_gf_mul(0x0D, a0) ^ _gf_mul(0x09, a1) ^ _gf_mul(0x0E, a2) ^ _gf_mul(0x0B, a3))
        out[3][c] = (_gf_mul(0x0B, a0) ^ _gf_mul(0x0D, a1) ^ _gf_mul(0x09, a2) ^ _gf_mul(0x0E, a3))
    return out


def _xtime(byte: int) -> int:
    """Multiply a byte by x (i.e. by 2) in GF(2^8)."""
    doubled = (byte << 1) & 0xFF
    return doubled ^ 0x1B if byte & 0x80 else doubled


def _to_state(block: bytes) -> list[list[int]]:
    """Unpack 16 bytes into the column-major 4x4 state matrix.

    ``state[r][c] = block[4*c + r]``, so the block is filled down columns.
    """
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def _from_state(state: list[list[int]]) -> bytes:
    """Pack the state matrix back into 16 bytes."""
    return bytes(state[r][c] for c in range(4) for r in range(4))


# --------------------------------------------------------------------------
# Key schedule
# --------------------------------------------------------------------------

def _expand_key(key: bytes) -> list[bytes]:
    """Expand an AES key into 4*(rounds+1) round keys of 16 bytes each.

    The first round key is the key itself. Each subsequent word is
    ``w[i] = w[i-Nk] XOR w[i-1]``, with every fourth word first passing through
    SubWord (the S-box) and a round constant. ``Nk`` is 4, 6, or 8 words.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")

    nk = len(key) // 4
    rounds = nk + 6
    words = [list(key[4 * i : 4 * i + 4]) for i in range(nk)]

    for i in range(nk, 4 * (rounds + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]  # RotWord
            temp = [SBOX[b] for b in temp]  # SubWord
            temp[0] ^= RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])

    return [bytes(b for word in words[4 * r : 4 * r + 4] for b in word) for r in range(rounds + 1)]


def _add_round_key(state: list[list[int]], round_key: bytes) -> list[list[int]]:
    """XOR the round key into the state."""
    return [[state[r][c] ^ round_key[r + 4 * c] for c in range(4)] for r in range(4)]


# --------------------------------------------------------------------------
# Core cipher
# --------------------------------------------------------------------------

def _encrypt_block(block: bytes, round_keys: list[bytes], rounds: int) -> bytes:
    """Run the standard AES forward transform."""
    state = _add_round_key(_to_state(block), round_keys[0])

    for r in range(1, rounds):
        state = _mix_columns(_shift_rows(_sub_bytes(state, SBOX)))
        state = _add_round_key(state, round_keys[r])

    # Final round: no MixColumns, so the cipher stays invertible.
    state = _add_round_key(_shift_rows(_sub_bytes(state, SBOX)), round_keys[rounds])

    return _from_state(state)


def _decrypt_block(block: bytes, round_keys: list[bytes], rounds: int) -> bytes:
    """Run the equivalent inverse cipher.

    The round keys are applied in reverse order, and the three non-linear steps
    are undone in the opposite order to how encryption applies them.
    """
    state = _add_round_key(_to_state(block), round_keys[rounds])

    for r in range(rounds - 1, 0, -1):
        state = _inv_mix_columns(_add_round_key(_inv_shift_rows(_sub_bytes(state, INV_SBOX)), round_keys[r]))

    state = _inv_shift_rows(_sub_bytes(state, INV_SBOX))
    state = _add_round_key(state, round_keys[0])

    return _from_state(state)


def aes_encrypt_block(block: bytes, key: bytes) -> bytes:
    """Encrypt one 16-byte AES block."""
    rounds = len(key) // 4 + 6
    return _encrypt_block(block, _expand_key(key), rounds)


def aes_decrypt_block(block: bytes, key: bytes) -> bytes:
    """Decrypt one 16-byte AES block."""
    rounds = len(key) // 4 + 6
    return _decrypt_block(block, _expand_key(key), rounds)


class AES(BlockCipher):
    """AES as a :class:`~kriptografi.modes.BlockCipher`.

    >>> cipher = AES(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    >>> cipher.encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff")).hex().upper()
    '69C4E0D86A7B0430D8CDB78070B4C55A'
    """

    block_size = 16

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24, or 32 bytes")
        self.key = key
        self.rounds = len(key) // 4 + 6
        self.round_keys = _expand_key(key)

    def encrypt_block(self, block: bytes) -> bytes:
        return _encrypt_block(self._check(block), self.round_keys, self.rounds)

    def decrypt_block(self, block: bytes) -> bytes:
        return _decrypt_block(self._check(block), self.round_keys, self.rounds)