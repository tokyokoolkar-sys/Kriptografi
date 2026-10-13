"""Data Encryption Standard (FIPS 46-3), implemented from scratch.

DES is a 16-round Feistel cipher on 64-bit blocks with a 56-bit effective key.
The key schedule drops eight parity bits, leaving 56 bits that are rotated and
split into two 28-bit halves; each round consumes one 8-bit subkey from each half.

This is written for study, not for protecting real data: DES's 56-bit key space
is trivially brute-forceable and the cipher has been deprecated since 2005. The
value here is seeing the Feistel structure, the permutation tables, and the S-box
substitution layer built from scratch.
"""

from __future__ import annotations

from ..modes import BlockCipher

__all__ = ["DES", "des_encrypt_block", "des_decrypt_block", "generate_subkeys"]


# --------------------------------------------------------------------------
# Permutation tables (FIPS 46-3 section 3)
# --------------------------------------------------------------------------

# Initial permutation applied to the plaintext and the ciphertext.
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]

# Final permutation, the inverse of IP.
FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25,
]

# Expansion: 32-bit right half -> 48 bits.
E = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
]

# Permutation applied to the S-box output.
P = [
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25,
]

# Key schedule permutations.
PC1 = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4,
]

PC2 = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

# Shift schedule: how far each half rotates for each of the 16 rounds.
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# The eight S-boxes. Each maps 6 bits to 4 bits: the outer two bits index the
# row, the middle four the column.
SBOXES = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
]


# --------------------------------------------------------------------------
# Bit-level helpers
# --------------------------------------------------------------------------

def _bits(data: bytes) -> list[int]:
    """Expand bytes into a list of bits, most significant bit first."""
    out: list[int] = []
    for byte in data:
        for i in range(7, -1, -1):
            out.append((byte >> i) & 1)
    return out


def _bytes(bits: list[int]) -> bytes:
    """Pack a bit list back into bytes."""
    out = bytearray()
    for i in range(0, len(bits), 8):
        value = 0
        for bit in bits[i : i + 8]:
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)


def _permute(bits: list[int], table: list[int]) -> list[int]:
    """Apply a 1-indexed permutation table to a bit list."""
    return [bits[i - 1] for i in table]


def _rotate_left(bits: list[int], amount: int) -> list[int]:
    """Rotate a bit list left by ``amount`` positions."""
    amount %= len(bits)
    return bits[amount:] + bits[:amount]


# --------------------------------------------------------------------------
# Key schedule
# --------------------------------------------------------------------------

def generate_subkeys(key: bytes) -> list[int]:
    """Expand a 64-bit DES key into sixteen 48-bit round subkeys.

    PC1 drops the eight parity bits and permutes the remaining 56; the halves
    rotate left according to :data:`SHIFTS`; PC2 selects 48 of the 56 bits each
    round, leaving eight bits out that never reach the round function.
    """
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes")

    permuted = _permute(_bits(key), PC1)
    left, right = permuted[:28], permuted[28:]

    subkeys: list[int] = []
    for shift in SHIFTS:
        left = _rotate_left(left, shift)
        right = _rotate_left(right, shift)
        round_key = _permute(left + right, PC2)
        subkeys.append(int("".join(str(b) for b in round_key), 2))

    return subkeys


def _feistel(right: list[int], subkey: int) -> list[int]:
    """The DES round function ``f``.

    Expand the 32-bit half to 48 bits, XOR the subkey in, run the eight S-boxes,
    then permute the 32-bit result. The S-boxes supply the cipher's only
    nonlinearity, which is what makes DES resistant to differential and linear
    cryptanalysis.
    """
    expanded = _permute(right, E)
    xored = [b ^ ((subkey >> (47 - i)) & 1) for i, b in enumerate(expanded)]

    sbox_output: list[int] = []
    for i in range(8):
        chunk = xored[i * 6 : i * 6 + 6]
        row = (chunk[0] << 1) | chunk[5]
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        sbox_output.extend([(SBOXES[i][row][col] >> 3) & 1, (SBOXES[i][row][col] >> 2) & 1,
                            (SBOXES[i][row][col] >> 1) & 1, SBOXES[i][row][col] & 1])

    return _permute(sbox_output, P)


def _crypt(block: bytes, subkeys: list[int], encrypt: bool) -> bytes:
    """Run the 16-round Feistel network.

    Feistel structure is symmetric: the same function serves both directions,
    so decryption simply feeds the round keys in reverse order.
    """
    if len(block) != 8:
        raise ValueError("DES block must be exactly 8 bytes")

    bits = _permute(_bits(block), IP)
    left, right = bits[:32], bits[32:]

    order = subkeys if encrypt else subkeys[::-1]
    for subkey in order:
        left, right = right, [l ^ r for l, r in zip(left, _feistel(right, subkey))]

    # Final swap, then the inverse of IP.
    return _bytes(_permute(right + left, FP))


def des_encrypt_block(block: bytes, key: bytes) -> bytes:
    """Encrypt one 64-bit DES block with a 64-bit key."""
    return _crypt(block, generate_subkeys(key), encrypt=True)


def des_decrypt_block(block: bytes, key: bytes) -> bytes:
    """Decrypt one 64-bit DES block."""
    return _crypt(block, generate_subkeys(key), encrypt=False)


class DES(BlockCipher):
    """DES as a :class:`~kriptografi.modes.BlockCipher` for use with the modes.

    >>> cipher = DES(bytes.fromhex("133457799BBCDFF1"))
    >>> cipher.encrypt_block(bytes.fromhex("0123456789ABCDEF")).hex().upper()
    '85E813540F0AB405'
    """

    block_size = 8
    key_size = 8

    def __init__(self, key: bytes):
        if len(key) != 8:
            raise ValueError("DES key must be exactly 8 bytes")
        self.key = key
        self.subkeys = generate_subkeys(key)

    def encrypt_block(self, block: bytes) -> bytes:
        return _crypt(self._check(block), self.subkeys, encrypt=True)

    def decrypt_block(self, block: bytes) -> bytes:
        return _crypt(self._check(block), self.subkeys, encrypt=False)