"""SHA-256 (FIPS 180-4) and HMAC (RFC 2104), implemented from scratch.

SHA-256 is a Merkle-Damgard construction: the message is padded to a multiple of
512 bits, split into 64-byte blocks, and each block is run through a compression
function built from 32-bit rotate/xor/add operations. There is no key, so it is
a hash function rather than a cipher.

HMAC layers a keyed hash on top: ``H((K ^ opad) || H((K ^ ipad) || m))``, which
turns a bare hash into a keyed message authentication code.
"""

from __future__ import annotations

import struct
from math import isqrt

__all__ = [
    "sha256",
    "sha256_bytes",
    "hmac_sha256",
    "SHA256_K",
    "SHA256_H0",
]


# --------------------------------------------------------------------------
# Round constants: the first 32 bits of the fractional parts of the cube roots
# of the first 64 primes.
# --------------------------------------------------------------------------

def _icbrt(n: int) -> int:
    """Exact integer cube root of a non-negative integer."""
    if n == 0:
        return 0
    x = 1 << ((n.bit_length() + 2) // 3 + 1)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            return x
        x = y


def _build_constants() -> tuple[list[int], list[int]]:
    """Derive the round constants and initial hash values from first principles.

    Both come from the same idea: take ``frac(cbrt(p))`` for the round constants
    and ``frac(sqrt(p))`` for the initial state, where ``p`` runs over the first
    primes. Fractional parts are taken with exact integer arithmetic so the
    result is bit-for-bit reproducible with no floating point involved.
    """

    def primes(count: int) -> list[int]:
        found: list[int] = []
        candidate = 2
        while len(found) < count:
            if all(candidate % p for p in found):
                found.append(candidate)
            candidate += 1
        return found

    def frac_cube_root(p: int) -> int:
        # Take floor(cbrt(p) * 2**64) exactly, then keep the fractional part and
        # cut it down to the top 32 bits. Working in integers avoids the rounding
        # error a float-based cbrt would introduce.
        root = _icbrt(p << 192)
        return (root & ((1 << 64) - 1)) >> 32

    def frac_square_root(p: int) -> int:
        # Same approach for frac(sqrt(p)), where isqrt already gives an exact root.
        root = isqrt(p << 128)
        return (root & ((1 << 64) - 1)) >> 32

    ps = primes(64)
    k = [frac_cube_root(p) for p in ps]
    h0 = [frac_square_root(p) for p in ps[:8]]

    return k, h0


SHA256_K, SHA256_H0 = _build_constants()


# --------------------------------------------------------------------------
# Core operations
# --------------------------------------------------------------------------

_MASK = 0xFFFFFFFF


def _rotr(x: int, n: int) -> int:
    """Rotate a 32-bit word right by ``n`` bits."""
    x &= _MASK
    return ((x >> n) | (x << (32 - n))) & _MASK


def _compress(state: list[int], block: bytes) -> list[int]:
    """The SHA-256 compression function over one 512-bit block.

    Eight working variables are initialised from the incoming state, mixed
    through 64 rounds, then added back into the state. Adding the original state
    back at the end is what makes the whole thing a Merkle-Damgard chain, so a
    one-bit change early in the message cannot be localised.
    """
    if len(block) != 64:
        raise ValueError("SHA-256 block must be exactly 64 bytes")

    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & _MASK)

    a, b, c, d, e, f, g, h = state

    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) & _MASK
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & _MASK

        h, g, f, e = g, f, e, (d + temp1) & _MASK
        d, c, b, a = c, b, a, (temp1 + temp2) & _MASK

    return [(x + y) & _MASK for x, y in zip(state, [a, b, c, d, e, f, g, h])]


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> bytes:
    """Return the 32-byte SHA-256 digest of ``data``.

    >>> sha256_bytes(b"abc").hex()
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    """
    # Padding per FIPS 180-4 section 5.1.1: append a single 0x80, then zeros until
    # the length is 56 bytes short of a 64-byte multiple, then the 64-bit
    # big-endian message length in bits. The 56 comes from the 8-byte length
    # field that must still fit.
    bit_length = len(data) * 8
    padded = data + b"\x80"
    padded += bytes((56 - len(padded) % 64) % 64)
    padded += struct.pack(">Q", bit_length & 0xFFFFFFFFFFFFFFFF)

    state = list(SHA256_H0)
    for i in range(0, len(padded), 64):
        state = _compress(state, padded[i : i + 64])

    return struct.pack(">8I", *state)


def sha256(message: str | bytes) -> str:
    """SHA-256 of a string or bytes, returned as lowercase hex.

    Strings are encoded as UTF-8, so hashing is deterministic across platforms.
    """
    data = message.encode("utf-8") if isinstance(message, str) else message
    return sha256_bytes(data).hex()


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA256 (RFC 2104).

    Keys longer than the 64-byte block size are hashed first, and shorter keys are
    zero-padded. The two nested hashes with XOR-ed pads are what give HMAC its
    security properties; a plain ``H(key || message)`` would be breakable by
    length extension.
    """
    block_size = 64

    if len(key) > block_size:
        key = sha256_bytes(key)
    key = key.ljust(block_size, b"\x00")

    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)

    inner = sha256_bytes(ipad + message)
    return sha256_bytes(opad + inner)


def hmac_sha256_hex(key: bytes, message: bytes) -> str:
    """:func:`hmac_sha256` returned as lowercase hex."""
    return hmac_sha256(key, message).hex()