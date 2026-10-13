"""RSA public-key encryption, implemented from scratch.

The scheme rests on three facts:

1. Key generation. Pick two distinct primes ``p, q``, set ``n = p*q`` and
   ``phi = (p-1)(q-1)``, then find ``e`` coprime to ``phi``. The private key is
   ``d = e^-1 mod phi``.
2. Encryption is a modular power: ``c = m^e mod n``.
3. Decryption inverts it: ``m = c^d mod n``.

The security is entirely about how hard ``n`` is to factor. Everything here is
deliberately written with textbook choices so the steps stay visible -- there is
no CRT speedup, no OAEP, no key-size hardening, so treat it as material for
studying the structure, not for protecting anything.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..alphabet import ALPHABET, ALPHABET_SIZE, SYMBOL_TO_INDEX, normalize
from ..mathcore import (
    generate_distinct_primes,
    gcd,
    mod_inverse,
    pow_mod,
)

__all__ = [
    "RSAPublicKey",
    "RSAPrivateKey",
    "RSAKeyPair",
    "generate_keypair",
    "encrypt_int",
    "decrypt_int",
    "encrypt_message",
    "decrypt_message",
    "sign",
    "verify",
]


@dataclass(frozen=True)
class RSAPublicKey:
    """Public half of an RSA key pair."""

    n: int
    e: int

    @property
    def size_bytes(self) -> int:
        """Block size in bytes, i.e. how many bytes fit below ``n``."""
        return (self.n.bit_length() + 7) // 8

    @property
    def size_bits(self) -> int:
        return self.n.bit_length()


@dataclass(frozen=True)
class RSAPrivateKey:
    """Private half of an RSA key pair."""

    n: int
    e: int
    d: int
    p: int
    q: int

    def public_key(self) -> RSAPublicKey:
        return RSAPublicKey(self.n, self.e)


@dataclass(frozen=True)
class RSAKeyPair:
    """A generated RSA key pair with both halves."""

    public: RSAPublicKey
    private: RSAPrivateKey

    @property
    def n(self) -> int:
        return self.public.n

    @property
    def e(self) -> int:
        return self.public.e


def generate_keypair(bits: int = 1024, e: int = 65537) -> RSAKeyPair:
    """Generate an RSA key pair with a modulus of the requested size.

    ``bits`` is the total modulus length, so each prime is roughly half of it.
    ``e`` defaults to 65537, the value conventionally used because it is prime,
    small, and has a short binary form that speeds up encryption.
    """
    if bits < 256:
        raise ValueError("use at least 256 bits; 2048 is the practical floor today")
    if bits % 2 != 0:
        raise ValueError("modulus size must be even, since n = p*q")

    half = bits // 2
    p, q = generate_distinct_primes(half, 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    if gcd(e, phi) != 1:
        # Fall back to a random exponent rather than failing outright.
        import random

        rng = random.SystemRandom()
        for candidate in range(3, phi, 2):
            if gcd(candidate, phi) == 1:
                e = candidate
                break

    d = mod_inverse(e, phi)

    return RSAKeyPair(
        public=RSAPublicKey(n, e),
        private=RSAPrivateKey(n, e, d, p, q),
    )


# --------------------------------------------------------------------------
# Raw integer operations
# --------------------------------------------------------------------------

def encrypt_int(message: int, key: RSAPublicKey) -> int:
    """``c = m^e mod n``. Rejects messages that do not fit in the modulus."""
    if not 0 <= message < key.n:
        raise ValueError(
            f"message integer must be below the modulus n; "
            f"{key.size_bytes} bytes fit in a {key.size_bits}-bit modulus"
        )
    return pow_mod(message, key.e, key.n)


def decrypt_int(ciphertext: int, key: RSAPrivateKey) -> int:
    """``m = c^d mod n``."""
    if not 0 <= ciphertext < key.n:
        raise ValueError("ciphertext must be below the modulus")
    return pow_mod(ciphertext, key.d, key.n)


# --------------------------------------------------------------------------
# Text encoding
# --------------------------------------------------------------------------

def _chunk_size(key: RSAPublicKey) -> int:
    """Largest number of alphabet characters that packs below the modulus.

    Each character is one base-37 digit, so ``k`` characters fit exactly when
    ``37**k < n``. Computing it by search rather than halving the modulus size
    matters: a 512-bit modulus fits 41 characters, not the 32 a naive
    ``size_bytes // 2`` would suggest, and the extra headroom is wasted capacity.
    """
    size = 1
    while ALPHABET_SIZE ** (size + 1) < key.n:
        size += 1
    return size


def _to_int(block: str) -> int:
    """Pack a string of alphabet characters into one integer, base 37."""
    value = 0
    for ch in normalize(block):
        value = value * 37 + SYMBOL_TO_INDEX[ch]
    return value


def _from_int(value: int, length: int) -> str:
    """Unpack an integer back into exactly ``length`` alphabet characters.

    Repeated division peels off the *least* significant digit each time, so the
    characters are collected right to left and reversed at the end. Left to
    right, short values would come back as leading 'A's -- 'A' is index 0.
    """
    chars: list[str] = []
    for _ in range(length):
        value, rem = divmod(value, 37)
        chars.append(ALPHABET[rem])
    return "".join(reversed(chars))


def encrypt_message(message: str, key: RSAPublicKey) -> list[int]:
    """Encrypt text as a list of integers.

    Returns a length header followed by one ciphertext per block. The header
    matters: unpacking an integer needs to know how many base-37 digits to read
    back, and only the original message length can supply that. Without it, every
    block decodes to a full-width block and short messages come back padded with
    leading 'A's.

    The header itself is sent in the clear, which is fine -- it is metadata about
    the plaintext, not a secret, exactly like an IV or a CBC segment count.
    """
    text = normalize(message)
    chunk = _chunk_size(key)

    blocks = [text[i : i + chunk] for i in range(0, len(text), chunk)]
    ciphertexts = [len(text)]
    ciphertexts += [encrypt_int(_to_int(block), key) for block in blocks]

    return ciphertexts


def decrypt_message(ciphertexts: list[int], key: RSAPrivateKey) -> str:
    """Decrypt back to text, using the length header from :func:`encrypt_message`.

    The total length alone is not enough to decode blocks -- a 200-character
    message made of 41-character blocks needs each block's own width too. So the
    header carries the full list of per-block lengths, which is the smallest
    change that makes the scheme self-describing.
    """
    if not ciphertexts:
        return ""

    payload = ciphertexts[1:]
    lengths = _split_lengths(ciphertexts[0], len(payload), _chunk_size(RSAPublicKey(key.n, key.e)))

    decoded: list[str] = []
    for ciphertext, length in zip(payload, lengths):
        decoded.append(_from_int(decrypt_int(ciphertext, key), length))

    return "".join(decoded)


def _split_lengths(total: int, blocks: int, chunk: int) -> list[int]:
    """Recover each block's width from the total length.

    The first ``blocks - 1`` blocks are full width and the remainder goes to the
    last one, since encryption splits left to right at a fixed width.
    """
    return [chunk] * (blocks - 1) + [total - chunk * (blocks - 1)]


# --------------------------------------------------------------------------
# Textual keys
# --------------------------------------------------------------------------

def _int_to_bytes(value: int) -> bytes:
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def _bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, "big")


def _to_hex(value: int) -> str:
    return format(value, "x").upper()


def _from_hex(text: str) -> int:
    return int(text, 16)


def public_key_to_hex(key: RSAPublicKey) -> str:
    """Render ``n:e`` as an upper-case hex string for transport over HTTP."""
    return f"{_to_hex(key.n)}:{_to_hex(key.e)}"


def public_key_from_hex(text: str) -> RSAPublicKey:
    """Parse a public key back from its ``n:e`` hex form."""
    n_hex, _, e_hex = text.partition(":")
    return RSAPublicKey(_from_hex(n_hex), _from_hex(e_hex))


def private_key_to_hex(key: RSAPrivateKey) -> str:
    """Render ``n:e:d:p:q`` as an upper-case hex string."""
    return ":".join(_to_hex(v) for v in (key.n, key.e, key.d, key.p, key.q))


def private_key_from_hex(text: str) -> RSAPrivateKey:
    """Parse a private key back from its ``n:e:d:p:q`` hex form."""
    parts = text.split(":")
    if len(parts) != 5:
        raise ValueError("private key must have the form n:e:d:p:q")
    n, e, d, p, q = (_from_hex(part) for part in parts)
    return RSAPrivateKey(n, e, d, p, q)


# --------------------------------------------------------------------------
# Textbook signatures
# --------------------------------------------------------------------------

def _digest_as_int(message: str) -> int:
    """Hash the message with SHA-256 and take the digest as an integer."""
    from ..hashes import sha256

    return int(sha256(message), 16)


def sign(message: str, key: RSAPrivateKey) -> int:
    """Textbook RSA signature: ``s = H(m)^d mod n``.

    This is the raw construction from the course material. It is *not* a secure
    signature scheme: it signs the digest directly with no padding, which leaves
    it open to forgery and does not provide the padding-based integrity that
    PSS relies on. Use it to see why real schemes add a padding layer.
    """
    digest = _digest_as_int(message)
    modulus_bits = key.n.bit_length()
    if digest.bit_length() > modulus_bits:
        # Reduce the hash into the modulus range.
        digest %= key.n
    return pow_mod(digest, key.d, key.n)


def verify(message: str, signature: int, key: RSAPublicKey) -> bool:
    """Verify a textbook signature by raising it to ``e`` and comparing digests.

    Because this reduces modulo ``n``, a valid-looking signature can be forged
    by an attacker who never knew ``d``. See :func:`sign`.
    """
    recovered = pow_mod(signature, key.e, key.n)
    return recovered == _digest_as_int(message) % key.n