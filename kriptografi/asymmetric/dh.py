"""Diffie-Hellman key exchange and ElGamal public-key encryption.

Both schemes work in the group of powers of a generator ``g`` modulo a prime
``p``, relying on the difficulty of the discrete logarithm:

    Diffie-Hellman    Alice sends g^a, Bob sends g^b, both derive g^(a*b)
    ElGamal           encrypt with g^k and m * g^(a*k); decrypt cancels the secret

Diffie-Hellman is a key agreement protocol, not encryption -- it establishes a
shared secret that still needs a key derivation step before use. ElGamal turns
the same structure into actual message encryption.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from ..mathcore import generate_prime, mod_inverse, pow_mod

__all__ = [
    "DHParameters",
    "DHParty",
    "generate_parameters",
    "generate_keypair",
    "compute_shared_secret",
    "ElGamalKeyPair",
    "elgamal_keypair",
    "elgamal_encrypt",
    "elgamal_decrypt",
    "encode_message",
    "decode_message",
]


@dataclass(frozen=True)
class DHParameters:
    """Public group parameters agreed before the exchange begins."""

    p: int
    g: int


@dataclass(frozen=True)
class DHParty:
    """One participant's DH state."""

    parameters: DHParameters
    private: int
    public: int

    def derive(self, other_public: int) -> int:
        """Shared secret ``other_public ** private mod p``."""
        return compute_shared_secret(self.parameters, self.private, other_public)


def generate_parameters(bits: int = 512) -> DHParameters:
    """Generate safe DH parameters: a prime ``p`` and a generator ``g``.

    A safe prime ``p = 2q + 1`` makes the subgroup of quadratic residues have
    prime order ``q``, which rules out the small-subgroup attacks that plague
    naive parameter choice. ``g = 2`` is a common generator for these groups.
    """
    if bits < 128:
        raise ValueError("use at least 128 bits; 2048 is the practical floor today")

    while True:
        q = generate_prime(bits - 1)
        p = 2 * q + 1
        from ..mathcore import is_prime

        if is_prime(p):
            return DHParameters(p, 2)


def generate_keypair(parameters: DHParameters) -> DHParty:
    """Pick a private exponent in ``[2, q-2]`` and publish ``g^a mod p``.

    The exponent is capped at ``q - 2`` so it always lands in the prime-order
    subgroup rather than the order-2 part of the group.
    """
    q = (parameters.p - 1) // 2
    private = secrets.randbelow(q - 3) + 2
    return DHParty(parameters, private, pow_mod(parameters.g, private, parameters.p))


def compute_shared_secret(parameters: DHParameters, private: int, other_public: int) -> int:
    """Compute ``other_public ** private mod p``.

    Validates that the peer's public value is in range, which rejects the
    degenerate values 0 and 1 that an attacker can otherwise force.
    """
    if not 2 <= other_public < parameters.p - 1:
        raise ValueError(
            "peer public value must be in [2, p-2]; rejecting the trivial "
            "subgroup values 0, 1, and p-1"
        )
    return pow_mod(other_public, private, parameters.p)


# --------------------------------------------------------------------------
# ElGamal
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ElGamalKeyPair:
    """An ElGamal key pair: ``(y = g^x mod p, x)``."""

    parameters: DHParameters
    y: int
    x: int


def elgamal_keypair(parameters: DHParameters) -> ElGamalKeyPair:
    """Generate an ElGamal key pair in the given group."""
    q = (parameters.p - 1) // 2
    x = secrets.randbelow(q - 3) + 2
    return ElGamalKeyPair(parameters, pow_mod(parameters.g, x, parameters.p), x)


def _random_below(bound: int) -> int:
    """Uniform random integer in ``[2, bound - 2]``."""
    return secrets.randbelow(bound - 4) + 2


def elgamal_encrypt(message_int: int, key: ElGamalKeyPair) -> tuple[int, int]:
    """Encrypt an integer as ``(c1, c2) = (g^k mod p, m * y^k mod p)``.

    ``k`` is chosen fresh per message. Reusing it across two messages leaks
    ``m1 / m2``, which is the classic reason ElGamal must use a fresh ephemeral
    key every time.
    """
    if not 0 < message_int < key.parameters.p:
        raise ValueError("message integer must be in (0, p)")
    if not 0 < key.y < key.parameters.p:
        raise ValueError("invalid public key")

    k = _random_below(key.parameters.p)
    c1 = pow_mod(key.parameters.g, k, key.parameters.p)
    c2 = message_int * pow_mod(key.y, k, key.parameters.p) % key.parameters.p

    return c1, c2


def elgamal_decrypt(ciphertext: tuple[int, int], key: ElGamalKeyPair) -> int:
    """Recover the integer: ``m = c2 * (c1^x)^-1 mod p``.

    Uses the modular inverse from the extended Euclidean algorithm, which is why
    this works even though ``c1^x`` is not a power of two or otherwise special.
    """
    c1, c2 = ciphertext
    shared = pow_mod(c1, key.x, key.parameters.p)
    return c2 * mod_inverse(shared, key.parameters.p) % key.parameters.p


# --------------------------------------------------------------------------
# Message encoding
# --------------------------------------------------------------------------

def _block_chars(p: int, alphabet_size: int = 37) -> int:
    """Largest ``k`` with ``alphabet_size**k <= p``.

    This is the per-block ceiling. Because blocks are recombined with
    ``alphabet_size**k`` as the base, a long message can still overflow ``p``, so
    :func:`encode_message` shrinks ``k`` further until the whole value fits.
    """
    k = 0
    value = 1
    while value * alphabet_size <= p:
        value *= alphabet_size
        k += 1
    return max(1, k)


def encode_message(message: str, p: int, alphabet_size: int = 37) -> tuple[list[int], list[int]]:
    """Pack text into a list of integers, each guaranteed to fit below ``p``.

    Returns ``(values, lengths)``: one integer per block plus that block's exact
    character count. The counts are not optional -- unpacking an integer needs to
    know how many base-37 digits to read back, and a block shorter than the
    maximum width would otherwise decode as a run of leading 'A's, since 'A' is
    index 0. Every block width is recorded so the message survives exactly.

    Blocks are shrunk from the widest that fits until every one is below ``p``,
    so messages of any length encode safely.
    """
    from ..alphabet import SYMBOL_TO_INDEX, normalize

    text = normalize(message)

    for block_chars in range(_block_chars(p, alphabet_size), 0, -1):
        blocks = [text[i : i + block_chars] for i in range(0, len(text), block_chars)]
        values = [_pack(block, alphabet_size, SYMBOL_TO_INDEX) for block in blocks]

        if all(value < p for value in values):
            return values, [len(block) for block in blocks]

    raise ValueError(f"cannot encode the message below a {p.bit_length()}-bit modulus")


def _pack(block: str, base: int, values: dict[str, int]) -> int:
    """Pack one block of characters into an integer of the given base."""
    out = 0
    for ch in block:
        out = out * base + values[ch]
    return out


def decode_message(values: list[int], lengths: list[int],
                   alphabet_size: int = 37) -> str:
    """Inverse of :func:`encode_message`, given each block's ``lengths``.

    Without those lengths the tail of every short block would be indistinguishable
    from genuine 'A' characters.
    """
    from ..alphabet import ALPHABET

    out: list[str] = []
    for value, length in zip(values, lengths):
        chars: list[str] = []
        for _ in range(length):
            value, rem = divmod(value, alphabet_size)
            chars.append(ALPHABET[rem])
        out.append("".join(reversed(chars)))

    return "".join(out)