"""Classical polyalphabetic and substitution ciphers over the 37-symbol alphabet.

All of these work modulo 37. Because 37 is prime, every non-zero affine
coefficient has an inverse, and because the extended Euclidean algorithm gives
us that inverse directly, decryption is exact with no brute-force search.

Shared convention: keys for the polyalphabetic ciphers are words drawn from the
same 37-character alphabet, and shift values are integers reduced mod 37.
"""

from __future__ import annotations

from ..alphabet import ALPHABET_SIZE, from_numbers, normalize, to_numbers
from ..mathcore import gcd, mod_inverse

__all__ = [
    "caesar",
    "vigenere",
    "beaufort",
    "autokey",
    "affine_encrypt",
    "affine_decrypt",
    "generate_affine_key",
    "valid_affine_keys",
    "playfair_encrypt",
    "playfair_decrypt",
    "hill_encrypt",
    "hill_decrypt",
]

MOD = ALPHABET_SIZE  # 37


# --------------------------------------------------------------------------
# Caesar cipher
# --------------------------------------------------------------------------

def caesar(text: str, shift: int, decrypt: bool = False) -> str:
    """Caesar cipher: shift every letter by ``shift`` places mod 37.

    Decryption is the same operation with the negated shift, so one code path
    serves both directions.
    """
    offset = -shift if decrypt else shift
    return from_numbers([(v + offset) % MOD for v in to_numbers(text)])


# --------------------------------------------------------------------------
# Vigenere
# --------------------------------------------------------------------------

def _key_stream(text_values: list[int], key_values: list[int]) -> list[int]:
    """Repeat the key to the length of the text, preserving key alignment."""
    if not key_values:
        raise ValueError("key must not be empty")
    return [key_values[i % len(key_values)] for i in range(len(text_values))]


def vigenere(text: str, key: str, decrypt: bool = False) -> str:
    """Vigenere cipher: ``c = (p + k) mod 37``, decrypt with ``c = (p - k) mod 37``.

    The key repeats over the length of the message, which is exactly why
    Vigenere resists frequency analysis: each position uses a different shift.
    """
    text_values = to_numbers(text)
    key_values = to_numbers(key)
    stream = _key_stream(text_values, key_values)

    if decrypt:
        return from_numbers([(p - k) % MOD for p, k in zip(text_values, stream)])
    return from_numbers([(p + k) % MOD for p, k in zip(text_values, stream)])


def beaufort(text: str, key: str, decrypt: bool = False) -> str:
    """Beaufort cipher: ``c = (k - p) mod 37``, and it is its own inverse.

    Substituting ``p = k - c`` gives ``c = k - p`` again, so encryption and
    decryption run identical code with no sign flip.
    """
    text_values = to_numbers(text)
    key_values = to_numbers(key)
    stream = _key_stream(text_values, key_values)

    return from_numbers([(k - p) % MOD for p, k in zip(text_values, stream)])


def autokey(text: str, key: str, decrypt: bool = False) -> str:
    """Autokey cipher: the key is extended by the message itself.

    Encrypting uses ``c_i = (p_i + k_i) mod n`` where the keystream is the primer
    followed by the plaintext. Decrypting uses ``p_i = (c_i - k_i) mod n`` and the
    keystream is the primer followed by the ciphertext -- recovering each
    plaintext character as we go is what lets the keystream be rebuilt.
    """
    text_values = to_numbers(text)
    primer = to_numbers(key)
    if not primer:
        raise ValueError("key must not be empty")

    if decrypt:
        stream = list(primer)
        out: list[int] = []
        for i, c in enumerate(text_values):
            p = (c - stream[i]) % MOD
            out.append(p)
            # The keystream beyond the primer is the plaintext itself, so feed the
            # character we just recovered back into the stream.
            stream.append(p)
        return from_numbers(out)

    stream = list(primer) + text_values
    return from_numbers([(p + stream[i]) % MOD for i, p in enumerate(text_values)])


# --------------------------------------------------------------------------
# Affine cipher
# --------------------------------------------------------------------------

def valid_affine_keys(modulus: int = MOD) -> list[tuple[int, int]]:
    """Every ``(a, b)`` pair that yields a valid affine cipher.

    ``a`` must be coprime to the modulus for the map to stay one-to-one; since
    37 is prime that means any ``a`` in 1..36. There are ``phi(37) * 37 = 1332``
    such keys.
    """
    return [
        (a, b)
        for a in range(1, modulus)
        if gcd(a, modulus) == 1
        for b in range(modulus)
    ]


def generate_affine_key(modulus: int = MOD) -> tuple[int, int]:
    """Pick one valid affine key at random."""
    import random

    keys = valid_affine_keys(modulus)
    return random.SystemRandom().choice(keys)


def affine_encrypt(text: str, a: int, b: int, modulus: int = MOD) -> str:
    """Affine cipher: ``c = (a*p + b) mod n``.

    A generalisation of Caesar -- ``a = 1`` recovers Caesar, and every affine key
    is a Caesar cipher under a relabelled alphabet, so affine is only a small
    step up in security over Caesar.
    """
    _validate_affine(a, modulus)
    return from_numbers([(a * p + b) % modulus for p in to_numbers(text)])


def affine_decrypt(text: str, a: int, b: int, modulus: int = MOD) -> str:
    """Inverse affine map: ``p = a_inv * (c - b) mod n``.

    Requires the modular inverse of ``a``, which is where the extended Euclidean
    algorithm earns its place: ``a * a_inv == 1 (mod n)``.
    """
    _validate_affine(a, modulus)
    a_inv = mod_inverse(a, modulus)
    return from_numbers([a_inv * (c - b) % modulus for c in to_numbers(text)])


def _validate_affine(a: int, modulus: int) -> None:
    if gcd(a, modulus) != 1:
        raise ValueError(
            f"invalid affine coefficient a={a}: gcd({a}, {modulus}) must be 1 "
            f"for the cipher to be reversible"
        )


# --------------------------------------------------------------------------
# Playfair
# --------------------------------------------------------------------------

_PLAYFAIR_FILLERS = {"J"}
_PLAYFAIR_LETTERS = set("ABCDEFGHIKLMNOPQRSTUVWXYZ")


def _build_playfair_key(key: str) -> str:
    """Merge key and alphabet, dropping repeated letters and the letter J."""
    seen: list[str] = []
    present: set[str] = set()
    for ch in normalize(key) + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch in _PLAYFAIR_FILLERS or ch in present:
            continue
        present.add(ch)
        seen.append(ch)
    return "".join(seen)


def _playfair_square(key: str) -> list[list[str]]:
    """Build the 5x5 square from the deduped key."""
    flat = _build_playfair_key(key)
    return [list(flat[i * 5 : i * 5 + 5]) for i in range(5)]


def _find_position(square: list[list[str]], ch: str) -> tuple[int, int]:
    for r in range(5):
        for c in range(5):
            if square[r][c] == ch:
                return r, c
    raise ValueError(f"character {ch!r} is not in the Playfair square")


def _playfair_clean(text: str) -> str:
    """Keep only the 25 square letters, folding J into I first.

    Playfair operates on a 5x5 letter square, so unlike the other ciphers here it
    cannot carry digits or spaces through the round trip. The J-to-I fold has to
    happen before the membership test, otherwise J is dropped rather than merged.
    """
    folded = ("I" if ch == "J" else ch for ch in normalize(text))
    return "".join(ch for ch in folded if ch in _PLAYFAIR_LETTERS)


def _prepare_playfair_digraphs(text: str) -> list[str]:
    """Normalize then split into letter pairs, inserting X between doubles.

    'BALLOON' becomes BA LX LO ON because the doubled LL is not allowed to sit
    inside one digraph.
    """
    cleaned = _playfair_clean(text)
    if not cleaned:
        return []

    digraphs: list[str] = []
    i = 0
    while i < len(cleaned):
        if i + 1 >= len(cleaned):
            digraphs.append(cleaned[i] + "X")
            break
        a, b = cleaned[i], cleaned[i + 1]
        if a == b:
            digraphs.append(a + "X")
            i += 1
        else:
            digraphs.append(a + b)
            i += 2

    return digraphs


def _transform_playfair(
    digraphs: list[str], square: list[list[str]], decrypt: bool
) -> str:
    out: list[str] = []

    for pair in digraphs:
        r1, c1 = _find_position(square, pair[0])
        r2, c2 = _find_position(square, pair[1])

        if r1 == r2:
            # Same row: shift one column in the requested direction.
            shift = -1 if decrypt else 1
            out.append(square[r1][(c1 + shift) % 5])
            out.append(square[r2][(c2 + shift) % 5])
        elif c1 == c2:
            # Same column: shift one row in the requested direction.
            shift = -1 if decrypt else 1
            out.append(square[(r1 + shift) % 5][c1])
            out.append(square[(r2 + shift) % 5][c2])
        else:
            # Rectangle rule: keep the row, swap the columns. The rule is its
            # own inverse, so encryption and decryption share this branch.
            out.append(square[r1][c2])
            out.append(square[r2][c1])

    return "".join(out)


def playfair_encrypt(text: str, key: str) -> str:
    """Playfair cipher over a 5x5 square built from ``key``.

    Every pair is transformed by one of three rules: same row, same column, or
    rectangle. Each digraph depends on two letters, which halves the information
    an attacker can harvest from letter frequencies.
    """
    if not normalize(key):
        raise ValueError("key must not be empty")

    square = _playfair_square(key)
    return _transform_playfair(_prepare_playfair_digraphs(text), square, decrypt=False)


def playfair_decrypt(text: str, key: str) -> str:
    """Inverse Playfair.

    Rules are identical with the shift reversed. Two asymmetries are worth
    knowing about. Digits and spaces cannot survive, since the square holds only
    the 25 letters. And the filler X characters inserted during encryption cannot
    be removed, so a decrypted message comes back padded with X -- a known
    property of Playfair rather than a defect here.
    """
    if not normalize(key):
        raise ValueError("key must not be empty")

    square = _playfair_square(key)
    cleaned = _playfair_clean(text)

    digraphs = [cleaned[i : i + 2] for i in range(0, len(cleaned) - 1, 2)]
    if len(cleaned) % 2:
        digraphs.append(cleaned[-1] + "X")

    return _transform_playfair(digraphs, square, decrypt=True)


# --------------------------------------------------------------------------
# Hill cipher
# --------------------------------------------------------------------------

def hill_encrypt(text: str, matrix: list[list[int]], modulus: int = MOD) -> str:
    """Hill cipher: ``c = K * p mod n`` with ``K`` an ``n x n`` key matrix.

    Each block of ``n`` letters is a column vector multiplied by the key matrix.
    Because 37 is prime, every matrix with non-zero determinant has an inverse,
    so any invertible matrix works.
    """
    size = len(matrix)
    _validate_matrix(matrix, size, modulus)

    values = to_numbers(text)
    padded = values + [0] * ((size - len(values) % size) % size)
    out: list[int] = []

    for start in range(0, len(padded), size):
        block = padded[start : start + size]
        for r in range(size):
            out.append(sum(matrix[r][c] * block[c] for c in range(size)) % modulus)

    return from_numbers(out)


def hill_decrypt(text: str, matrix: list[list[int]], modulus: int = MOD) -> str:
    """Inverse Hill cipher, using the adjugate of the key matrix.

    The plaintext comes back zero-padded to a whole number of blocks; the
    caller is expected to strip that padding from the original message length.
    """
    size = len(matrix)
    _validate_matrix(matrix, size, modulus)

    inverse = matrix_inverse(matrix, modulus)
    values = to_numbers(text)

    out: list[int] = []
    for start in range(0, len(values), size):
        block = values[start : start + size]
        for r in range(size):
            out.append(sum(inverse[r][c] * block[c] for c in range(size)) % modulus)

    return from_numbers(out)


def matrix_inverse(matrix: list[list[int]], modulus: int = MOD) -> list[list[int]]:
    """Invert a square matrix mod ``n`` by Gauss-Jordan elimination.

    The matrix is augmented with the identity and reduced to ``[I | K^-1]``.
    Each pivot is inverted with the modular inverse from the extended Euclidean
    algorithm, which is why a non-coprime pivot row is a hard error.
    """
    size = len(matrix)
    _validate_matrix(matrix, size, modulus)

    augmented = [
        [matrix[r][c] % modulus for c in range(size)] + [1 if r == c else 0 for c in range(size)]
        for r in range(size)
    ]

    for col in range(size):
        pivot_row = next((r for r in range(col, size) if augmented[r][col] % modulus), None)
        if pivot_row is None:
            raise ValueError("key matrix is singular modulo the modulus and cannot be inverted")

        augmented[col], augmented[pivot_row] = augmented[pivot_row], augmented[col]

        pivot_inv = mod_inverse(augmented[col][col], modulus)
        augmented[col] = [(v * pivot_inv) % modulus for v in augmented[col]]

        for r in range(size):
            if r == col:
                continue
            factor = augmented[r][col]
            if factor:
                augmented[r] = [
                    (augmented[r][k] - factor * augmented[col][k]) % modulus
                    for k in range(2 * size)
                ]

    return [row[size:] for row in augmented]


def determinant(matrix: list[list[int]], modulus: int = MOD) -> int:
    """Determinant via cofactor expansion, computed mod ``n``."""
    size = len(matrix)
    if size == 1:
        return matrix[0][0] % modulus
    if size == 2:
        return (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % modulus

    total = 0
    for c in range(size):
        minor = [row[:c] + row[c + 1 :] for row in matrix[1:]]
        total += ((-1) ** c) * matrix[0][c] * determinant(minor, modulus)
    return total % modulus


def _validate_matrix(matrix: list[list[int]], size: int, modulus: int) -> None:
    if len(matrix) != size:
        raise ValueError("key matrix must be square")
    for row in matrix:
        if len(row) != size:
            raise ValueError("key matrix must be square")