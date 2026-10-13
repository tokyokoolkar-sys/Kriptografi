"""Text codec mapping the 37-character alphabet to numbers 0-36.

The chosen alphabet is ``A-Z``, ``0-9`` and space, which makes every classical
cipher work modulo 37 instead of modulo 26. The practical payoff is that digits
survive the round trip, so ``HALLO 2026`` encrypts and decrypts back to
``HALLO 2026`` without any preprocessing.

    'A' -> 0    'Z' -> 25    '0' -> 26    '9' -> 35    ' ' -> 36
"""

from __future__ import annotations

__all__ = [
    "ALPHABET",
    "ALPHABET_SIZE",
    "SYMBOL_TO_INDEX",
    "INDEX_TO_SYMBOL",
    "normalize",
    "to_numbers",
    "from_numbers",
    "to_digits_base37",
    "from_digits_base37",
]

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
ALPHABET_SIZE = len(ALPHABET)

SYMBOL_TO_INDEX: dict[str, int] = {ch: i for i, ch in enumerate(ALPHABET)}
INDEX_TO_SYMBOL: str = ALPHABET

Digit = str


def normalize(text: str) -> str:
    """Fold a string into the 37-character alphabet.

    Lowercase letters are uppercased; anything outside the alphabet (punctuation,
    tabs, newlines) is dropped. ``None`` and empty input yield an empty string so
    downstream code never has to special-case missing text.
    """
    if not text:
        return ""
    return "".join(ch for ch in text.upper() if ch in SYMBOL_TO_INDEX)


def to_numbers(text: str) -> list[int]:
    """Convert text to its numeric form, one value per character in [0, 36]."""
    return [SYMBOL_TO_INDEX[ch] for ch in normalize(text)]


def from_numbers(values: list[int], modulus: int | None = None) -> str:
    """Convert numbers back to text.

    ``modulus`` folds the values into range first, which makes decryption a plain
    ``from_numbers`` call with the cipher's own modulus.
    """
    out: list[str] = []
    for value in values:
        if modulus is not None:
            value %= modulus
        out.append(INDEX_TO_SYMBOL[value % ALPHABET_SIZE])
    return "".join(out)


def to_digits_base37(text: str) -> str:
    """Encode text as base-37 digits for use as a big integer.

    This is the standard trick for turning RSA plaintext into a number: each
    character becomes a base-37 digit, so the whole string packs into one big
    integer that can be raised to a power modulo ``n``.
    """
    return "".join(f"{SYMBOL_TO_INDEX[ch]:02d}" for ch in normalize(text))


def from_digits_base37(digits: str) -> str:
    """Decode base-37 digits produced by :func:`to_digits_base37`."""
    if len(digits) % 2 != 0:
        digits = digits.rjust(len(digits) + 1, "0")
    values = [int(digits[i : i + 2]) for i in range(0, len(digits), 2)]
    return "".join(INDEX_TO_SYMBOL[v] for v in values if v < ALPHABET_SIZE)