"""Cryptanalysis helpers: frequency analysis and key recovery for the classical ciphers.

These are the attack side of the course material -- what an adversary can do to
Caesar and Vigenere once the alphabet and the scheme are known. Having them in the
toolkit makes the weakness of these ciphers concrete instead of theoretical.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from .alphabet import ALPHABET, ALPHABET_SIZE, from_numbers, normalize, to_numbers

__all__ = [
    "frequency_analysis",
    "index_of_coincidence",
    "crack_caesar",
    "caesar_crack_all",
    "crack_vigenere",
    "VigenereBreakResult",
]

# English letter frequencies as percentages, for a chi-squared style score.
# Digits and spaces are included with a small but non-zero expected share, since
# this toolkit's alphabet mixes letters with 0-9 and space -- treating those as
# free would let a decryption full of them score well by accident.
_ENGLISH_FREQ = {
    "A": 8.17, "B": 1.49, "C": 2.78, "D": 4.25, "E": 12.70, "F": 2.23,
    "G": 2.02, "H": 6.09, "I": 6.97, "J": 0.15, "K": 0.77, "L": 4.03,
    "M": 2.41, "N": 6.75, "O": 7.51, "P": 1.93, "Q": 0.10, "R": 5.99,
    "S": 6.33, "T": 9.06, "U": 2.76, "V": 0.98, "W": 2.36, "X": 0.15,
    "Y": 1.97, "Z": 0.07,
}
for _digit in "0123456789":
    _ENGLISH_FREQ[_digit] = 1.2
_ENGLISH_FREQ[" "] = 8.0

# The 40 most frequent English bigrams, weighted by rough rank. Bigrams are far
# more discriminating than single-letter frequencies: 'TH', 'HE' and 'IN' appear
# constantly in English and almost never by chance, whereas 'E' on its own is only
# moderately informative. This is what makes the score survive noise from spaces
# and digits that a letter-frequency count alone cannot handle.
_COMMON_BIGRAMS = [
    "TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT", "EN", "ND",
    "TI", "ES", "OR", "TE", "OF", "ED", "IS", "IT", "AL", "AR",
    "ST", "TO", "NT", "NG", "SE", "HA", "AS", "OU", "IO", "LE",
    "VE", "CO", "ME", "DE", "HI", "RI", "RO", "IC", "NE", "EA",
]

# Bigram bonus: the most common bigram is worth this much, decaying with rank.
_BIGRAM_WEIGHTS = [12.0 * (1.0 - i / len(_COMMON_BIGRAMS)) for i in range(len(_COMMON_BIGRAMS))]


def frequency_analysis(text: str) -> dict:
    """Count character frequencies and rank them by occurrence.

    A substitution cipher leaves the frequency profile intact but shuffles which
    letter sits at the top, so comparing this ranking against English is the
    first step of most attacks here.
    """
    counts = Counter(normalize(text))
    total = sum(counts.values()) or 1

    items = counts.most_common()
    return {
        "total_characters": total,
        "distinct_characters": len(counts),
        "counts": dict(items),
        "frequencies": {ch: round(count / total * 100, 2) for ch, count in items},
        "ranking": [ch for ch, _ in items],
        "most_common": items[0][0] if items else None,
    }


def index_of_coincidence(text: str) -> float:
    """Index of coincidence: the probability two random positions match.

    English text scores around 0.066, true random about 0.038. For Vigenere the
    score is diluted by the key length, so measuring it at candidate key lengths
    reveals the key period -- the Kasiski observation in numeric form.
    """
    values = to_numbers(text)
    n = len(values)
    if n < 2:
        return 0.0

    counts = Counter(values)
    pairs = sum(c * (c - 1) for c in counts.values())
    return pairs / (n * (n - 1))


_BIGRAM_WEIGHTS_MAP = dict(zip(_COMMON_BIGRAMS, _BIGRAM_WEIGHTS))


def _english_score(text: str) -> float:
    """Score text by how English it looks.

    Combines two signals. The chi-squared term compares single-character
    frequencies against English, which handles unigrams but is easily fooled by
    the digits and spaces that this toolkit's 37-symbol alphabet scatters through
    the text. The bigram term then dominates: real English is full of 'TH', 'IN'
    and 'ER', and random-looking text almost never produces them. Together they
    rank a correct decryption far above every wrong shift.
    """
    normalized = normalize(text)
    chars = [ch for ch in normalized if ch != " "]
    if not chars:
        return 0.0

    # Expected frequency is summed over all 37 symbols, whether or not they
    # appear, so a decryption stuffed with rare characters cannot win by having
    # an artificially small chi-squared sum.
    counts = Counter(chars)
    total = len(chars)
    expected_total = sum(_ENGLISH_FREQ.values())

    chi_squared = 0.0
    for ch, share in _ENGLISH_FREQ.items():
        expected = share * total / expected_total
        chi_squared -= (counts.get(ch, 0) - expected) ** 2 / max(expected, 1e-9)

    bigram_score = 0.0
    for i in range(len(normalized) - 1):
        bigram = normalized[i : i + 2]
        weight = _BIGRAM_WEIGHTS_MAP.get(bigram)
        if weight:
            bigram_score += weight

    # Scale by length so longer candidates are not automatically preferred over
    # short ones purely because they contain more characters.
    return chi_squared + bigram_score * total**0.5


# --------------------------------------------------------------------------
# Caesar
# --------------------------------------------------------------------------

def caesar_crack_all(ciphertext: str) -> list[dict]:
    """Try every Caesar shift and rank the results by English-likeness.

    Caesar has only 36 usable keys, so it is fully breakable by exhaustion --
    there is no key that survives this search.
    """
    results = []
    for shift in range(ALPHABET_SIZE):
        plaintext = from_numbers([(c - shift) % ALPHABET_SIZE for c in to_numbers(ciphertext)])
        results.append({
            "shift": shift,
            "plaintext": plaintext,
            "score": round(_english_score(plaintext), 4),
        })

    return sorted(results, key=lambda r: r["score"], reverse=True)


def crack_caesar(ciphertext: str, top: int = 5) -> list[dict]:
    """The ``top`` most plausible Caesar decryptions, best first."""
    return caesar_crack_all(ciphertext)[:top]


# --------------------------------------------------------------------------
# Vigenere
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class VigenereBreakResult:
    """One candidate Vigenere key with its recovered plaintext."""

    key: str
    key_length: int
    plaintext: str
    score: float
    average_ic: float


def crack_vigenere(ciphertext: str, max_key_length: int = 12) -> list[VigenereBreakResult]:
    """Recover a Vigenere key by testing every key length.

    For each candidate length the ciphertext is split into that many Caesar
    sub-ciphertexts, each is solved independently by frequency analysis, and the
    per-column shifts are reassembled into the full key. The candidate with the
    best English-likeness wins.

    This works because each column is a simple Caesar cipher, and it is the same
    insight behind Kasiski examination -- just automated.
    """
    values = to_numbers(ciphertext)
    if not values:
        return []

    results: list[VigenereBreakResult] = []

    for length in range(1, min(max_key_length, len(values)) + 1):
        key_chars: list[str] = []
        column_ics: list[float] = []

        for offset in range(length):
            column = values[offset::length]
            column_text = from_numbers(column)

            best_shift = max(
                range(ALPHABET_SIZE),
                key=lambda shift: _english_score(
                    from_numbers([(c - shift) % ALPHABET_SIZE for c in column])
                ),
            )

            key_chars.append(ALPHABET[best_shift] if best_shift < 26 else str(best_shift))
            column_ics.append(index_of_coincidence(column_text))

        key = "".join(key_chars)
        plaintext = from_numbers(
            [(c - to_numbers(key)[i % length]) % ALPHABET_SIZE
             for i, c in enumerate(values)]
        )

        results.append(VigenereBreakResult(
            key=key,
            key_length=length,
            plaintext=plaintext,
            score=round(_english_score(plaintext), 4),
            average_ic=round(sum(column_ics) / length, 5),
        ))

    return sorted(results, key=lambda r: r.score, reverse=True)