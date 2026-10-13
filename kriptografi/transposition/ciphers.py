"""Transposition ciphers: they rearrange the ciphertext, never substitute.

Every function here is a pure permutation of the input's characters, so
``decrypt(encrypt(x)) == x`` exactly with no padding side effects. That makes
them ideal to demonstrate the substitution/transposition distinction from the
course material.
"""

from __future__ import annotations

from ..alphabet import normalize

__all__ = [
    "rail_fence_encrypt",
    "rail_fence_decrypt",
    "columnar_encrypt",
    "columnar_decrypt",
    "row_transposition_encrypt",
    "row_transposition_decrypt",
    "columnar_key_order",
]


# --------------------------------------------------------------------------
# Rail fence
# --------------------------------------------------------------------------

def rail_fence_encrypt(text: str, rails: int) -> str:
    """Rail fence: write the text in a zigzag across ``rails``, read row by row.

    With 3 rails and 'WEAREDISCOVEREDFLEEATONCE' the zigzag is::

        W . . . . . E . . . . C . . . . R . . . . D . . . . E . . . . E
        . E . . . . . R . . . . I . . . . V . . . . L . . . . A .
        . . O . . . . . E . . . . C . . . . O . . . . T . . . . .

    and reading rows off the rails gives the ciphertext.
    """
    if rails < 2:
        raise ValueError("need at least 2 rails")

    text = normalize(text)
    if not text:
        return ""

    pattern = _rail_pattern(len(text), rails)
    return "".join(text[i] for i in range(len(text)) if pattern[i] == 0) + "".join(
        text[i] for rail in range(1, rails) for i in range(len(text)) if pattern[i] == rail
    )


def rail_fence_decrypt(text: str, rails: int) -> str:
    """Inverse rail fence: rebuild the zigzag positions, then read across.

    Rather than reasoning about rail lengths and seams, the decryption places
    characters back at every index where the zigzag pattern puts them in reading
    order.
    """
    if rails < 2:
        raise ValueError("need at least 2 rails")

    text = normalize(text)
    if not text:
        return ""

    pattern = _rail_pattern(len(text), rails)

    rail_lengths = [pattern.count(rail) for rail in range(rails)]
    rail_slices: list[str] = []
    pos = 0
    for length in rail_lengths:
        rail_slices.append(text[pos : pos + length])
        pos += length

    # Walk the zigzag position by position, pulling the next unused character
    # from whichever rail that position belongs to.
    consumed = [0] * rails
    out: list[str] = []
    for rail in pattern:
        out.append(rail_slices[rail][consumed[rail]])
        consumed[rail] += 1

    return "".join(out)


def _rail_pattern(length: int, rails: int) -> list[int]:
    """Which rail each character index sits on, following the zigzag.

    The cycle length is ``2 * (rails - 1)``: going down ``rails - 1`` steps and
    back up again.
    """
    cycle = 2 * (rails - 1)
    pattern: list[int] = []
    for i in range(length):
        step = i % cycle
        pattern.append(step if step < rails else cycle - step)
    return pattern


# --------------------------------------------------------------------------
# Columnar transposition
# --------------------------------------------------------------------------

def columnar_key_order(key: str) -> list[int]:
    """Positions of the key letters in alphabetical order.

    'ZEBRA' sorts to A, B, E, R, Z, giving read order [1, 3, 4, 2, 0]. Sorting
    the key letters alphabetically is what makes the scheme reversible.
    """
    key = normalize(key)
    if not key:
        raise ValueError("key must not be empty")
    return sorted(range(len(key)), key=lambda i: key[i])


def _ragged_rows(length: int, columns: int) -> list[list[int]]:
    """Build a ragged grid and return, per column, the text indices it holds.

    The last row is short when ``length`` is not a multiple of ``columns``, so the
    rightmost columns end up one entry shorter. Recording each column's index list
    makes encryption and decryption exact mirrors of each other -- no padding is
    invented and no original length has to be smuggled through separately.
    """
    return [
        [r * columns + c for r in range(length) if r * columns + c < length]
        for c in range(columns)
    ]


def columnar_encrypt(text: str, key: str) -> str:
    """Columnar transposition: write the text in rows under the key, read columns.

    The number of columns equals the key length. Characters are emitted column by
    column in alphabetical key order, so ``WEAREDISCOVEREDFLEEATONCE`` under key
    'ZEBRA' (read order A B E R Z, i.e. columns 1 3 4 2 0) becomes
    ``EODAEASRENEIELORCEECWDVFT``.
    """
    key = normalize(key)
    text = normalize(text)
    if not key:
        raise ValueError("key must not be empty")
    if not text:
        return ""

    columns = len(key)
    index_rows = _ragged_rows(len(text), columns)

    return "".join(text[i] for c in columnar_key_order(key) for i in index_rows[c])


def columnar_decrypt(text: str, key: str) -> str:
    """Inverse columnar transposition: refill the columns, then read row by row.

    Ciphertext is consumed in exactly the order encryption produced it, which
    restores each index to its slot in the ragged grid.
    """
    key = normalize(key)
    text = normalize(text)
    if not key:
        raise ValueError("key must not be empty")
    if not text:
        return ""

    columns = len(key)
    index_rows = _ragged_rows(len(text), columns)
    order = columnar_key_order(key)

    out: list[str | None] = [None] * len(text)
    pos = 0
    for c in order:
        for i in index_rows[c]:
            if pos < len(text):
                out[i] = text[pos]
                pos += 1

    return "".join(ch for ch in out if ch is not None)


# --------------------------------------------------------------------------
# Row transposition
# --------------------------------------------------------------------------

def _ragged_columns(length: int, columns: int) -> list[list[int]]:
    """Per column, the text indices it holds when the text runs *down* columns.

    Companion to :func:`_ragged_rows`, but for text filled column-major. Column
    ``c`` owns indices ``c, c + columns, c + 2*columns, ...`` below ``length``.
    """
    return [list(range(c, length, columns)) for c in range(columns)]


def row_transposition_encrypt(text: str, key: str, columns: int) -> str:
    """Row transposition: the mirror image of columnar, read out by rows.

    The text is written *down* the columns and then read off row by row in
    alphabetical key order, which yields a genuinely different permutation from
    :func:`columnar_encrypt` over the same key -- useful for showing the two
    schemes are distinct rather than relabelings of each other.
    """
    key = normalize(key)
    text = normalize(text)
    if not key:
        raise ValueError("key must not be empty")
    if len(key) != columns:
        raise ValueError("key length must equal the column count")
    if columns < 1:
        raise ValueError("need at least 1 column")
    if not text:
        return ""

    index_cols = _ragged_columns(len(text), columns)
    order = columnar_key_order(key)

    # Rows of a ragged grid are uneven: build them by bucketing indices by row.
    buckets: list[list[int]] = [[] for _ in range(max(len(c) for c in index_cols) + 1)]
    for c in order:
        for pos in range(len(index_cols[c])):
            row = pos
            buckets[row].append(index_cols[c][pos])

    return "".join(text[i] for bucket in buckets for i in bucket)


def row_transposition_decrypt(text: str, key: str, columns: int) -> str:
    """Inverse row transposition."""
    key = normalize(key)
    text = normalize(text)
    if not key:
        raise ValueError("key must not be empty")
    if len(key) != columns:
        raise ValueError("key length must equal the column count")
    if not text:
        return ""

    index_cols = _ragged_columns(len(text), columns)
    order = columnar_key_order(key)

    buckets: list[list[int]] = [[] for _ in range(max(len(c) for c in index_cols) + 1)]
    for c in order:
        for pos in range(len(index_cols[c])):
            buckets[pos].append(index_cols[c][pos])

    out: list[str | None] = [None] * len(text)
    pos = 0
    for bucket in buckets:
        for i in bucket:
            if pos < len(text):
                out[i] = text[pos]
                pos += 1

    return "".join(ch for ch in out if ch is not None)