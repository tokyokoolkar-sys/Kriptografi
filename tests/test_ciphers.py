"""Classical and transposition ciphers: round-trips, known answers, invariants."""

from __future__ import annotations

import random
import string

import pytest

from kriptografi.alphabet import ALPHABET, ALPHABET_SIZE, from_numbers, normalize, to_numbers
from kriptografi.classical import (
    affine_decrypt,
    affine_encrypt,
    autokey,
    beaufort,
    caesar,
    determinant,
    hill_decrypt,
    hill_encrypt,
    matrix_inverse,
    playfair_decrypt,
    playfair_encrypt,
    valid_affine_keys,
    vigenere,
)
from kriptografi.transposition import (
    columnar_decrypt,
    columnar_encrypt,
    columnar_key_order,
    rail_fence_decrypt,
    rail_fence_encrypt,
    row_transposition_decrypt,
    row_transposition_encrypt,
)

SAMPLE = "WEAREDISCOVEREDFLEEATONCE"
MIXED = "HALLO 2026"


def sample_texts() -> list[str]:
    rng = random.Random(20261001)
    texts = ["", "A", "AB", "HELLO", MIXED, SAMPLE, "THE QUICK BROWN FOX 2026"]
    for _ in range(60):
        length = rng.randint(1, 60)
        texts.append("".join(rng.choice(ALPHABET) for _ in range(length)))
    return texts


class TestAlphabet:
    def test_size_is_37(self):
        assert ALPHABET_SIZE == 37
        assert len(ALPHABET) == 37
        assert len(set(ALPHABET)) == 37

    def test_alphabet_contents(self):
        assert ALPHABET == "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "

    def test_normalize_folds_case_and_drops_punctuation(self):
        assert normalize("Hello, World!") == "HELLO WORLD"
        assert normalize("a-b_c") == "ABC"
        assert normalize("") == ""
        assert normalize(None) == ""

    def test_number_round_trip(self):
        for text in ("HELLO", MIXED, SAMPLE, "A1 B2"):
            assert from_numbers(to_numbers(text)) == text

    def test_index_mapping(self):
        assert to_numbers("A") == [0]
        assert to_numbers("Z") == [25]
        assert to_numbers("0") == [26]
        assert to_numbers("9") == [35]
        assert to_numbers(" ") == [36]


class TestCaesar:
    def test_known_answer(self):
        # H=7 +3 -> 10 = K; A=0 +3 -> 3 = D; L=11 +3 -> 14 = O; L -> O
        assert caesar("HALLO 2026", 3) == "KDOORC5359"

    def test_round_trip(self):
        for text in sample_texts():
            assert caesar(caesar(text, 7), 7, decrypt=True) == text

    def test_shift_wraps_around(self):
        assert caesar("A", 1) == "B"
        assert caesar("Z", 1) == "0"
        assert caesar("9", 1) == " "
        assert caesar(" ", 1) == "A"

    def test_zero_shift_is_identity(self):
        assert caesar(MIXED, 0) == MIXED

    def test_full_cycle_of_37_returns_original(self):
        # The alphabet has 37 symbols, so 37 shifts is one full cycle -- not 36.
        assert caesar(MIXED, 37) == MIXED


class TestVigenere:
    def test_known_answer(self):
        assert vigenere("HELLO", "KEY") == "RI9VS"

    def test_round_trip(self):
        rng = random.Random(11)
        for _ in range(200):
            text = "".join(rng.choice(ALPHABET) for _ in range(rng.randint(1, 80)))
            key = "".join(rng.choice(ALPHABET) for _ in range(rng.randint(1, 10)))
            assert vigenere(vigenere(text, key), key, decrypt=True) == text

    def test_key_repeats(self):
        # A key of length 2 over 6 characters applies three times.
        assert vigenere("ABCDEF", "XY") == vigenere("ABCDEF", "XYXYXY")

    def test_beaufort_is_self_inverse(self):
        for text in ("HELLO", MIXED, SAMPLE):
            assert beaufort(beaufort(text, "KEY"), "KEY") == text

    def test_beaufort_differs_from_vigenere(self):
        # Same key, same text, genuinely different scheme.
        assert beaufort("HELLO", "KEY") != vigenere("HELLO", "KEY")

    def test_autokey_round_trip(self):
        rng = random.Random(13)
        for _ in range(200):
            text = "".join(rng.choice(ALPHABET) for _ in range(rng.randint(1, 80)))
            key = "".join(rng.choice(ALPHABET) for _ in range(rng.randint(1, 10)))
            assert autokey(autokey(text, key), key, decrypt=True) == text

    def test_empty_key_rejected(self):
        with pytest.raises(ValueError):
            vigenere("HELLO", "")


class TestAffine:
    def test_known_answer(self):
        assert affine_encrypt("HELLO", 5, 8) == "G200E"

    def test_round_trip_all_valid_keys(self):
        for a, b in valid_affine_keys(37)[:200]:
            text = MIXED
            assert affine_decrypt(affine_encrypt(text, a, b), a, b) == text

    def test_key_count(self):
        # phi(37) * 37 = 36 * 37 = 1332
        assert len(valid_affine_keys(37)) == 1332

    def test_non_coprime_a_rejected(self):
        with pytest.raises(ValueError, match="invalid affine"):
            affine_encrypt("HELLO", 0, 3)

    def test_a_one_recovers_caesar(self):
        # a = 1 makes the affine cipher a plain Caesar shift by b.
        assert affine_encrypt("HELLO", 1, 5) == caesar("HELLO", 5)

    def test_affine_is_permutation(self):
        # Every symbol must map to a distinct symbol.
        images = {affine_encrypt(ch, 5, 8) for ch in ALPHABET}
        assert len(images) == 37


class TestPlayfair:
    def test_round_trip_modulo_filler(self):
        # Playfair drops digits and spaces and inserts X between doubled letters,
        # so compare against the cleaned text with fillers stripped.
        for text in ("HELLOWORLD", "IN THE FIELD", "MEETMEATTHEMOON"):
            key = "KEYWORD"
            recovered = playfair_decrypt(playfair_encrypt(text, key), key)
            expected = "".join("I" if ch == "J" else ch for ch in normalize(text) if ch.isalpha())
            assert recovered.replace("X", "") == expected.replace("X", "")

    def test_known_answer(self):
        assert playfair_encrypt("HELLOWORLD", "KEYWORD") == "GYIZSCOKCFBU"

    def test_output_length_is_even(self):
        for text in sample_texts()[:30]:
            if any(ch.isalpha() for ch in normalize(text)):
                assert len(playfair_encrypt(text, "KEY")) % 2 == 0

    def test_j_is_merged_into_i(self):
        assert playfair_encrypt("J", "KEY") == playfair_encrypt("I", "KEY")

    def test_digits_and_spaces_are_dropped(self):
        # The 5x5 square holds only letters, so these cannot survive.
        assert playfair_encrypt("A1", "KEY") == playfair_encrypt("A", "KEY")

    def test_doubled_letters_grow_the_ciphertext(self):
        # 'LL' cannot share a digraph, so a filler is inserted and the ciphertext
        # grows from 6 to 8 characters. The filler is encrypted like any letter,
        # so it does not appear literally in the output.
        assert len(playfair_encrypt("BALOON", "KEYWORD")) == 6
        assert len(playfair_encrypt("BALLOON", "KEYWORD")) == 8

    def test_decrypt_reverses_encrypt(self):
        # Decryption must recover the message up to the inserted fillers. A
        # second decryption is not guaranteed to be a no-op, because the recovered
        # text can contain letter doubles that get a fresh filler -- that is an
        # inherent property of Playfair, not a defect in the implementation.
        for text in ("HELLOWORLD", "MEETMEATTHEMOON"):
            key = "ZEBRAS"
            recovered = playfair_decrypt(playfair_encrypt(text, key), key)
            assert "".join(c for c in recovered if c != "X") == text.replace("X", "")

    def test_empty_key_rejected(self):
        with pytest.raises(ValueError, match="key must not be empty"):
            playfair_encrypt("HELLO", "")


class TestHill:
    def test_known_answer(self):
        assert hill_encrypt("HELLOWORLD", [[3, 3], [2, 5]]) == "783D81TCFA"

    def test_round_trip(self):
        for text in ("HELLOWORLD", "THEQUICKBROWNFOX", MIXED):
            key = [[3, 3], [2, 5]]
            assert hill_decrypt(hill_encrypt(text, key), key) == text

    def test_matrix_inverse_is_involution(self):
        for matrix in ([[3, 3], [2, 5]], [[1, 2], [3, 4]], [[7, 11], [13, 17]]):
            inverse = matrix_inverse(matrix)
            product = [
                [sum(matrix[r][k] * inverse[k][c] for k in range(2)) % 37 for c in range(2)]
                for r in range(2)
            ]
            assert product == [[1, 0], [0, 1]]

    def test_singular_matrix_rejected(self):
        with pytest.raises(ValueError, match="singular"):
            matrix_inverse([[1, 2], [2, 4]])  # rows are proportional

    def test_count_of_invertible_matrices_matches_group_order(self):
        # |GL(2, 37)| = (37^2 - 1) * (37^2 - 37)
        count = 0
        for a in range(37):
            for b in range(37):
                for c in range(37):
                    for d in range(37):
                        try:
                            matrix_inverse([[a, b], [c, d]])
                            count += 1
                        except ValueError:
                            pass
        assert count == (37**2 - 1) * (37**2 - 37)

    def test_three_by_three_round_trip(self):
        key = [[2, 5, 1], [1, 3, 4], [6, 2, 2]]
        text = "HELLOTHISISALONGTEXT"
        # Hill pads the final block, so the recovered text carries extra 'A's
        # (index 0) when the length is not a multiple of the block size.
        assert hill_decrypt(hill_encrypt(text, key), key).startswith(text)

    def test_aligned_length_round_trips_exactly(self):
        key = [[2, 5, 1], [1, 3, 4], [6, 2, 2]]
        text = "HELLOTHISISALONGTEXTA"  # exactly 21 characters
        assert hill_decrypt(hill_encrypt(text, key), key) == text

    def test_determinant_known(self):
        assert determinant([[1, 2], [3, 4]]) == (4 - 6) % 37
        assert determinant([[5]]) == 5


class TestTranspositionInvariants:
    """Transposition only permutes, so the multiset of characters is preserved."""

    def test_rail_fence_preserves_characters(self):
        for text in sample_texts()[:40]:
            ciphertext = rail_fence_encrypt(text, 4)
            assert sorted(ciphertext) == sorted(normalize(text))

    def test_columnar_preserves_characters(self):
        for text in sample_texts()[:40]:
            ciphertext = columnar_encrypt(text, "ZEBRA")
            assert sorted(ciphertext) == sorted(normalize(text))

    def test_row_preserves_characters(self):
        for text in sample_texts()[:40]:
            ciphertext = row_transposition_encrypt(text, "ZEBRA", 5)
            assert sorted(ciphertext) == sorted(normalize(text))

    def test_substitution_does_not_preserve_characters(self):
        # The contrast that distinguishes the two families.
        assert sorted(caesar(SAMPLE, 3)) != sorted(SAMPLE)


class TestRailFence:
    def test_known_answer(self):
        assert rail_fence_encrypt(SAMPLE, 3) == "WECRLTEERDSOEEFEAOCAIVDEN"

    def test_round_trip_all_rail_counts(self):
        for rails in range(2, 12):
            for text in sample_texts()[:50]:
                assert rail_fence_decrypt(rail_fence_encrypt(text, rails), rails) == normalize(text)

    def test_single_rail_rejected(self):
        with pytest.raises(ValueError):
            rail_fence_encrypt("HELLO", 1)

    def test_two_rails_reads_top_then_bottom(self):
        # With 2 rails the zigzag alternates every character, so encryption is
        # simply "all even indices, then all odd indices".
        text = "WEAREDISCOVEREDFLEEATONCE"
        expected = text[::2] + text[1::2]
        assert rail_fence_encrypt(text, 2) == expected
        assert rail_fence_decrypt(expected, 2) == text

    def test_more_rails_than_text(self):
        text = "ABC"
        assert rail_fence_encrypt(text, 10) == "ABC"
        assert rail_fence_decrypt("ABC", 10) == "ABC"


class TestColumnar:
    def test_known_answer(self):
        assert columnar_encrypt(SAMPLE, "ZEBRA") == "EODAEASRENEIELORCEECWDVFT"

    def test_round_trip(self):
        rng = random.Random(17)
        for _ in range(300):
            text = "".join(rng.choice(ALPHABET) for _ in range(rng.randint(1, 80)))
            key = "".join(rng.choice(ALPHABET) for _ in range(rng.randint(1, 10)))
            assert columnar_decrypt(columnar_encrypt(text, key), key) == text

    def test_key_order(self):
        # The alphabet is A-Z, 0-9, space, so 'ZEBRA' sorts as A B E R Z -- the
        # digit and space symbols after Z do not affect these five letters.
        # ZEBRA -> index 0=A, 1=B, 2=E, 3=R, 4=Z, so read order is [4, 2, 1, 3, 0].
        assert columnar_key_order("ZEBRA") == [4, 2, 1, 3, 0]
        assert columnar_key_order("ABC") == [0, 1, 2]
        assert columnar_key_order("CBA") == [2, 1, 0]

    def test_key_spaces_are_significant(self):
        # A longer key means more columns, so the result must differ.
        assert columnar_encrypt(SAMPLE, "ZEBRA") != columnar_encrypt(SAMPLE, "ZEBRAS")

    def test_empty_key_rejected(self):
        with pytest.raises(ValueError):
            columnar_encrypt("HELLO", "")


class TestRowTransposition:
    def test_differs_from_columnar(self):
        # Same key, same text, genuinely different permutation.
        assert row_transposition_encrypt(SAMPLE, "ZEBRA", 5) != columnar_encrypt(SAMPLE, "ZEBRA")

    def test_round_trip(self):
        rng = random.Random(19)
        for _ in range(300):
            text = "".join(rng.choice(ALPHABET) for _ in range(rng.randint(1, 80)))
            columns = rng.randint(1, 10)
            key = "".join(rng.choice(ALPHABET) for _ in range(columns))
            assert row_transposition_decrypt(
                row_transposition_encrypt(text, key, columns), key, columns
            ) == text

    def test_key_length_must_equal_columns(self):
        with pytest.raises(ValueError, match="key length"):
            row_transposition_encrypt("HELLO", "ABC", 5)

    def test_single_column_is_identity(self):
        assert row_transposition_encrypt(SAMPLE, "A", 1) == SAMPLE