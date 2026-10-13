"""Public-key cryptography: RSA, Diffie-Hellman, ElGamal, and elliptic curves."""

from __future__ import annotations

import random

import pytest

from kriptografi.alphabet import normalize
from kriptografi.asymmetric.dh import (
    DHParameters,
    compute_shared_secret,
    decode_message,
    elgamal_decrypt,
    elgamal_encrypt,
    elgamal_keypair,
    encode_message,
    generate_keypair,
    generate_parameters,
)
from kriptografi.asymmetric.ecc import (
    CURVE_PARAMS,
    Curve,
    Point,
    generate_keypair as ecc_keypair,
    point_add,
    point_double,
    scalar_mult,
    sign,
    verify,
)
from kriptografi.asymmetric.ecc import INFINITY
from kriptografi.asymmetric.rsa import (
    decrypt_int,
    decrypt_message,
    encrypt_int,
    encrypt_message,
    generate_keypair as rsa_keypair,
    private_key_from_hex,
    private_key_to_hex,
    public_key_from_hex,
    public_key_to_hex,
)
from kriptografi.mathcore import gcd, is_prime, mod_inverse, pow_mod


# --------------------------------------------------------------------------
# RSA
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def rsa_keys():
    return rsa_keypair(512)


class TestRSA:
    def test_key_structure(self, rsa_keys):
        priv = rsa_keys.private
        assert priv.p != priv.q
        assert priv.n == priv.p * priv.q
        assert is_prime(priv.p) and is_prime(priv.q)
        assert gcd(priv.e, (priv.p - 1) * (priv.q - 1)) == 1

    def test_private_exponent_inverts_public(self, rsa_keys):
        priv = rsa_keys.private
        phi = (priv.p - 1) * (priv.q - 1)
        assert (priv.e * priv.d) % phi == 1

    def test_default_public_exponent(self, rsa_keys):
        assert rsa_keys.public.e == 65537

    def test_integer_round_trip(self, rsa_keys):
        for message in (0, 1, 2, 42, 1000, 65537, rsa_keys.public.n - 1):
            assert decrypt_int(encrypt_int(message, rsa_keys.public), rsa_keys.private) == message

    def test_encrypt_matches_raw_modexp(self, rsa_keys):
        message = 12345
        assert encrypt_int(message, rsa_keys.public) == pow_mod(message, rsa_keys.public.e,
                                                                rsa_keys.public.n)

    def test_message_round_trip(self, rsa_keys):
        for message in ("", "A", "HELLO", "HALLO 2026", "THE QUICK BROWN FOX", "X" * 200,
                        "SPACES  AND 123 456"):
            ciphertext = encrypt_message(message, rsa_keys.public)
            assert decrypt_message(ciphertext, rsa_keys.private) == normalize(message)

    def test_rejects_oversized_integer(self, rsa_keys):
        with pytest.raises(ValueError, match="below the modulus"):
            encrypt_int(rsa_keys.public.n, rsa_keys.public)

    def test_key_serialisation_round_trip(self, rsa_keys):
        assert public_key_from_hex(public_key_to_hex(rsa_keys.public)) == rsa_keys.public
        assert private_key_from_hex(private_key_to_hex(rsa_keys.private)) == rsa_keys.private

    def test_rejects_odd_modulus_size(self):
        with pytest.raises(ValueError, match="even"):
            rsa_keypair(511)

    def test_rejects_tiny_modulus(self):
        with pytest.raises(ValueError, match="at least 256 bits"):
            rsa_keypair(128)

    def test_ciphertext_differs_from_plaintext(self, rsa_keys):
        ciphertext = encrypt_message("ATTACKATDAWN", rsa_keys.public)
        assert "ATTACKATDAWN" not in "".join(str(c) for c in ciphertext)


# --------------------------------------------------------------------------
# Diffie-Hellman
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def dh_params():
    return generate_parameters(256)


class TestDiffieHellman:
    def test_parameters_are_safe_prime(self, dh_params):
        q = (dh_params.p - 1) // 2
        assert is_prime(dh_params.p)
        assert is_prime(q)

    def test_shared_secrets_agree(self, dh_params):
        alice = generate_keypair(dh_params)
        bob = generate_keypair(dh_params)
        assert alice.derive(bob.public) == bob.derive(alice.public)

    def test_shared_secret_matches_formula(self, dh_params):
        alice = generate_keypair(dh_params)
        bob = generate_keypair(dh_params)
        expected = pow_mod(dh_params.g, alice.private * bob.private, dh_params.p)
        assert alice.derive(bob.public) == expected

    def test_private_exponent_in_range(self, dh_params):
        party = generate_keypair(dh_params)
        q = (dh_params.p - 1) // 2
        assert 2 <= party.private <= q - 2

    def test_rejects_degenerate_peer_values(self, dh_params):
        party = generate_keypair(dh_params)
        for bad in (0, 1, dh_params.p - 1, dh_params.p):
            with pytest.raises(ValueError, match="peer public value"):
                party.derive(bad)

    def test_small_group(self):
        params = DHParameters(23, 5)
        alice = generate_keypair(params)
        bob = generate_keypair(params)
        assert alice.derive(bob.public) == bob.derive(alice.public)

    def test_rejects_small_parameters(self):
        with pytest.raises(ValueError, match="at least 128 bits"):
            generate_parameters(64)


# --------------------------------------------------------------------------
# ElGamal
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def elgamal_key(dh_params):
    return elgamal_keypair(dh_params)


class TestElGamal:
    def test_encrypt_decrypt_integer(self, elgamal_key):
        for message in (1, 2, 42, 1000):
            assert elgamal_decrypt(elgamal_encrypt(message, elgamal_key), elgamal_key) == message

    def test_ciphertext_components_in_range(self, elgamal_key):
        c1, c2 = elgamal_encrypt(12345, elgamal_key)
        assert 0 < c1 < elgamal_key.parameters.p
        assert 0 < c2 < elgamal_key.parameters.p

    def test_fresh_nonce_per_message(self, elgamal_key):
        # Reusing k would let an attacker cancel the shared term across two
        # messages and recover the plaintext ratio.
        c1_a, _ = elgamal_encrypt(100, elgamal_key)
        c1_b, _ = elgamal_encrypt(100, elgamal_key)
        assert c1_a != c1_b

    def test_rejects_out_of_range_message(self, elgamal_key):
        with pytest.raises(ValueError, match="in \\(0, p\\)"):
            elgamal_encrypt(0, elgamal_key)

    def test_message_round_trip(self, elgamal_key):
        rng = random.Random(21)
        for _ in range(20):
            message = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ")
                              for _ in range(rng.randint(1, 300)))
            values, lengths = encode_message(message, elgamal_key.parameters.p)
            assert all(0 <= v < elgamal_key.parameters.p for v in values)
            recovered = [elgamal_decrypt(elgamal_encrypt(v, elgamal_key), elgamal_key)
                         for v in values]
            assert recovered == values
            assert decode_message(recovered, lengths) == normalize(message)

    def test_long_message_spans_blocks(self, elgamal_key):
        values, lengths = encode_message("X" * 5000, elgamal_key.parameters.p)
        assert len(values) > 1
        assert len(values) == len(lengths)
        assert sum(lengths) == 5000

    def test_encoding_is_exact_not_padded(self, elgamal_key):
        # Decoding must not invent 'A' padding, which is what happens when the
        # block width is used to reconstruct the text.
        for message in ("A", "AB", "EOUW", "PZC040QSP"):
            values, lengths = encode_message(message, elgamal_key.parameters.p)
            assert decode_message(values, lengths) == normalize(message)


# --------------------------------------------------------------------------
# Elliptic curves
# --------------------------------------------------------------------------

class TestEllipticCurves:
    @pytest.mark.parametrize("name", list(CURVE_PARAMS))
    def test_generator_on_curve(self, name):
        assert CURVE_PARAMS[name].contains(CURVE_PARAMS[name].generator)

    @pytest.mark.parametrize("name", list(CURVE_PARAMS))
    def test_fields_are_prime(self, name):
        assert is_prime(CURVE_PARAMS[name].p)
        assert is_prime(CURVE_PARAMS[name].n)

    @pytest.mark.parametrize("name", list(CURVE_PARAMS))
    def test_generator_has_order_n(self, name):
        curve = CURVE_PARAMS[name]
        assert scalar_mult(curve, curve.n, curve.generator).is_infinity

    @pytest.mark.parametrize("name", list(CURVE_PARAMS))
    def test_negation_is_inverse(self, name):
        curve = CURVE_PARAMS[name]
        g = curve.generator
        negated = Point(g.x, (curve.p - g.y) % curve.p)
        assert point_add(curve, g, negated).is_infinity

    @pytest.mark.parametrize("name", list(CURVE_PARAMS))
    def test_scalar_mult_matches_repeated_addition(self, name):
        curve = CURVE_PARAMS[name]
        g = curve.generator
        accumulator = INFINITY
        for i in range(1, 12):
            accumulator = point_add(curve, accumulator, g)
            assert scalar_mult(curve, i, g) == accumulator

    @pytest.mark.parametrize("name", list(CURVE_PARAMS))
    def test_identity_is_neutral(self, name):
        curve = CURVE_PARAMS[name]
        g = curve.generator
        assert point_add(curve, g, INFINITY) == g
        assert point_add(curve, INFINITY, g) == g

    @pytest.mark.parametrize("name", list(CURVE_PARAMS))
    def test_keypair_consistent(self, name):
        curve = CURVE_PARAMS[name]
        d, q = ecc_keypair(curve)
        assert 1 <= d < curve.n
        assert scalar_mult(curve, d, curve.generator) == q
        assert curve.contains(q)

    @pytest.mark.parametrize("name", list(CURVE_PARAMS))
    def test_sign_and_verify(self, name):
        curve = CURVE_PARAMS[name]
        d, q = ecc_keypair(curve)
        signature = sign("HELLO 2026", d, curve)
        assert verify("HELLO 2026", signature, q, curve)

    @pytest.mark.parametrize("name", list(CURVE_PARAMS))
    def test_verify_rejects_tampered_message(self, name):
        curve = CURVE_PARAMS[name]
        d, q = ecc_keypair(curve)
        signature = sign("HELLO 2026", d, curve)
        assert not verify("TAMPERED", signature, q, curve)

    @pytest.mark.parametrize("name", list(CURVE_PARAMS))
    def test_verify_rejects_wrong_key(self, name):
        curve = CURVE_PARAMS[name]
        d, q = ecc_keypair(curve)
        _, other = ecc_keypair(curve)
        signature = sign("HELLO 2026", d, curve)
        assert not verify("HELLO 2026", signature, other, curve)

    def test_rejects_out_of_range_signature(self):
        curve = CURVE_PARAMS["secp192r1"]
        _, q = ecc_keypair(curve)
        assert not verify("msg", (0, 1), q, curve)
        assert not verify("msg", (1, 0), q, curve)

    def test_rejects_point_off_curve(self):
        curve = CURVE_PARAMS["secp192r1"]
        assert not curve.contains(Point(1, 1))
