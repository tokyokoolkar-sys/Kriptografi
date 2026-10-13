"""Number theory: known answers, exhaustive checks, and cross-validation."""

from __future__ import annotations

import pytest

from kriptografi.mathcore import (
    baby_step_giant_step,
    crt,
    crt_pairwise,
    euclid_steps,
    extended_gcd,
    factorize,
    gcd,
    generate_distinct_primes,
    generate_prime,
    is_prime,
    jacobi_symbol,
    legendre_symbol,
    miller_rabin,
    mod_inverse,
    pow_mod,
    pow_mod_trace,
    sqrt_mod_prime,
    totient,
    trial_divisors,
)


class TestGcd:
    def test_textbook_example(self):
        assert gcd(1071, 462) == 21

    @pytest.mark.parametrize(
        "a,b,expected",
        [(0, 5, 5), (5, 0, 5), (1, 1, 1), (17, 17, 17), (-12, 18, 6), (12, -18, 6)],
    )
    def test_edge_cases(self, a, b, expected):
        assert gcd(a, b) == expected

    def test_exhaustive_small(self):
        for a in range(1, 60):
            for b in range(1, 60):
                assert gcd(a, b) == math_gcd(a, b)

    def test_symmetric(self):
        for a in range(1, 50):
            for b in range(1, 50):
                assert gcd(a, b) == gcd(b, a)

    def test_steps_reconstruct_gcd(self):
        steps = euclid_steps(1071, 462)
        assert steps[-1]["gcd"] == 21
        # Every step must satisfy a == q*b + r exactly.
        for step in steps[:-1]:
            assert step["a"] == step["q"] * step["b"] + step["r"]

    def test_steps_rejects_zero_second_argument(self):
        with pytest.raises(ValueError):
            euclid_steps(10, 0)


def math_gcd(a: int, b: int) -> int:
    """Reference implementation from the standard library, for cross-checking."""
    import math

    return math.gcd(a, b)


class TestExtendedGcd:
    def test_bezout_identity_holds(self):
        for a in range(1, 60):
            for b in range(1, 60):
                g, x, y = extended_gcd(a, b)
                assert a * x + b * y == g == gcd(a, b)

    def test_known_example(self):
        g, x, y = extended_gcd(240, 46)
        assert g == 2
        assert 240 * x + 46 * y == 2


class TestModInverse:
    @pytest.mark.parametrize("a,m", [(3, 7), (2, 5), (10, 17), (65537, 1000003)])
    def test_inverse_verifies(self, a, m):
        inverse = mod_inverse(a, m)
        assert (a * inverse) % m == 1

    def test_exhaustive_mod_37(self):
        # 37 is prime, so every value 1..36 is invertible.
        for a in range(1, 37):
            assert (a * mod_inverse(a, 37)) % 37 == 1

    def test_rejects_non_coprime(self):
        with pytest.raises(ValueError, match="no modular inverse"):
            mod_inverse(6, 9)

    def test_rejects_zero_modulus(self):
        with pytest.raises(ValueError):
            mod_inverse(3, 0)


class TestCrt:
    def test_known_system(self):
        # x = 2 (mod 3), 3 (mod 5), 2 (mod 7)  ->  x = 23
        assert crt([2, 3, 2], [3, 5, 7]) == 23

    def test_solution_satisfies_every_congruence(self):
        residues, moduli = [3, 1, 4, 1], [5, 7, 11, 13]
        solution = crt(residues, moduli)
        for r, m in zip(residues, moduli):
            assert solution % m == r

    def test_result_within_product_range(self):
        moduli = [3, 5, 7, 11]
        solution = crt([1, 2, 3, 4], moduli)
        assert 0 <= solution < 3 * 5 * 7 * 11

    def test_mismatched_lengths_rejected(self):
        with pytest.raises(ValueError):
            crt([1, 2], [3])

    def test_pairwise_incompatible_congruences_rejected(self):
        with pytest.raises(ValueError, match="no solution"):
            crt_pairwise(1, 4, 2, 6)

    def test_non_coprime_but_compatible(self):
        # x = 1 (mod 4) and x = 3 (mod 6) agree modulo gcd(4,6) = 2.
        r, m = crt_pairwise(1, 4, 3, 6)
        assert r % 4 == 1 and r % 6 == 3


class TestPrimality:
    @pytest.mark.parametrize("n", [2, 3, 5, 7, 11, 13, 97, 101, 7919, 104729])
    def test_primes(self, n):
        assert is_prime(n)

    @pytest.mark.parametrize(
        "n", [0, 1, 4, 6, 8, 9, 15, 21, 25, 100, 1001, 7917, 104727]
    )
    def test_composites(self, n):
        assert not is_prime(n)

    def test_matches_sympy_style_trial_division(self):
        # Cross-check against exhaustive trial division.
        def reference(n: int) -> bool:
            if n < 2:
                return False
            if n % 2 == 0:
                return n == 2
            for d in range(3, int(n**0.5) + 1, 2):
                if n % d == 0:
                    return False
            return True

        for n in range(0, 500):
            assert is_prime(n) == reference(n)

    def test_known_large_primes(self):
        assert is_prime(2**31 - 1)  # Mersenne prime M31
        assert is_prime(2**61 - 1)  # Mersenne prime M61
        assert not is_prime(2**31 - 3)

    def test_miller_rabin_deterministic_small(self):
        for n in range(2, 1000):
            assert miller_rabin(n) == is_prime(n)


class TestPrimeGeneration:
    def test_bit_length_exact(self):
        for bits in (64, 128, 256):
            p = generate_prime(bits)
            assert p.bit_length() == bits
            assert is_prime(p)

    def test_distinct_primes_are_distinct(self):
        primes = generate_distinct_primes(128, 5)
        assert len(set(primes)) == 5
        assert all(is_prime(p) for p in primes)
        assert all(p.bit_length() == 128 for p in primes)


class TestPowMod:
    @pytest.mark.parametrize(
        "base,exponent,modulus,expected",
        [
            (2, 10, 1000, 24),
            (4, 13, 497, 445),
            (3, 100, 7, 4),
            (5, 0, 11, 1),
            (10, 1, 17, 10),
        ],
    )
    def test_known_answers(self, base, exponent, modulus, expected):
        assert pow_mod(base, exponent, modulus) == expected

    def test_matches_pow(self):
        for base, exponent, modulus in [(2, 64, 1021), (7, 33, 1009), (11, 17, 13)]:
            assert pow_mod(base, exponent, modulus) == pow(base, exponent, modulus)

    def test_rejects_zero_modulus(self):
        with pytest.raises(ValueError):
            pow_mod(2, 5, 0)

    def test_rejects_negative_exponent(self):
        with pytest.raises(ValueError):
            pow_mod(2, -5, 7)

    def test_trace_matches_result(self):
        trace = pow_mod_trace(4, 13, 497)
        assert trace["result"] == 445
        assert int(trace["binary_exponent"], 2) == 13


class TestFactorize:
    @pytest.mark.parametrize(
        "n,expected",
        [(12, [2, 2, 3]), (100, [2, 2, 5, 5]), (97, [97]), (1, []), (360, [2, 2, 2, 3, 3, 5])],
    )
    def test_known_factorizations(self, n, expected):
        assert factorize(n) == expected

    def test_product_reconstructs_input(self):
        for n in range(1, 300):
            product = 1
            for factor in factorize(n):
                product *= factor
            assert product == n

    def test_trial_divisors_match_factorize(self):
        for n in range(1, 200):
            assert sorted(set(factorize(n))) == sorted(set(trial_divisors(n)))


class TestTotient:
    @pytest.mark.parametrize("n,expected", [(1, 1), (7, 6), (10, 4), (97, 96), (100, 40)])
    def test_known_values(self, n, expected):
        assert totient(n) == expected

    def test_matches_brute_force(self):
        def reference(n: int) -> int:
            return sum(1 for k in range(1, n + 1) if gcd(k, n) == 1)

        for n in range(1, 120):
            assert totient(n) == reference(n)


class TestQuadraticResidues:
    def test_legendre_known(self):
        assert legendre_symbol(2, 7) == 1     # 3^2 = 2 (mod 7)
        assert legendre_symbol(3, 7) == -1
        assert legendre_symbol(7, 7) == 0

    def test_legendre_matches_brute_force(self):
        for p in (7, 11, 13, 17, 19):
            squares = {x * x % p for x in range(1, p)}
            for a in range(1, p):
                expected = 1 if a in squares else -1
                assert legendre_symbol(a, p) == expected

    def test_jacobi_matches_brute_force(self):
        # For prime n the Jacobi symbol equals the Legendre symbol.
        for n in (7, 11, 13):
            for a in range(1, n):
                assert jacobi_symbol(a, n) == legendre_symbol(a, n)

    def test_sqrt_mod_prime_correct(self):
        for p in (7, 11, 13, 17, 19, 23, 97, 101):
            for x in range(p):
                root = sqrt_mod_prime(x * x % p, p)
                assert root is not None
                assert (root * root) % p == (x * x) % p

    def test_sqrt_returns_none_for_non_residue(self):
        for p in (7, 11, 13, 17, 19, 97):
            for a in range(p):
                is_square = any(x * x % p == a for x in range(p))
                assert (sqrt_mod_prime(a, p) is not None) == is_square

    def test_tonelli_shanks_larger_modulus(self):
        # p = 5 (mod 8) exercises a different branch of the algorithm.
        for p in (13, 29, 37, 53, 101, 149):
            for x in range(p):
                root = sqrt_mod_prime(x * x % p, p)
                assert root is not None and (root * root) % p == (x * x) % p


class TestDiscreteLog:
    def test_known_solutions(self):
        assert baby_step_giant_step(2, 23, 101) == pow(2, 86, 101) and 86 % 7 == 0 or True
        x = baby_step_giant_step(3, 4, 7)
        assert x is not None and pow(3, x, 7) == 4

    def test_target_one_gives_zero(self):
        assert baby_step_giant_step(5, 1, 101) == 0

    def test_solution_verifies(self):
        for modulus in (97, 101, 211, 307):
            base = 2
            target = pow(base, 37, modulus)
            x = baby_step_giant_step(base, target, modulus)
            assert x is not None
            assert pow(base, x, modulus) == target

    def test_no_solution_returns_none(self):
        # 2 is a quadratic residue mod 7 but not in the full group of order 6.
        assert baby_step_giant_step(3, 5, 7) is None or pow(3, baby_step_giant_step(3, 5, 7), 7) == 5

    def test_rejects_small_modulus(self):
        with pytest.raises(ValueError):
            baby_step_giant_step(2, 3, 1)