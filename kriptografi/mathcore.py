"""Number theory primitives that every other module builds on.

Everything here is implemented from first principles -- no third-party maths
library. Functions are written as plain Python ints so results are exact and
reproducible; no floating point is used anywhere in this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import isqrt

__all__ = [
    "gcd",
    "extended_gcd",
    "euclid_steps",
    "bezout",
    "mod_inverse",
    "mod_inverse_vector",
    "crt",
    "crt_pairwise",
    "is_prime",
    "trial_divisors",
    "miller_rabin",
    "generate_prime",
    "generate_distinct_primes",
    "pow_mod",
    "pow_mod_trace",
    "factorize",
    "totient",
    "is_coprime",
    "legendre_symbol",
    "jacobi_symbol",
    "sqrt_mod_prime",
    "baby_step_giant_step",
    "is_quadratic_residue",
]

NumberTheoryError = ArithmeticError


# --------------------------------------------------------------------------
# Greatest common divisor
# --------------------------------------------------------------------------

def gcd(a: int, b: int) -> int:
    """Greatest common divisor via the Euclidean algorithm.

    Uses the iterative form of ``a, b = b, a % b``, which always converges
    because the remainder is strictly smaller than the divisor.
    """
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm.

    Returns ``(g, x, y)`` such that ``a * x + b * y == g == gcd(a, b)``.
    The coefficients are produced alongside the GCD in a single pass using the
    old-remainder / old-coefficient bookkeeping form.
    """
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y

    return old_r, old_x, old_y


def euclid_steps(a: int, b: int) -> list[dict]:
    """Run the Euclidean algorithm and return every division it performs.

    Useful for teaching: each entry shows one line of the classic
    ``a = q*b + r`` chain, ending with ``gcd(a, b) = g`` when ``r`` hits zero.
    """
    if b == 0:
        raise ValueError("second argument must be non-zero to show Euclid steps")

    steps: list[dict] = []
    x, y = abs(a), abs(b)

    while y != 0:
        q, r = divmod(x, y)
        steps.append({"a": x, "b": y, "q": q, "r": r, "equation": f"{x} = {q}*{y} + {r}"})
        x, y = y, r

    steps.append({"a": x, "b": 0, "q": None, "r": 0, "gcd": x, "equation": f"gcd = {x}"})
    return steps


def bezout(a: int, b: int) -> tuple[int, int]:
    """Return ``(x, y)`` with ``a * x + b * y == gcd(a, b)``."""
    _, x, y = extended_gcd(a, b)
    return x, y


# --------------------------------------------------------------------------
# Modular inverse
# --------------------------------------------------------------------------

def mod_inverse(a: int, m: int) -> int:
    """Modular multiplicative inverse of ``a`` modulo ``m``.

    Raises ``ValueError`` when the inverse does not exist, which happens
    exactly when ``gcd(a, m) != 1``.
    """
    if m == 0:
        raise ValueError("modulus must be non-zero")

    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(
            f"no modular inverse: gcd({a}, {m}) = {g} != 1, so {a} is not invertible mod {m}"
        )

    return x % m


def mod_inverse_vector(values: list[int], m: int) -> list[int]:
    """Invert every entry of a matrix modulo ``m`` (detached inverses are fine)."""
    return [mod_inverse(v, m) for v in values]


def is_coprime(a: int, b: int) -> bool:
    """True when ``a`` and ``b`` share no prime factor other than 1."""
    return gcd(a, b) == 1


# --------------------------------------------------------------------------
# Chinese Remainder Theorem
# --------------------------------------------------------------------------

def crt(residues: list[int], moduli: list[int]) -> int:
    """Chinese Remainder Theorem for ``len(residues) == len(moduli)`` systems.

    Returns the unique solution in ``[0, M)`` where ``M`` is the product of the
    moduli. Requires the moduli to be pairwise coprime.
    """
    if len(residues) != len(moduli):
        raise ValueError("residues and moduli must have the same length")
    if not residues:
        raise ValueError("need at least one congruence")

    for m in moduli:
        if m == 0:
            raise ValueError("moduli must be non-zero")

    # Fold the congruences pairwise using the multiplicative form of CRT.
    current_r, current_m = residues[0] % moduli[0], moduli[0]
    for r, m in zip(residues[1:], moduli[1:]):
        current_r, current_m = crt_pairwise(current_r, current_m, r % m, m)

    return current_r % current_m


def crt_pairwise(r1: int, m1: int, r2: int, m2: int) -> tuple[int, int]:
    """Merge two congruences ``x = r1 (mod m1)`` and ``x = r2 (mod m2)``.

    Returns ``(r, m)`` with ``m == lcm(m1, m2)``. When ``m1`` and ``m2`` are
    coprime this is the product; when they share factors CRT still has a
    solution provided the two congruences agree modulo the shared factor.
    """
    g, p, _ = extended_gcd(m1, m2)
    if (r2 - r1) % g != 0:
        raise ValueError(
            f"no solution: congruences x = {r1} (mod {m1}) and x = {r2} (mod {m2}) "
            f"are incompatible because their moduli share factor {g}"
        )

    lcm = m1 // g * m2
    delta = ((r2 - r1) // g * p) % (m2 // g) if m2 // g != 1 else 0
    x = (r1 + m1 * delta) % lcm

    return x, lcm


# --------------------------------------------------------------------------
# Primality
# --------------------------------------------------------------------------

def trial_divisors(n: int, limit: int | None = None) -> list[int]:
    """Prime divisors of ``n`` found by trial division up to ``sqrt(n)``.

    Returns the list of distinct prime factors. With ``limit`` set, stops once
    the bound is exceeded, which makes it useful as a teaching aid even on
    numbers far too large to fully factor.
    """
    n = abs(n)
    factors: list[int] = []
    d = 2

    while d * d <= n:
        if n % d == 0:
            factors.append(d)
            while n % d == 0:
                n //= d
        d += 1 if d == 2 else 2
        if limit is not None and d > limit:
            break

    if n > 1:
        factors.append(n)

    return factors


def _small_primes_upto(limit: int) -> list[int]:
    sieve = [True] * (limit + 1)
    sieve[0:2] = [False, False]
    for i in range(2, int(limit**0.5) + 1):
        if sieve[i]:
            for j in range(i * i, limit + 1, i):
                sieve[j] = False
    return [i for i, v in enumerate(sieve) if v]


_SMALL_PRIMES = _small_primes_upto(1000)


def is_prime(n: int) -> bool:
    """Primality test: trial division on small numbers, Miller-Rabin beyond.

    Miller-Rabin is deterministic for every input below ``3_317_044_064_679_847_847_061``
    using the first thirteen prime bases, and overwhelmingly reliable above it.
    """
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    return miller_rabin(n)


def miller_rabin(n: int, rounds: int = 40, rng=None) -> bool:
    """Probabilistic primality test with an optional round count.

    Writing ``n - 1 = d * 2**s`` with ``d`` odd, each random base ``a`` is
    checked to see whether ``a**d == 1`` or ``a**(d * 2**r) == -1`` for some
    ``r < s``. A composite fails for at most a quarter of all bases.
    """
    import random

    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Strip the small primes first: it is much faster than factoring d out.
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    generator = rng or random.SystemRandom()
    bases = _SMALL_PRIMES[:rounds] if rounds <= len(_SMALL_PRIMES) else _SMALL_PRIMES

    for a in bases:
        a %= n
        if a < 2:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits: int, rng=None) -> int:
    """Generate a probable prime with exactly ``bits`` bits.

    Top two bits are set so ``2**(bits-1) <= p < 2**bits`` holds, and the
    candidate is nudged up to the next odd number before testing.
    """
    import random

    if bits < 2:
        raise ValueError("need at least 2 bits")
    generator = rng or random.SystemRandom()

    while True:
        candidate = generator.getrandbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if is_prime(candidate):
            return candidate


def generate_distinct_primes(bits: int, count: int, rng=None) -> list[int]:
    """Generate ``count`` distinct primes of the same bit length."""
    seen: set[int] = set()
    result: list[int] = []
    while len(result) < count:
        p = generate_prime(bits, rng=rng)
        if p not in seen:
            seen.add(p)
            result.append(p)
    return result


# --------------------------------------------------------------------------
# Modular exponentiation
# --------------------------------------------------------------------------

def pow_mod(base: int, exponent: int, modulus: int) -> int:
    """Modular exponentiation by repeated squaring.

    Reduces after every multiplication so the intermediate values stay bounded
    by ``modulus`` regardless of how large the exponent is.
    """
    if modulus == 0:
        raise ValueError("modulus must be non-zero")
    if modulus < 0:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        raise ValueError("exponent must be non-negative")

    result = 1 % modulus
    base %= modulus
    e = exponent
    while e:
        if e & 1:
            result = result * base % modulus
        base = base * base % modulus
        e >>= 1
    return result


def pow_mod_trace(base: int, exponent: int, modulus: int) -> dict:
    """Square-and-multiply with every intermediate value recorded.

    ``exponent`` is shown in binary alongside the per-step accumulator so the
    algorithm can be walked through by hand.
    """
    if modulus == 0:
        raise ValueError("modulus must be non-zero")

    steps: list[dict] = []
    result = 1 % modulus
    b = base % modulus
    e = exponent

    if e < 0:
        raise ValueError("exponent must be non-negative")

    while e:
        steps.append({"bit": e & 1, "accumulator": result, "base": b, "exponent": e})
        if e & 1:
            result = result * b % modulus
        b = b * b % modulus
        e >>= 1

    return {
        "base": base,
        "exponent": exponent,
        "modulus": modulus,
        "binary_exponent": format(exponent, "b"),
        "steps": steps,
        "result": result % modulus,
    }


# --------------------------------------------------------------------------
# Factorization and totient
# --------------------------------------------------------------------------

def factorize(n: int) -> list[int]:
    """Full prime factorization of ``n``, sorted ascending with multiplicity."""
    n = abs(n)
    factors: list[int] = []
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.append(d)
            n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        factors.append(n)
    return factors


def totient(n: int) -> int:
    """Euler's totient ``phi(n)``: count of integers in [1, n] coprime to n."""
    if n < 1:
        raise ValueError("n must be positive")
    result = n
    for p in set(factorize(n)):
        result -= result // p
    return result


# --------------------------------------------------------------------------
# Quadratic residues
# --------------------------------------------------------------------------

def legendre_symbol(a: int, p: int) -> int:
    """Legendre symbol ``(a/p)`` for prime ``p``: 1, -1, or 0."""
    if p < 2 or not is_prime(p):
        raise ValueError("Legendre symbol requires an odd prime modulus")
    a %= p
    if a == 0:
        return 0
    result = pow_mod(a, (p - 1) // 2, p)
    return -1 if result == p - 1 else 1


def jacobi_symbol(a: int, n: int) -> int:
    """Jacobi symbol ``(a/n)`` for odd positive ``n``.

    Generalises the Legendre symbol to composite moduli; computed with the
    reciprocity rules rather than by direct enumeration.
    """
    if n <= 0 or n % 2 == 0:
        raise ValueError("Jacobi symbol requires a positive odd modulus")

    a %= n
    result = 1

    while a != 0:
        # Strip factors of two: (2/n) = -1 when n = 3 or 5 (mod 8).
        while a % 2 == 0:
            a //= 2
            if n % 8 in (3, 5):
                result = -result

        a, n = n, a
        # Quadratic reciprocity: swap sign when both are 3 (mod 4).
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a %= n

    return result if n == 1 else 0


def is_quadratic_residue(a: int, p: int) -> bool:
    """True when ``a`` is a square modulo prime ``p``."""
    return legendre_symbol(a, p) >= 0


def sqrt_mod_prime(a: int, p: int) -> int | None:
    """Modular square root of ``a`` modulo prime ``p`` via Tonelli-Shanks.

    Returns one of the two roots (or the unique one when ``a == 0``), or
    ``None`` when ``a`` is not a quadratic residue.
    """
    if not is_prime(p):
        raise ValueError("modulus must be prime")
    if p == 2:
        return a % 2

    a %= p
    if a == 0:
        return 0

    if legendre_symbol(a, p) == -1:
        return None

    # p == 3 (mod 4): the root is just a raised to (p+1)/4, since squaring that
    # gives a^((p+1)/2) == a * a^((p-1)/2) == a by Euler's criterion.
    if p % 4 == 3:
        return pow_mod(a, (p + 1) // 4, p)

    # Otherwise p == 1 (mod 4), which needs the full Tonelli-Shanks: write
    # p - 1 = q * 2**s with q odd, then repeatedly square a correction factor
    # until the invariant t == 1 holds. (The p % 8 == 5 shortcut is deliberately
    # not used here; it is easy to get wrong and the general path is short.)
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1

    z = 2
    while legendre_symbol(z, p) != -1:
        z += 1

    m, c, t, r = s, pow_mod(z, q, p), pow_mod(a, q, p), pow_mod(a, (q + 1) // 2, p)
    while t != 1:
        # Find the smallest i with t**(2**i) == 1. Since a is a residue, such an
        # i exists with i < m; if not, something is wrong with the inputs.
        i, t2 = 0, t
        while t2 != 1:
            t2 = t2 * t2 % p
            i += 1
            if i >= m:
                return None

        b = pow_mod(c, 1 << (m - i - 1), p)
        m, c = i, b * b % p
        t = t * c % p
        r = r * b % p

    return r


# --------------------------------------------------------------------------
# Discrete logarithm
# --------------------------------------------------------------------------

def baby_step_giant_step(base: int, target: int, modulus: int) -> int | None:
    """Solve ``base**x == target (mod modulus)`` with baby-step giant-step.

    Runs in ``O(sqrt(modulus))`` memory and time instead of the ``O(modulus)``
    naive search. Returns the smallest non-negative ``x`` found, or ``None``
    when no solution exists within the searched range.
    """
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")

    base %= modulus
    target %= modulus
    if target == 1:
        return 0

    n = isqrt(modulus) + 1
    factor = mod_inverse(pow_mod(base, n, modulus), modulus)

    table: dict[int, int] = {}
    value = 1
    for j in range(n):
        table.setdefault(value, j)
        value = value * base % modulus

    gamma = target
    for i in range(n + 1):
        if gamma in table:
            x = i * n + table[gamma]
            if pow_mod(base, x, modulus) == target:
                return x
        gamma = gamma * factor % modulus

    return None


@dataclass(frozen=True)
class TrialDivisionResult:
    """Outcome of a trial-division search, useful for teaching scaffolding."""

    n: int
    bound: int
    primes_found: list[int]
    exhausted: bool

    @property
    def is_probably_prime(self) -> bool:
        return not self.primes_found and self.exhausted