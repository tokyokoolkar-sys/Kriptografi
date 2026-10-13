"""Elliptic-curve cryptography over short Weierstrass curves ``y^2 = x^3 + ax + b``.

The group law uses point addition with modular inverse, and scalar multiplication
is done by double-and-add on that law. ECC reaches a given security level with far
smaller keys than RSA -- a 256-bit curve offers roughly the strength of a
3072-bit RSA modulus, which is why it matters on constrained devices.

Implemented on curves over prime fields (``a, b, p``) with prime order ``n``.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from ..mathcore import mod_inverse

__all__ = [
    "Point",
    "Curve",
    "CURVE_PARAMS",
    "point_add",
    "point_double",
    "scalar_mult",
    "generate_keypair",
    "sign",
    "verify",
    "on_curve",
]


@dataclass(frozen=True)
class Point:
    """A curve point. ``None`` for either coordinate means the point at infinity."""

    x: int | None
    y: int | None

    @property
    def is_infinity(self) -> bool:
        return self.x is None and self.y is None

    def __str__(self) -> str:
        if self.is_infinity:
            return "O"
        return f"({self.x}, {self.y})"


INFINITY = Point(None, None)


@dataclass(frozen=True)
class Curve:
    """A short Weierstrass curve over the prime field ``p``."""

    p: int
    a: int
    b: int
    n: int  # order of the base point
    gx: int
    gy: int

    @property
    def generator(self) -> Point:
        return Point(self.gx, self.gy)

    def contains(self, point: Point) -> bool:
        """True when ``point`` satisfies ``y^2 == x^3 + ax + b (mod p)``."""
        if point.is_infinity:
            return True
        if point.x is None or point.y is None:
            return False
        return (point.y * point.y - (pow(point.x, 3, self.p) + self.a * point.x + self.b)) % self.p == 0


def on_curve(curve: Curve, point: Point) -> bool:
    """Check that a point lies on the curve."""
    return curve.contains(point)


# --------------------------------------------------------------------------
# Group law
# --------------------------------------------------------------------------

def point_double(curve: Curve, point: Point) -> Point:
    """Double a point via the tangent-line formula.

    Uses the slope ``lambda = (3x^2 + a) / (2y)``. When ``y == 0`` the tangent
    is vertical and the result is the point at infinity.
    """
    if point.is_infinity or point.y == 0:
        return INFINITY

    numerator = (3 * point.x * point.x + curve.a) % curve.p
    denominator = (2 * point.y) % curve.p
    lam = numerator * mod_inverse(denominator, curve.p) % curve.p

    x3 = (lam * lam - 2 * point.x) % curve.p
    y3 = (lam * (point.x - x3) - point.y) % curve.p

    return Point(x3, y3)


def point_add(curve: Curve, p1: Point, p2: Point) -> Point:
    """Add two curve points.

    Three cases: an identity operand returns the other point, two points with the
    same ``x`` are negatives of each other (or a doubling), and everything else
    uses the chord slope ``lambda = (y2-y1) / (x2-x1)``.
    """
    if p1.is_infinity:
        return p2
    if p2.is_infinity:
        return p1

    if p1.x == p2.x:
        if (p1.y + p2.y) % curve.p == 0:
            return INFINITY
        return point_double(curve, p1)

    numerator = (p2.y - p1.y) % curve.p
    denominator = (p2.x - p1.x) % curve.p
    lam = numerator * mod_inverse(denominator, curve.p) % curve.p

    x3 = (lam * lam - p1.x - p2.x) % curve.p
    y3 = (lam * (p1.x - x3) - p1.y) % curve.p

    return Point(x3, y3)


def scalar_mult(curve: Curve, k: int, point: Point) -> Point:
    """Multiply a point by a scalar via double-and-add.

    Each bit of ``k`` either doubles the running result or adds the base point,
    so the whole multiplication costs at most ``2 * bit_length(k)`` group
    operations.
    """
    if k < 0:
        return scalar_mult(curve, -k, Point(point.x, (curve.p - point.y) % curve.p if point.y else None))
    if k == 0 or point.is_infinity:
        return INFINITY

    result = INFINITY
    addend = point

    while k:
        if k & 1:
            result = point_add(curve, result, addend)
        addend = point_double(curve, addend)
        k >>= 1

    return result


# --------------------------------------------------------------------------
# Named curves
# --------------------------------------------------------------------------

# Standard short Weierstrass curves over prime fields. These are the NIST/SECG
# parameter sets, kept so ECDSA behaves exactly as it does in practice.
CURVE_PARAMS: dict[str, Curve] = {
    "secp192r1": Curve(
        p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF,
        a=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC,
        b=0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1,
        n=0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831,
        gx=0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012,
        gy=0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811,
    ),
    "secp256k1": Curve(
        p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        a=0,
        b=7,
        n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
        gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    ),
}


def generate_keypair(curve: Curve) -> tuple[int, Point]:
    """Pick a private scalar in ``[1, n-1]`` and publish ``d * G``.

    Publishing only ``Q = dG`` reveals nothing about ``d`` without solving the
    discrete logarithm problem on the curve.
    """
    d = secrets.randbelow(curve.n - 1) + 1
    return d, scalar_mult(curve, d, curve.generator)


# --------------------------------------------------------------------------
# ECDSA
# --------------------------------------------------------------------------

def _hash_to_int(message: str, n: int) -> int:
    """Hash a message and reduce it into the curve order."""
    from ..hashes import sha256

    return int(sha256(message), 16) % n


def sign(message: str, d: int, curve: Curve) -> tuple[int, int]:
    """ECDSA signature ``(r, s)``.

    Pick a random ``k``, compute ``R = kG``, take ``r = R.x mod n``, then
    ``s = k^-1 (H(m) + r*d) mod n``. The nonce must be secret and never reused:
    reusing ``k`` across two signatures exposes ``d`` algebraically.
    """
    z = _hash_to_int(message, curve.n)

    while True:
        k = secrets.randbelow(curve.n - 1) + 1
        point = scalar_mult(curve, k, curve.generator)

        if point.is_infinity:
            continue

        r = point.x % curve.n
        if r == 0:
            continue

        s = mod_inverse(k, curve.n) * (z + r * d) % curve.n
        if s == 0:
            continue

        return r, s


def verify(message: str, signature: tuple[int, int], public_point: Point, curve: Curve) -> bool:
    """Verify an ECDSA signature ``(r, s)``.

    Recomputes ``u1 = H(m)/s`` and ``u2 = r/s``, forms ``P = u1*G + u2*Q``, and
    accepts when ``P.x mod n == r``.
    """
    r, s = signature

    if not (1 <= r < curve.n and 1 <= s < curve.n):
        return False

    z = _hash_to_int(message, curve.n)

    w = mod_inverse(s, curve.n)
    u1 = z * w % curve.n
    u2 = r * w % curve.n

    point = point_add(curve,
                      scalar_mult(curve, u1, curve.generator),
                      scalar_mult(curve, u2, public_point))

    if point.is_infinity:
        return False

    return point.x % curve.n == r