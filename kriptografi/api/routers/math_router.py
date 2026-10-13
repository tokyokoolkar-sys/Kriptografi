"""Number-theory endpoints: gcd, modular inverse, CRT, primality, factorisation.

These are the arithmetic primitives the ciphers are built on, exposed directly so
each step can be inspected and shown alongside the cipher that uses it.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ...mathcore import (
    baby_step_giant_step,
    crt,
    euclid_steps,
    extended_gcd,
    factorize,
    gcd,
    is_prime,
    mod_inverse,
    pow_mod,
    pow_mod_trace,
    totient,
)
from ..schemas import (
    CrtRequest,
    CrtResponse,
    FactorizeRequest,
    FactorizeResponse,
    GcdRequest,
    GcdResponse,
    ModInverseRequest,
    ModInverseResponse,
    PowModRequest,
    PowModResponse,
    PrimalityRequest,
    PrimalityResponse,
    TotientRequest,
    TotientResponse,
)

router = APIRouter(prefix="/math", tags=["number theory"])


@router.post("/gcd", response_model=GcdResponse, summary="Greatest common divisor via Euclid")
def compute_gcd(request: GcdRequest) -> GcdResponse:
    """Run the Euclidean algorithm and return every division it performs.

    Returns the GCD along with the full ``a = q*b + r`` chain, so the algorithm
    can be followed step by step rather than taken on faith.
    """
    if request.b == 0 and request.a == 0:
        raise HTTPException(status_code=400, detail="gcd(0, 0) is undefined")

    try:
        steps = euclid_steps(request.a, request.b)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return GcdResponse(
        a=request.a,
        b=request.b,
        gcd=gcd(request.a, request.b),
        steps=steps,
    )


@router.post("/mod-inverse", response_model=ModInverseResponse,
             summary="Modular inverse via the extended Euclidean algorithm")
def compute_mod_inverse(request: ModInverseRequest) -> ModInverseResponse:
    """Find ``x`` with ``a * x == 1 (mod m)``.

    Uses the extended Euclidean algorithm, which returns the Bezout coefficients
    alongside the GCD. Fails when ``gcd(a, m) != 1``, since no inverse exists then.
    """
    if request.m == 0:
        raise HTTPException(status_code=400, detail="modulus must be non-zero")

    g, x, y = extended_gcd(request.a, request.m)

    if g != 1:
        raise HTTPException(
            status_code=400,
            detail=f"no modular inverse: gcd({request.a}, {request.m}) = {g} != 1",
        )

    inverse = x % request.m
    return ModInverseResponse(
        a=request.a,
        m=request.m,
        inverse=inverse,
        bezout_x=x,
        bezout_y=y,
        verification=f"{request.a}*{x} + {request.m}*{y} = {request.a * x + request.m * y}, "
                     f"so inverse = {inverse}",
    )


@router.post("/crt", response_model=CrtResponse,
             summary="Chinese Remainder Theorem for pairwise-coprime moduli")
def solve_crt(request: CrtRequest) -> CrtResponse:
    """Solve a system of simultaneous congruences.

    Returns the solution in ``[0, M)`` where ``M`` is the product of the moduli,
    plus a per-congruence check so the answer is verifiable at a glance.
    """
    try:
        solution = crt(request.residues, request.moduli)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    product = 1
    for m in request.moduli:
        product *= m

    steps = [
        {
            "modulus": m,
            "expected_residue": r,
            "actual_residue": solution % m,
            "satisfies": solution % m == r,
        }
        for r, m in zip(request.residues, request.moduli)
    ]

    return CrtResponse(
        residues=request.residues,
        moduli=request.moduli,
        solution=solution,
        modulus_product=product,
        steps=steps,
    )


@router.post("/primality", response_model=PrimalityResponse,
             summary="Test whether a number is prime")
def check_primality(request: PrimalityRequest) -> PrimalityResponse:
    """Trial division for small inputs, Miller-Rabin for large ones.

    Factorisation is included when the number is small enough to factor quickly,
    which makes the verdict easy to sanity-check by hand.
    """
    n = request.n
    prime = is_prime(n)

    factors: list[int] = []
    if n > 1 and not prime and abs(n) < 10**12:
        factors = factorize(n)

    return PrimalityResponse(n=n, is_prime=prime, factorization=factors)


@router.post("/factorize", response_model=FactorizeResponse,
             summary="Full prime factorisation by trial division")
def do_factorize(request: FactorizeRequest) -> FactorizeResponse:
    """Factorise ``n`` completely.

    Exhaustive trial division, so it is only practical for small numbers -- large
    composites are what makes RSA hard, and brute force is exactly why.
    """
    n = request.n
    if abs(n) > 10**14:
        raise HTTPException(
            status_code=400,
            detail="refusing to factor a number this large by trial division; "
                   "use Miller-Rabin or a specialised factorisation method",
        )

    factors = factorize(n) if n > 1 else []
    return FactorizeResponse(n=n, factors=factors, is_prime=is_prime(n))


@router.post("/powmod", response_model=PowModResponse,
             summary="Modular exponentiation by repeated squaring")
def compute_pow_mod(request: PowModRequest) -> PowModResponse:
    """Compute ``base ** exponent mod modulus`` with a step-by-step trace.

    Exponentiation by squaring reduces a 1024-bit exponent to about 1024
    modular multiplications, which is what makes RSA feasible at all.
    """
    if request.modulus == 0:
        raise HTTPException(status_code=400, detail="modulus must be non-zero")
    if request.exponent < 0:
        raise HTTPException(status_code=400, detail="exponent must be non-negative")

    trace = pow_mod_trace(request.base, request.exponent, request.modulus)

    return PowModResponse(
        base=request.base,
        exponent=request.exponent,
        modulus=request.modulus,
        binary_exponent=trace["binary_exponent"],
        result=trace["result"],
        steps=trace["steps"],
    )


@router.post("/totient", response_model=TotientResponse, summary="Euler's totient function")
def compute_totient(request: TotientRequest) -> TotientResponse:
    """Count the integers in ``[1, n]`` that are coprime to ``n``.

    This is the ``phi`` in RSA key generation: the order of the multiplicative
    group modulo ``n``.
    """
    if request.n < 1:
        raise HTTPException(status_code=400, detail="n must be positive")

    return TotientResponse(n=request.n, phi=totient(request.n), is_prime=is_prime(request.n))


@router.get("/discrete-log", summary="Solve a discrete logarithm with baby-step giant-step")
def solve_discrete_log(base: int, target: int, modulus: int) -> dict:
    """Find ``x`` with ``base**x == target (mod modulus)``.

    Baby-step giant-step solves this in ``O(sqrt(modulus))`` rather than
    ``O(modulus)``, the same asymptotic cost as Pollard's rho.
    """
    if modulus <= 1:
        raise HTTPException(status_code=400, detail="modulus must be greater than 1")

    x = baby_step_giant_step(base, target, modulus)

    return {
        "base": base,
        "target": target,
        "modulus": modulus,
        "discrete_log": x,
        "solution_exists": x is not None,
    }


@router.get("/verify-powmod", summary="Check a modular exponentiation result")
def verify_pow_mod(base: int, exponent: int, modulus: int, expected: int) -> dict:
    """Verify ``base**exponent mod modulus == expected``.

    Provided so the frontend can confirm a claimed result rather than trust it.
    """
    actual = pow_mod(base, exponent, modulus)
    return {
        "base": base,
        "exponent": exponent,
        "modulus": modulus,
        "expected": expected,
        "actual": actual,
        "matches": actual == expected,
    }