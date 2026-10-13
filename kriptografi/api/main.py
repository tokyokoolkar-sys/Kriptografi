"""FastAPI application factory and OpenAPI configuration."""

from __future__ import annotations

from fastapi import FastAPI

from .. import __version__
from .routers import (
    block_router,
    classical_router,
    dh_router,
    ecc_router,
    hash_router,
    math_router,
    rsa_router,
    transposition_router,
)

DESCRIPTION = """
A cryptography toolkit implemented from scratch in pure Python.

Nothing here calls a third-party crypto library. Every algorithm -- the Euclidean
algorithm, modular inverse, DES, AES, SHA-256, RSA, ECDSA -- is written out and
verified against published test vectors, so the code can be read alongside the
results it produces.

**Number theory** -- gcd, extended Euclid, modular inverse, CRT, primality, factorisation.

**Classical ciphers** -- Caesar, Vigenere, Beaufort, autokey, affine, Playfair, Hill, all over a 37-symbol alphabet of `A-Z`, `0-9`, and space.

**Transposition** -- rail fence, columnar, row transposition.

**Block ciphers** -- DES and AES built from the specification, with ECB, CBC, and CTR modes.

**Hashing** -- SHA-256 and HMAC-SHA256.

**Public key** -- RSA, Diffie-Hellman, ElGamal, and ECDSA over secp192r1 and secp256k1.

**Cryptanalysis** -- frequency analysis, index of coincidence, and key recovery for Caesar and Vigenere.

Every algorithm here is educational. The textbook RSA and ECDSA constructions
lack the padding and hardening that production requires, and DES is long
deprecated. Use a vetted library for anything real.
"""

app = FastAPI(
    title="Kriptografi API",
    description=DESCRIPTION,
    version=__version__,
    contact={"name": "Kriptografi"},
    license_info={"name": "MIT"},
)

app.include_router(math_router)
app.include_router(classical_router)
app.include_router(transposition_router)
app.include_router(block_router)
app.include_router(hash_router)
app.include_router(rsa_router)
app.include_router(dh_router)
app.include_router(ecc_router)


@app.get("/", tags=["meta"], summary="API overview")
def root() -> dict:
    """List the route groups, as a map of name to prefix."""
    return {
        "name": "Kriptografi API",
        "version": __version__,
        "docs": "/docs",
        "openapi": "/openapi.json",
        "endpoints": {
            "number theory": "/math",
            "classical ciphers": "/classical",
            "transposition & analysis": "/transposition",
            "block ciphers": "/block",
            "hashing": "/hash",
            "rsa": "/rsa",
            "diffie-hellman & elgamal": "/dh",
            "elliptic curves": "/ecc",
        },
    }


@app.get("/health", tags=["meta"], summary="Health check")
def health() -> dict:
    """Liveness probe."""
    return {"status": "ok", "version": __version__}