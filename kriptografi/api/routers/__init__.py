"""API routers, one module per domain.

Each name exported here is the router *object*, so :mod:`kriptografi.api.main`
can attach them directly.
"""

from .block_router import block_router, dh_router, ecc_router, hash_router, rsa_router
from .classical_router import router as classical_router
from .math_router import router as math_router
from .transposition_router import router as transposition_router

__all__ = [
    "math_router",
    "classical_router",
    "transposition_router",
    "block_router",
    "hash_router",
    "rsa_router",
    "dh_router",
    "ecc_router",
]