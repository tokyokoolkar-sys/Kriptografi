"""Classical cipher endpoints: Caesar, Vigenere, Beaufort, affine, Playfair, Hill.

Each route takes an ``operation`` of encrypt or decrypt and returns the result
along with the parameters used, so the interface can show the round trip.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ...alphabet import ALPHABET_SIZE
from ...classical import (
    affine_decrypt,
    affine_encrypt,
    autokey,
    beaufort,
    caesar,
    hill_decrypt,
    hill_encrypt,
    playfair_decrypt,
    playfair_encrypt,
    valid_affine_keys,
    vigenere,
)
from ..schemas import (
    AffineRequest,
    AffineResponse,
    CaesarRequest,
    CaesarResponse,
    HillRequest,
    HillResponse,
    PlayfairRequest,
    PlayfairResponse,
    VigenereRequest,
    VigenereResponse,
)

router = APIRouter(prefix="/classical", tags=["classical ciphers"])


@router.post("/caesar/encrypt", response_model=CaesarResponse, summary="Caesar cipher encrypt")
def caesar_encrypt(request: CaesarRequest) -> CaesarResponse:
    """Shift every character by ``shift`` places, modulo 37.

    Because the alphabet is 37 symbols wide (A-Z, 0-9, space), digits survive the
    round trip without any preprocessing.
    """
    return CaesarResponse(
        text=request.text,
        shift=request.shift,
        result=caesar(request.text, request.shift),
        alphabet_size=ALPHABET_SIZE,
    )


@router.post("/caesar/decrypt", response_model=CaesarResponse, summary="Caesar cipher decrypt")
def caesar_decrypt(request: CaesarRequest) -> CaesarResponse:
    """Undo a Caesar shift by negating it."""
    return CaesarResponse(
        text=request.text,
        shift=request.shift,
        result=caesar(request.text, request.shift, decrypt=True),
        alphabet_size=ALPHABET_SIZE,
    )


@router.post("/vigenere", response_model=VigenereResponse, summary="Vigenere cipher")
def vigenere_route(request: VigenereRequest) -> VigenereResponse:
    """Encrypt or decrypt with a repeating key, ``c = (p +/- k) mod 37``.

    The key must be supplied. Recovering an unknown key is a separate problem --
    see ``/transposition/analysis/crack-vigenere``, which tests every candidate
    key length and scores the result on English-like letter patterns.
    """
    if not request.key.strip():
        raise HTTPException(status_code=400, detail="key must not be empty")

    result = vigenere(request.text, request.key, decrypt=request.operation == "decrypt")

    return VigenereResponse(
        text=request.text,
        key=request.key,
        operation=request.operation,
        result=result,
    )


@router.post("/beaufort", response_model=VigenereResponse,
             summary="Beaufort cipher (self-inverse)")
def beaufort_route(request: VigenereRequest) -> VigenereResponse:
    """Encrypt or decrypt with ``c = (k - p) mod 37``.

    Encryption and decryption are the same operation, so the ``operation`` field
    changes nothing -- which is the point of a self-inverse cipher.
    """
    if not request.key.strip():
        raise HTTPException(status_code=400, detail="key must not be empty")

    return VigenereResponse(
        text=request.text,
        key=request.key,
        operation=request.operation,
        result=beaufort(request.text, request.key),
    )


@router.post("/autokey", response_model=VigenereResponse,
             summary="Autokey cipher (key extended by the message)")
def autokey_route(request: VigenereRequest) -> VigenereResponse:
    """Encrypt or decrypt with a self-extending key.

    The key is extended by the message itself, removing the periodicity that
    makes Vigenere breakable by the Kasiski examination.
    """
    if not request.key.strip():
        raise HTTPException(status_code=400, detail="key must not be empty")

    return VigenereResponse(
        text=request.text,
        key=request.key,
        operation=request.operation,
        result=autokey(request.text, request.key, decrypt=request.operation == "decrypt"),
    )


@router.post("/affine", response_model=AffineResponse, summary="Affine cipher")
def affine_route(request: AffineRequest) -> AffineResponse:
    """Encrypt or decrypt with ``c = (a*p + b) mod 37``.

    Decryption needs the modular inverse of ``a``, which exists exactly when
    ``gcd(a, 37) == 1`` -- true for every non-zero ``a``, since 37 is prime.
    """
    try:
        if request.operation == "decrypt":
            result = affine_decrypt(request.text, request.a, request.b)
        else:
            result = affine_encrypt(request.text, request.a, request.b)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return AffineResponse(
        text=request.text,
        a=request.a,
        b=request.b,
        operation=request.operation,
        result=result,
    )


@router.get("/affine/keys", summary="List every valid affine key")
def list_affine_keys() -> dict:
    """All ``(a, b)`` pairs that yield a reversible affine cipher.

    There are ``phi(37) * 37 = 1332`` of them -- few enough to exhaust in one
    pass, which is exactly why the affine cipher offers no real security.
    """
    keys = valid_affine_keys()
    return {
        "count": len(keys),
        "modulus": ALPHABET_SIZE,
        "keys": [[a, b] for a, b in keys],
    }


@router.post("/playfair", response_model=PlayfairResponse, summary="Playfair cipher")
def playfair_route(request: PlayfairRequest) -> PlayfairResponse:
    """Encrypt or decrypt with a 5x5 keyed square.

    Doubled letters are separated with a filler X during encryption, and those
    fillers cannot be removed on decryption -- so a decrypted message may come back
    with extra X characters. That is a known property of Playfair, not a defect.
    """
    if not request.key.strip():
        raise HTTPException(status_code=400, detail="key must not be empty")

    try:
        if request.operation == "decrypt":
            result = playfair_decrypt(request.text, request.key)
        else:
            result = playfair_encrypt(request.text, request.key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return PlayfairResponse(
        text=request.text,
        key=request.key,
        operation=request.operation,
        result=result,
    )


@router.post("/hill", response_model=HillResponse, summary="Hill cipher")
def hill_route(request: HillRequest) -> HillResponse:
    """Encrypt or decrypt with a key matrix, ``c = K*p mod 37``.

    Decryption inverts the matrix by Gauss-Jordan elimination over GF(37), which
    requires a non-zero determinant -- a singular matrix cannot recover plaintext.
    """
    if not request.matrix or not all(len(row) == len(request.matrix) for row in request.matrix):
        raise HTTPException(status_code=400, detail="matrix must be square and non-empty")

    try:
        if request.operation == "decrypt":
            result = hill_decrypt(request.text, request.matrix)
        else:
            result = hill_encrypt(request.text, request.matrix)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return HillResponse(
        text=request.text,
        matrix=request.matrix,
        operation=request.operation,
        result=result,
    )