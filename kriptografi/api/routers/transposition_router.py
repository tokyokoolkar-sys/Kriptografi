"""Transposition cipher endpoints and cryptanalysis routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from ...analysis import (
    crack_caesar,
    crack_vigenere,
    frequency_analysis,
    index_of_coincidence,
)
from ...transposition import (
    columnar_decrypt,
    columnar_encrypt,
    rail_fence_decrypt,
    rail_fence_encrypt,
    row_transposition_decrypt,
    row_transposition_encrypt,
)
from ..schemas import (
    ColumnarRequest,
    ColumnarResponse,
    RailFenceRequest,
    RailFenceResponse,
    RowTranspositionRequest,
    RowTranspositionResponse,
)

router = APIRouter(prefix="/transposition", tags=["transposition & analysis"])


@router.post("/rail-fence/encrypt", response_model=RailFenceResponse,
             summary="Rail fence encrypt")
def rail_fence_encrypt_route(request: RailFenceRequest) -> RailFenceResponse:
    """Write the text in a zigzag across ``rails`` rows and read each rail off."""
    try:
        result = rail_fence_encrypt(request.text, request.rails)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return RailFenceResponse(
        text=request.text, rails=request.rails, operation="encrypt", result=result
    )


@router.post("/rail-fence/decrypt", response_model=RailFenceResponse,
             summary="Rail fence decrypt")
def rail_fence_decrypt_route(request: RailFenceRequest) -> RailFenceResponse:
    """Rebuild the zigzag positions and read across them."""
    try:
        result = rail_fence_decrypt(request.text, request.rails)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return RailFenceResponse(
        text=request.text, rails=request.rails, operation="decrypt", result=result
    )


@router.post("/columnar", response_model=ColumnarResponse, summary="Columnar transposition")
def columnar_route(
    request: ColumnarRequest,
    operation: str = Query("encrypt", pattern="^(encrypt|decrypt)$"),
) -> ColumnarResponse:
    """Encrypt or decrypt with a keyed columnar transposition.

    The permutation only rearranges characters, so the ciphertext has exactly the
    same character frequencies as the plaintext -- that invariance is what makes
    columnar transposition weak on its own.
    """
    try:
        if operation == "decrypt":
            result = columnar_decrypt(request.text, request.key)
        else:
            result = columnar_encrypt(request.text, request.key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return ColumnarResponse(
        text=request.text, key=request.key, operation=operation, result=result
    )


@router.post("/row", response_model=RowTranspositionResponse, summary="Row transposition")
def row_route(
    request: RowTranspositionRequest,
    operation: str = Query("encrypt", pattern="^(encrypt|decrypt)$"),
) -> RowTranspositionResponse:
    """Encrypt or decrypt with a row transposition over the given columns."""
    try:
        if operation == "decrypt":
            result = row_transposition_decrypt(request.text, request.key, request.columns)
        else:
            result = row_transposition_encrypt(request.text, request.key, request.columns)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return RowTranspositionResponse(
        text=request.text,
        key=request.key,
        columns=request.columns,
        operation=operation,
        result=result,
    )


# --------------------------------------------------------------------------
# Cryptanalysis
# --------------------------------------------------------------------------

@router.get("/analysis/frequency", summary="Character frequency analysis")
def analyze_frequency(text: str) -> dict:
    """Count and rank character frequencies, the first step of most attacks."""
    return frequency_analysis(text)


@router.get("/analysis/ic", summary="Index of coincidence")
def analyze_ic(text: str) -> dict:
    """Measure how likely two positions are to hold the same character.

    English sits near 0.066 and random text near 0.038; for Vigenere the score
    rises as you group by the true key length, which is how the period is found.
    """
    return {"text": text, "index_of_coincidence": round(index_of_coincidence(text), 6)}


@router.get("/analysis/crack-caesar", summary="Break a Caesar cipher")
def crack_caesar_route(text: str, top: int = 5) -> dict:
    """Try all 36 shifts and return the most English-looking results, best first.

    Caesar has only 36 usable keys, so no key survives this search.
    """
    return {"text": text, "results": crack_caesar(text, top=top)}


@router.get("/analysis/crack-vigenere", summary="Break a Vigenere cipher")
def crack_vigenere_route(text: str, max_key_length: int = 12) -> dict:
    """Recover a Vigenere key by solving each column as a Caesar cipher.

    Works best on text long enough that each key column holds enough characters
    for its own frequency profile; on short inputs it may pick a wrong key length.
    """
    results = crack_vigenere(text, max_key_length=max_key_length)
    return {
        "text": text,
        "max_key_length": max_key_length,
        "results": [
            {
                "key": r.key,
                "key_length": r.key_length,
                "plaintext": r.plaintext,
                "score": r.score,
                "average_ic": r.average_ic,
            }
            for r in results
        ],
    }