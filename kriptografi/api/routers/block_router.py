"""Block cipher, hashing, and public-key endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ...asymmetric.dh import (
    DHParameters,
    ElGamalKeyPair,
    compute_shared_secret,
    decode_message,
    elgamal_decrypt,
    elgamal_encrypt,
    elgamal_keypair,
    encode_message,
    generate_parameters,
)
from ...asymmetric.ecc import CURVE_PARAMS, Point
from ...asymmetric.ecc import generate_keypair as ecc_keypair
from ...asymmetric.ecc import sign as ecc_sign
from ...asymmetric.ecc import verify as ecc_verify
from ...asymmetric.rsa import (
    decrypt_message,
    encrypt_int,
    encrypt_message,
    private_key_from_hex,
    private_key_to_hex,
    public_key_from_hex,
    public_key_to_hex,
)
from ...asymmetric.rsa import generate_keypair as rsa_keypair
from ...block import AES, DES
from ...hashes import hmac_sha256, sha256
from ...modes import (
    MODE_INFO,
    cbc_decrypt,
    cbc_encrypt,
    ctr_crypt,
    ecb_decrypt,
    ecb_encrypt,
)
from ..schemas import (
    BlockDecryptRequest,
    BlockDecryptResponse,
    BlockEncryptRequest,
    BlockEncryptResponse,
    DhExchangeRequest,
    DhExchangeResponse,
    DhParamsRequest,
    DhParamsResponse,
    EccKeygenRequest,
    EccKeygenResponse,
    EccSignRequest,
    EccSignResponse,
    EccVerifyRequest,
    EccVerifyResponse,
    ElGamalDecryptRequest,
    ElGamalDecryptResponse,
    ElGamalEncryptRequest,
    ElGamalEncryptResponse,
    ElGamalKeygenRequest,
    ElGamalKeygenResponse,
    HashRequest,
    HashResponse,
    HmacRequest,
    HmacResponse,
    RsaDecryptRequest,
    RsaDecryptResponse,
    RsaEncryptRequest,
    RsaEncryptResponse,
    RsaKeygenRequest,
    RsaKeygenResponse,
)

block_router = APIRouter(prefix="/block", tags=["block ciphers"])
hash_router = APIRouter(prefix="/hash", tags=["hashing"])
rsa_router = APIRouter(prefix="/rsa", tags=["RSA"])
dh_router = APIRouter(prefix="/dh", tags=["Diffie-Hellman & ElGamal"])
ecc_router = APIRouter(prefix="/ecc", tags=["elliptic curves"])


def _parse_hex(value: str, name: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"{name} must be valid hex") from exc


def _int(value, base: int = 10) -> int:
    """Parse a group-sized integer given the radix it was encoded in.

    Pydantic hands back an ``int`` for small fields like ``g`` and a ``str`` for
    the large ones, so this accepts either rather than requiring a matching
    ``int(x, base)`` at every call site.
    """
    if isinstance(value, int):
        return value
    return int(str(value), base)


def _make_cipher(kind: str, key: bytes):
    if kind == "aes":
        return AES(key)
    if kind == "des":
        return DES(key)
    raise HTTPException(status_code=400, detail=f"unknown cipher {kind!r}; use 'aes' or 'des'")


# --------------------------------------------------------------------------
# Block ciphers
# --------------------------------------------------------------------------

@block_router.post("/encrypt", response_model=BlockEncryptResponse,
                   summary="Encrypt with AES or DES")
def block_encrypt(request: BlockEncryptRequest) -> BlockEncryptResponse:
    """Encrypt UTF-8 text with AES or DES under ECB, CBC, or CTR.

    CBC and CTR generate a random IV or nonce when none is supplied and return it;
    the caller must send it back for decryption. ECB has no IV.
    """
    key = _parse_hex(request.key, "key")
    cipher = _make_cipher(request.cipher, key)
    plaintext = request.plaintext.encode("utf-8")

    try:
        if request.mode == "ecb":
            ciphertext, iv = ecb_encrypt(cipher, plaintext), None
        elif request.mode == "cbc":
            ciphertext, iv = cbc_encrypt(cipher, plaintext)
        elif request.mode == "ctr":
            ciphertext, iv = ctr_crypt(cipher, plaintext)
        else:
            raise HTTPException(status_code=400, detail="mode must be ecb, cbc, or ctr")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return BlockEncryptResponse(
        ciphertext=ciphertext.hex(),
        iv=iv.hex() if iv else None,
        cipher=request.cipher,
        mode=request.mode,
    )


@block_router.post("/decrypt", response_model=BlockDecryptResponse,
                   summary="Decrypt AES or DES")
def block_decrypt(request: BlockDecryptRequest) -> BlockDecryptResponse:
    """Decrypt a hex ciphertext produced by :func:`block_encrypt`.

    ``iv`` is required for CBC and CTR and ignored for ECB. ``original_length``,
    when given, truncates the result to that many bytes to strip padding without
    relying on the scheme's own unpadding.
    """
    key = _parse_hex(request.key, "key")
    cipher = _make_cipher(request.cipher, key)
    ciphertext = _parse_hex(request.ciphertext, "ciphertext")

    try:
        if request.mode == "ecb":
            plaintext = ecb_decrypt(cipher, ciphertext)
        elif request.mode in ("cbc", "ctr"):
            if not request.iv:
                raise HTTPException(status_code=400,
                                    detail=f"mode {request.mode} requires the IV/nonce")
            iv = _parse_hex(request.iv, "iv")
            if request.mode == "cbc":
                plaintext = cbc_decrypt(cipher, ciphertext, iv)
            else:
                plaintext, _ = ctr_crypt(cipher, ciphertext, iv)
        else:
            raise HTTPException(status_code=400, detail="mode must be ecb, cbc, or ctr")
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if request.original_length is not None:
        plaintext = plaintext[: request.original_length]

    return BlockDecryptResponse(
        plaintext=plaintext.decode("utf-8", errors="replace"),
        cipher=request.cipher,
        mode=request.mode,
    )


@block_router.get("/modes", summary="Describe the available modes of operation")
def list_modes() -> dict:
    """Summaries of each mode, with its security properties spelled out."""
    return {
        "modes": [
            {
                "id": key,
                "name": info.name,
                "summary": info.summary,
                "needs_iv": info.needs_iv,
                "malleable": info.malleable,
                "parallelizable": info.parallelizable,
            }
            for key, info in MODE_INFO.items()
        ]
    }


# --------------------------------------------------------------------------
# Hashing
# --------------------------------------------------------------------------

@hash_router.post("/sha256", response_model=HashResponse, summary="SHA-256 digest")
def hash_sha256(request: HashRequest) -> HashResponse:
    """Hash a UTF-8 string with SHA-256 (FIPS 180-4)."""
    return HashResponse(algorithm="SHA-256", message=request.message, digest=sha256(request.message))


@hash_router.post("/hmac-sha256", response_model=HmacResponse, summary="HMAC-SHA256")
def hash_hmac(request: HmacRequest) -> HmacResponse:
    """Keyed message authentication with HMAC-SHA256 (RFC 2104)."""
    digest = hmac_sha256(request.key.encode("utf-8"), request.message.encode("utf-8"))
    return HmacResponse(algorithm="HMAC-SHA256", digest=digest.hex())


# --------------------------------------------------------------------------
# RSA
# --------------------------------------------------------------------------

@rsa_router.post("/keygen", response_model=RsaKeygenResponse, summary="Generate an RSA key pair")
def rsa_keygen_route(request: RsaKeygenRequest) -> RsaKeygenResponse:
    """Generate an RSA key pair of the requested modulus size.

    Textbook RSA: no CRT, no OAEP. Good for study, not for production.
    """
    try:
        pair = rsa_keypair(request.bits)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    priv = pair.private
    return RsaKeygenResponse(
        n=format(priv.n, "X"),
        e=priv.e,
        phi=(priv.p - 1) * (priv.q - 1),
        d=format(priv.d, "X"),
        p=format(priv.p, "X"),
        q=format(priv.q, "X"),
        bits=request.bits,
        public_key_hex=public_key_to_hex(pair.public),
        private_key_hex=private_key_to_hex(priv),
    )


@rsa_router.post("/encrypt", response_model=RsaEncryptResponse, summary="RSA encrypt")
def rsa_encrypt_route(request: RsaEncryptRequest) -> RsaEncryptResponse:
    """Encrypt text with an RSA public key given as ``n:e`` hex."""
    try:
        key = public_key_from_hex(request.public_key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    ciphertexts = encrypt_message(request.message, key)

    return RsaEncryptResponse(
        ciphertext=[format(c, "X") for c in ciphertexts],
        block_count=len(ciphertexts) - 1,
    )


@rsa_router.post("/decrypt", response_model=RsaDecryptResponse, summary="RSA decrypt")
def rsa_decrypt_route(request: RsaDecryptRequest) -> RsaDecryptResponse:
    """Decrypt with a private key given as ``n:e:d:p:q`` hex."""
    try:
        key = private_key_from_hex(request.private_key)
        plaintext = decrypt_message([int(c, 16) for c in request.ciphertext], key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return RsaDecryptResponse(plaintext=plaintext)


@rsa_router.post("/encrypt-int", summary="Encrypt a single integer")
def rsa_encrypt_int(message: int, public_key: str) -> dict:
    """Encrypt one integer, showing the raw ``c = m^e mod n`` step."""
    try:
        key = public_key_from_hex(public_key)
        ciphertext = encrypt_int(message, key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "message": message,
        "ciphertext": format(ciphertext, "X"),
        "n": format(key.n, "X"),
        "e": key.e,
        "n_bits": key.size_bits,
    }


# --------------------------------------------------------------------------
# Diffie-Hellman and ElGamal
# --------------------------------------------------------------------------

@dh_router.post("/parameters", response_model=DhParamsResponse,
                summary="Generate safe Diffie-Hellman parameters")
def dh_parameters_route(request: DhParamsRequest) -> DhParamsResponse:
    """Generate a safe prime ``p = 2q + 1`` and a generator ``g``.

    Safe primes rule out the small-subgroup attacks that naive parameters suffer.
    """
    params = generate_parameters(request.bits)
    return DhParamsResponse(p=format(params.p, "X"), g=params.g, bits=params.p.bit_length())


@dh_router.post("/exchange", response_model=DhExchangeResponse,
                summary="Derive a Diffie-Hellman shared secret")
def dh_exchange_route(request: DhExchangeRequest) -> DhExchangeResponse:
    """Compute ``peer_public ** private mod p``.

    All four values arrive as strings because they are far larger than a double
    can hold exactly, so they are parsed as Python ints (arbitrary precision)
    rather than being coerced through a float.

    The radix differs per field and is not interchangeable: ``p`` comes back
    from /dh/parameters in hex, while the exponents and public values are
    decimal. Parsing everything as one base silently produces a peer value in
    the wrong subgroup, which the range check then rejects.
    """
    params = DHParameters(_int(request.p, 16), _int(request.g))
    try:
        secret = compute_shared_secret(
            params, _int(request.private), _int(request.peer_public)
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return DhExchangeResponse(shared_secret=format(secret, "X"))


@dh_router.post("/elgamal/keygen", response_model=ElGamalKeygenResponse,
                summary="Generate an ElGamal key pair")
def elgamal_keygen_route(request: ElGamalKeygenRequest) -> ElGamalKeygenResponse:
    """Pick an ElGamal secret exponent and publish ``y = g^x mod p``.

    The private exponent is a decimal string: it is group-sized and would lose
    precision as a JSON number.
    """
    key = elgamal_keypair(DHParameters(_int(request.p, 16), _int(request.g)))
    return ElGamalKeygenResponse(public=format(key.y, "X"), private=str(key.x))


@dh_router.post("/elgamal/encrypt", response_model=ElGamalEncryptResponse,
                summary="Encrypt with ElGamal")
def elgamal_encrypt_route(request: ElGamalEncryptRequest) -> ElGamalEncryptResponse:
    """Encrypt text by splitting it into blocks that each fit below ``p``.

    A fresh random nonce is drawn per block, which the scheme requires -- reusing
    one across messages would let an attacker recover the ratio of the plaintexts.
    """
    params = DHParameters(_int(request.p, 16), _int(request.g))
    key = ElGamalKeyPair(params, _int(request.public, 16), 0)

    try:
        values, lengths = encode_message(request.message, params.p)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    pairs = [elgamal_encrypt(value, key) for value in values]

    return ElGamalEncryptResponse(
        c1=[format(c1, "X") for c1, _ in pairs],
        c2=[format(c2, "X") for _, c2 in pairs],
        lengths=lengths,
        block_count=len(pairs),
    )


@dh_router.post("/elgamal/decrypt", response_model=ElGamalDecryptResponse,
                summary="Decrypt with ElGamal")
def elgamal_decrypt_route(request: ElGamalDecryptRequest) -> ElGamalDecryptResponse:
    """Recover the text from an ElGamal ciphertext, one block pair at a time."""
    if len(request.c1) != len(request.c2):
        raise HTTPException(status_code=400, detail="c1 and c2 must have the same length")
    if len(request.lengths) != len(request.c1):
        raise HTTPException(status_code=400, detail="lengths must match the block count")

    key = ElGamalKeyPair(
        DHParameters(_int(request.p, 16), _int(request.g)), 0, _int(request.private)
    )

    values: list[int] = []
    try:
        for c1, c2 in zip(request.c1, request.c2):
            values.append(elgamal_decrypt((int(c1, 16), int(c2, 16)), key))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    plaintext = decode_message(values, request.lengths) if values else ""
    return ElGamalDecryptResponse(plaintext=plaintext)


# --------------------------------------------------------------------------
# Elliptic curves
# --------------------------------------------------------------------------

@ecc_router.get("/curves", summary="List available curves")
def list_curves() -> dict:
    """Every named curve with its field size and group order."""
    return {
        "curves": [
            {
                "name": name,
                "field_bits": curve.p.bit_length(),
                "order_bits": curve.n.bit_length(),
                "p": format(curve.p, "X"),
            }
            for name, curve in CURVE_PARAMS.items()
        ]
    }


def _get_curve(name: str):
    if name not in CURVE_PARAMS:
        raise HTTPException(
            status_code=400,
            detail=f"unknown curve {name!r}; available: {', '.join(CURVE_PARAMS)}",
        )
    return CURVE_PARAMS[name]


@ecc_router.post("/keygen", response_model=EccKeygenResponse, summary="Generate an EC key pair")
def ecc_keygen_route(request: EccKeygenRequest) -> EccKeygenResponse:
    """Pick a private scalar and publish ``Q = dG``.

    Recovering ``d`` from ``Q`` means solving a discrete logarithm on the curve,
    which is the assumption ECC's security rests on.
    """
    curve = _get_curve(request.curve)
    d, q = ecc_keypair(curve)
    return EccKeygenResponse(curve=request.curve, private=str(d), public=f"{q.x},{q.y}")


def _parse_point(text: str, curve) -> Point:
    x_str, _, y_str = text.partition(",")
    try:
        point = Point(int(x_str), int(y_str))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="public point must look like 'x,y'") from exc

    if not curve.contains(point):
        raise HTTPException(status_code=400, detail="that point does not lie on the curve")
    return point


@ecc_router.post("/sign", response_model=EccSignResponse, summary="Sign a message with ECDSA")
def ecc_sign_route(request: EccSignRequest) -> EccSignResponse:
    """Produce an ECDSA signature ``(r, s)`` using a fresh random nonce.

    ``r`` and ``s`` are returned as decimal strings: they exceed what a JSON
    number can represent exactly, so serialising them as numbers would silently
    corrupt the signature for any client that parses it as a double.
    """
    curve = _get_curve(request.curve)
    r, s = ecc_sign(request.message, _int(request.private), curve)
    return EccSignResponse(curve=request.curve, r=str(r), s=str(s))


@ecc_router.post("/verify", response_model=EccVerifyResponse, summary="Verify an ECDSA signature")
def ecc_verify_route(request: EccVerifyRequest) -> EccVerifyResponse:
    """Check a signature against a public point."""
    curve = _get_curve(request.curve)
    point = _parse_point(request.public, curve)
    return EccVerifyResponse(
        valid=ecc_verify(
            request.message, (_int(request.r), _int(request.s)), point, curve
        )
    )