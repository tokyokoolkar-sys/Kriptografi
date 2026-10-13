"""Pydantic request and response schemas for the HTTP API.

Kept separate from the routers so the wire format is visible in one place, and
so the same models can be reused by the tests as fixtures.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------
# Number theory
# --------------------------------------------------------------------------

class GcdRequest(BaseModel):
    a: int
    b: int


class GcdResponse(BaseModel):
    a: int
    b: int
    gcd: int
    steps: list[dict]


class ModInverseRequest(BaseModel):
    a: int
    m: int


class ModInverseResponse(BaseModel):
    a: int
    m: int
    inverse: int
    bezout_x: int
    bezout_y: int
    verification: str = Field(description="Human-readable check that a*x + m*y == 1")


class CrtRequest(BaseModel):
    residues: list[int]
    moduli: list[int]


class CrtResponse(BaseModel):
    residues: list[int]
    moduli: list[int]
    solution: int
    modulus_product: int
    steps: list[dict] = Field(description="Verification of each congruence")


class PrimalityRequest(BaseModel):
    n: int


class PrimalityResponse(BaseModel):
    n: int
    is_prime: bool
    factorization: list[int] = Field(description="Empty when n is prime or too large")


class PowModRequest(BaseModel):
    base: int
    exponent: int
    modulus: int


class PowModResponse(BaseModel):
    base: int
    exponent: int
    modulus: int
    binary_exponent: str
    result: int
    steps: list[dict] = Field(description="Square-and-multiply trace")


class FactorizeRequest(BaseModel):
    n: int


class FactorizeResponse(BaseModel):
    n: int
    factors: list[int]
    is_prime: bool


class TotientRequest(BaseModel):
    n: int


class TotientResponse(BaseModel):
    n: int
    phi: int
    is_prime: bool


# --------------------------------------------------------------------------
# Classical ciphers
# --------------------------------------------------------------------------

class CaesarRequest(BaseModel):
    text: str
    shift: int = Field(description="Shift amount; negative values shift backwards")


class CaesarResponse(BaseModel):
    text: str
    shift: int
    result: str
    alphabet_size: int = 37


class VigenereRequest(BaseModel):
    text: str
    key: str
    operation: str = Field(default="encrypt", pattern="^(encrypt|decrypt)$")


class VigenereResponse(BaseModel):
    text: str
    key: str
    operation: str
    result: str


class AffineRequest(BaseModel):
    text: str
    a: int
    b: int
    operation: str = Field(default="encrypt", pattern="^(encrypt|decrypt)$")


class AffineResponse(BaseModel):
    text: str
    a: int
    b: int
    operation: str
    result: str


class PlayfairRequest(BaseModel):
    text: str
    key: str
    operation: str = Field(default="encrypt", pattern="^(encrypt|decrypt)$")


class PlayfairResponse(BaseModel):
    text: str
    key: str
    operation: str
    result: str


class HillRequest(BaseModel):
    text: str
    matrix: list[list[int]]
    operation: str = Field(default="encrypt", pattern="^(encrypt|decrypt)$")


class HillResponse(BaseModel):
    text: str
    matrix: list[list[int]]
    operation: str
    result: str


# --------------------------------------------------------------------------
# Transposition ciphers
# --------------------------------------------------------------------------

class RailFenceRequest(BaseModel):
    text: str
    rails: int = Field(ge=2, description="Number of rails in the zigzag")


class RailFenceResponse(BaseModel):
    text: str
    rails: int
    operation: str
    result: str


class ColumnarRequest(BaseModel):
    text: str
    key: str


class ColumnarResponse(BaseModel):
    text: str
    key: str
    operation: str
    result: str


class RowTranspositionRequest(BaseModel):
    text: str
    key: str
    columns: int = Field(ge=1)


class RowTranspositionResponse(BaseModel):
    text: str
    key: str
    columns: int
    operation: str
    result: str


# --------------------------------------------------------------------------
# Block ciphers
# --------------------------------------------------------------------------

class BlockEncryptRequest(BaseModel):
    plaintext: str = Field(description="Text to encrypt; encoded as UTF-8 bytes")
    key: str = Field(description="Hex-encoded key")
    cipher: str = Field(default="aes", pattern="^(aes|des)$")
    mode: str = Field(default="cbc", pattern="^(ecb|cbc|ctr)$")


class BlockDecryptRequest(BaseModel):
    ciphertext: str = Field(description="Hex-encoded ciphertext")
    key: str = Field(description="Hex-encoded key")
    iv: str | None = Field(default=None, description="Hex IV/nonce; required for CBC and CTR")
    cipher: str = Field(default="aes", pattern="^(aes|des)$")
    mode: str = Field(default="cbc", pattern="^(ecb|cbc|ctr)$")
    original_length: int | None = Field(
        default=None, description="Optional byte length of the plaintext, to strip padding"
    )


class BlockEncryptResponse(BaseModel):
    ciphertext: str
    iv: str | None = None
    cipher: str
    mode: str


class BlockDecryptResponse(BaseModel):
    plaintext: str
    cipher: str
    mode: str


# --------------------------------------------------------------------------
# Hashing
# --------------------------------------------------------------------------

class HashRequest(BaseModel):
    message: str


class HashResponse(BaseModel):
    algorithm: str
    message: str
    digest: str


class HmacRequest(BaseModel):
    key: str
    message: str


class HmacResponse(BaseModel):
    algorithm: str
    digest: str


# --------------------------------------------------------------------------
# RSA
# --------------------------------------------------------------------------

class RsaKeygenRequest(BaseModel):
    bits: int = Field(default=1024, ge=256, le=4096, description="Modulus size in bits")


class RsaKeygenResponse(BaseModel):
    n: str
    e: int
    phi: int
    d: str
    p: str = Field(description="First prime factor; with q it forms the private key")
    q: str = Field(description="Second prime factor; with p it forms the private key")
    bits: int
    public_key_hex: str
    private_key_hex: str = Field(description="n:e:d:p:q in hex, ready for /rsa/decrypt")


class RsaEncryptRequest(BaseModel):
    message: str
    public_key: str = Field(description="Public key as n:e in hex")


class RsaEncryptResponse(BaseModel):
    ciphertext: list[str] = Field(description="Length header followed by per-block ciphertexts")
    block_count: int


class RsaDecryptRequest(BaseModel):
    ciphertext: list[str]
    private_key: str = Field(description="Private key as n:e:d:p:q in hex")


class RsaDecryptResponse(BaseModel):
    plaintext: str


# --------------------------------------------------------------------------
# Diffie-Hellman / ElGamal
# --------------------------------------------------------------------------

class DhParamsRequest(BaseModel):
    bits: int = Field(default=512, ge=256, le=2048)


class DhParamsResponse(BaseModel):
    p: str
    g: int
    bits: int


class DhExchangeRequest(BaseModel):
    # These are curve-group sized integers, well past JavaScript's safe range,
    # so they arrive as decimal or hex strings and must not be narrowed.
    private: str
    peer_public: str
    p: str
    g: str


class DhExchangeResponse(BaseModel):
    shared_secret: str


class ElGamalKeygenRequest(BaseModel):
    p: str
    g: int


class ElGamalKeygenResponse(BaseModel):
    public: str
    private: str = Field(description="Decimal string; exceeds JSON safe-integer range")


class ElGamalEncryptRequest(BaseModel):
    message: str
    public: str
    p: str
    g: int


class ElGamalEncryptResponse(BaseModel):
    c1: list[str] = Field(description="First ciphertext component per block")
    c2: list[str] = Field(description="Second ciphertext component per block")
    lengths: list[int] = Field(description="Character count of each block")
    block_count: int


class ElGamalDecryptRequest(BaseModel):
    c1: list[str]
    c2: list[str]
    lengths: list[int] = Field(description="Character count per block, from encryption")
    private: str = Field(description="Decimal string; exceeds JSON safe-integer range")
    p: str
    g: int


class ElGamalDecryptResponse(BaseModel):
    plaintext: str


# --------------------------------------------------------------------------
# ECC
# --------------------------------------------------------------------------

class EccKeygenRequest(BaseModel):
    curve: str


class EccKeygenResponse(BaseModel):
    curve: str
    private: str = Field(description="Decimal string; exceeds JSON safe-integer range")
    public: str


class EccSignRequest(BaseModel):
    message: str
    # ECDSA scalars are 192- or 256-bit integers. They travel as decimal strings
    # because a JSON number cannot carry that many significant digits exactly.
    private: str
    curve: str


class EccSignResponse(BaseModel):
    curve: str
    r: str
    s: str


class EccVerifyRequest(BaseModel):
    message: str
    r: str
    s: str
    public: str
    curve: str


class EccVerifyResponse(BaseModel):
    valid: bool