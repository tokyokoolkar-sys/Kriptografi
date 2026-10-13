"""Brankas: brankas catatan teks terenkripsi lokal (komponen aman R1).

Komponen ini adalah SATU-SATUNYA bagian produk yang melindungi data pengguna.
Ia memakai pustaka kriptografi terpelihara ``cryptography`` dan tidak memakai
sandi klasik apa pun untuk data produk. Modul edukasi lain di paket ini
(Caesar, Vigenere, DES dari nol, dsb.) TIDAK dipakai oleh Brankas.

Primitif:
  - KDF: PBKDF2-HMAC-SHA256, 600.000 iterasi (rekomendasi OWASP 2023+),
    salt 16 byte.
  - AEAD: AES-256-GCM, nonce 96-bit, tag 128-bit (ditangani AESGCM).
  - Keacakan: :func:`secrets.token_bytes` (CSPRNG OS; di Windows
    ``BCryptGenRandom``). Modul :mod:`random` TIDAK PERNAH dipakai di sini.

Format envelope JSON (yang disimpan di disk)::

    {"v": 1, "kdf": "PBKDF2-HMAC-SHA256", "iterations": 600000,
     "salt": "<base64>", "nonce": "<base64>", "ct": "<base64>"}

``ct`` adalah keluaran AESGCM (ciphertext || tag 16 byte).
"""

from __future__ import annotations

import base64
import json
import secrets
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

__all__ = [
    "DEFAULT_ITERATIONS",
    "KEY_LEN",
    "NONCE_LEN",
    "SALT_LEN",
    "InvalidEnvelope",
    "decrypt",
    "derive_key",
    "encrypt",
    "load_envelope",
    "save_envelope",
]

DEFAULT_ITERATIONS = 600_000
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
KDF_NAME = "PBKDF2-HMAC-SHA256"
ENVELOPE_VERSION = 1
MIN_ITERATIONS = 100_000


class InvalidEnvelope(ValueError):
    """Envelope JSON tidak valid (hilang/rusak/format salah)."""


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str, field: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except Exception as exc:
        raise InvalidEnvelope(f"kolom '{field}' bukan base64 valid") from exc


def derive_key(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    """Turunkan kunci AES-256 dari password.

    Args:
        password: password pengguna (di-encode UTF-8; tidak disimpan).
        salt: 16 byte acak dari CSPRNG.
        iterations: jumlah iterasi PBKDF2, minimal 100.000.

    Raises:
        InvalidEnvelope: bila salt/iterasi tidak valid.
    """
    if not isinstance(password, str) or not password:
        raise InvalidEnvelope("password harus string tak-kosong")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < SALT_LEN:
        raise InvalidEnvelope(f"salt minimal {SALT_LEN} byte")
    if not isinstance(iterations, int) or iterations < MIN_ITERATIONS:
        raise InvalidEnvelope(f"iterasi minimal {MIN_ITERATIONS}")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=bytes(salt),
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt(
    password: str,
    plaintext: bytes,
    *,
    salt: bytes | None = None,
    nonce: bytes | None = None,
    iterations: int = DEFAULT_ITERATIONS,
) -> dict[str, Any]:
    """Enkripsi plaintext menjadi envelope JSON-serializable.

    ``salt``/``nonce`` hanya boleh diinjeksikan oleh uji; pemakaian normal
    selalu menghasilkannya dari :func:`secrets.token_bytes`.
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise InvalidEnvelope("plaintext harus bytes")
    if salt is None:
        salt = secrets.token_bytes(SALT_LEN)
    if nonce is None:
        nonce = secrets.token_bytes(NONCE_LEN)
    if len(salt) != SALT_LEN:
        raise InvalidEnvelope(f"salt harus {SALT_LEN} byte")
    if len(nonce) != NONCE_LEN:
        raise InvalidEnvelope(f"nonce harus {NONCE_LEN} byte")
    key = derive_key(password, salt, iterations)
    ct = AESGCM(key).encrypt(bytes(nonce), bytes(plaintext), associated_data=None)
    return {
        "v": ENVELOPE_VERSION,
        "kdf": KDF_NAME,
        "iterations": iterations,
        "salt": _b64e(bytes(salt)),
        "nonce": _b64e(bytes(nonce)),
        "ct": _b64e(ct),
    }


def decrypt(password: str, envelope: dict[str, Any]) -> bytes:
    """Dekripsi envelope; gagal autentikasi bila password salah/data dirusak.

    Raises:
        InvalidEnvelope: struktur envelope rusak.
        InvalidTag: password salah ATAU ciphertext/nonce/salt dimodifikasi.
            (Sengaja tidak dibedakan untuk menghindari oracle.)
    """
    if not isinstance(envelope, dict):
        raise InvalidEnvelope("envelope harus object JSON")
    try:
        version = envelope["v"]
        kdf_name = envelope["kdf"]
        iterations = envelope["iterations"]
        salt = _b64d(envelope["salt"], "salt")
        nonce = _b64d(envelope["nonce"], "nonce")
        ct = _b64d(envelope["ct"], "ct")
    except KeyError as exc:
        raise InvalidEnvelope(f"kolom hilang: {exc}") from exc
    if version != ENVELOPE_VERSION:
        raise InvalidEnvelope(f"versi tak didukung: {version!r}")
    if kdf_name != KDF_NAME:
        raise InvalidEnvelope(f"kdf tak didukung: {kdf_name!r}")
    if len(salt) != SALT_LEN:
        raise InvalidEnvelope("panjang salt salah")
    if len(nonce) != NONCE_LEN:
        raise InvalidEnvelope("panjang nonce salah")
    if len(ct) < 16:  # tag GCM 16 byte; plaintext boleh 0 byte
        raise InvalidEnvelope("ciphertext terlalu pendek")
    key = derive_key(password, salt, iterations)
    return AESGCM(key).decrypt(nonce, ct, associated_data=None)


def save_envelope(envelope: dict[str, Any], path: str | Path) -> None:
    """Simpan envelope sebagai JSON UTF-8 (hanya berisi salt/nonce/ct)."""
    Path(path).write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")


def load_envelope(path: str | Path) -> dict[str, Any]:
    """Muat envelope JSON; raises InvalidEnvelope bila rusak."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InvalidEnvelope(f"gagal membaca envelope: {exc}") from exc
    if not isinstance(data, dict):
        raise InvalidEnvelope("envelope harus object JSON")
    return data
