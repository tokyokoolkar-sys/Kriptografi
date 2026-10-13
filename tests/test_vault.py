"""Skenario uji otomatis Brankas (R1-K4): 5 skenario, 4 di antaranya positif.

Semua data SINTETIS. Tidak ada password/kunci asli di repository.
Kunci uji: "Kunci-Sintetis-123!" dan "Salah-Sintetis-000!".

  1. test_roundtrip_ok ..................... positif: enkripsi->dekripsi utuh
  2. test_password_salah_gagal ............. NEGATIF: password salah -> InvalidTag
  3. test_ciphertext_dirusak_gagal ......... NEGATIF: ct diutak-atik -> InvalidTag
  4. test_batas_plaintext_kosong ........... BATAS: b"" tetap round-trip
  5. test_salt_nonce_selalu_unik ........... keacakan: dua enkripsi -> ct berbeda
"""

from __future__ import annotations

import base64

import pytest
from cryptography.exceptions import InvalidTag

from kriptografi.vault import decrypt, encrypt

PASSWORD = "Kunci-Sintetis-123!"
WRONG_PASSWORD = "Salah-Sintetis-000!"


def test_roundtrip_ok():
    plaintext = "Catatan sintetis: rapat pekan 3, anggaran 2026.".encode("utf-8")
    envelope = encrypt(PASSWORD, plaintext)
    assert envelope["v"] == 1
    assert envelope["kdf"] == "PBKDF2-HMAC-SHA256"
    assert decrypt(PASSWORD, envelope) == plaintext


def test_password_salah_gagal():
    """Uji negatif: password salah wajib gagal autentikasi."""
    envelope = encrypt(PASSWORD, b"data sintetis rahasia")
    with pytest.raises(InvalidTag):
        decrypt(WRONG_PASSWORD, envelope)


def test_ciphertext_dirusak_gagal():
    """Uji negatif integritas: satu byte ct dibalik -> wajib gagal."""
    envelope = encrypt(PASSWORD, b"integritas sintetis")
    raw = bytearray(base64.b64decode(envelope["ct"]))
    raw[-1] ^= 0x01
    envelope["ct"] = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(InvalidTag):
        decrypt(PASSWORD, envelope)


def test_batas_plaintext_kosong():
    """Uji batas: plaintext kosong (0 byte) tetap round-trip via GCM."""
    envelope = encrypt(PASSWORD, b"")
    assert decrypt(PASSWORD, envelope) == b""


def test_salt_nonce_selalu_unik():
    """Keacakan: salt+nonce fresh -> dua ct plaintext sama wajib berbeda."""
    plaintext = b"sama sintetis"
    env1 = encrypt(PASSWORD, plaintext)
    env2 = encrypt(PASSWORD, plaintext)
    assert env1["salt"] != env2["salt"]
    assert env1["nonce"] != env2["nonce"]
    assert env1["ct"] != env2["ct"]
    assert decrypt(PASSWORD, env1) == plaintext
    assert decrypt(PASSWORD, env2) == plaintext
