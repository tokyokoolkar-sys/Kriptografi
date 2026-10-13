"""CLI Brankas: seal (enkripsi) dan open (dekripsi) file lokal.

Password TIDAK PERNAH menjadi argumen CLI (agar tidak masuk shell history).
Urutan pengambilan: variabel lingkungan BRANKAS_PASSWORD -> prompt getpass.

Contoh:
    $env:BRANKAS_PASSWORD="Kunci-Sintetis-123!"  # Powershell, sesi demo saja
    python -m kriptografi.vault_cli seal catatan.txt catatan.brankas.json
    python -m kriptografi.vault_cli open catatan.brankas.json hasil.txt
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag

from kriptografi.vault import decrypt, encrypt, load_envelope, save_envelope, InvalidEnvelope


def _get_password(confirm: bool = False) -> str:
    pw = os.environ.get("BRANKAS_PASSWORD")
    if pw:
        return pw
    pw = getpass.getpass("Password brankas: ")
    if confirm:
        pw2 = getpass.getpass("Ulangi password: ")
        if pw != pw2:
            print("error: password tidak sama", file=sys.stderr)
            raise SystemExit(2)
    if not pw:
        print("error: password kosong", file=sys.stderr)
        raise SystemExit(2)
    return pw


def cmd_seal(args: argparse.Namespace) -> int:
    src = Path(args.input)
    dst = Path(args.output)
    try:
        plaintext = src.read_bytes()
    except OSError as exc:
        print(f"error: tidak bisa membaca {src}: {exc}", file=sys.stderr)
        return 1
    password = _get_password(confirm=True)
    envelope = encrypt(password, plaintext)
    try:
        save_envelope(envelope, dst)
    except OSError as exc:
        print(f"error: tidak bisa menulis {dst}: {exc}", file=sys.stderr)
        return 1
    print(f"tersegel: {src} ({len(plaintext)} byte) -> {dst}")
    return 0


def cmd_open(args: argparse.Namespace) -> int:
    src = Path(args.input)
    dst = Path(args.output)
    try:
        envelope = load_envelope(src)
    except InvalidEnvelope as exc:
        print(f"error: envelope rusak: {exc}", file=sys.stderr)
        return 1
    password = _get_password(confirm=False)
    try:
        plaintext = decrypt(password, envelope)
    except InvalidEnvelope as exc:
        print(f"error: envelope rusak: {exc}", file=sys.stderr)
        return 1
    except InvalidTag:
        # Sengaja satu pesan untuk password salah vs data dirusak.
        print("error: gagal dibuka (password salah atau data dirusak)", file=sys.stderr)
        return 1
    try:
        dst.write_bytes(plaintext)
    except OSError as exc:
        print(f"error: tidak bisa menulis {dst}: {exc}", file=sys.stderr)
        return 1
    print(f"terbuka: {src} -> {dst} ({len(plaintext)} byte)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="brankas", description="Brankas catatan terenkripsi lokal (AES-256-GCM + PBKDF2).")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("seal", help="enkripsi file menjadi envelope JSON")
    s.add_argument("input", help="file plaintext masuk")
    s.add_argument("output", help="file envelope JSON keluar")
    s.set_defaults(func=cmd_seal)
    o = sub.add_parser("open", help="dekripsi envelope JSON menjadi file")
    o.add_argument("input", help="file envelope JSON masuk")
    o.add_argument("output", help="file plaintext keluar")
    o.set_defaults(func=cmd_open)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
