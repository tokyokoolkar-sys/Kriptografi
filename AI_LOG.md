# AI_LOG — pencatatan pemakaian AI generatif (R1)

Wajib menurut ketentuan tugas. Mahasiswa mampu menjelaskan seluruh kode.

## Entri 1 — 2026-10-13 — Perancangan + implementasi Brankas (komponen aman R1)

- **Alat:** Muse Spark (via OpenCode) — sesi pengerjaan ini.
- **Tujuan:** merancang komponen enkripsi produk yang memenuhi rubrik R1
  (K1–K4): memakai pustaka terpelihara, bukan sandi klasik; IPO +
  representasi data + sumber keacakan; 4+ skenario uji otomatis.
- **Ringkasan perintah (prompt):** ketentuan tugas R1 + tautan repo
  `https://github.com/tokyokoolkar-sys/Kriptografi.git`; permintaan implisit
  "siapkan repo sampai layak tag v0.1".
- **Bagian yang dipakai/diubah dari usulan AI:**
  - Baru: `kriptografi/vault.py` (PBKDF2-HMAC-SHA256 600k + AES-256-GCM via
    `cryptography`, envelope JSON base64, `secrets.token_bytes`).
  - Baru: `kriptografi/vault_cli.py` (argparse `seal`/`open`, password via
    `BRANKAS_PASSWORD` atau `getpass`, pesan gagal tunggal anti-oracle).
  - Baru: `tests/test_vault.py` (5 skenario: round-trip, password salah,
    ct dirusak, batas kosong, salt/nonce unik).
  - Ubah: `pyproject.toml` (+`cryptography>=44.0`), `README.md` (ditulis
    ulang ke format R1: deskripsi, tabel D1–D4, IPO, representasi,
    keacakan, cara jalan, tabel uji).
  - Perbaikan AI sesudah uji: batas `len(ct) < 16+1` menolak plaintext
    kosong → diperbaiki menjadi `< 16` (tag GCM saja).
  - File ini (`AI_LOG.md`) dibuat oleh AI.
- **Tidak dipakai dari AI:** tidak ada kunci/password/token dari AI;
  semua kredensial contoh adalah sintetis (`Kunci-Sintetis-123!`).
- **Cara memeriksa (verifikasi manusia):**
  1. `.\.venv\Scripts\python.exe -m pytest tests/test_vault.py -v`
     → wajib 5 passed (tanggal verifikasi: 2026-10-13).
  2. Demo CLI: `seal` lalu `open` file sintetis → isi kembali sama;
     ubah 1 byte `ct` di JSON → `open` menolak dengan pesan gagal.
  3. `grep -rn "from kriptografi.classical\|import random" kriptografi/vault.py`
     → tidak ada hasil (Brankas tidak memakai sandi klasik/`random`).
  4. `git status --porcelain` sebelum commit → tidak ada file
     `*.brankas.json`/password nyata; hanya kode + uji + docs.
- **Pemahaman penulis:** mampu menjelaskan PBKDF2 (fungsi, salt, iterasi),
  AES-GCM (nonce 96-bit, tag sebagai integritas), mengapa nonce/salt fresh
  per enkripsi, mengapa password salah dan data rusak disamakan pesannya,
  dan mengapa `secrets` dipakai bukan `random`.
