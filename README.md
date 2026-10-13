# Brankas — Brankas Catatan Terenkripsi Lokal (R1, tag `v0.1`)

Brankas adalah aplikasi lokal kecil untuk menyimpan **satu file catatan teks
sebagai envelope terenkripsi** yang hanya bisa dibuka dengan password yang
benar. Fokus R1: **satu komponen aman yang dapat dijalankan**, bukan rangkaian
fitur.

- Masalah: catatan sensitif (token cadangan, arsip pribadi) sering tersimpan
  sebagai plaintext di laptop.
- Solusi R1: perintah `seal` mengenkripsi file menjadi JSON
  (`salt + nonce + ciphertext+tag`), perintah `open` mendekripsinya kembali.
  Password salah atau satu byte dirusak → dekripsi **gagal tertolak** (GCM).
- Yang TIDAK ditangani v0.1: lupa password (tidak ada recovery by design),
  multi-file/database, sinkronisasi cloud, AAD pengikat nama file.

> Batas tegas: **sandi klasik (Caesar, Vigenère, Hill, dsb.) TIDAK dipakai
> untuk melindungi data produk.** Modul edukasi peninggalan di repo ini
> (`kriptografi/classical/`, `transposition/`, `block/` dari-nol) tidak
> dipanggil oleh Brankas sama sekali. Seluruh perlindungan data memakai
> pustaka terpelihara **`cryptography`** (AES-256-GCM + PBKDF2-HMAC-SHA256).

Repo: https://github.com/tokyokoolkar-sys/Kriptografi.git — yang dinilai
adalah commit yang ditunjuk tag **`v0.1`**.

## 1. Tabel kebutuhan kriptografi (K1)

| # | Data / aset | Tujuan keamanan | Prioritas | Mekanisme v0.1 |
|---|---|---|---|---|
| D1 | Isi catatan pengguna (plaintext) | **Confidentiality + Integrity**: tidak bisa dibaca/diubah tanpa password | **Tinggi** | AES-256-GCM (AEAD, tag 128-bit); kunci 256-bit dari PBKDF2 |
| D2 | Salt KDF (16 B) + nonce GCM (12 B) | **Uniqueness / anti-reuse**: tiap enkripsi acak segar; cegah rainbow-table & bencana nonce-reuse GCM | **Tinggi** | `secrets.token_bytes` (CSPRNG OS) per enkripsi, disimpan di envelope |
| D3 | Envelope JSON (salt, nonce, ct+tag, parameter KDF) | **Authenticity / tamper-evidence**: modifikasi terdeteksi, gagal autentikasi | **Tinggi** | Tag GCM terverifikasi saat `decrypt`; password salah vs data dirusak menghasilkan satu pesan gagal yang sama (tanpa oracle) |
| D4 | Password di memori & di CLI | **Exposure-minimisation**: tidak bocor ke disk/history/log | Sedang | Password hanya dari env `BRANKAS_PASSWORD` (sesi demo) atau prompt `getpass`; tidak pernah jadi argumen CLI, tidak disimpan, tidak di-log |

Kunci turunan: PBKDF2-HMAC-SHA256, **600.000 iterasi** (ambang OWASP), salt
16 byte. Ancaman di luar skorpe v0.1 (dicatat jujur): keylogger di OS,
swap/hibernasi RAM, penyerang dengan 600k×GPU farm tetap bisa brute-force
password lemah — mitigasinya password kuat, bukan iterasi tak berhingga.

## 2. Rancangan komponen awal (K2)

Satu komponen: `kriptografi/vault.py` + CLI tipis `kriptografi/vault_cli.py`.

### 2.1 Masukan – Proses – Keluaran

| Tahap | Masukan | Proses | Keluaran |
|---|---|---|---|
| `derive_key` | `password: str`, `salt: 16 B`, `iterations` | UTF-8 → PBKDF2-HMAC-SHA256 → 32 B | `key: 32 B` (di memori saja) |
| `encrypt` | `password`, `plaintext: bytes`, `salt?`, `nonce?` | Salt/nonce default dari CSPRNG → `derive_key` → `AESGCM(key).encrypt(nonce, plaintext, None)` | `envelope: dict` (siap JSON) |
| `decrypt` | `password`, `envelope` | Validasi struktur → `derive_key` → `AESGCM(key).decrypt(nonce, ct, None)`; gagal → `InvalidTag` | `plaintext: bytes` atau gagal tertolak |
| CLI `seal` | file plaintext, password (env/prompt) | `encrypt` → tulis JSON | `*.brankas.json` |
| CLI `open` | `*.brankas.json`, password | `load` → `decrypt` → tulis file | file plaintext pulih |

Aturan gagal-aman: struktur rusak → `InvalidEnvelope` (ValueError);
autentikasi gagal → `cryptography.exceptions.InvalidTag`. CLI memetakan
keduanya ke pesan tunggal *"gagal dibuka (password salah atau data dirusak)"*
agar tidak menjadi oracle pembeda.

### 2.2 Representasi data

- Plaintext di program: `bytes`; konversi teks: **UTF-8** (`str.encode`).
- Salt/nonce/ciphertext di JSON: **base64 standar** (`base64.b64encode`).
- Ciphertext GCM = `ciphertext || tag(16 B)` (format bawaan `AESGCM`).
- File: **JSON UTF-8**, kunci tetap: `v, kdf, iterations, salt, nonce, ct`.
  Contoh (nilai sintetis, bukan rahasia):
  ```json
  {"v": 1, "kdf": "PBKDF2-HMAC-SHA256", "iterations": 600000,
   "salt": "521cI8fwt/cKg19DMLNQDA==", "nonce": "DQdKJzKi1F+VWoWz",
   "ct": "2Zexmq4RgKSA66cns9NjgLEjmVuXthwnAJn3Kt14O25aELFtGjRdsnLM"}
  ```

### 2.3 Sumber keacakan

- **Hanya** `secrets.token_bytes(n)` → `os.urandom` → CSPRNG OS
  (di Windows: `BCryptGenRandom`). Dipakai untuk **salt 16 B dan nonce 12 B
  setiap enkripsi**.
- Modul `random` (PRNG deterministik) **dilarang** di komponen ini dan tidak
  diimpor oleh `vault.py`.
- Pengecualian uji: injeksi `salt`/`nonce` eksplisit hanya untuk determinisme
  bila diperlukan; uji bawaan memakai jalur acak normal kecuali dinyatakan.

### 2.4 Pustaka dan batasan

- `cryptography==50.0.2` (terpelihara, backend OpenSSL/Rust, audited).
  Kelas dipakai: `PBKDF2HMAC`, `hashes.SHA256`, `ciphers.aead.AESGCM`.
- Python stdlib: `secrets`, `base64`, `json`, `getpass`, `argparse`.
- Sandi klasik repo ini tidak tersentuh oleh Brankas (tidak ada import dari
  `classical/`/`transposition/`/blok-dari-nol di `vault.py`).

## 3. Cara menjalankan

Prasyarat: Python ≥3.11, `pip`.

```powershell
# 1) venv + dependensi (Windows Powershell)
py -m venv .venv
.\.venv\Scripts\Activate.ps1
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
# atau minimal: pip install cryptography pytest fastapi uvicorn

# 2) uji otomatis Brankas (5 skenario, wajib hijau)
.\.venv\Scripts\python.exe -m pytest tests/test_vault.py -v

# 3) demo CLI ±1 menit (data sintetis; password via env sesi demo saja)
$env:BRANKAS_PASSWORD="Kunci-Sintetis-123!"
"Catatan sintetis demo R1" | Out-File -Encoding utf8 catatan.txt
.\.venv\Scripts\python.exe -m kriptografi.vault_cli seal catatan.txt catatan.brankas.json
.\.venv\Scripts\python.exe -m kriptografi.vault_cli open catatan.brankas.json hasil.txt
Get-Content hasil.txt   # -> Catatan sintetis demo R1
```

Tanpa env var, CLI meminta password interaktif via `getpass`
(tidak tampil di layar, tidak masuk history).

Skenario demo 3 menit (pekan 3): 30 dtk deskripsi + tabel D1–D4 →
30 dtk IPO + tunjuk `vault.py` (PBKDF2/AESGCM/`secrets`) →
60 dtk `seal`/`open` live → 30 dtk buka envelope, ubah 1 byte `ct`,
tunjukkan `open` menolak → 30 dtk `pytest tests/test_vault.py -v` hijau.

## 4. Skenario uji dan hasil (K4)

File: `tests/test_vault.py` — 5 skenario (syarat: min. 4, min. 3 berhasil,
min. 1 negatif/batas). Hasil lokal: **5/5 lolos**.

| # | Skenario | Jenis | Ekspektasi | Hasil |
|---|---|---|---|---|
| 1 | `test_roundtrip_ok` | positif | `decrypt(encrypt(m)) == m` | lolos |
| 2 | `test_password_salah_gagal` | **negatif** | password salah → `InvalidTag` | lolos |
| 3 | `test_ciphertext_dirusak_gagal` | **negatif** (integritas) | 1 byte `ct` dibalik → `InvalidTag` | lolos |
| 4 | `test_batas_plaintext_kosong` | **batas** | `b""` round-trip | lolos |
| 5 | `test_salt_nonce_selalu_unik` | keacakan | dua enkripsi teks sama → salt/nonce/ct berbeda, keduanya terbuka | lolos |

Jalankan: `.\.venv\Scripts\python.exe -m pytest tests/test_vault.py -v`.
Seluruh suite repo (`pytest`) juga tetap dijalankan sebelum tag; modul
edukasi dari-nol tidak terpengaruh perubahan ini.

## 5. Keamanan repo & AI_LOG

- Tidak ada kunci privat, token, password, secrets, atau data pribadi di
  repo. Semua password/nilai di kode, uji, dan contoh adalah **sintetis**
  (`Kunci-Sintetis-123!`, `Salah-Sintetis-000!`). File `*.brankas.json`
  contoh tidak di-commit.
- Pemakaian AI generatif dicatat di [`AI_LOG.md`](AI_LOG.md) (alat, tujuan,
  ringkasan perintah, bagian dipakai/diubah, cara verifikasi). Penulis wajib
  dan mampu menjelaskan seluruh kode yang dikumpulkan.

---

## Lampiran A — Toolkit edukasi dari-nol (di luar penilaian Brankas R1)

Repo ini juga memuat toolkit pembelajaran lama (implementasi mandiri tanpa
lib kripto pihak ketiga): teori bilangan (`mathcore.py`), codec alfabet
37-simbol, sandi klasik (`classical/`), transposisi, DES/AES dari-nol
(`block/` + `modes/`), SHA-256/HMAC, kunci-publik edukasional, analisis,
serta API FastAPI + frontend React. **Itu bahan ajar dan BUKAN pelindung
data produk** — README aslinya menyimpan 324 uji backend dan 30/30
verifikasi frontend. Brankas (bagian R1 yang dinilai K3) sengaja tidak
mengimpor satu pun dari modul tersebut.
