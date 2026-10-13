/**
 * The algorithm registry.
 *
 * One entry per algorithm the backend exposes. This is the single source of
 * truth for the landing dropdown, the family mosaics, and the per-algorithm
 * pages, so adding an algorithm means adding one object here.
 *
 * Each entry declares:
 *   id, family, kind  — identity and grouping
 *   name              — {id, en} bilingual label
 *   blurb             — {id, en} one line on what it does
 *   caution           — a lossiness or safety note, shown verbatim when present
 *   fields            — the input controls to render
 *   run               — maps field values to an API call, returns a result
 *   steps             — pulls the step table out of the response, if any
 *   verify            — a known-answer check against the published spec
 *
 * `kind` is one of:
 *   text      single text + key -> text
 *   numeric   numeric inputs -> number, with a step table
 *   block     key/block cipher over hex
 *   keygen    generates a key, then can encrypt/decrypt with it
 *   signature signs and verifies
 */

import { api } from "./api.js";

/** Call an API method by name. Lets `run` stay a short arrow in the table. */
const call = (method, ...args) => api[method](...args);

const textField = (key, label, opts = {}) => ({
  key,
  label,
  type: "text",
  placeholder: opts.placeholder ?? "",
  mono: true,
});

const numField = (key, label, opts = {}) => ({
  key,
  label,
  type: "number",
  min: opts.min,
  max: opts.max,
  step: opts.step ?? 1,
  default: opts.default,
});

const demo = {
  caesar: "HALLO 2026",
  vigenere: "ATTACK AT DAWN",
  beaufort: "ATTACK AT DAWN",
  autokey: "ATTACK AT DAWN",
  affine: "HELLO 2026",
  playfair: "HELLOWORLD",
  hill: "HELLOWORLD",
  rail: "WEAREDISCOVEREDFLEEATONCE",
  columnar: "WEAREDISCOVEREDFLEEATONCE",
  row: "WEAREDISCOVEREDFLEEATONCE",
};

export const FAMILIES = [
  { id: "math", name: { id: "Matematika", en: "Mathematics" }, plate: "01" },
  { id: "classical", name: { id: "Klasik", en: "Classical" }, plate: "02" },
  { id: "transposition", name: { id: "Transposisi", en: "Transposition" }, plate: "03" },
  { id: "block", name: { id: "Blok", en: "Block" }, plate: "04" },
  { id: "hash", name: { id: "Hash", en: "Hash" }, plate: "05" },
  { id: "asymmetric", name: { id: "Asimetris", en: "Asymmetric" }, plate: "06" },
];

/** Parse "3 4 5" or "3,4,5" into [3, 4, 5]. */
const nums = (value) =>
  String(value ?? "")
    .split(/[\s,]+/)
    .filter(Boolean)
    .map(Number);

/**
 * Parse a matrix field into a square matrix of numbers.
 *
 * Accepts nested JSON (`[[3,3],[2,5]]`) or a flat list (`3 3 2 5`, which is
 * reshaped by its own square root). Returns null when the shape is wrong, so
 * the caller can fail loudly rather than sending the API an empty matrix.
 *
 * Lives here rather than in a component because both the Workbench and the
 * verification script must parse identically -- a mismatch is what silently sent
 * a null matrix and produced "matrix must be square".
 */
export function parseMatrix(value) {
  const text = String(value ?? "").trim();
  if (!text) return null;

  try {
    const parsed = JSON.parse(text);
    if (
      Array.isArray(parsed) &&
      parsed.length > 0 &&
      Array.isArray(parsed[0]) &&
      parsed.every((row) => Array.isArray(row) && row.length === parsed[0].length)
    ) {
      return parsed.map((row) => row.map(Number));
    }
  } catch {
    /* not JSON; fall through to the flat form */
  }

  const flat = nums(text);
  const size = Math.sqrt(flat.length);
  if (!Number.isInteger(size) || size < 2) return null;

  const rows = [];
  for (let i = 0; i < size; i += 1) rows.push(flat.slice(i * size, (i + 1) * size));
  return rows;
}

export const ALGORITHMS = [
  /* ---------------------------------------------------------------- math -- */

  {
    id: "gcd",
    family: "math",
    kind: "numeric",
    name: { id: "FPB / Euclidean", en: "GCD / Euclidean" },
    blurb: {
      id: "Membagi berulang sampai sisa nol. Setiap langkah ditampilkan.",
      en: "Repeated division until the remainder is zero. Every step shown.",
    },
    fields: [numField("a", "a", { default: 1071 }), numField("b", "b", { default: 462 })],
    run: (v) => call("gcd", v.a, v.b),
    /* The row index is synthesised by the table; these are the real columns. */
    stepHeads: ["a", "b", "q", "r"],
    steps: (r) => r.steps.map((s) => ({ a: s.a, b: s.b, q: s.q, r: s.r })),
    resultText: (r) => `FPB = ${r.gcd}`,
  },
  {
    id: "mod-inverse",
    family: "math",
    kind: "numeric",
    name: { id: "Invers Modulo", en: "Modular Inverse" },
    blurb: {
      id: "Extended Euclid mencari x dengan a·x ≡ 1 (mod m).",
      en: "Extended Euclid finds x where a·x ≡ 1 (mod m).",
    },
    fields: [numField("a", "a", { default: 3 }), numField("m", "m", { default: 7 })],
    run: (v) => call("modInverse", v.a, v.m),
    resultText: (r) => `inverse = ${r.inverse}`,
  },
  {
    id: "crt",
    family: "math",
    kind: "numeric",
    name: { id: "CRT", en: "CRT" },
    blurb: {
      id: "Chinese Remainder Theorem untuk sistem kongruensi.",
      en: "Chinese Remainder Theorem for a system of congruences.",
    },
    fields: [
      textField("residues", "residu", { placeholder: "2 3 2" }),
      textField("moduli", "modulus", { placeholder: "3 5 7" }),
    ],
    run: (v) => call("crt", nums(v.residues), nums(v.moduli)),
    steps: (r) => r.steps,
    resultText: (r) => `x = ${r.solution}`,
  },
  {
    id: "powmod",
    family: "math",
    kind: "numeric",
    name: { id: "Pangkat Modulo", en: "Modular Power" },
    blurb: {
      id: "Exponentiation by squaring, dengan eksponen biner.",
      en: "Exponentiation by squaring, with the binary exponent.",
    },
    fields: [
      numField("base", "base", { default: 4 }),
      numField("exponent", "exponent", { default: 13 }),
      numField("modulus", "modulus", { default: 497 }),
    ],
    run: (v) => call("powmod", v.base, v.exponent, v.modulus),
    steps: (r) => r.steps,
    resultText: (r) => `${r.base}^${r.exponent} mod ${r.modulus} = ${r.result}`,
  },
  {
    id: "primality",
    family: "math",
    kind: "numeric",
    name: { id: "Primalitas", en: "Primality" },
    blurb: {
      id: "Miller-Rabin untuk bilangan besar, trial division untuk yang kecil.",
      en: "Miller-Rabin for large numbers, trial division for small ones.",
    },
    fields: [numField("n", "n", { default: 104729 })],
    run: (v) => call("primality", v.n),
    resultText: (r) => (r.is_prime ? "prima" : `komposit = ${r.factorization.join(" × ") || "—"}`),
  },
  {
    id: "factorize",
    family: "math",
    kind: "numeric",
    name: { id: "Faktorisasi", en: "Factorisation" },
    blurb: {
      id: "Faktorisasi prima lengkap dengan trial division.",
      en: "Complete prime factorisation by trial division.",
    },
    fields: [numField("n", "n", { default: 360 })],
    run: (v) => call("factorize", v.n),
    resultText: (r) => r.factors.join(" × ") || "—",
  },
  {
    id: "totient",
    family: "math",
    kind: "numeric",
    name: { id: "Totient φ(n)", en: "Totient φ(n)" },
    blurb: {
      id: "Banyaknya bilangan koprima dengan n dalam [1, n].",
      en: "How many integers in [1, n] are coprime to n.",
    },
    fields: [numField("n", "n", { default: 100 })],
    run: (v) => call("totient", v.n),
    resultText: (r) => `φ(${r.n}) = ${r.phi}`,
  },
  {
    id: "discrete-log",
    family: "math",
    kind: "numeric",
    name: { id: "Log Diskret", en: "Discrete Log" },
    blurb: {
      id: "Baby-step giant-step: O(√p) alih-alih O(p).",
      en: "Baby-step giant-step: O(√p) instead of O(p).",
    },
    fields: [
      numField("base", "base", { default: 2 }),
      numField("target", "target", { default: 23 }),
      numField("modulus", "modulus", { default: 101 }),
    ],
    run: (v) => call("discreteLog", v.base, v.target, v.modulus),
    resultText: (r) =>
      r.solution_exists ? `x = ${r.discrete_log}` : "tidak ada solusi",
  },

  /* ----------------------------------------------------------- classical -- */

  {
    id: "caesar",
    family: "classical",
    kind: "text",
    name: { id: "Caesar", en: "Caesar" },
    blurb: {
      id: "Pergeseran tetap pada 37 simbol. Hanya 36 kunci yang mungkin.",
      en: "A fixed shift over 37 symbols. Only 36 keys exist.",
    },
    fields: [
      textField("text", "Teks", { placeholder: demo.caesar }),
      numField("shift", "Pergeseran", { default: 3 }),
    ],
    run: (v) => call("caesarEncrypt", v.text, v.shift),
    decrypt: (v) => call("caesarDecrypt", v.text, v.shift),
    resultText: (r) => r.result,
  },
  {
    id: "vigenere",
    family: "classical",
    kind: "text",
    name: { id: "Vigenère", en: "Vigenère" },
    blurb: {
      id: "Kunci berulang. Tahan frekuensi, bocor oleh periodicitas.",
      en: "A repeating key. Beats frequency analysis, leaks through periodicity.",
    },
    fields: [
      textField("text", "Teks", { placeholder: demo.vigenere }),
      textField("key", "Kunci", { placeholder: "LIME" }),
    ],
    run: (v) => call("vigenere", v.text, v.key, "encrypt"),
    decrypt: (v) => call("vigenere", v.text, v.key, "decrypt"),
    resultText: textOut0,
  },
  {
    id: "beaufort",
    family: "classical",
    kind: "text",
    name: { id: "Beaufort", en: "Beaufort" },
    blurb: {
      id: "c = (k − p) mod 37. Involusi: enkripsi sama dengan dekripsi.",
      en: "c = (k − p) mod 37. An involution: encryption is decryption.",
    },
    fields: [
      textField("text", "Teks", { placeholder: demo.beaufort }),
      textField("key", "Kunci", { placeholder: "LIME" }),
    ],
    run: (v) => call("beaufort", v.text, v.key, "encrypt"),
    decrypt: (v) => call("beaufort", v.text, v.key, "decrypt"),
    resultText: textOut0,
  },
  {
    id: "autokey",
    family: "classical",
    kind: "text",
    name: { id: "Autokey", en: "Autokey" },
    blurb: {
      id: "Kunci diperpanjang plaintext, jadi tanpa perioda.",
      en: "The key extends with the plaintext, so there is no period.",
    },
    fields: [
      textField("text", "Teks", { placeholder: demo.autokey }),
      textField("key", "Kunci", { placeholder: "LIME" }),
    ],
    run: (v) => call("autokey", v.text, v.key, "encrypt"),
    decrypt: (v) => call("autokey", v.text, v.key, "decrypt"),
    resultText: textOut0,
  },
  {
    id: "affine",
    family: "classical",
    kind: "text",
    name: { id: "Affine", en: "Affine" },
    blurb: {
      id: "c = (a·p + b) mod 37. Butuh invers a dari extended Euclid.",
      en: "c = (a·p + b) mod 37. Needs the inverse of a from extended Euclid.",
    },
    fields: [
      textField("text", "Teks", { placeholder: demo.affine }),
      numField("a", "a", { default: 5, min: 1, max: 36 }),
      numField("b", "b", { default: 8, min: 0, max: 36 }),
    ],
    run: (v) => call("affine", v.text, v.a, v.b, "encrypt"),
    decrypt: (v) => call("affine", v.text, v.a, v.b, "decrypt"),
    resultText: textOut0,
    caution: {
      id: "Nilai a harus koprima dengan 37. Karena 37 prima, semua a dari 1–36 valid.",
      en: "a must be coprime with 37. Since 37 is prime, every a in 1–36 is valid.",
    },
  },
  {
    id: "playfair",
    family: "classical",
    kind: "text",
    name: { id: "Playfair", en: "Playfair" },
    blurb: {
      id: "Kotak 5×5. Huruf kembar dipisah filler X.",
      en: "A 5×5 square. Doubled letters are split with a filler X.",
    },
    fields: [
      textField("text", "Teks", { placeholder: demo.playfair }),
      textField("key", "Kunci", { placeholder: "KEYWORD" }),
    ],
    run: (v) => call("playfair", v.text, v.key, "encrypt"),
    decrypt: (v) => call("playfair", v.text, v.key, "decrypt"),
    resultText: textOut0,
    caution: {
      id: "Kotak hanya berisi 25 huruf: angka dan spasi hilang, J digabung ke I, dan filler X tidak dapat dihapus saat dekripsi.",
      en: "The square holds only 25 letters: digits and spaces are dropped, J is merged into I, and the X fillers cannot be removed on decryption.",
    },
  },
  {
    id: "hill",
    family: "classical",
    kind: "text",
    name: { id: "Hill", en: "Hill" },
    blurb: {
      id: "c = K·p mod 37. Inversi matriks dengan Gauss-Jordan.",
      en: "c = K·p mod 37. Matrix inverted by Gauss-Jordan elimination.",
    },
    fields: [
      textField("text", "Teks", { placeholder: demo.hill }),
      textField("matrix", "Matriks", { placeholder: "3 3 2 5" }),
    ],
    run: (v) => call("hill", v.text, parseMatrix(v.matrix) ?? [], "encrypt"),
    decrypt: (v) => call("hill", v.text, parseMatrix(v.matrix) ?? [], "decrypt"),
    resultText: textOut0,
    caution: {
      id: "Blok terakhir di-pad nol, jadi dekripsi teks panjang berakhiran huruf 'A'. Matriks harus punya determinan bukan nol.",
      en: "The final block is zero-padded, so decrypting a long message ends with 'A' characters. The matrix must have a non-zero determinant.",
    },
  },

  /* -------------------------------------------------------- transposition -- */

  {
    id: "rail-fence",
    family: "transposition",
    kind: "text",
    name: { id: "Rail Fence", en: "Rail Fence" },
    blurb: {
      id: "Zigzag lintas rel, dibaca baris per baris. Permutasi saja.",
      en: "A zigzag across rails, read row by row. A pure permutation.",
    },
    fields: [
      textField("text", "Teks", { placeholder: demo.rail }),
      numField("rails", "Rel", { default: 3, min: 2, max: 12 }),
    ],
    run: (v) => call("railFenceEncrypt", v.text, v.rails),
    decrypt: (v) => call("railFenceDecrypt", v.text, v.rails),
    resultText: textOut0,
  },
  {
    id: "columnar",
    family: "transposition",
    kind: "text",
    name: { id: "Columnar", en: "Columnar" },
    blurb: {
      id: "Teks ditulis di bawah kunci, dibaca per kolom. Permutasi saja.",
      en: "Text written under the key, read by column. A pure permutation.",
    },
    fields: [
      textField("text", "Teks", { placeholder: demo.columnar }),
      textField("key", "Kunci", { placeholder: "ZEBRA" }),
    ],
    run: (v) => call("columnar", v.text, v.key, "encrypt"),
    decrypt: (v) => call("columnar", v.text, v.key, "decrypt"),
    resultText: textOut0,
  },
  {
    id: "row-transposition",
    family: "transposition",
    kind: "text",
    name: { id: "Row Transposition", en: "Row Transposition" },
    blurb: {
      id: "Cermin columnar: ditulis turun kolom, dibaca per baris.",
      en: "Columnar's mirror: written down columns, read by row.",
    },
    fields: [
      textField("text", "Teks", { placeholder: demo.row }),
      textField("key", "Kunci", { placeholder: "ZEBRA" }),
      numField("columns", "Kolom", { default: 5, min: 1, max: 12 }),
    ],
    run: (v) => call("rowTransposition", v.text, v.key, v.columns, "encrypt"),
    decrypt: (v) => call("rowTransposition", v.text, v.key, v.columns, "decrypt"),
    resultText: textOut0,
  },
  {
    id: "freq-analysis",
    family: "transposition",
    kind: "text",
    name: { id: "Analisis Frekuensi", en: "Frequency Analysis" },
    blurb: {
      id: "Hitung frekuensi karakter. Langkah pertama sebagian besar serangan.",
      en: "Count character frequencies. The first step of most attacks.",
    },
    fields: [textField("text", "Teks", { placeholder: demo.rail })],
    run: (v) => call("frequency", v.text),
    steps: (r) =>
      Object.entries(r.counts).map(([ch, n]) => ({
        char: ch === " " ? "␣" : ch,
        count: n,
        percent: r.frequencies[ch],
      })),
    stepHeads: ["karakter", "jumlah", "%"],
    resultText: (r) => `paling sering: ${r.most_common ?? "—"}`,
  },
  {
    id: "index-coincidence",
    family: "transposition",
    kind: "text",
    name: { id: "Index of Coincidence", en: "Index of Coincidence" },
    blurb: {
      id: "Seberapa mungkin dua posisi memuat karakter sama. Inggris ≈ 0.066.",
      en: "How likely two positions hold the same character. English ≈ 0.066.",
    },
    fields: [textField("text", "Teks", { placeholder: demo.rail })],
    run: (v) => call("ic", v.text),
    resultText: (r) => `IC = ${r.index_of_coincidence}`,
  },
  {
    id: "crack-caesar",
    family: "transposition",
    kind: "text",
    name: { id: "Pecah Caesar", en: "Crack Caesar" },
    blurb: {
      id: "Coba 36 pergeseran, beri skor kemiripan bahasa Inggris.",
      en: "Try all 36 shifts and score them for English-likeness.",
    },
    fields: [textField("text", "Ciphertext", { placeholder: "KDOORC5359" })],
    run: (v) => call("crackCaesar", v.text, 5),
    steps: (r) =>
      r.results.map((x) => ({ shift: x.shift, score: x.score, plaintext: x.plaintext })),
    stepHeads: ["pergeseran", "skor", "plaintext"],
    resultText: (r) => `terbaik: shift ${r.results[0]?.shift}`,
    extra: true,
  },
  {
    id: "crack-vigenere",
    family: "transposition",
    kind: "text",
    name: { id: "Pecah Vigenère", en: "Crack Vigenère" },
    blurb: {
      id: "Uji tiap panjang kunci, pecah tiap kolom seperti Caesar.",
      en: "Test each key length, breaking every column as a Caesar cipher.",
    },
    fields: [textField("text", "Ciphertext", { placeholder: "U1C11N63U5M17734N35R6P..." })],
    run: (v) => call("crackVigenere", v.text, 10),
    steps: (r) =>
      r.results.map((x) => ({
        length: x.key_length,
        key: x.key,
        score: x.score,
        plaintext: x.plaintext,
      })),
    stepHeads: ["panjang", "kunci", "skor", "plaintext"],
    resultText: (r) => `terbaik: panjang ${r.results[0]?.key_length}, kunci ${r.results[0]?.key}`,
    extra: true,
  },

  /* ---------------------------------------------------------------- block -- */

  {
    id: "aes",
    family: "block",
    kind: "block",
    name: { id: "AES", en: "AES" },
    blurb: {
      id: "FIPS 197. S-box diturunkan dari invers di GF(2⁸), bukan ditempel.",
      en: "FIPS 197. The S-box is derived from GF(2⁸) inverses, not pasted in.",
    },
    fields: [
      textField("text", "Teks", { placeholder: "HALLO 2026" }),
      { key: "key", label: "Kunci (hex)", type: "hex", placeholder: "000102030405060708090a0b0c0d0e0f" },
      {
        key: "mode",
        label: "Mode",
        type: "select",
        options: [
          ["cbc", "CBC"],
          ["ecb", "ECB"],
          ["ctr", "CTR"],
        ],
        default: "cbc",
      },
    ],
    run: (v) => call("blockEncrypt", {
      plaintext: v.text,
      key: v.key,
      cipher: "aes",
      mode: v.mode,
    }),
    /* The ciphertext comes from the encrypt run when there is one, so a
       visitor never has to copy it by hand. It falls back to the text field so
       a ciphertext pasted from elsewhere still decrypts. The IV travels with it:
       CBC and CTR cannot decrypt without the one used to encrypt. */
    decrypt: (v, _keys, extra) =>
      call("blockDecrypt", {
        ciphertext: extra?.ciphertext ?? v.text,
        key: v.key,
        iv: extra?.iv ?? null,
        cipher: "aes",
        mode: v.mode,
        original_length: extra?.byteLength ?? null,
      }),
    resultText: (r) => r.ciphertext,
    decryptText: (r) => r.plaintext,
    carriesIv: true,
    specNote: "FIPS 197",
  },
  {
    id: "des",
    family: "block",
    kind: "block",
    name: { id: "DES", en: "DES" },
    blurb: {
      id: "FIPS 46-3. Feistel 16 ronde, 8 S-box, kunci efektif 56-bit.",
      en: "FIPS 46-3. A 16-round Feistel, 8 S-boxes, a 56-bit effective key.",
    },
    caution: {
      id: "Deprecated sejak 2005. Ruang kunci 56-bit bisa dipecah brute force. Dipakai di sini sebagai studi, bukan untuk melindungi data.",
      en: "Deprecated since 2005. Its 56-bit key space is brute-forceable. Present for study, not to protect data.",
    },
    fields: [
      textField("text", "Teks", { placeholder: "HALLO 2026" }),
      { key: "key", label: "Kunci (hex)", type: "hex", placeholder: "133457799bbcdff1" },
      {
        key: "mode",
        label: "Mode",
        type: "select",
        options: [
          ["cbc", "CBC"],
          ["ecb", "ECB"],
          ["ctr", "CTR"],
        ],
        default: "cbc",
      },
    ],
    run: (v) => call("blockEncrypt", {
      plaintext: v.text,
      key: v.key,
      cipher: "des",
      mode: v.mode,
    }),
    decrypt: (v, _keys, extra) => call("blockDecrypt", {
      ciphertext: extra?.ciphertext ?? v.text,
      key: v.key,
      iv: extra?.iv ?? null,
      cipher: "des",
      mode: v.mode,
      original_length: extra?.byteLength ?? null,
    }),
    resultText: (r) => r.ciphertext,
    decryptText: (r) => r.plaintext,
    carriesIv: true,
    specNote: "FIPS 46-3",
  },

  /* ----------------------------------------------------------------- hash -- */

  {
    id: "sha256",
    family: "hash",
    kind: "text",
    name: { id: "SHA-256", en: "SHA-256" },
    blurb: {
      id: "FIPS 180-4. Konstanta diturunkan dari akar prima pertama.",
      en: "FIPS 180-4. The constants are derived from the first primes' roots.",
    },
    fields: [textField("text", "Pesan", { placeholder: "abc" })],
    run: (v) => call("sha256", v.text),
    resultText: (r) => r.digest,
    specNote: "FIPS 180-4",
  },
  {
    id: "hmac",
    family: "hash",
    kind: "text",
    name: { id: "HMAC-SHA256", en: "HMAC-SHA256" },
    blurb: {
      id: "RFC 2104. Hash berkey, tahan serangan perpanjangan panjang.",
      en: "RFC 2104. A keyed hash, resistant to length extension.",
    },
    fields: [
      textField("key", "Kunci", { placeholder: "key" }),
      textField("text", "Pesan", { placeholder: "The quick brown fox" }),
    ],
    run: (v) => call("hmac", v.key, v.text),
    resultText: (r) => r.digest,
    specNote: "RFC 2104",
  },

  /* ----------------------------------------------------------- asymmetric -- */

  {
    id: "rsa",
    family: "asymmetric",
    kind: "keygen",
    name: { id: "RSA", en: "RSA" },
    blurb: {
      id: "c = mᵉ mod n. Keamanan sepenuhnya pada seberapa sulit n difaktorkan.",
      en: "c = mᵉ mod n. Security rests entirely on how hard n is to factor.",
    },
    caution: {
      id: "Buku teks apa adanya: tanpa OAEP, tanpa PSS, tanpa CRT. Bukan untuk produksi.",
      en: "Unaltered textbook construction: no OAEP, no PSS, no CRT. Not production-safe.",
    },
    fields: [
      numField("bits", "Ukuran modulus", { default: 1024, min: 256, max: 2048, step: 256 }),
      textField("text", "Pesan", { placeholder: "HALLO 2026" }),
    ],
    keygen: (v) => call("rsaKeygen", v.bits),
    run: (v, keys) => call("rsaEncrypt", v.text, keys.public_key_hex),
    decrypt: (v, keys, extra) =>
      call("rsaDecrypt", extra?.ciphertext ?? [], keys.private_key_hex),
    resultText: (r) => r.ciphertext?.join("\n") ?? "",
    decryptText: (r) => r.plaintext,
  },
  {
    id: "diffie-hellman",
    family: "asymmetric",
    kind: "keygen",
    name: { id: "Diffie-Hellman", en: "Diffie-Hellman" },
    blurb: {
      id: "Dua pihak sepakat pada rahasia lewat g^(ab) mod p. Bergantung pada logaritma diskret.",
      en: "Two parties agree a secret through g^(ab) mod p. Rests on the discrete log.",
    },
    caution: {
      id: "Kesepakatan kunci, bukan enkripsi. Secret-nya masih perlu diturunkan menjadi kunci sebelum dipakai.",
      en: "A key agreement, not encryption. The shared secret still needs a key derivation step before use.",
    },
    fields: [
      numField("bits", "Ukuran p", { default: 512, min: 256, max: 1024, step: 256 }),
      numField("peer_public", "Public peer", {
        default: 0,
        min: 2,
        step: 1,
      }),
    ],
    /* The backend's /dh/parameters returns p and g only, so this derives a real
       key pair locally with the same algorithm the server uses: a random
       exponent in [2, q-2] and g^a mod p. Both parties then agree. */
    keygen: async (v) => {
      const params = await call("dhParameters", v.bits);
      const q = (BigInt(`0x${params.p}`) - 1n) / 2n;

      // A cryptographically-seeded exponent, reduced into the subgroup.
      const bytes = new Uint8Array(24);
      crypto.getRandomValues(bytes);
      let a = 0n;
      for (const byte of bytes) a = (a << 8n) | BigInt(byte);
      a = 2n + (a % (q - 3n));

      const g = BigInt(params.g);
      const p = BigInt(`0x${params.p}`);

      // g^a mod p by square-and-multiply. A plain loop would be O(a), which at
      // 512 bits is not viable in JavaScript's BigInt.
      const modPow = (base, exp, mod) => {
        let result = 1n;
        let b = base % mod;
        let e = exp;
        while (e > 0n) {
          if (e & 1n) result = (result * b) % mod;
          b = (b * b) % mod;
          e >>= 1n;
        }
        return result;
      };

      return {
        p: params.p,
        g: params.g,
        private_exponent: a.toString(),
        public: modPow(g, a, p).toString(),
      };
    },
    run: (v, keys) =>
      call(
        "dhExchange",
        keys.private_exponent,
        v.peer_public,
        keys.p,
        keys.g,
      ),
    resultText: (r) => `shared = ${r.shared_secret}`,
  },
  {
    id: "elgamal",
    family: "asymmetric",
    kind: "keygen",
    name: { id: "ElGamal", en: "ElGamal" },
    blurb: {
      id: "c₁ = gᵏ, c₂ = m·yᵏ. Nonce k baru untuk tiap pesan.",
      en: "c₁ = gᵏ, c₂ = m·yᵏ. A fresh nonce k per message.",
    },
    caution: {
      id: "Menggunakan k yang sama untuk dua pesan membocorkan rasio plaintext-nya.",
      en: "Reusing k across two messages leaks the ratio of the plaintexts.",
    },
    fields: [
      numField("bits", "Ukuran p", { default: 512, min: 256, max: 1024, step: 256 }),
      textField("text", "Pesan", { placeholder: "ATTACK AT DAWN" }),
    ],
    keygen: async (v) => {
      const params = await call("dhParameters", v.bits);
      const keypair = await call("elgamalKeygen", params.p, params.g);
      return { ...params, ...keypair };
    },
    run: (v, keys) => call("elgamalEncrypt", v.text, keys.public, keys.p, keys.g),
    decrypt: (v, keys, extra) =>
      call("elgamalDecrypt", {
        c1: extra?.c1 ?? [],
        c2: extra?.c2 ?? [],
        lengths: extra?.lengths ?? [],
        private: keys.private,
        p: keys.p,
        g: keys.g,
      }),
    resultText: (r) => (r.c1?.length ? `c1: ${r.c1.join("\n")}\nc2: ${r.c2.join("\n")}` : ""),
    decryptText: (r) => r.plaintext,
    carriesIv: true,
  },
  {
    id: "ecdsa",
    family: "asymmetric",
    kind: "signature",
    name: { id: "ECDSA", en: "ECDSA" },
    blurb: {
      id: "Tanda tangan pada kurva elips. r = x(kG) mod n, s = k⁻¹(H + rd) mod n.",
      en: "Signatures over an elliptic curve. r = x(kG) mod n, s = k⁻¹(H + rd) mod n.",
    },
    fields: [
      {
        key: "curve",
        label: "Kurva",
        type: "select",
        options: [
          ["secp192r1", "secp192r1"],
          ["secp256k1", "secp256k1"],
        ],
        default: "secp192r1",
      },
      textField("text", "Pesan", { placeholder: "HELLO 2026" }),
    ],
    keygen: (v) => call("eccKeygen", v.curve),
    run: (v, keys) => call("eccSign", v.text, keys.private, v.curve),
    decrypt: (v, keys, extra) =>
      call("eccVerify", v.text, extra?.r ?? 0, extra?.s ?? 0, keys.public, v.curve),
    resultText: (r) => `r = ${r.r}\ns = ${r.s}`,
    decryptText: (r) => (r.valid ? "valid" : "invalid"),
    labelFor: { encrypt: "Tanda tangan", decrypt: "Verifikasi" },
  },
];

/** Read the `result` field from a text-cipher response. */
function textOut0(r) {
  return r.result;
}

export const byId = Object.fromEntries(ALGORITHMS.map((a) => [a.id, a]));

export const byFamily = FAMILIES.reduce((acc, family) => {
  acc[family.id] = ALGORITHMS.filter((a) => a.family === family.id);
  return acc;
}, {});

export const counts = Object.fromEntries(
  FAMILIES.map((f) => [f.id, byFamily[f.id].length]),
);

export const TOTAL = ALGORITHMS.length;