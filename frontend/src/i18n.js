/**
 * Bilingual copy. Indonesian is the default; English is a peer, not a fallback.
 *
 * Keys are grouped by surface so a missing string is obvious at the call site.
 * Every user-visible string lives here — no inline copy in components.
 */

export const LANGS = ["id", "en"];
export const DEFAULT_LANG = "id";

/** The 37-symbol alphabet, in order. Shared by every cipher on the site. */
export const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";

const dict = {
  id: {
    "brand.name": "Kriptografi",
    "brand.tagline": "Meja gambar untuk algoritma",

    "nav.home": "Beranda",
    "nav.math": "Matematika",
    "nav.classical": "Klasik",
    "nav.transposition": "Transposisi",
    "nav.block": "Blok",
    "nav.asymmetric": "Asimetris",
    "nav.hash": "Hash",

    "theme.toggle": "Ganti tema",
    "theme.dark": "Gelap",
    "theme.light": "Terang",
    "lang.toggle": "Ganti bahasa",
    "lang.id": "ID",
    "lang.en": "EN",

    "hero.plate": "Pelat 01",
    "hero.title": "Kriptografi",
    "hero.lead":
      "Seluruh algoritma ditulis dari nol. Tidak ada pustaka kriptografi yang dipanggil. Setiap hasil diverifikasi terhadap vektor uji yang dipublikasikan.",
    "hero.canvasAlt":
      "Animasi substitution cipher: baris plaintext dan ciphertext bergerak, dengan grid karakter dan penggeseran yang terlihat",

    "eggs.plate": "Pelat 02 / Temuan",
    "eggs.title": "Yang tersembunyi",
    "eggs.egcd.title": "Bukti Extended Euclid",
    "eggs.egcd.note": "K inversely 3 mod 7 = 5",
    "eggs.spec.title": "Vektor Uji",
    "eggs.spec.note": "7/7 DES lolos FIPS 46-3",
    "eggs.hack.title": "Kunci Salah",
    "eggs.hack.note": "RSA memberitahu kamu itu salah",
    "eggs.spectre.title": "Rahasia Karakter",
    "eggs.spectre.note": "Alfabet punya 37 simbol",
    "eggs.closed": "Tertutup lagi",
    "eggs.open": "Terbuka",

    "pick.plate": "Pelat 03 / Pilih",
    "pick.title": "Pilih algoritma",
    "pick.lead": "Tiga puluh algoritma, diuji, dengan langkah-langkahnya sendiri.",
    "pick.label": "Algoritma",
    "pick.cta": "Buka",
    "pick.search": "Saring algoritma",

    "family.plate": "Pelat",
    "family.count": "algoritma",
    "family.toSpec": "Lihat spesifikasi",
    "family.specNote":
      "Bahan ajar. Bukan implementasi produksi — tanpa OAEP, tanpa PSS, tanpa CRT.",

    "spec.plate": "Spesifikasi",
    "spec.cautionTitle": "Bahan ajar, bukan produksi",
    "spec.caution":
      "RSA dan ECDSA di sini adalah konstruksi buku teks yang begitu apa adanya. Tidak ada padding OAEP atau PSS, tidak ada Chinese Remainder Theorem, dan nonce ECDSA bukan versi constant-time. DES sudah deprecated sejak 2005. Gunakan pustaka terverifikasi untuk apa pun yang penting.",

    "run.plate": "Masukan",
    "run.text": "Teks",
    "run.key": "Kunci",
    "run.plaintext": "Plaintext",
    "run.ciphertext": "Ciphertext",
    "run.shift": "Pergeseran",
    "run.rails": "Rel",
    "run.columns": "Kolom",
    "run.a": "Koefisien a",
    "run.b": "Konstanta b",
    "run.matrix": "Matriks",
    "run.aVal": "Nilai a",
    "run.bVal": "Nilai b",
    "run.cipher": "Cipher",
    "run.mode": "Mode",
    "run.nonce": "IV / Nonce",
    "run.payload": "Payload",
    "run.op": "Operasi",
    "run.encrypt": "Enkripsi",
    "run.decrypt": "Dekripsi",
    "run.go": "Jalankan",
    "run.result": "Hasil",
    "run.steps": "Langkah",
    "run.stepsNone": "Algoritma ini tidak mengembalikan langkah.",
    "run.empty": "Hasil akan muncul di sini.",
    "run.synthetic": "Data contoh — ganti dengan milikmu sendiri",

    "verify.plate": "Verifikasi",
    "verify.pass": "LOLOS",
    "verify.fail": "GAGAL",
    "verify.idle": "—",
    "verify.title": "Vektor Uji Resmi",
    "verify.sub": "Diknown-answer terhadap spesifikasi yang dipublikasikan",
    "verify.running": "Menghitung…",
    "verify.allPass": "Semua vektor lolos",
    "verify.since": "terverifikasi",

    "opt.outcome": "Hasil",
    "opt.error": "Kesalahan",
    "opt.demo": "Klik Jalankan",

    "foot.note":
      "Seluruh algoritma diimplementasikan dari spesifikasi publik dan diverifikasi terhadap vektor uji masing-masing.",
    "foot.verif": "Verifikasi",
    "foot.stack": "Tumpukan",
    "foot.api": "Dokumentasi API",
  },

  en: {
    "brand.name": "Kriptografi",
    "brand.tagline": "A drafting table for algorithms",

    "nav.home": "Home",
    "nav.math": "Mathematics",
    "nav.classical": "Classical",
    "nav.transposition": "Transposition",
    "nav.block": "Block",
    "nav.asymmetric": "Asymmetric",
    "nav.hash": "Hash",

    "theme.toggle": "Toggle theme",
    "theme.dark": "Dark",
    "theme.light": "Light",
    "lang.toggle": "Switch language",
    "lang.id": "ID",
    "lang.en": "EN",

    "hero.plate": "Plate 01",
    "hero.title": "Kriptografi",
    "hero.lead":
      "Every algorithm written from scratch. No cryptography library is called. Each result is verified against published test vectors.",
    "hero.canvasAlt":
      "Animated substitution cipher: plaintext and ciphertext rows in motion, with the character grid and active shift visible",

    "eggs.plate": "Plate 02 / Findings",
    "eggs.title": "What is hidden",
    "eggs.egcd.title": "Extended Euclid proof",
    "eggs.egcd.note": "3 inverse mod 7 = 5",
    "eggs.spec.title": "Test vectors",
    "eggs.spec.note": "7/7 DES pass FIPS 46-3",
    "eggs.hack.title": "Wrong key",
    "eggs.hack.note": "RSA tells you it failed",
    "eggs.spectre.title": "Character secret",
    "eggs.spectre.note": "The alphabet has 37 symbols",
    "eggs.closed": "Closed again",
    "eggs.open": "Open",

    "pick.plate": "Plate 03 / Select",
    "pick.title": "Pick an algorithm",
    "pick.lead": "Thirty algorithms, tested, each with its own steps.",
    "pick.label": "Algorithm",
    "pick.cta": "Open",
    "pick.search": "Filter algorithms",

    "family.plate": "Plate",
    "family.count": "algorithms",
    "family.toSpec": "Read the spec",
    "family.specNote":
      "Teaching material. Not a production implementation — no OAEP, no PSS, no CRT.",

    "spec.plate": "Specification",
    "spec.cautionTitle": "Teaching material, not production",
    "spec.caution":
      "The RSA and ECDSA here are textbook constructions, unaltered. There is no OAEP or PSS padding, no Chinese Remainder Theorem, and the ECDSA nonce is not the constant-time version. DES has been deprecated since 2005. Use a vetted library for anything that matters.",

    "run.plate": "Input",
    "run.text": "Text",
    "run.key": "Key",
    "run.plaintext": "Plaintext",
    "run.ciphertext": "Ciphertext",
    "run.shift": "Shift",
    "run.rails": "Rails",
    "run.columns": "Columns",
    "run.a": "Coefficient a",
    "run.b": "Constant b",
    "run.matrix": "Matrix",
    "run.aVal": "Value a",
    "run.bVal": "Value b",
    "run.cipher": "Cipher",
    "run.mode": "Mode",
    "run.nonce": "IV / Nonce",
    "run.payload": "Payload",
    "run.op": "Operation",
    "run.encrypt": "Encrypt",
    "run.decrypt": "Decrypt",
    "run.go": "Run",
    "run.result": "Result",
    "run.steps": "Steps",
    "run.stepsNone": "This algorithm returns no steps.",
    "run.empty": "The result will appear here.",
    "run.synthetic": "Sample data — replace with your own",

    "verify.plate": "Verification",
    "verify.pass": "PASS",
    "verify.fail": "FAIL",
    "verify.idle": "—",
    "verify.title": "Official test vectors",
    "verify.sub": "Known-answer against the published specifications",
    "verify.running": "Computing…",
    "verify.allPass": "All vectors pass",
    "verify.since": "verified",

    "opt.outcome": "Result",
    "opt.error": "Error",
    "opt.demo": "Press Run",

    "foot.note":
      "Every algorithm implemented from public specifications and checked against their published test vectors.",
    "foot.verif": "Verification",
    "foot.stack": "Stack",
    "foot.api": "API documentation",
  },
};

/** Look up a key, falling back to Indonesian then to the key itself. */
export function translate(lang, key) {
  return dict[lang]?.[key] ?? dict[DEFAULT_LANG][key] ?? key;
}

/** Bind a language to a lookup function. */
export function makeT(lang) {
  return (key) => translate(lang, key);
}