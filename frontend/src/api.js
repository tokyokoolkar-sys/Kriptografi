/**
 * Thin fetch wrapper around the FastAPI backend.
 *
 * The backend is a thin wrapper too: every endpoint takes JSON and returns JSON
 * with a typed shape, so this stays deliberately dumb. Error detail is lifted
 * out of FastAPI's `{detail: ...}` envelope so callers get a plain string.
 */

/**
 * Base URL for the API.
 *
 * Under Vite, `import.meta.env.VITE_API_BASE` supplies the value and defaults to
 * the `/api` prefix that vite.config.js proxies to :8000. Outside a browser --
 * Node scripts that import this module to exercise the registry -- there is no
 * `import.meta.env` and no origin to be relative to, so fall back to the backend
 * address directly rather than producing an unresolvable relative URL.
 */
const ENV = (typeof import.meta !== "undefined" && import.meta.env) || {};
const IN_BROWSER = typeof window !== "undefined";
const BASE =
  ENV.VITE_API_BASE ?? (IN_BROWSER ? "/api" : "http://localhost:8000");

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(`${BASE}${path}`, {
      headers: { "Content-Type": "application/json" },
      ...options,
    });
  } catch (cause) {
    throw new Error(
      "Cannot reach the API. Start the backend with: uvicorn kriptografi.api.main:app --reload",
    );
  }

  const text = await response.text();
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = { detail: text };
    }
  }

  if (!response.ok) {
    const detail =
      typeof body?.detail === "string"
        ? body.detail
        : Array.isArray(body?.detail)
          ? body.detail.map((d) => d.msg ?? JSON.stringify(d)).join("; ")
          : `Request failed with status ${response.status}`;
    throw new Error(detail);
  }

  return body;
}

const get = (path, params) => {
  const search = new URLSearchParams(
    Object.entries(params ?? {}).filter(([, v]) => v !== undefined && v !== null),
  );
  const qs = search.toString();
  return request(`${path}${qs ? `?${qs}` : ""}`);
};

const post = (path, payload) =>
  request(path, { method: "POST", body: JSON.stringify(payload) });

export const api = {
  health: () => get("/health"),
  openapi: () => get("/openapi.json"),

  // Number theory
  gcd: (a, b) => post("/math/gcd", { a: Number(a), b: Number(b) }),
  modInverse: (a, m) => post("/math/mod-inverse", { a: Number(a), m: Number(m) }),
  crt: (residues, moduli) =>
    post("/math/crt", { residues: residues.map(Number), moduli: moduli.map(Number) }),
  primality: (n) => post("/math/primality", { n: Number(n) }),
  factorize: (n) => post("/math/factorize", { n: Number(n) }),
  powmod: (base, exponent, modulus) =>
    post("/math/powmod", {
      base: Number(base),
      exponent: Number(exponent),
      modulus: Number(modulus),
    }),
  totient: (n) => post("/math/totient", { n: Number(n) }),
  discreteLog: (base, target, modulus) =>
    get("/math/discrete-log", { base: Number(base), target: Number(target), modulus: Number(modulus) }),

  // Classical
  caesarEncrypt: (text, shift) =>
    post("/classical/caesar/encrypt", { text, shift: Number(shift) }),
  caesarDecrypt: (text, shift) =>
    post("/classical/caesar/decrypt", { text, shift: Number(shift) }),
  vigenere: (text, key, operation = "encrypt") =>
    post("/classical/vigenere", { text, key, operation }),
  beaufort: (text, key, operation = "encrypt") =>
    post("/classical/beaufort", { text, key, operation }),
  autokey: (text, key, operation = "encrypt") =>
    post("/classical/autokey", { text, key, operation }),
  affine: (text, a, b, operation = "encrypt") =>
    post("/classical/affine", { text, a: Number(a), b: Number(b), operation }),
  affineKeys: () => get("/classical/affine/keys"),
  playfair: (text, key, operation = "encrypt") =>
    post("/classical/playfair", { text, key, operation }),
  hill: (text, matrix, operation = "encrypt") =>
    post("/classical/hill", { text, matrix, operation }),

  // Transposition
  railFenceEncrypt: (text, rails) =>
    post("/transposition/rail-fence/encrypt", { text, rails: Number(rails) }),
  railFenceDecrypt: (text, rails) =>
    post("/transposition/rail-fence/decrypt", { text, rails: Number(rails) }),
  columnar: (text, key, operation = "encrypt") =>
    request(`/transposition/columnar?operation=${operation}`, {
      method: "POST",
      body: JSON.stringify({ text, key }),
    }),
  rowTransposition: (text, key, columns, operation = "encrypt") =>
    request(`/transposition/row?operation=${operation}`, {
      method: "POST",
      body: JSON.stringify({ text, key, columns: Number(columns) }),
    }),

  // Analysis
  frequency: (text) => get("/transposition/analysis/frequency", { text }),
  ic: (text) => get("/transposition/analysis/ic", { text }),
  crackCaesar: (text, top = 5) => get("/transposition/analysis/crack-caesar", { text, top }),
  crackVigenere: (text, maxKeyLength = 12) =>
    get("/transposition/analysis/crack-vigenere", { text, max_key_length: maxKeyLength }),

  // Block
  blockEncrypt: (payload) => post("/block/encrypt", payload),
  blockDecrypt: (payload) => post("/block/decrypt", payload),
  blockModes: () => get("/block/modes"),

  // Hash
  sha256: (message) => post("/hash/sha256", { message }),
  hmac: (key, message) => post("/hash/hmac-sha256", { key, message }),

  // RSA
  rsaKeygen: (bits) => post("/rsa/keygen", { bits: Number(bits) }),
  rsaEncrypt: (message, publicKey) => post("/rsa/encrypt", { message, public_key: publicKey }),
  rsaDecrypt: (ciphertext, privateKey) =>
    post("/rsa/decrypt", { ciphertext, private_key: privateKey }),

  // Diffie-Hellman. Every group value is group-sized and crosses the wire as a
  // string; p is hex, the rest decimal, matching what the backend parses.
  dhParameters: (bits) => post("/dh/parameters", { bits: Number(bits) }),
  dhExchange: (privateExp, peerPublic, p, g) =>
    post("/dh/exchange", {
      private: String(privateExp),
      peer_public: String(peerPublic),
      p: String(p),
      g: String(g),
    }),
  elgamalKeygen: (p, g) => post("/dh/elgamal/keygen", { p, g: Number(g) }),
  elgamalEncrypt: (message, publicKey, p, g) =>
    post("/dh/elgamal/encrypt", { message, public: publicKey, p, g: Number(g) }),
  elgamalDecrypt: (payload) => post("/dh/elgamal/decrypt", payload),

  // ECC. ECDSA's r and s are 192- or 256-bit integers, far past
  // Number.MAX_SAFE_INTEGER, so every value crosses the wire as a decimal
  // string and is never coerced to a Number on either side.
  eccCurves: () => get("/ecc/curves"),
  eccKeygen: (curve) => post("/ecc/keygen", { curve }),
  eccSign: (message, priv, curve) =>
    post("/ecc/sign", { message, private: String(priv), curve }),
  eccVerify: (message, r, s, publicPoint, curve) =>
    post("/ecc/verify", {
      message,
      r: String(r),
      s: String(s),
      public: publicPoint,
      curve,
    }),
};

export { BASE as API_BASE };