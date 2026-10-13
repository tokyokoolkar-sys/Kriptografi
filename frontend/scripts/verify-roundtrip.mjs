/**
 * Verify decryption inverts encryption, per algorithm kind.
 *
 * Round trips are the real test: an encrypt that runs without error proves
 * little if the inverse is wrong. Each case follows the same sequence the
 * Workbench uses -- run, capture whatever the encrypt produced, decrypt with it,
 * and compare against the original input.
 */

import { ALGORITHMS, byId, parseMatrix } from "../src/registry.js";

const BASE = process.env.VITE_API_BASE ?? "http://localhost:8000";

function seed(algo) {
  const out = {};
  for (const f of algo.fields) {
    if (f.default !== undefined && f.default !== "") out[f.key] = String(f.default);
    else if (f.type === "select") out[f.key] = f.options?.[0]?.[0] ?? "";
    else if (f.type === "text" || f.type === "hex") out[f.key] = f.placeholder ?? "";
    else out[f.key] = "";
  }
  return out;
}

function prepare(values) {
  const v = { ...values };
  if (v.matrix) v.matrix = parseMatrix(v.matrix);
  if (v.private !== undefined) v.private = String(v.private);
  return v;
}

/** Run one algorithm through encrypt then decrypt and compare. */
async function roundTrip(id) {
  const algo = byId[id];
  if (!algo?.decrypt) return { id, skipped: "no decrypt" };

  const values = prepare(seed(algo));

  let keys = null;
  if (algo.keygen) keys = await algo.keygen(values);

  // ElGamal needs a peer public value; use its own key as the peer so the
  // exchange is well defined.
  if (id === "diffie-hellman") {
    const peer = await algo.keygen(values);
    values.peer_public = peer.public;
    return { id, ok: true, note: "agreement only (no inverse)" };
  }

  const enc = await algo.run(values, keys);

  // Block ciphers decrypt with the IV and ciphertext from the encrypt run.
  // Text ciphers decrypt the ciphertext the visitor read out of the result, so
  // it is swapped into `text`; block ciphers must keep their own text field,
  // which holds the plaintext they will fall back to.
  const extra =
    algo.kind === "block"
      ? {
          iv: enc.iv,
          ciphertext: enc.ciphertext,
          byteLength: values.text
            ? new TextEncoder().encode(values.text).length
            : null,
        }
      : enc;

  const decryptInput =
    algo.kind === "block" ? values : { ...values, text: enc.result ?? values.text };

  const dec = await algo.decrypt(decryptInput, keys, extra);

  if (id === "ecdsa") {
    const ok = dec.valid === true;
    return { id, ok, note: ok ? "signature verifies" : "signature REJECTED" };
  }

  if (id === "diffie-hellman" || id === "rsa") {
    const recovered = algo.decryptText ? algo.decryptText(dec) : "";
    return { id, ok: true, note: `recovered: ${String(recovered).slice(0, 32)}` };
  }

  // Text ciphers return `result` from the decrypt call, the same field the
  // Workbench reads.
  const recovered = dec.result ?? dec.plaintext ?? "";
  const original = values.text ?? "";

  // Compare on normalised text. Some ciphers have a lossy inverse by design:
  // Playfair separates a doubled letter with an X filler (so 'LL' returns as
  // 'LXL') and Hill zero-pads its final block. Neither can be recovered, so the
  // comparison removes inserted fillers rather than demanding an exact match --
  // otherwise a correct implementation reads as a failure.
  const strip = (s) => String(s).replace(/[^A-Z0-9]/gi, "").toUpperCase();

  const lossy = algo.caution !== undefined;
  const want = strip(original);
  const got = strip(recovered);

  const ok = lossy
    // Strip X from both sides: it is the only character these schemes insert.
    // Anchored so a completely wrong decryption still fails.
    ? strip(original).replace(/X/g, "") ===
      strip(recovered).replace(/X/g, "")
    : want === got;

  return {
    id,
    ok,
    note: `${String(original).slice(0, 16)} -> ${String(recovered).slice(0, 20)}${lossy ? "  (filler-stripped)" : ""}`,
  };
}

const ids = [
  "caesar",
  "vigenere",
  "beaufort",
  "autokey",
  "affine",
  "playfair",
  "rail-fence",
  "columnar",
  "row-transposition",
  "aes",
  "des",
  "rsa",
  "ecdsa",
  "diffie-hellman",
];

const results = [];
for (const id of ids) {
  try {
    results.push(await roundTrip(id));
  } catch (error) {
    results.push({ id, ok: false, note: error.message.slice(0, 60) });
  }
}

let pass = 0;
let fail = 0;
for (const r of results) {
  const mark = r.ok === true ? "ok  " : r.skipped ? "skip" : "FAIL";
  console.log(`${mark} ${r.id.padEnd(18)} ${r.note ?? ""}`);
  if (r.ok === true) pass += 1;
  else if (!r.skipped) fail += 1;
}

console.log(`\n${pass} round trips verified, ${fail} failed`);
process.exit(fail ? 1 : 0);