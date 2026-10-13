/**
 * Exercise every registry entry against the live API from Node.
 *
 * Imports the real registry and the real API client, calls each entry's `run`
 * with its seeded field values, and reports the outcome. This covers exactly the
 * contract the React components use, without a browser in the loop.
 *
 * Run:  node scripts/verify-registry.mjs
 */

import { ALGORITHMS, parseMatrix } from "../src/registry.js";

// The API client reads import.meta.env, which Node lacks; api.js already falls
// back to the direct backend address outside a browser.
const BASE = process.env.VITE_API_BASE ?? "http://localhost:8000";

async function seedValues(algo) {
  const out = {};
  for (const f of algo.fields) {
    if (f.default !== undefined && f.default !== "") out[f.key] = String(f.default);
    else if (f.type === "select") out[f.key] = f.options?.[0]?.[0] ?? "";
    else if (f.type === "text" || f.type === "hex") out[f.key] = f.placeholder ?? "";
    else out[f.key] = "";
  }
  return out;
}

/** Apply the same coercions the Workbench applies before calling run(). */
function prepare(values) {
  const v = { ...values };
  if (v.matrix) v.matrix = parseMatrix(v.matrix);
  if (v.residues) v.residues = v.residues.split(/[\s,]+/).filter(Boolean).map(Number);
  if (v.moduli) v.moduli = v.moduli.split(/[\s,]+/).filter(Boolean).map(Number);
  // ECDSA scalars exceed Number.MAX_SAFE_INTEGER and travel as strings.
  if (v.private !== undefined) v.private = String(v.private);
  return v;
}

const results = [];

for (const algo of ALGORITHMS) {
  const started = Date.now();

  // A keygen entry needs its key before run() can work.
  let keys = null;
  try {
    if (algo.keygen) keys = await algo.keygen(await seedValues(algo));
  } catch (error) {
    results.push({ id: algo.id, stage: "keygen", ok: false, note: error.message });
    continue;
  }

  const values = prepare(await seedValues(algo));

  // Diffie-Hellman needs the other party's public value. Derive a second party
  // from the same parameters so the exchange is real rather than a placeholder.
  if (algo.id === "diffie-hellman") {
    const peer = await algo.keygen(values);
    values.peer_public = peer.public;
  }

  try {
    const response = await algo.run(values, keys);
    const text = algo.resultText ? String(algo.resultText(response) ?? "") : "";
    const steps = algo.steps ? (algo.steps(response)?.length ?? 0) : 0;
    results.push({
      id: algo.id,
      stage: "run",
      ok: true,
      note: text.slice(0, 46).replace(/\n/g, " / "),
      steps,
      ms: Date.now() - started,
    });
  } catch (error) {
    results.push({ id: algo.id, stage: "run", ok: false, note: error.message.slice(0, 70) });
  }
}

let pass = 0;
let fail = 0;
for (const r of results) {
  const mark = r.ok ? "ok  " : "FAIL";
  const steps = r.ok && r.steps ? `  steps=${r.steps}` : "";
  console.log(`${mark} ${r.id.padEnd(22)} ${String(r.note).padEnd(48)}${steps}`);
  if (r.ok) pass += 1;
  else fail += 1;
}

console.log(`\n${pass} passed, ${fail} failed, of ${ALGORITHMS.length} algorithms`);
console.log(`base: ${BASE}`);
process.exit(fail ? 1 : 0);