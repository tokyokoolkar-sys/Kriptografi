/**
 * The algorithm workbench.
 *
 * One page per algorithm: inputs, a run button, the result, and the step trace.
 * The trace is the product — where the backend returns one, it is rendered as a
 * ruled table rather than collapsed behind a summary.
 *
 * Keygen algorithms generate a key first, then use it. Block ciphers carry the
 * IV from encryption to decryption, because that is exactly the step people lose.
 */

import { useState, useMemo, useEffect } from "react";
import { useApp } from "../app-context.jsx";
import {
  Plate,
  TitleBlock,
  AsciiTable,
  Readout,
  Field,
  Segmented,
  Mark,
  CharMap,
  useCopy,
} from "../components/ui.jsx";
import { ALPHABET } from "../i18n.js";

/**
 * Seed an algorithm's input values.
 *
 * A field's `default` wins; otherwise a text or hex field falls back to its
 * placeholder, so every page opens with something runnable instead of an empty
 * box the visitor has to guess at. Numbers without a default stay empty rather
 * than being invented.
 */
function seedValues(algo) {
  return Object.fromEntries(
    algo.fields.map((f) => {
      if (f.default !== undefined && f.default !== "") {
        return [f.key, String(f.default)];
      }
      if (f.type === "select") {
        return [f.key, f.options?.[0]?.[0] ?? ""];
      }
      if (f.type === "text" || f.type === "hex") {
        return [f.key, f.placeholder ?? ""];
      }
      return [f.key, ""];
    }),
  );
}

/** Pull a readable step table out of whatever shape the backend returned. */
function stepsToRows(algo, response) {
  if (!algo.steps) return null;
  let raw;
  try {
    raw = algo.steps(response);
  } catch {
    return null;
  }
  if (!Array.isArray(raw) || !raw.length) return null;
  return raw;
}

export default function Workbench({ algoId }) {
  const { t, pick, byId, navigate } = useApp();
  const algo = byId[algoId];

  const [values, setValues] = useState(() => (algo ? seedValues(algo) : {}));

  const [operation, setOperation] = useState("encrypt");
  const [result, setResult] = useState(null);
  const [keys, setKeys] = useState(null);
  const [status, setStatus] = useState("idle");
  const [error, setError] = useState(null);
  const { copied, copy } = useCopy();

  /* Reset when navigating between algorithms. */
  useEffect(() => {
    if (!algo) return;
    setValues(seedValues(algo));
    setOperation("encrypt");
    setResult(null);
    setKeys(null);
    setError(null);
    setStatus("idle");
  }, [algoId, algo]);

  const stepRows = useMemo(
    () => (result ? stepsToRows(algo, result.response) : null),
    [algo, result],
  );

  if (!algo) {
    return (
      <div className="wrap" style={{ paddingBlock: "var(--sp-8)" }}>
        <Plate tab="404" tone="signal">
          <h2>{t("opt.error")}</h2>
          <p className="dim mono">{algoId}</p>
        </Plate>
      </div>
    );
  }

  const setValue = (key, value) => setValues((prev) => ({ ...prev, [key]: value }));

  const canDecrypt = Boolean(algo.decrypt);
  const isKeygen = Boolean(algo.keygen);
  const isSignature = algo.kind === "signature";

  /* ---- keygen ---------------------------------------------------------- */

  const generateKey = async () => {
    setStatus("keygen");
    setError(null);
    try {
      const generated = await algo.keygen(values);
      setKeys(generated);
      setStatus("idle");
    } catch (err) {
      setError(err.message);
      setStatus("error");
    }
  };

  /* ---- run ------------------------------------------------------------- */

  const run = async () => {
    setStatus("running");
    setError(null);
    try {
      const decrypting = operation === "decrypt";

      /* Decryption needs whatever the encrypt run produced: the IV for block
         ciphers (CBC and CTR cannot decrypt without it) and, for every other
         kind, the ciphertext itself so the visitor never copies it by hand. */
      let extra;
      if (decrypting) {
        if (!result) {
          throw new Error(
            "Run an encryption first — decryption needs its output.",
          );
        }
        if (algo.kind === "block") {
          if (!result.iv && result.response.mode !== "ecb" && v.mode !== "ecb") {
            throw new Error(
              "This mode needs the IV from the encryption run. Run an encryption first.",
            );
          }
          extra = {
            iv: result.iv,
            ciphertext: result.response.ciphertext ?? result.response.plaintext,
            byteLength: result.byteLength,
          };
        } else {
          extra = result.response;
        }
      } else if (isKeygen && !keys) {
        throw new Error("Generate a key pair first.");
      }

      const response = await algo[decrypting ? "decrypt" : "run"](values, keys, extra);

      setResult({
        response,
        iv: response.iv ?? null,
        byteLength: values.text ? new TextEncoder().encode(values.text).length : null,
      });
      setStatus("idle");
    } catch (err) {
      setError(err.message);
      setStatus("error");
    }
  };

  /* ---- output rendering -------------------------------------------------- */

  const outputText = (() => {
    if (!result) return null;
    if (operation === "decrypt" && algo.decryptText) return algo.decryptText(result.response);
    if (algo.resultText) return algo.resultText(result.response);
    return null;
  })();

  /* For the signature kind, "decrypt" is verification, so read it as a verdict. */
  const isVerdict = isSignature && operation === "decrypt" && result;

  const encryptLabel = algo.labelFor?.encrypt ?? t("run.encrypt");
  const decryptLabel = algo.labelFor?.decrypt ?? t("run.decrypt");

  return (
    <div className="wrap" style={{ paddingBlock: "var(--sp-5)" }}>
      {/* ---- header ---------------------------------------------------- */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: "var(--sp-3)", alignItems: "flex-end", justifyContent: "space-between", marginBottom: "var(--sp-4)" }}>
        <div>
          <span className="label">
            {algo.family} · {algo.kind}
            {algo.specNote ? ` · ${algo.specNote}` : ""}
          </span>
          <h2 style={{ marginTop: "var(--sp-2)" }}>{pick(algo.name)}</h2>
          <p className="lead" style={{ fontSize: "var(--fs-small)", marginTop: "var(--sp-1)" }}>
            {pick(algo.blurb)}
          </p>
        </div>
        <button
          type="button"
          className="btn btn--sm"
          onClick={() => navigate(`/${algo.family}`)}
        >
          ← {algo.family}
        </button>
      </div>

      {algo.caution && (
        <div className="note" style={{ marginBottom: "var(--sp-4)" }}>
          <strong>{t("spec.cautionTitle")}</strong>
          <div style={{ marginTop: 4 }}>{pick(algo.caution)}</div>
        </div>
      )}

      <div className="mosaic mosaic--wide">
        {/* ---- input plate ------------------------------------------- */}
        <div className="mosaic__cell">
          <Plate tab={t("run.plate")} meta={t("run.synthetic")} tone={status === "error" ? "signal" : undefined}>
            <div className="stack" style={{ gap: "var(--sp-3)" }}>
              {canDecrypt && (
                <Segmented
                  label={t("run.op")}
                  value={operation}
                  onChange={(v) => {
                    setOperation(v);
                    setError(null);
                  }}
                  options={[
                    ["encrypt", encryptLabel],
                    ["decrypt", decryptLabel],
                  ]}
                />
              )}

              {algo.fields.map((field) => (
                <Field
                  key={field.key}
                  field={field}
                  value={values[field.key]}
                  onChange={setValue}
                  t={t}
                />
              ))}

              {isKeygen && (
                <button
                  type="button"
                  className="btn btn--block"
                  onClick={generateKey}
                  disabled={status === "keygen"}
                >
                  {status === "keygen" ? t("verify.running") : "Generate key pair"}
                </button>
              )}

              <button
                type="button"
                className="btn btn--primary btn--block"
                onClick={run}
                disabled={status === "running"}
              >
                {status === "running" ? t("verify.running") : t("run.go")}
              </button>

              {error && (
                <div className="note">
                  <span className="label label--signal">{t("opt.error")}</span>
                  <div className="mono" style={{ fontSize: "var(--fs-micro)", marginTop: 4 }}>
                    {error}
                  </div>
                </div>
              )}
            </div>
          </Plate>
        </div>

        {/* ---- result plate ------------------------------------------- */}
        <div className="mosaic__cell">
          <Plate
            tab={t("run.result")}
            meta={
              result ? (
                <button
                  type="button"
                  className="label label--signal"
                  onClick={() => copy(String(outputText ?? ""))}
                  style={{ textDecoration: "underline" }}
                >
                  {copied ? "copied ✓" : "copy"}
                </button>
              ) : null
            }
            tone={result ? "signal" : undefined}
          >
            <div className="stack" style={{ gap: "var(--sp-3)", flex: 1 }}>
              <Readout tone={result ? "signal" : undefined} empty={t("run.empty")}>
                {isVerdict ? (
                  <span
                    style={{
                      color: result.response.valid ? "var(--signal)" : "var(--ink-faint)",
                      fontWeight: 800,
                    }}
                  >
                    {result.response.valid ? "✓ VALID" : "✗ INVALID"}
                  </span>
                ) : (
                  outputText
                )}
              </Readout>

              {/* The inputs echoed back, so the plate carries real information
                  instead of standing empty beside a one-line result. */}
              {!isVerdict && (
                <div className="stack" style={{ gap: "var(--sp-2)" }}>
                  {algo.fields
                    .filter((f) => f.type !== "select" && values[f.key])
                    .map((field) => (
                      <div key={field.key}>
                        <span className="label">
                          {typeof field.label === "string" ? field.label : field.label?.id}
                        </span>
                        <div className="readout mono" style={{ marginTop: 4 }}>
                          {String(values[field.key])}
                        </div>
                      </div>
                    ))}
                </div>
              )}

              {result?.iv && algo.kind === "block" && (
                <div>
                  <span className="label">{t("run.nonce")}</span>
                  <div className="readout mono" style={{ marginTop: 4, fontSize: "var(--fs-micro)" }}>
                    {result.iv}
                  </div>
                </div>
              )}

              {/* Plaintext/ciphertext side by side where the kind allows it. */}
              {algo.kind === "text" && !isVerdict && (
                <div style={{ display: "grid", gap: "var(--sp-2)" }}>
                  <div>
                    <span className="label">{t("run.plaintext")}</span>
                    <div className="readout mono" style={{ marginTop: 4 }}>
                      {values.text}
                    </div>
                  </div>
                  <div>
                    <span className="label label--signal">{t("run.ciphertext")}</span>
                    <div className="readout readout--signal mono" style={{ marginTop: 4 }}>
                      {String(outputText ?? "")}
                    </div>
                  </div>
                </div>
              )}

              {/* The alphabet mapping, for the text ciphers. */}
              {algo.kind === "text" && (
                <div>
                  <span className="label">base 37</span>
                  <div style={{ marginTop: 6 }}>
                    <CharMap />
                  </div>
                </div>
              )}
            </div>
          </Plate>
        </div>

        {/* ---- steps plate, full width -------------------------------- */}
        {stepRows && (
          <div className="mosaic__cell" style={{ gridColumn: "1 / -1" }}>
            <Plate tab={t("run.steps")} meta={`${stepRows.length} rows`}>
              <StepTable algo={algo} rows={stepRows} t={t} />
            </Plate>
          </div>
        )}

        {/* ---- key plate for keygen kinds ------------------------------ */}
        {keys && (
          <div className="mosaic__cell" style={{ gridColumn: "1 / -1" }}>
            <Plate tab="KEY" meta={isKeygen ? "generated" : undefined}>
              <KeyTable keys={keys} t={t} />
            </Plate>
          </div>
        )}
      </div>

      <div style={{ marginTop: "var(--sp-5)" }}>
        <TitleBlock
          cells={[
            { k: "SHEET", v: `${algo.family.toUpperCase()} / ${algo.id.toUpperCase()}` },
            { k: "SPEC", v: algo.specNote ?? "—" },
            { k: "KIND", v: algo.kind },
            { k: "STEPS", v: stepRows ? String(stepRows.length) : "—" },
          ]}
        />
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ steps -- */

/**
 * Render the step table.
 *
 * The row index lives in a reserved `__i` key so it can never collide with a
 * real field. Every algorithm's `steps()` returns exactly the columns its
 * `stepHeads` names, in that order, so the two always line up -- an earlier
 * version keyed the index off the first real field and shifted every column by
 * one, which is what displayed the wrong remainders.
 */
function StepTable({ algo, rows, t }) {
  const keys = useMemo(
    () => ["__i", ...Object.keys(rows[0])],
    [rows],
  );

  const columns = useMemo(
    () =>
      keys.map((key, i) => {
        const numeric =
          typeof rows[0][key] === "number" && rows.every((r) => typeof r[key] === "number");
        const head =
          i === 0
            ? "#"
            : (algo.stepHeads?.[i - 1] ?? key);
        return { key, head, num: numeric && i > 0 };
      }),
    [keys, rows, algo.stepHeads],
  );

  const withIndex = useMemo(
    () => rows.map((row, i) => ({ __i: i + 1, ...row })),
    [rows],
  );

  return (
    <AsciiTable
      columns={columns}
      rows={withIndex}
      empty={t("run.stepsNone")}
    />
  );
}

/* -------------------------------------------------------------------- key -- */

function KeyTable({ keys, t }) {
  const rows = Object.entries(keys).map(([k, v]) => ({
    key: k,
    name: k,
    value: String(v).slice(0, 120),
  }));

  return (
    <AsciiTable
      columns={[
        { key: "name", head: "field" },
        { key: "value", head: "value" },
      ]}
      rows={rows}
      empty={t("run.empty")}
    />
  );
}