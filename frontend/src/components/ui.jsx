/**
 * Shared components, all built in the drafting-board language.
 *
 * Every plate carries a tab, every number is monospace, every result lands in a
 * bordered readout. Nothing here is a stock element with a border drawn on.
 */

import { useEffect, useRef, useState, useCallback } from "react";
import { ALPHABET } from "../i18n.js";

/* ------------------------------------------------------------------ plate -- */

export function Plate({ tab, meta, tone, flush, tight, children, className = "" }) {
  const classes = [
    "plate",
    tone === "signal" ? "plate--signal" : "",
    flush ? "plate--flush" : "",
    className,
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <section className={classes}>
      {(tab || meta) && (
        <header className="plate__head">
          {tab && (
            <span className={`plate__tab${tone === "signal" ? "" : " plate__tab--quiet"}`}>
              {tab}
            </span>
          )}
          {meta && <span className="label">{meta}</span>}
        </header>
      )}
      <div className={`plate__body${flush ? " plate__body--flush" : ""}${tight ? " plate__body--tight" : ""}`}>
        {children}
      </div>
    </section>
  );
}

/* ------------------------------------------------------------ title block -- */

export function TitleBlock({ cells }) {
  return (
    <div className="titleblock">
      {cells.filter(Boolean).map(({ k, v }) => (
        <div className="titleblock__cell" key={k}>
          <span className="titleblock__key">{k}</span>
          <span className="titleblock__val">{v}</span>
        </div>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------- ascii table -- */

/**
 * A ruled data table. `columns` is [{key, head, num?}] and `rows` is a plain
 * array. Long values wrap rather than truncate — a ciphertext you cannot read in
 * full is not a result.
 */
export function AsciiTable({ columns, rows, caption, empty }) {
  if (!rows?.length) {
    return empty ? <p className="faint mono" style={{ fontSize: "var(--fs-small)" }}>{empty}</p> : null;
  }

  return (
    <div className="ascii-scroll">
      <table className="ascii">
        {caption && <caption>{caption}</caption>}
        <thead>
          <tr>
            {columns.map((col) => (
              <th key={col.key} className={col.num ? "num" : ""} scope="col">
                {col.head}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={row.key ?? i}>
              {columns.map((col) => {
                const value = row[col.key];
                const cls = [col.num ? "num" : "", col.signal ? "is-signal" : "", col.strong ? "is-good" : ""]
                  .filter(Boolean)
                  .join(" ");
                return (
                  <td key={col.key} className={cls}>
                    {value === undefined || value === null ? "—" : String(value)}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ---------------------------------------------------------------- readout -- */

export function Readout({ children, tone, empty }) {
  const isEmpty = !children;
  return (
    <div
      className={`readout${tone === "signal" ? " readout--signal" : ""}${isEmpty ? " readout--empty" : ""}`}
    >
      {isEmpty ? empty : children}
    </div>
  );
}

/* --------------------------------------------------------------- verdict -- */

export function Mark({ state, label }) {
  const cls = state === "pass" ? "mark--pass" : state === "fail" ? "mark--fail" : "mark--idle";
  return <span className={`mark ${cls}`}>{label}</span>;
}

/* ------------------------------------------------------------ alphabet map -- */

/** The 37 symbols as cells, with the hot ones highlighted. */
export function CharMap({ hot = new Set(), showIndices = true }) {
  return (
    <div className="chars">
      {ALPHABET.split("").map((ch, i) => (
        <div
          key={`${ch}-${i}`}
          className={`chars__cell${hot.has(i) ? " chars__cell--hot" : ""}`}
          title={`${ch === " " ? "space" : ch} = ${i}`}
        >
          {ch === " " ? "␣" : ch}
          {showIndices && <small>{i}</small>}
        </div>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------ dimension -- */

export function Dimension({ label }) {
  return (
    <div className="dimension" role="presentation">
      {label && (
        <span
          className="label"
          style={{
            position: "absolute",
            left: "50%",
            top: "2px",
            transform: "translateX(-50%)",
            background: "var(--ground)",
            padding: "0 6px",
            whiteSpace: "nowrap",
          }}
        >
          {label}
        </span>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ field -- */

export function Field({ field, value, onChange, t, id }) {
  const fieldId = id ?? `f-${field.key}`;
  const label = typeof field.label === "string" ? field.label : field.label?.id;

  if (field.type === "select") {
    return (
      <div className="field">
        <label className="label" htmlFor={fieldId}>
          {label}
        </label>
        <select
          id={fieldId}
          className="select"
          value={value ?? ""}
          onChange={(e) => onChange(field.key, e.target.value)}
        >
          {field.options.map(([v, text]) => (
            <option key={v} value={v}>
              {text}
            </option>
          ))}
        </select>
      </div>
    );
  }

  const numeric = field.type === "number";
  const inputClass = numeric ? "input" : "input";

  return (
    <div className="field">
      <label className="label" htmlFor={fieldId}>
        {label}
      </label>
      <input
        id={fieldId}
        className={inputClass}
        type={numeric ? "number" : field.type === "hex" ? "text" : "text"}
        inputMode={numeric ? "numeric" : undefined}
        value={value ?? ""}
        placeholder={field.placeholder}
        min={field.min}
        max={field.max}
        step={field.step}
        spellCheck={false}
        autoComplete="off"
        onChange={(e) => onChange(field.key, e.target.value)}
      />
    </div>
  );
}

/* --------------------------------------------------------------- segmented -- */

export function Segmented({ options, value, onChange, label }) {
  return (
    <div className="field">
      {label && <span className="label">{label}</span>}
      <div className="segmented" role="group" aria-label={label}>
        {options.map(([v, text]) => (
          <button
            key={v}
            type="button"
            className="segmented__opt"
            aria-pressed={value === v}
            onClick={() => onChange(v)}
          >
            {text}
          </button>
        ))}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ hook -- */

/** Persist a small piece of UI state (theme, language) to localStorage. */
export function usePersistent(key, initial) {
  const [value, setValue] = useState(() => {
    try {
      return localStorage.getItem(key) ?? initial;
    } catch {
      return initial;
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem(key, value);
    } catch {
      /* private mode; state still works for this session */
    }
  }, [key, value]);

  return [value, setValue];
}

/** Copy text to the clipboard, reporting success for two seconds. */
export function useCopy() {
  const [copied, setCopied] = useState(false);
  const copy = useCallback(async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  }, []);
  return { copied, copy };
}

/** Track whether the visitor has asked for reduced motion. */
export function useReducedMotion() {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    const query = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReduced(query.matches);
    const onChange = (e) => setReduced(e.matches);
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  }, []);
  return reduced;
}

/** Read a themed CSS custom property off the document. */
export function useThemeColor(names, deps = []) {
  const ref = useRef(null);
  const [colors, setColors] = useState(null);

  useEffect(() => {
    const styles = getComputedStyle(document.documentElement);
    const read = () =>
      setColors(Object.fromEntries(names.map((n) => [n, styles.getPropertyValue(n).trim()])));
    read();
    const observer = new MutationObserver(read);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    return () => observer.disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return colors;
}

export function hexToRgb(hex) {
  const clean = hex.replace("#", "").trim();
  const full = clean.length === 3 ? clean.split("").map((c) => c + c).join("") : clean;
  const n = parseInt(full.slice(0, 6), 16);
  if (Number.isNaN(n)) return [0, 0, 0];
  return [((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255];
}