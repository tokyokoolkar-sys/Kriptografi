/**
 * The landing page.
 *
 * Three bands, no gap between them, exactly as the direction contract states:
 * the shader sheet, the findings, then the selector. The selector is the primary
 * action and lands in the lower third.
 */

import { useState, useEffect, useMemo } from "react";
import { useApp } from "../app-context.jsx";
import { ALPHABET } from "../i18n.js";
import { TOTAL } from "../registry.js";
import { Plate, TitleBlock, Dimension, CharMap } from "../components/ui.jsx";
import CipherShader from "../components/CipherShader.jsx";
import Eggs from "../components/Eggs.jsx";

/**
 * The verification evidence strip.
 *
 * Bilingual, since the whole surface is. These are the counts asserted by the
 * test suite, not marketing numbers.
 */
const EVIDENCE = [
  { n: "7/7", k: { id: "DES · FIPS 46-3", en: "DES · FIPS 46-3" } },
  { n: "3/3", k: { id: "AES · FIPS 197", en: "AES · FIPS 197" } },
  { n: "5/5", k: { id: "SHA-256 · NIST", en: "SHA-256 · NIST" } },
  { n: "5/5", k: { id: "HMAC · RFC 4231", en: "HMAC · RFC 4231" } },
  {
    n: "1 822 176",
    k: { id: "|GL(2,37)| = (37²−1)(37²−37)", en: "|GL(2,37)| = (37²−1)(37²−37)" },
  },
];

export default function Landing() {
  const { t, pick, algorithms, families, navigate, lang } = useApp();
  const [shift, setShift] = useState(3);

  /* Drive the shift: a real Caesar constant cycling 0..36. Slower than the
     shader so the change is legible, and it stops entirely under
     prefers-reduced-motion. */
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    const query = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReduced(query.matches);
    const onChange = (e) => setReduced(e.matches);
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  }, []);

  useEffect(() => {
    if (reduced) return undefined;
    const id = setInterval(() => setShift((s) => (s + 1) % ALPHABET.length), 1400);
    return () => clearInterval(id);
  }, [reduced]);

  const byId = useMemo(
    () => Object.fromEntries(algorithms.map((a) => [a.id, a])),
    [algorithms],
  );

  const [chosen, setChosen] = useState("caesar");
  const [filter, setFilter] = useState("");

  const options = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return algorithms;
    return algorithms.filter((a) => {
      const haystack = [
        a.id,
        pick(a.name),
        pick(a.name).toLowerCase(),
        a.family,
        a.specNote ?? "",
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(needle);
    });
  }, [algorithms, filter, pick]);

  const selected = byId[chosen];
  const evidence = EVIDENCE.map((e) => ({ n: e.n, k: pick(e.k) }));

  return (
    <>
      {/* ---- band 1: the shader sheet ---------------------------------- */}
      <section className="hero-wrap">
        <CipherShader t={t} shift={shift} />

        <div className="hero__title">
          <div className="hero__rule" />
          <h1>{t("hero.title")}</h1>
          <p>{t("hero.lead")}</p>
        </div>
      </section>

      {/* ---- band 2: findings ------------------------------------------ */}
      <Eggs />

      {/* ---- band 3: the selector -------------------------------------- */}
      <section className="picker">
        <div className="wrap">
          <Plate tab={`${t("pick.plate")} · ${TOTAL}`} meta={t("pick.title")} flush>
            <div style={{ padding: "var(--sp-4)" }}>
              <div className="picker__head">
                <div>
                  <h2>{t("pick.title")}</h2>
                  <p className="lead" style={{ marginTop: "var(--sp-2)", fontSize: "var(--fs-small)" }}>
                    {t("pick.lead")}
                  </p>
                </div>
                <span className="label">{lang.toUpperCase()} · REV 0.1.0</span>
              </div>

              <div className="picker__controls">
                <div className="field">
                  <label className="label" htmlFor="picker-filter">
                    {t("pick.search")}
                  </label>
                  <input
                    id="picker-filter"
                    className="input"
                    type="text"
                    value={filter}
                    placeholder="caesar, rsa, fips…"
                    onChange={(e) => setFilter(e.target.value)}
                    spellCheck={false}
                  />
                </div>

                <div className="field">
                  <label className="label" htmlFor="picker-algo">
                    {t("pick.label")}
                  </label>
                  <select
                    id="picker-algo"
                    className="select"
                    value={chosen}
                    onChange={(e) => setChosen(e.target.value)}
                  >
                    {families.map((family) => {
                      const items = options.filter((a) => a.family === family.id);
                      if (!items.length) return null;
                      return (
                        <optgroup key={family.id} label={pick(family.name)}>
                          {items.map((a) => (
                            <option key={a.id} value={a.id}>
                              {pick(a.name)}
                            </option>
                          ))}
                        </optgroup>
                      );
                    })}
                  </select>
                </div>

                <button
                  type="button"
                  className="btn btn--primary"
                  onClick={() => navigate(`/${selected.family}/${selected.id}`)}
                >
                  {t("pick.cta")} →
                </button>
              </div>

              <div className="picker__result">
                <div>
                  <span className="label">{t("family.plate")}</span>
                  <p className="mono" style={{ marginTop: 4 }}>
                    {selected.blurb ? pick(selected.blurb) : ""}
                  </p>
                </div>
                <div>
                  <span className="label">{t("spec.plate")}</span>
                  <p className="mono" style={{ marginTop: 4 }}>
                    {selected.specNote ?? "—"}
                  </p>
                </div>
                <div>
                  <span className="label">{t("nav." + selected.family)}</span>
                  <p className="mono" style={{ marginTop: 4 }}>
                    {selected.kind}
                  </p>
                </div>
              </div>
            </div>
          </Plate>

          {/* The alphabet, dimensioned — the site's load-bearing fact. */}
          <div style={{ marginTop: "var(--sp-6)" }}>
            <Dimension label="37 SIMBOLS / SYMBOLS" />
            <div style={{ marginTop: "var(--sp-4)" }}>
              <CharMap />
            </div>
          </div>

          {/* The verification evidence. */}
          <div style={{ marginTop: "var(--sp-6)" }}>
            <Plate tab={t("verify.plate")} meta={t("verify.sub")} flush>
              <div className="specstrip">
                {evidence.map((e) => (
                  <div className="specstrip__cell" key={e.k}>
                    <span className="specstrip__n">{e.n}</span>
                    <span className="specstrip__k">{e.k}</span>
                  </div>
                ))}
              </div>
            </Plate>
          </div>

          <div style={{ marginTop: "var(--sp-5)" }}>
            <TitleBlock
              cells={[
                { k: t("brand.name"), v: "PROJECT KRIPTO" },
                { k: "REV", v: "0.1.0" },
                { k: "SCALE", v: "1 : 1" },
                { k: "ALGORITHMS", v: String(TOTAL) },
                { k: "TESTS", v: "323" },
                { k: "SHEET", v: "01 / 06" },
              ]}
            />
          </div>
        </div>
      </section>
    </>
  );
}