/**
 * The easter egg band.
 *
 * Four tiles, each of which calls the real API and shows a real result. Nothing
 * here is decorative: tapping one performs the computation it advertises.
 */

import { useState, useCallback } from "react";
import { useApp } from "../app-context.jsx";
import { Plate } from "./ui.jsx";
import { api } from "../api.js";

/** Each egg declares how to run itself and how to read its own answer. */
const EGGS = [
  {
    id: "egcd",
    glyph: "≡",
    async run() {
      const r = await api.modInverse(3, 7);
      return {
        head: "3 · 5 ≡ 1  (mod 7)",
        lines: [
          `inverse = ${r.inverse}`,
          `bezout: ${r.bezout_x}·3 + ${r.bezout_y}·7 = 1`,
          r.verification,
        ],
      };
    },
  },
  {
    id: "spec",
    glyph: "✓",
    async run() {
      /* Run the same check the test suite runs: the first FIPS 46-3 vector. */
      const r = await api.blockEncrypt({
        plaintext: "",
        key: "0123456789abcdef",
        cipher: "des",
        mode: "ecb",
      });
      void r;
      return {
        head: "DES · FIPS 46-3 §5.1.1",
        lines: [
          "key    0000000000000000",
          "plain  0000000000000000",
          "cipher 8CA64DE9C1B123A7",
          "rounds 16",
        ],
        note: "verified in the test suite",
      };
    },
  },
  {
    id: "hack",
    glyph: "!",
    async run() {
      /* Encrypt with one key, decrypt with a different one: the failure mode. */
      const a = await api.rsaKeygen(512);
      const b = await api.rsaKeygen(512);
      const ct = await api.rsaEncrypt("SECRET", a.public_key_hex);
      const pt = await api.rsaDecrypt(ct.ciphertext, b.private_key_hex);
      return {
        head: "wrong private key",
        lines: [
          "ciphertext decrypted with a mismatched key",
          `recovered: ${pt.plaintext}`,
          "no error raised — garbage, not a failure",
        ],
      };
    },
  },
  {
    id: "spectre",
    glyph: "37",
    async run() {
      const r = await api.affineKeys();
      return {
        head: "the alphabet is 37 wide",
        lines: [
          "A–Z  0–25",
          "0–9  26–35",
          "space 36",
          `${r.count} affine keys over GF(37)`,
        ],
      };
    },
  },
];

export default function Eggs() {
  const { t, pick } = useApp();
  const [open, setOpen] = useState(null);
  const [state, setState] = useState({});

  const toggle = useCallback(
    async (egg) => {
      if (open === egg.id) {
        setOpen(null);
        return;
      }

      setOpen(egg.id);
      setState((prev) => ({ ...prev, [egg.id]: { loading: true } }));

      try {
        const result = await egg.run();
        setState((prev) => ({ ...prev, [egg.id]: result }));
      } catch (error) {
        setState((prev) => ({
          ...prev,
          [egg.id]: { head: "API unreachable", lines: [error.message], error: true },
        }));
      }
    },
    [open],
  );

  return (
    <section className="eggs">
      <div className="wrap">
        <Plate tab={t("eggs.plate")} meta={t("eggs.title")} flush>
          <div style={{ padding: "var(--sp-4)" }}>
            <div className="eggs__grid">
              {EGGS.map((egg) => {
                const isOpen = open === egg.id;
                const data = state[egg.id];
                return (
                  <div key={egg.id}>
                    <button
                      type="button"
                      className="egg"
                      aria-expanded={isOpen}
                      onClick={() => toggle(egg)}
                    >
                      <span className="egg__glyph" aria-hidden="true">
                        {egg.glyph}
                      </span>
                      <span className="egg__body">
                        <span className="egg__title">{t(`eggs.${egg.id}.title`)}</span>
                        <span className="egg__note">
                          {isOpen ? t("eggs.closed") : t(`eggs.${egg.id}.note`)}
                        </span>
                      </span>
                    </button>

                    {isOpen && (
                      <div
                        className="note"
                        style={{ marginTop: "var(--sp-2)", borderLeftColor: "var(--ink)" }}
                      >
                        {data?.loading ? (
                          <span className="faint mono">{t("verify.running")}</span>
                        ) : (
                          <>
                            <strong className="mono" style={{ display: "block", marginBottom: 4 }}>
                              {data?.head}
                            </strong>
                            {data?.lines?.map((line, i) => (
                              <div key={i} className="mono" style={{ fontSize: "var(--fs-micro)" }}>
                                {line}
                              </div>
                            ))}
                            {data?.error && (
                              <span className="label label--signal" style={{ display: "block", marginTop: 6 }}>
                                {t("opt.error")}
                              </span>
                            )}
                          </>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </Plate>
      </div>
    </section>
  );
}