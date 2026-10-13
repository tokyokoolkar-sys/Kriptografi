/**
 * A family page: the dense mosaic of every algorithm in one group.
 *
 * Small ruled modules tiling edge to edge, each headed by a tab. The point is to
 * see the whole family at once and pick from it.
 */

import { useMemo } from "react";
import { useApp } from "../app-context.jsx";
import { Plate, TitleBlock } from "../components/ui.jsx";

export default function Family({ familyId }) {
  const { t, pick, families, byFamily, navigate } = useApp();

  const family = families.find((f) => f.id === familyId);
  const items = byFamily[familyId] ?? [];

  const counts = useMemo(() => {
    const out = {};
    for (const f of families) out[f.id] = (byFamily[f.id] ?? []).length;
    return out;
  }, [families, byFamily]);

  if (!family) {
    return (
      <div className="wrap" style={{ paddingBlock: "var(--sp-8)" }}>
        <Plate tab="404" tone="signal">
          <h2>{t("opt.error")}</h2>
          <p className="dim mono">{familyId}</p>
        </Plate>
      </div>
    );
  }

  return (
    <div className="wrap" style={{ paddingBlock: "var(--sp-6)" }}>
      <Plate tab={`${t("family.plate")} ${family.plate}`} meta={`${items.length} ${t("family.count")}`}>
        <h2>{pick(family.name)}</h2>
        <p className="lead" style={{ marginTop: "var(--sp-2)", fontSize: "var(--fs-small)" }}>
          {t("family.specNote")}
        </p>
      </Plate>

      <div className="mosaic" style={{ marginTop: "var(--sp-5)" }}>
        {items.map((algo) => (
          <div className="mosaic__cell" key={algo.id}>
            <Plate tab={algo.id} meta={algo.kind} tight>
              <div className="stack" style={{ gap: "var(--sp-2)", flex: 1 }}>
                <h3 style={{ fontSize: "var(--fs-lead)" }}>{pick(algo.name)}</h3>
                <p className="dim" style={{ fontSize: "var(--fs-small)", flex: 1 }}>
                  {pick(algo.blurb)}
                </p>

                {algo.caution && (
                  <p
                    className="mono"
                    style={{
                      fontSize: "var(--fs-micro)",
                      color: "var(--signal)",
                      lineHeight: 1.4,
                    }}
                  >
                    ⚠ {pick(algo.caution)}
                  </p>
                )}

                <div style={{ display: "flex", gap: "var(--sp-2)", alignItems: "center" }}>
                  <button
                    type="button"
                    className="btn btn--sm"
                    onClick={() => navigate(`/${family.id}/${algo.id}`)}
                  >
                    {t("pick.cta")} →
                  </button>
                  {algo.specNote && (
                    <span className="label" style={{ marginLeft: "auto" }}>
                      {algo.specNote}
                    </span>
                  )}
                </div>
              </div>
            </Plate>
          </div>
        ))}
      </div>

      <div style={{ marginTop: "var(--sp-6)" }}>
        <TitleBlock
          cells={[
            { k: "FAMILY", v: family.id.toUpperCase() },
            { k: "ALGORITHMS", v: String(items.length) },
            { k: "SHEET", v: `${family.plate} / 06` },
          ]}
        />
      </div>

      {/* Sibling sheets, so the whole set stays reachable without the top bar. */}
      <div style={{ marginTop: "var(--sp-5)" }}>
        <span className="label">{t("nav.home")}</span>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "var(--sp-2)", marginTop: "var(--sp-2)" }}>
          {families.map((f) => (
            <a
              key={f.id}
              className={`btn btn--sm${f.id === family.id ? " btn--primary" : ""}`}
              href={`#/${f.id}`}
              onClick={(e) => {
                e.preventDefault();
                navigate(`/${f.id}`);
              }}
            >
              {f.plate} · {pick(f.name)} ({counts[f.id]})
            </a>
          ))}
        </div>
      </div>
    </div>
  );
}