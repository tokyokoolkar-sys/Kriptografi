/**
 * Route dispatch. Seven routes, no nesting, so a switch is enough.
 */

import { useApp } from "./app-context.jsx";
import TopBar from "./components/TopBar.jsx";
import Landing from "./pages/Landing.jsx";
import Family from "./pages/Family.jsx";
import Workbench from "./pages/Workbench.jsx";

function Footer() {
  const { t, navigate, families, pick } = useApp();

  return (
    <footer className="foot">
      <div className="wrap">
        <div className="foot__grid">
          <div style={{ maxWidth: "52ch" }}>
            <div className="label">{t("brand.name")}</div>
            <p className="dim" style={{ fontSize: "var(--fs-small)", marginTop: "var(--sp-2)" }}>
              {t("foot.note")}
            </p>
          </div>

          <nav aria-label={t("family.plate")}>
            <div className="label">{t("foot.verif")}</div>
            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                gap: "var(--sp-2)",
                marginTop: "var(--sp-2)",
              }}
            >
              {families.map((f) => (
                <a
                  key={f.id}
                  className="topbar__link"
                  href={`#/${f.id}`}
                  onClick={(e) => {
                    e.preventDefault();
                    navigate(`/${f.id}`);
                  }}
                >
                  {pick(f.name)}
                </a>
              ))}
            </div>
          </nav>

          <div>
            <div className="label">{t("foot.stack")}</div>
            <p
              className="mono dim"
              style={{
                fontSize: "var(--fs-micro)",
                marginTop: "var(--sp-2)",
                lineHeight: 1.7,
              }}
            >
              React 19 · Vite 8
              <br />
              FastAPI · Python 3.12
              <br />
              pure Python · no crypto library
            </p>
            <a
              className="topbar__link"
              style={{ display: "inline-block", marginTop: "var(--sp-2)" }}
              href="http://localhost:8000/docs"
              target="_blank"
              rel="noreferrer"
            >
              {t("foot.api")} ↗
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}

export default function App() {
  const { route } = useApp();

  let page;
  if (!route.family) {
    page = <Landing />;
  } else if (route.algo) {
    page = <Workbench algoId={route.algo} />;
  } else {
    page = <Family familyId={route.family} />;
  }

  return (
    <>
      <TopBar />
      <main>{page}</main>
      <Footer />
    </>
  );
}