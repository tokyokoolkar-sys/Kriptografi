/**
 * The top bar: brand, family nav, theme and language toggles.
 */

import { useApp } from "../app-context.jsx";

export default function TopBar() {
  const { t, theme, setTheme, lang, setLang, families, route, navigate, pick } = useApp();

  const links = [{ id: null, name: { id: "Beranda", en: "Home" } }, ...families];

  return (
    <header className="topbar">
      <div className="wrap topbar__inner">
        <a
          className="topbar__brand"
          href="#/"
          aria-label={`${t("brand.name")} — ${t("brand.tagline")}`}
        >
          <span>[</span>
          <span>{t("brand.name")}</span>
          <span>]</span>
        </a>

        <nav className="topbar__nav" aria-label={t("brand.tagline")}>
          {links.map((link) => {
            const target = link.id ? `#/${link.id}` : "#/";
            const isActive = link.id
              ? route.family === link.id
              : !route.family;
            return (
              <a
                key={link.id ?? "home"}
                className={`topbar__link${isActive ? " is-active" : ""}`}
                href={target}
                aria-current={isActive ? "page" : undefined}
                onClick={(e) => {
                  e.preventDefault();
                  navigate(target);
                }}
              >
                {pick(link.name)}
              </a>
            );
          })}

          <div className="toggles">
            <button
              type="button"
              className="toggle"
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
              aria-label={t("theme.toggle")}
              title={`${t("theme.toggle")} — ${theme === "dark" ? t("theme.dark") : t("theme.light")}`}
              aria-pressed={theme === "light"}
            >
              {theme === "dark" ? "◐" : "◑"}
            </button>

            <button
              type="button"
              className="toggle"
              onClick={() => setLang(lang === "id" ? "en" : "id")}
              aria-label={t("lang.toggle")}
              title={t("lang.toggle")}
              aria-pressed={lang === "en"}
            >
              {lang === "id" ? "ID" : "EN"}
            </button>
          </div>
        </nav>
      </div>
    </header>
  );
}