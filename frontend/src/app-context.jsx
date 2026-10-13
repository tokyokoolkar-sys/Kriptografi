/**
 * App shell: theme, language, and routing.
 *
 * Routing is a tiny hash router. The site has seven routes and no nested layouts
 * worth a framework, so a dependency here would cost more than it saves.
 */

import { createContext, useContext, useEffect, useMemo, useState, useCallback } from "react";
import { DEFAULT_LANG, makeT } from "./i18n.js";
import { ALGORITHMS, FAMILIES, byId } from "./registry.js";
import { usePersistent } from "./components/ui.jsx";

/* --------------------------------------------------------------- context -- */

const AppContext = createContext(null);

export function useApp() {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error("useApp must be used inside AppProvider");
  return ctx;
}

/* ---------------------------------------------------------------- router -- */

/** Parse "#/math/caesar" into { family, algo }. */
function parseHash(hash) {
  const clean = hash.replace(/^#\/?/, "");
  const [family, algo] = clean.split("/");
  return { family: family || null, algo: algo || null };
}

function useHashRoute() {
  const [route, setRoute] = useState(() => parseHash(window.location.hash));

  useEffect(() => {
    const onChange = () => setRoute(parseHash(window.location.hash));
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);

  const navigate = useCallback((next) => {
    window.location.hash = next.startsWith("#") ? next : `#${next}`;
  }, []);

  return [route, navigate];
}

/* -------------------------------------------------------------- provider -- */

export function AppProvider({ children }) {
  const [theme, setTheme] = usePersistent("kriptografi.theme", "dark");
  const [lang, setLang] = usePersistent("kriptografi.lang", DEFAULT_LANG);
  const [route, navigate] = useHashRoute();

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.lang = lang === "id" ? "id" : "en";
  }, [theme, lang]);

  const t = useMemo(() => makeT(lang), [lang]);

  /** Pick the right side of a bilingual field. */
  const pick = useCallback((value) => {
    if (value == null) return "";
    if (typeof value === "string") return value;
    return value[lang] ?? value[DEFAULT_LANG] ?? "";
  }, [lang]);

  const value = useMemo(
    () => ({
      theme,
      setTheme,
      lang,
      setLang,
      t,
      pick,
      route,
      navigate,
      families: FAMILIES,
      algorithms: ALGORITHMS,
      byId,
    }),
    [theme, lang, t, pick, route, navigate],
  );

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}