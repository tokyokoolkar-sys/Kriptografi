/**
 * The hero canvas.
 *
 * A single WebGL2 pass that draws the substitution structure. The glyph rows
 * themselves are HTML laid over the canvas, so the text stays selectable,
 * searchable, and readable by assistive tech — the shader draws the sheet, not
 * the words.
 *
 * Falls back to a static ruled sheet when WebGL2 is unavailable, so the hero is
 * never an empty box.
 */

import { useEffect, useRef } from "react";
import { vertexShader, fragmentShader } from "../glsl.js";
import { useReducedMotion, hexToRgb } from "./ui.jsx";
import { ALPHABET } from "../i18n.js";

const SAMPLE = "HALLO 2026";
const VOWELS = new Set([0, 1, 4, 5, 8, 9, 14, 18, 19, 24, 25]);
const ALPHABET_SIZE = ALPHABET.length;

export default function CipherShader({ t, shift }) {
  const canvasRef = useRef(null);
  const glyphRowRef = useRef(null);
  const reduced = useReducedMotion();

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const gl = canvas.getContext("webgl2", { antialias: true, alpha: false });
    if (!gl) {
      canvas.dataset.fallback = "true";
      return;
    }

    /* --- compile ------------------------------------------------------- */

    const compile = (type, source) => {
      const shader = gl.createShader(type);
      gl.shaderSource(shader, source);
      gl.compileShader(shader);
      if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
        console.error(
          `[shader] ${type === gl.VERTEX_SHADER ? "vertex" : "fragment"} compile failed:`,
          gl.getShaderInfoLog(shader),
        );
        gl.deleteShader(shader);
        return null;
      }
      return shader;
    };

    const vs = compile(gl.VERTEX_SHADER, vertexShader);
    const fs = compile(gl.FRAGMENT_SHADER, fragmentShader);
    if (!vs || !fs) {
      canvas.dataset.fallback = "compile";
      return;
    }

    const program = gl.createProgram();
    gl.attachShader(program, vs);
    gl.attachShader(program, fs);
    gl.linkProgram(program);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      /* Keep the reason: a silent fallback here is indistinguishable from a
         missing WebGL2, which is a much harder bug to chase. */
      console.error("[shader] link failed:", gl.getProgramInfoLog(program));
      canvas.dataset.fallback = "link";
      return;
    }
    gl.useProgram(program);

    /* --- a single full-screen triangle pair ---------------------------- */

    const buffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(
      gl.ARRAY_BUFFER,
      new Float32Array([-1, -1, 3, -1, -1, 3]),
      gl.STATIC_DRAW,
    );

    const aPos = gl.getAttribLocation(program, "aPos");
    gl.enableVertexAttribArray(aPos);
    gl.vertexAttribPointer(aPos, 2, gl.FLOAT, false, 0, 0);

    /* --- uniforms ------------------------------------------------------ */

    const uniforms = {
      uRes: gl.getUniformLocation(program, "uRes"),
      uTime: gl.getUniformLocation(program, "uTime"),
      uShift: gl.getUniformLocation(program, "uShift"),
      uInk: gl.getUniformLocation(program, "uInk"),
      uGround: gl.getUniformLocation(program, "uGround"),
      uSignal: gl.getUniformLocation(program, "uSignal"),
      uRule: gl.getUniformLocation(program, "uRule"),
      uReduced: gl.getUniformLocation(program, "uReduced"),
    };

    const readTheme = () => {
      const styles = getComputedStyle(document.documentElement);
      const pick = (name, fallback) => (styles.getPropertyValue(name).trim() || fallback);
      gl.uniform3fv(uniforms.uInk, hexToRgb(pick("--ink", "#f2f0e9")));
      gl.uniform3fv(uniforms.uGround, hexToRgb(pick("--ground", "#0e0e0f")));
      gl.uniform3fv(uniforms.uSignal, hexToRgb(pick("--signal", "#ff5c00")));
      gl.uniform3fv(uniforms.uRule, hexToRgb(pick("--rule-strong", "#5c5c62")));
    };

    /* --- resize -------------------------------------------------------- */

    /* Size explicitly rather than trusting clientWidth at mount: inside
       StrictMode the effect runs before layout has settled, so clientWidth can
       still be 0 and the canvas would keep its 300x150 default. Setting real
       width/height up front guarantees a correct first frame. */
    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const cssWidth = canvas.clientWidth || canvas.parentElement?.clientWidth || 1200;
      const cssHeight = canvas.clientHeight || canvas.parentElement?.clientHeight || 620;
      const width = Math.max(1, Math.floor(cssWidth * dpr));
      const height = Math.max(1, Math.floor(cssHeight * dpr));
      if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width;
        canvas.height = height;
        gl.viewport(0, 0, width, height);
        gl.uniform2f(uniforms.uRes, width, height);
      }
    };

    resize();
    readTheme();

    const observer = new ResizeObserver(resize);
    observer.observe(canvas);

    const themeObserver = new MutationObserver(readTheme);
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });

    /* --- draw ---------------------------------------------------------- */

    let frame = 0;
    let start = performance.now();
    let running = true;

    const draw = (now) => {
      if (!running) return;
      resize();
      const elapsed = (now - start) / 1000;
      gl.uniform1f(uniforms.uTime, elapsed);
      gl.uniform1f(uniforms.uShift, shift);
      gl.uniform1f(uniforms.uReduced, reduced ? 1 : 0);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
      frame = requestAnimationFrame(draw);
    };

    if (reduced) {
      /* Draw one frame and stop: a still sheet, no rAF loop. */
      draw(start);
    } else {
      frame = requestAnimationFrame(draw);
    }

    const onVisibility = () => {
      if (document.hidden) {
        running = false;
        cancelAnimationFrame(frame);
      } else if (!reduced) {
        running = true;
        start = performance.now() - 0;
        frame = requestAnimationFrame(draw);
      }
    };
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      running = false;
      cancelAnimationFrame(frame);
      observer.disconnect();
      themeObserver.disconnect();
      document.removeEventListener("visibilitychange", onVisibility);
      gl.deleteProgram(program);
      gl.deleteShader(vs);
      gl.deleteShader(fs);
      gl.deleteBuffer(buffer);
    };
  }, [shift, reduced]);

  /* --- the glyph rows, positioned over the shader bands ---------------- */

  const cipher = [...SAMPLE]
    .map((ch) => {
      const index = ALPHABET.indexOf(ch);
      return ALPHABET[(index + shift) % ALPHABET_SIZE];
    })
    .join("");

  return (
    <div className="hero">
      <canvas
        ref={canvasRef}
        className="hero__canvas"
        role="img"
        aria-label={t("hero.canvasAlt")}
      />

      {/* The rows: real characters, positioned over the shader's bands. */}
      <div className="hero__rows" ref={glyphRowRef} aria-hidden="true">
        <div className="hero__row hero__row--plain">
          <span className="hero__rowlabel label">{t("run.plaintext")}</span>
          <span className="hero__glyphs">
            {[...SAMPLE].map((ch, i) => (
              <span
                key={i}
                className={`hero__glyph${VOWELS.has(ALPHABET.indexOf(ch)) ? " is-hot" : ""}`}
                style={{ "--i": i }}
              >
                {ch === " " ? "␣" : ch}
              </span>
            ))}
          </span>
        </div>

        <div className="hero__row hero__row--cipher">
          <span className="hero__rowlabel label label--signal">{t("run.ciphertext")}</span>
          <span className="hero__glyphs">
            {[...cipher].map((ch, i) => (
              <span key={i} className="hero__glyph is-cipher" style={{ "--i": i }}>
                {ch === " " ? "␣" : ch}
              </span>
            ))}
          </span>
        </div>

        <div className="hero__shift">
          <span className="label">{t("run.shift")}</span>
          <span className="hero__shiftval mono">{String(shift).padStart(2, "0")}</span>
          <span className="label faint">mod 37</span>
        </div>
      </div>
    </div>
  );
}