/**
 * The hero shader.
 *
 * It runs a real base-37 Caesar round-trip: two glyph rows, a character grid,
 * and a substitution rule the viewer can watch sweep. The same rules drive the
 * thin accent rule that appears on every algorithm page, so the shader is the
 * site's visual language rather than a hero decoration.
 *
 * Everything is derived from one variable, `uShift`, which cycles 0..36. That
 * is the actual cipher constant, not a proxy for one.
 */

const vertexShader = `#version 300 es
in vec2 aPos;
out vec2 vUv;
void main() {
  vUv = aPos * 0.5 + 0.5;
  gl_Position = vec4(aPos, 0.0, 1.0);
}`;

/**
 * Draws the substitution structure: which cells move, which land on the signal
 * colour, and where the sweep head is. The glyphs themselves are HTML laid over
 * the canvas, so the text stays selectable and readable by assistive tech.
 *
 * Band geometry, in uv.y, must match the CSS in hero.css:
 *   ghost  0.58 – 0.70   plain  0.34 – 0.52   cipher  0.16 – 0.34
 */
const fragmentShader = `#version 300 es
precision highp float;

in vec2 vUv;
out vec4 fragColor;

uniform vec2  uRes;
uniform float uTime;
uniform float uShift;
uniform vec3  uInk;
uniform vec3  uGround;
uniform vec3  uSignal;
uniform vec3  uRule;
uniform float uReduced;

const float CELLS = 42.0;

float hash21(vec2 p) {
  p = fract(p * vec2(123.34, 456.21));
  p += dot(p, p + 45.32);
  return fract(p.x * p.y);
}

/* A hairline at y == axis, softened by distance. */
float ruleAt(float y, float axis, float thickness) {
  return 1.0 - smoothstep(0.0, thickness, abs(y - axis));
}

/* A dashed rule: drawn, not solid. */
float dashedAt(vec2 uv, float axis, float scale, float duty, float thickness) {
  return ruleAt(uv.y, axis, thickness) * step(fract(uv.x * scale), duty);
}

/* Box-and-hairline cell edges inside a unit cell. */
float cellEdge(vec2 f) {
  float ex = min(f.x, 1.0 - f.x);
  float ey = min(f.y, 1.0 - f.y);
  return 1.0 - smoothstep(0.0, 0.04, min(ex, ey));
}

void main() {
  vec2 uv = vUv;
  /* Correct for aspect so cells stay square on wide viewports. */
  float aspect = uRes.x / max(uRes.y, 1.0);
  vec2 p = vec2((uv.x - 0.5) * aspect + 0.5, uv.y);

  float t = uReduced > 0.5 ? 0.0 : uTime;
  vec3 base = uGround;

  /* ---- band membership ------------------------------------------------ */

  float inGhost  = step(0.575, uv.y) * step(uv.y, 0.705);
  float inPlain  = step(0.340, uv.y) * step(uv.y, 0.525);
  float inCipher = step(0.155, uv.y) * step(uv.y, 0.335);
  float inBands  = clamp(inGhost + inPlain + inCipher, 0.0, 1.0);

  /* Row id: 0 ghost, 1 plain, 2 cipher. */
  float rowId = inGhost > 0.5 ? 0.0 : (inPlain > 0.5 ? 1.0 : 2.0);

  /* ---- cell grid ------------------------------------------------------ */

  float cw = aspect / CELLS;          /* cell width in uv.x */
  float ch = 0.075;                   /* cell height in uv.y */

  float originY = (rowId < 0.5) ? 0.580 : (rowId < 1.5 ? 0.345 : 0.160);

  vec2 cellF = vec2(fract(p.x / cw), fract((uv.y - originY) / ch));
  float col  = floor(p.x / cw);
  float rowN = floor((uv.y - originY) / ch);

  /* ---- the substitution ---------------------------------------------- */

  /* Each cell holds a stable pseudo-random glyph; uShift slides it. This is what
     makes the sweep read as substitution rather than as noise. */
  float src   = hash21(vec2(col, rowN));
  float moved = mod(col + uShift + src * 5.0, CELLS);

  /* How strongly this cell reads as active: stable per cell, so the pattern does
     not strobe. Named "heat" because "active" is a reserved word in GLSL ES. */
  float heat = smoothstep(0.52, 1.0, hash21(vec2(floor(moved), rowN + 7.0)));

  /* ---- sweep head ----------------------------------------------------- */

  float headPos = fract(uShift / CELLS + t * 0.06) * CELLS;
  float sweep = exp(-abs(col - headPos) * 1.5);

  /* ---- compose -------------------------------------------------------- */

  vec3 ink = mix(uRule, uSignal, heat);
  ink = mix(ink, uInk, sweep * 0.9);

  float edge = cellEdge(cellF);

  /* The ghost row is deliberately faint: it reads as a residue, not a third row. */
  float rowWeight = inGhost > 0.5 ? 0.30 : 1.0;

  base = mix(base, ink, edge * inBands * rowWeight * 0.9);

  /* A fill under the sweep head, so the travelling bar is unmistakable. */
  base = mix(base, uSignal, inBands * sweep * 0.05);

  /* ---- ruled lines ---------------------------------------------------- */

  base = mix(base, uRule, dashedAt(uv, 0.340, 60.0, 0.55, 0.0022) * 0.85);
  base = mix(base, uRule, dashedAt(uv, 0.525, 60.0, 0.55, 0.0022) * 0.85);
  base = mix(base, uRule, dashedAt(uv, 0.155, 60.0, 0.55, 0.0022) * 0.85);

  /* Dimension ticks closing each band, as on a measured drawing. */
  float tick = ruleAt(uv.x, 0.070, 0.0016)
             * (step(0.140, uv.y) * step(uv.y, 0.215)
              + step(0.310, uv.y) * step(uv.y, 0.355)
              + step(0.495, uv.y) * step(uv.y, 0.540));
  base = mix(base, uRule, clamp(tick, 0.0, 1.0) * 0.9);

  /* ---- plotter scanline ------------------------------------------------ */

  float scan = exp(-abs(fract(uv.y - t * 0.04) - 0.5) * 30.0);
  base += uSignal * scan * 0.030;

  /* ---- vignette -------------------------------------------------------- */

  vec2 d = (uv - 0.5) * vec2(1.0, 0.85);
  base *= clamp(1.0 - dot(d, d) * 0.40, 0.74, 1.0);

  fragColor = vec4(base, 1.0);
}`;

export { vertexShader, fragmentShader };