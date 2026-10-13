# Design system

The visual language of the Kriptografi frontend, recorded from the built world.
Tokens live in `frontend/src/styles/tokens.css`; components in
`frontend/src/styles/components.css`; the hero in `frontend/src/styles/hero.css`.

## World

A neobrutalist drafting board. Hand-drawn rules, title blocks with real revision
data, ASCII at the centre, and hard offset shadows instead of soft elevation.
The neobrutalism is a material consequence of the subject rather than a style
applied on top of it: this is a table for working through algorithms by hand, so
it is ruled, dimensioned, and stamped like a technical drawing.

## Colour

Two first-class themes, both selected by `data-theme` on `<html>`.

**Graphite (dark, default)**

| Role | Value |
|---|---|
| Ground | `#0e0e0f` |
| Ground raised | `#161618` |
| Ground inset | `#1d1d20` |
| Ink | `#f2f0e9` |
| Ink dim | `#a8a6a0` |
| Ink faint | `#6b6a66` |
| Signal | `#ff5c00` (safety orange) |
| Rule | `#3a3a3e` |
| Rule strong | `#5c5c62` |

**Bone (warm light)**

| Role | Value |
|---|---|
| Ground | `#f4efe4` |
| Ground raised | `#ebe5d6` |
| Ground inset | `#e0d9c7` |
| Ink | `#16130f` |
| Ink dim | `#5c554a` |
| Ink faint | `#8d8578` |
| Signal | `#b23a1a` (oxide red) |
| Rule | `#c4bba7` |
| Rule strong | `#8d8578` |

The signal colour is **committed**, not accent-scattered: it carries result
readouts, the active hero glyphs, the pass mark, and the primary action. Nothing
else may use it. One saturated colour, two themes, no third hue.

## Type

Two faces, each with a single job.

- **Archivo** — prose. Headings, body copy, blurbs. Weights 400–800.
- **JetBrains Mono** — every datum. Numbers, characters, hex strings, step
  tables, labels, buttons. Weights 400–800, tabular numerals on.

The tracked micro caps (`.label`, 11px, `0.16em`) head every plate, table, and
field. They are the drawing sheet's annotation voice.

Scale: 11 / 13 / 15 / 18 / 22 / 32 / 52 px, with the hero title on its own
fluid clamp.

## Structure

- **Radius: 0 everywhere.** Enforced globally in the reset.
- **Borders: 2px** `--rule-strong` for plates, **3px** `--ink` for title blocks
  and the hard band under the hero.
- **Shadow: hard offset only** — `4px 4px 0`, no blur. Pressed state is
  `translate(3px, 3px)` with the shadow removed.
- **Rules: dashed hairlines.** A drafting line is drawn, not printed solid.
  `.dimension` renders a measurement line with tick ends.

## Components

| Component | Role |
|---|---|
| `.plate` | The container. Optional tab in the head, optional quiet meta. |
| `.plate__tab` | Small header tab, signal-filled or quiet-outlined. |
| `.titleblock` | The drafting signature. Key/value cells in ruled columns. |
| `.ascii` | Data table. Mono, tabular numerals, dashed row rules. |
| `.readout` | Where output lands. Bordered, wrapping, never truncated. |
| `.mark` | Verdict chip: pass (signal fill), fail (signal outline), idle. |
| `.chars__cell` | One alphabet symbol with its base-37 index beneath. |
| `.egg` | Easter-egg tile; expands to a live API result. |
| `.note` | Error or caveat. Full signal border, no side-tab accent. |
| `.btn` | Hard shadow, translates down on press. |

## The hero

A WebGL2 canvas draws the substitution structure; HTML glyph rows sit on top so
the text stays selectable and readable by assistive tech.

Band geometry is shared between GLSL (`frontend/src/glsl.js`) and CSS
(`hero.css`) and must be changed in both:

| Band | GLSL | CSS |
|---|---|---|
| ghost | 57.5–70.5% | not used |
| plain | 34–52.5% | `.hero__row--plain` top 34%, height 18.5% |
| cipher | 15.5–33.5% | `.hero__row--cipher` top 15.5%, height 18% |

`uShift` is the live Caesar constant, cycling 0–36, not a proxy for one. Under
`prefers-reduced-motion` the canvas draws a single frame and the glyph
animation is disabled.

## Motion

One orchestrated moment, not scattered hover effects: the hero's substitution
sweep. Glyphs land left to right on a 42ms stagger when the shift changes. Every
other transition is a state change under 150ms.

## Responsive

- **≥860px** — two-column mosaic, side-anchored hero title, full nav.
- **720–860px** — single-column mosaic, hero title moves to a top-left anchor,
  lead paragraph hidden.
- **<720px** — nav scrolls horizontally on one row (the bar does not wrap, which
  would cover the hero); hero rows tighten; glyphs shrink.

## Known detector advisories

`impeccable detect` reports two `codex-grid-background` advisories for the body
ground and the hero canvas fallback. Both are retained deliberately: this is a
drawing sheet, the shader's cells sit on the same 32px rhythm, and the hero's
dimension ticks only read as ticks against it.