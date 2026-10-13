# Surface brief — drafting board

Scope: landing + one page per algorithm family. Mode: Operate.

## Audience, job, proof

A cryptography student working alone at a laptop, exploring algorithms and producing
work they can show as evidence of understanding. They need to run an algorithm, see
its intermediate steps, and get output legible enough to project. The proof this
surface carries is the published-spec verification: DES against FIPS 46-3, AES against
FIPS 197, SHA-256 against NIST, HMAC against RFC 4231.

Constraints that must stay visible: the 37-symbol alphabet; Playfair's letter-only
square and X fillers; Hill's final-block padding; CBC/CTR IV handling; textbook RSA
and ECDSA labelled as not production-safe.

## Chosen direction

Neobrutalist drafting board. Hand-drawn rules and title blocks, ASCII at the centre,
animated cipher/decipher hero, one shader language across the whole site.

Memorable moment: the hero shader runs a real base-37 Caesar round-trip continuously,
drawing the same characters the user is about to encrypt by hand.

## Direction contract

**THESIS** — A drafting board for algorithms: ruled plates, dimensioned character
tables, title blocks with real revision data. Refuses the category default of a hero
image with feature cards below it, and refuses generic thick-border neobrutalism with
no material behind it.

**OWN-WORLD** — Graphite ground (#0e0e0f dark, warm bone #f4efe4 light), ink rules
drawn as dashed hairlines, one signal colour (safety orange #ff5c00 dark, oxide red
#b23a1a light) reserved for state and active edges. Chunky 2px borders with hard offset
shadows, zero radius. Two faces only: a grotesque for prose and a monospace for every
number, character, hex string, and step trace. ASCII tables and block characters
carry structure. Both themes are first-class and switchable.

**STORY** — The visitor learns this is a real instrument, sees one algorithm verified
against a published vector, finds the dropdown to pick any of 30+ algorithms, and
lands on a dense working page where every result comes with its intermediate steps.

**FIRST VIEWPORT** — Full-bleed shader canvas occupying the top ~62% of the viewport,
drawing an animated base-37 Caesar round-trip with the character grid, dimension
ticks, and the current substitution rule visible as live glyph rows. Below it, hard
against the shader with no gap, a ruled east-asian-ideographic-space band of three
easter eggs, then the algorithm selector dropdown in a bordered plate with a title
block reading PROJECT KRIPTO / REV 0.1.0 / SCALE 1:1. The selector is the primary
action and sits in the lower third, reachable without scrolling on a 900px viewport.

**FORM** — Code-first build (no image generation available on this machine). Chosen
form is the drafting-board world built from the student's own material traditions:
technical specification documents, punched cards, textbook plates. Candidate 3 of the
grounded list. Seed key `a4df36da`.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish
review, the verdict, DESIGN.md, and every shipping raster carrying its provenance.