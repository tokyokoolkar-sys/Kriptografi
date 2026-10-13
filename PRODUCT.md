# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

React 19 + Vite, served separately from the FastAPI backend in development. The
user chose this explicitly over static HTML/CSS and Jinja. No CSS framework; styling
is hand-written so the visual language stays under direct control.

Backend is Python 3.12 + FastAPI at `kriptografi.api.main:app`, serving a pure-Python
cryptography library. The frontend talks to it over JSON HTTP. No third-party
cryptography library is used anywhere in the backend.

## Users

Primary: the project owner, a cryptography student, working alone at a laptop. The
job is exploratory and coursework-driven: run an algorithm, inspect how each step
works, and get output that can be shown as evidence of understanding. This is an
instrument, not a demo — the user wants to see *inside* the algorithm (the Euclidean
division chain, the Feistel round structure, the base-37 alphabet mapping), not just
its output.

Secondary implied audience: whoever sees the coursework result later. The interface
should hold up when projected or screenshotted, and explanations should be readable
by someone who does not already know the algorithm.

## Product Purpose

The backend is a cryptography toolkit implemented from scratch and verified against
published test vectors (FIPS 46-3, FIPS 197, FIPS 180-4, RFC 4231, NIST). The
frontend exists to make that library usable and legible without reading Python.

Success means: a user can pick an algorithm, give it input and a key, see the result
*and* the intermediate steps, and understand why the result is correct. It also
means the cryptography is exposed honestly — the textbook constructions are labelled
as teaching material, not presented as production-safe.

## Positioning

The distinguishing mechanism is radical transparency: every algorithm exposes its
own intermediate state. Most crypto tools return only ciphertext. This one returns
the Euclid chain, the modular exponentiation trace with its binary exponent, the
frequency histogram that justifies a cracked Vigenere key, the Tonelli-Shanks
iterations. Combined with the fact that nothing is delegated to a library, a reader
can verify any claim by checking it against the published spec vectors the tool
displays.

## Operating Context

Single-user, desktop-first, in a browser next to a local FastAPI server. Sessions are
exploratory and unstructured — the user moves between algorithm families freely.
Long text output matters: ciphertexts, hex keys, step traces, and factor lists are all
legitimate results that need to be selectable and readable rather than truncated to a
card.

## Capabilities and Constraints

Backend surface, all implemented and tested (323 tests passing):

- Number theory: gcd, extended Euclid, modular inverse, CRT, primality, factorisation, totient, Legendre/Jacobi symbols, Tonelli-Shanks square roots, discrete logarithm, modular exponentiation with trace
- Classical ciphers over a 37-symbol alphabet (A-Z, 0-9, space): Caesar, Vigenere, Beaufort, autokey, affine, Playfair, Hill
- Transposition: rail fence, columnar, row transposition
- Block ciphers: DES (FIPS 46-3), AES (FIPS 197); modes ECB, CBC, CTR; PKCS#7 padding
- Hashing: SHA-256, HMAC-SHA256
- Public key: RSA, Diffie-Hellman, ElGamal, ECDSA over secp192r1 and secp256k1
- Cryptanalysis: frequency analysis, index of coincidence, Caesar and Vigenere key recovery

Constraints:

- The 37-symbol alphabet is deliberate and load-bearing: digits and spaces survive a round trip, unlike a 26-letter alphabet. Do not let UI copy imply letters-only.
- Playfair drops digits and spaces (its 5x5 square holds only letters) and inserts X fillers between doubled letters. This asymmetry must be surfaced, not hidden.
- Hill pads its final block, so decryption of a non-aligned message returns trailing padding characters.
- CBC and CTR require an IV/nonce that must be carried from encryption to decryption; ECB has none.
- Textbook RSA and ECDSA lack OAEP/PSS/CRT and are not production-safe. The UI must not imply otherwise.
- DES is deprecated. AES is the default choice.
- Key material must never be persisted to storage or logged.

Explicitly undecided: whether a light theme is a first-class mode or a variant. (The user asked for both dark and warm light, so both ship.)

## Brand Commitments

The user pinned the visual direction explicitly: **neobrutalism, dark, ASCII,
minimalistic**, with https://www.ascii-magic.com/landing named as the reference.

Also pinned by the user:
- Interface language is switchable between Bahasa Indonesia and English.
- Both a dark theme and a warm light theme are required.
- Structure is one page per algorithm family, plus a landing/hero page.

ASCII is load-bearing, not decoration: the alphabet itself is a 37-character symbol
set, and the most instructive thing about the ciphers is watching characters become
numbers and back. ASCII art and character grids are native to the subject matter.

## Evidence on Hand

- 323 passing tests, including published-spec known-answer vectors: 7 DES vectors
  (FIPS 46-3), 3 AES vectors (FIPS 197 appendix C, all three key sizes), 5 SHA-256
  NIST vectors including the one-million-`a` case, 5 HMAC vectors (RFC 4231)
- SHA-256 and HMAC cross-checked against Python's `hashlib` at block boundaries
- GCD cross-checked against `math.gcd`; totient cross-checked against brute force
- AES S-box re-derived from GF(2^8) inverses and compared against the spec table
- |GL(2, 37)| = 1 822 176 confirmed by exhaustive enumeration
- README.md documenting the library, its verification, and its security caveat

No user testimonials, no customer logos, no benchmarks, no pricing. The UI must not
invent any.

## Product Principles

1. **Show the working.** An algorithm's intermediate state is the product. Where the
   backend returns a step trace, the UI renders it as a readable sequence, never
   collapsed behind a summary.
2. **The spec is the proof.** Published test vectors are a real, verifiable asset.
   Surface them as evidence rather than hiding them in a test suite.
3. **Honest about safety.** Teaching material is labelled as teaching material. No
   screen implies production readiness for a construction that lacks it.
4. **Round-trip legibility.** A user should be able to see ciphertext and plaintext
   side by side and understand why the inverse works — including for ciphers whose
   inverse is lossy (Playfair, Hill padding).
5. **ASCII is native.** Character-level visualisations are the product's explanatory
   core, not ornament.

## Accessibility & Inclusion

Not yet established. Known tension worth resolving during design: a neobrutalist ASCII
interface risks failing contrast, small-text legibility, and screen-reader
comprehension. At minimum, colour contrast must meet WCAG AA in both themes, and
controls must be real focusable elements with accessible names — not styled divs.