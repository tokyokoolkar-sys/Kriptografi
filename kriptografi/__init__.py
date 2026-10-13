"""Pure-Python cryptography toolkit.

Layered so each module only depends on the ones below it:

    mathcore      number theory: gcd, inverse mod n, CRT, primality
    alphabet      37-character text <-> number codec
    classical     Caesar, Vigenere, Beaufort, affine, Playfair, Hill
    transposition rail fence, columnar, row transposition
    modes         padding plus ECB / CBC / CTR block cipher modes
    classical_modern  DES and AES written from scratch
    hashes        SHA-256, HMAC
    asymmetric    RSA, Diffie-Hellman, ElGamal, elliptic curves
"""

__version__ = "0.1.0"