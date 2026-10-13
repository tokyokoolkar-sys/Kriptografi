"""Padding schemes and block cipher modes of operation.

A block cipher only accepts whole blocks, so every practical scheme needs padding
to reach a block boundary. On top of that sit the modes of operation, which turn a
single-block cipher into something that can process arbitrary-length messages.

    ECB  encrypt each block independently -- simple, but leaks structure
    CBC  chain blocks with XOR and an IV -- hides patterns, but needs a random IV
    CTR  turn the block cipher into a stream cipher with a nonce counter
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "BlockCipher",
    "pad",
    "unpad",
    "pkcs7_pad",
    "pkcs7_unpad",
    "zero_pad",
    "zero_unpad",
    "ecb_encrypt",
    "ecb_decrypt",
    "cbc_encrypt",
    "cbc_decrypt",
    "ctr_crypt",
    "MODE_INFO",
    "MODE_REGISTRY",
]


# --------------------------------------------------------------------------
# Padding
# --------------------------------------------------------------------------

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """PKCS#7 padding: append ``n`` bytes of value ``n``.

    A full block of padding is added when the input is already aligned, so
    unpadding is never ambiguous. See RFC 5652.
    """
    if block_size < 1 or block_size > 255:
        raise ValueError("block size must be between 1 and 255 bytes")
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    """Strip and validate PKCS#7 padding."""
    if not data:
        raise ValueError("cannot unpad an empty message")
    if len(data) % block_size != 0:
        raise ValueError("padded length must be a multiple of the block size")

    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size or pad_len > len(data):
        raise ValueError("invalid PKCS#7 padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid PKCS#7 padding bytes")

    return data[:-pad_len]


def zero_pad(data: bytes, block_size: int) -> bytes:
    """Pad with zero bytes up to the next block boundary.

    Simpler than PKCS#7 but ambiguous: the unpadded length cannot be recovered,
    so decryption needs the original length out of band. Handy for teaching
    exactly why that weakness matters.
    """
    remainder = len(data) % block_size
    if remainder == 0:
        return data
    return data + bytes(block_size - remainder)


def zero_unpad(data: bytes, block_size: int) -> bytes:
    """Strip trailing zero bytes."""
    return data.rstrip(bytes([0]))


# ``pad``/``unpad`` are the names the mode functions use by default.
pad = pkcs7_pad
unpad = pkcs7_unpad


# --------------------------------------------------------------------------
# Block cipher protocol
# --------------------------------------------------------------------------

class BlockCipher:
    """Structural type for a cipher operating on fixed-size blocks.

    Implemented by :class:`kriptografi.block.aes.AES` and
    :class:`kriptografi.block.des.DES`, letting the modes below stay
    cipher-agnostic. ``encrypt_block`` and ``decrypt_block`` both take and return
    a :class:`bytes` of exactly ``block_size`` bytes.
    """

    block_size: int

    def encrypt_block(self, block: bytes) -> bytes:
        raise NotImplementedError

    def decrypt_block(self, block: bytes) -> bytes:
        raise NotImplementedError

    def _check(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError(
                f"expected a {self.block_size}-byte block, got {len(block)} bytes"
            )
        return block


# --------------------------------------------------------------------------
# Modes of operation
# --------------------------------------------------------------------------

def ecb_encrypt(cipher: BlockCipher, plaintext: bytes, pad_fn=pkcs7_pad) -> bytes:
    """Electronic Codebook: encrypt each block independently under the same key.

    Deterministic and parallel, which is exactly the problem -- identical
    plaintext blocks produce identical ciphertext blocks, so repeated structure
    in the message stays visible. This is the classic 'ECB penguin' failure.
    """
    padded = pad_fn(plaintext, cipher.block_size)
    return b"".join(
        cipher.encrypt_block(padded[i : i + cipher.block_size])
        for i in range(0, len(padded), cipher.block_size)
    )


def ecb_decrypt(cipher: BlockCipher, ciphertext: bytes, unpad_fn=pkcs7_unpad) -> bytes:
    """Inverse ECB."""
    if len(ciphertext) % cipher.block_size != 0:
        raise ValueError("ciphertext length must be a multiple of the block size")
    plain = b"".join(
        cipher.decrypt_block(ciphertext[i : i + cipher.block_size])
        for i in range(0, len(ciphertext), cipher.block_size)
    )
    return unpad_fn(plain, cipher.block_size)


def cbc_encrypt(cipher: BlockCipher, plaintext: bytes, iv: bytes | None = None,
                pad_fn=pkcs7_pad) -> tuple[bytes, bytes]:
    """Cipher Block Chaining: XOR each plaintext block with the previous
    ciphertext block before encrypting.

    Returns ``(ciphertext, iv)``. The IV must be unpredictable and must never be
    reused with the same key -- reuse lets an attacker XOR two ciphertexts
    together and cancel the chain, recovering plaintext. Supplying ``iv=None``
    generates a fresh random one via :mod:`os.urandom`.
    """
    if iv is None:
        import os

        iv = os.urandom(cipher.block_size)
    if len(iv) != cipher.block_size:
        raise ValueError(f"IV must be {cipher.block_size} bytes")

    padded = pad_fn(plaintext, cipher.block_size)
    out = bytearray()
    previous = iv

    for i in range(0, len(padded), cipher.block_size):
        block = padded[i : i + cipher.block_size]
        xored = bytes(a ^ b for a, b in zip(block, previous))
        chunk = cipher.encrypt_block(xored)
        out += chunk
        previous = chunk

    return bytes(out), iv


def cbc_decrypt(cipher: BlockCipher, ciphertext: bytes, iv: bytes,
                unpad_fn=pkcs7_unpad) -> bytes:
    """Inverse CBC: decrypt each block, then XOR the previous ciphertext back in."""
    if len(iv) != cipher.block_size:
        raise ValueError(f"IV must be {cipher.block_size} bytes")
    if len(ciphertext) % cipher.block_size != 0:
        raise ValueError("ciphertext length must be a multiple of the block size")

    out = bytearray()
    previous = iv

    for i in range(0, len(ciphertext), cipher.block_size):
        block = ciphertext[i : i + cipher.block_size]
        decrypted = cipher.decrypt_block(block)
        out += bytes(a ^ b for a, b in zip(decrypted, previous))
        previous = block

    return unpad_fn(bytes(out), cipher.block_size)


def ctr_crypt(cipher: BlockCipher, data: bytes, nonce: bytes | None = None) -> tuple[bytes, bytes]:
    """Counter mode: XOR the data with a stream of encrypted counter blocks.

    Works as a stream cipher for any block cipher, needs no padding, and is
    seekable -- block ``i`` can be computed without touching the others. It is
    malleable, though: flipping a ciphertext bit flips the same plaintext bit, so
    CTR alone provides no integrity. Returns ``(ciphertext, nonce)``.
    """
    import os

    if nonce is None:
        nonce = os.urandom(cipher.block_size)
    if len(nonce) != cipher.block_size:
        raise ValueError(f"nonce must be {cipher.block_size} bytes")

    counter = int.from_bytes(nonce, "big")
    modulus = 1 << (cipher.block_size * 8)
    out = bytearray()

    for i in range(0, len(data), cipher.block_size):
        keystream = cipher.encrypt_block((counter % modulus).to_bytes(cipher.block_size, "big"))
        chunk = data[i : i + cipher.block_size]
        out += bytes(a ^ b for a, b in zip(chunk, keystream))
        counter += 1

    return bytes(out), nonce


@dataclass(frozen=True)
class ModeInfo:
    """Human-readable summary of a mode, surfaced through the API."""

    name: str
    summary: str
    needs_iv: bool
    malleable: bool
    parallelizable: bool


MODE_INFO: dict[str, ModeInfo] = {
    "ecb": ModeInfo(
        name="ECB",
        summary="Each block encrypted independently. Leaks repeated plaintext blocks.",
        needs_iv=False,
        malleable=True,
        parallelizable=True,
    ),
    "cbc": ModeInfo(
        name="CBC",
        summary="Chains blocks with XOR and a random IV. Hides patterns; must never reuse an IV.",
        needs_iv=True,
        malleable=True,
        parallelizable=False,
    ),
    "ctr": ModeInfo(
        name="CTR",
        summary="Counter mode turns the block cipher into a stream cipher. Seekable, no padding.",
        needs_iv=True,
        malleable=True,
        parallelizable=True,
    ),
}

# ECB and CBC need a real IV; CTR's nonce doubles as the initial counter value.
MODE_REGISTRY = {
    "ecb": (ecb_encrypt, ecb_decrypt),
    "cbc": (cbc_encrypt, cbc_decrypt),
    "ctr": (ctr_crypt, ctr_crypt),
}