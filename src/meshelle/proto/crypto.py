# Copyright 2026 Chris Wells
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""MeshCore cryptographic primitives.

MeshCore's scheme, as implemented in ``src/Utils.cpp`` and ``src/Identity.cpp``:

* **Key agreement** — X25519. ``ed25519_key_exchange`` (lib/ed25519/key_exchange.c)
  clamps the low 32 bytes of the expanded private key exactly as RFC 7748
  requires, and maps the peer's Ed25519 public key onto the Montgomery curve with
  ``u = (y + 1) / (1 - y) mod p``. That is standard X25519, so OpenSSL computes
  it for us; there is no need for the pure-Python ladder meshcore-pi carries.
* **Cipher** — AES-128-ECB over the first 16 bytes of the shared secret
  (``CIPHER_KEY_SIZE`` is 16), with the final partial block zero-padded.
* **Authentication** — HMAC-SHA256 keyed with the *full* 32-byte shared secret
  over the ciphertext, truncated to 2 bytes (``CIPHER_MAC_SIZE``).

None of these choices are ours. ECB and a 2-byte tag are weak, but they are the
wire format: a room server that "improves" them cannot talk to any MeshCore app.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Final

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from meshelle.proto.constants import (
    CIPHER_BLOCK_SIZE,
    CIPHER_KEY_SIZE,
    CIPHER_MAC_SIZE,
    MAX_HASH_SIZE,
    PUB_KEY_SIZE,
)

P25519: Final = 2**255 - 19
"""The Curve25519 field prime."""


class DecryptionError(Exception):
    """The MAC did not match, so the packet is not for this key pair."""


def _edwards_to_montgomery_u(ed25519_public_key: bytes) -> bytes:
    """Map an Ed25519 public key to its Montgomery u-coordinate.

    ``u = (y + 1) * inverse(1 - y) mod p``, the birational map used by
    ``ed25519_key_exchange``. The sign bit (bit 255) is discarded, matching
    ``fe_frombytes``.
    """
    if len(ed25519_public_key) != PUB_KEY_SIZE:
        raise ValueError(f"public key must be {PUB_KEY_SIZE} bytes, got {len(ed25519_public_key)}")

    y = int.from_bytes(ed25519_public_key, "little") & ~(1 << 255)
    numerator = (y + 1) % P25519
    # pow(0, p - 2, p) == 0, which is also what fe_invert yields for zero, so a
    # degenerate y == 1 produces u == 0 here exactly as it does in firmware.
    denominator = pow((1 - y) % P25519, P25519 - 2, P25519)
    u = (numerator * denominator) % P25519
    return u.to_bytes(32, "little")


def shared_secret(private_key: bytes, peer_public_key: bytes) -> bytes:
    """Derive the 32-byte ECDH secret shared with ``peer_public_key``.

    ``private_key`` is the expanded 64-byte MeshCore private key (only its first
    32 bytes participate) or any 32-byte scalar.

    Raises:
        DecryptionError: the peer key is degenerate and yields an all-zero
            secret. Firmware would return the zeros; OpenSSL refuses, and a peer
            that sends such a key cannot be talked to anyway.
    """
    if len(private_key) not in (32, 64):
        raise ValueError(f"private key must be 32 or 64 bytes, got {len(private_key)}")

    scalar = private_key[:32]
    u_coordinate = _edwards_to_montgomery_u(peer_public_key)
    try:
        # OpenSSL applies the RFC 7748 clamping internally, so the raw scalar
        # gives the same answer as firmware's explicit e[0] &= 248 etc.
        return X25519PrivateKey.from_private_bytes(scalar).exchange(
            X25519PublicKey.from_public_bytes(u_coordinate)
        )
    except ValueError as exc:  # all-zero output: small-order peer key
        raise DecryptionError("peer public key yields a degenerate shared secret") from exc


def _aes_ecb(secret: bytes) -> Cipher[modes.ECB]:
    if len(secret) < CIPHER_KEY_SIZE:
        raise ValueError(f"shared secret must be at least {CIPHER_KEY_SIZE} bytes")
    return Cipher(algorithms.AES(secret[:CIPHER_KEY_SIZE]), modes.ECB())  # noqa: S305


def _mac(secret: bytes, ciphertext: bytes) -> bytes:
    """HMAC-SHA256 over the ciphertext, keyed with the full secret, truncated."""
    if len(secret) != PUB_KEY_SIZE:
        raise ValueError(f"MAC key must be {PUB_KEY_SIZE} bytes, got {len(secret)}")
    return hmac.digest(secret, ciphertext, hashlib.sha256)[:CIPHER_MAC_SIZE]


def encrypt_then_mac(secret: bytes, plaintext: bytes) -> bytes:
    """Encrypt ``plaintext`` and prefix the 2-byte MAC.

    Returns ``mac || ciphertext``. The ciphertext is zero-padded up to a block
    boundary, so the recipient recovers trailing zeros it must itself trim --
    every MeshCore payload therefore carries its own length or is delimited.
    """
    padding = -len(plaintext) % CIPHER_BLOCK_SIZE
    encryptor = _aes_ecb(secret).encryptor()
    ciphertext = encryptor.update(plaintext + bytes(padding)) + encryptor.finalize()
    return _mac(secret, ciphertext) + ciphertext


def mac_then_decrypt(secret: bytes, payload: bytes) -> bytes:
    """Verify the 2-byte MAC on ``mac || ciphertext`` and decrypt.

    The returned plaintext is still block-padded; callers trim it using the
    structure of the payload they expect.

    Raises:
        DecryptionError: the MAC did not match. With a 1-byte destination hash,
            several keys can be candidates for one packet, so this is the normal
            way to find out a packet was not meant for us -- not an error worth
            logging at anything above debug.
    """
    if len(payload) <= CIPHER_MAC_SIZE:
        raise DecryptionError(f"payload too short to contain a MAC: {len(payload)} bytes")

    received_mac, ciphertext = payload[:CIPHER_MAC_SIZE], payload[CIPHER_MAC_SIZE:]
    if len(ciphertext) % CIPHER_BLOCK_SIZE:
        raise DecryptionError(f"ciphertext is not a block multiple: {len(ciphertext)} bytes")

    if not hmac.compare_digest(received_mac, _mac(secret, ciphertext)):
        raise DecryptionError("MAC mismatch")

    decryptor = _aes_ecb(secret).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def ack_hash(data: bytes, peer_public_key: bytes) -> bytes:
    """The 4-byte ACK proving a message was received.

    ``sha256(data || peer_pubkey)[:4]``. The two-fragment form of
    ``Utils::sha256`` (src/Utils.cpp:36) hashes the fragments in order, so the
    concatenation order matters and is asserted by the tests.
    """
    return hashlib.sha256(data + peer_public_key).digest()[:4]


def packet_hash(payload_type: int, payload: bytes) -> bytes:
    """The duplicate-detection hash from ``Packet::calculatePacketHash``.

    ``sha256(payload_type || payload)[:8]``. Deliberately excludes the path, so
    the same packet arriving by different routes hashes identically -- which is
    also what makes it catch our own packets echoed back by a repeater.

    TRACE packets additionally mix in ``path_len`` upstream; meshelle ignores
    TRACE entirely, so that case is not reproduced here.
    """
    return hashlib.sha256(bytes([payload_type]) + payload).digest()[:MAX_HASH_SIZE]
