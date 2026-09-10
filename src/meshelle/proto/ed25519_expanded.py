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

"""Ed25519 signing from a MeshCore *expanded* private key.

MeshCore stores the 64-byte output of ``SHA-512(seed)`` as its private key and
discards the seed (``ed25519_create_keypair`` with ``ED25519_NO_SEED``). In
RFC 8032 terms that is ``(a, prefix)``: the clamped scalar followed by the nonce
prefix. No mainstream library accepts a key in that form -- they all want the
seed -- which is why this module exists.

It is used **only** for identities imported from MeshCore or meshcore-pi. When
meshelle generates a key it keeps the seed and signs via ``cryptography``, whose
implementation is the audited one. ``tests/proto/test_ed25519_expanded.py``
asserts the two paths produce byte-identical signatures for the same key, so
this code is continuously checked against OpenSSL rather than trusted on sight.

Scope is deliberately minimal: derive a public key, and sign. Verification uses
``cryptography``, so no point decompression is needed here.
"""

from __future__ import annotations

import hashlib
from typing import Final

from meshelle.proto.constants import PRV_KEY_SIZE, PUB_KEY_SIZE, SEED_SIZE

P: Final = 2**255 - 19
"""Field prime, 2^255 - 19."""

L: Final = 2**252 + 27742317777372353535851937790883648493
"""Order of the base point."""

_D: Final = (-121665 * pow(121666, P - 2, P)) % P
"""Curve constant d = -121665/121666."""

# Extended twisted Edwards coordinates: (X, Y, Z, T) with x = X/Z, y = Y/Z.
type Point = tuple[int, int, int, int]

_IDENTITY: Final[Point] = (0, 1, 1, 0)


def _recover_x(y: int) -> int:
    """Recover the even x for a given y on the curve."""
    xx = (y * y - 1) * pow(_D * y * y + 1, P - 2, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = x * pow(2, (P - 1) // 4, P) % P
    return P - x if x % 2 else x


_BASE_Y: Final = 4 * pow(5, P - 2, P) % P
_BASE: Final[Point] = (_recover_x(_BASE_Y), _BASE_Y, 1, _recover_x(_BASE_Y) * _BASE_Y % P)


def _add(p: Point, q: Point) -> Point:
    """Unified addition on the twisted Edwards curve (RFC 8032 §5.1.4)."""
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * _D * t2 % P
    d = z1 * 2 * z2 % P
    e, f, g, h = (b - a) % P, (d - c) % P, (d + c) % P, (b + a) % P
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _scalar_mult(scalar: int, point: Point = _BASE) -> Point:
    """Double-and-add.

    Not constant time. It only ever runs on our own long-term signing key with
    no attacker-chosen input and no remote timing signal (adverts are signed
    every few minutes at most), so the side channel has nothing to leak through.
    Do not reuse this for ephemeral or attacker-influenced scalars.
    """
    result = _IDENTITY
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _encode(point: Point) -> bytes:
    """Compress a point to 32 bytes: y with x's low bit in the top bit."""
    x, y, z, _ = point
    z_inv = pow(z, P - 2, P)
    x, y = x * z_inv % P, y * z_inv % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def clamp_scalar(raw: bytes) -> bytes:
    """Apply the RFC 8032 / RFC 7748 bit clamping to a 32-byte scalar.

    Clears the low three bits and the high bit, and sets bit 254 -- exactly what
    ``ed25519_create_keypair`` does in place after hashing the seed.
    """
    if len(raw) != 32:
        raise ValueError(f"scalar must be 32 bytes, got {len(raw)}")
    s = bytearray(raw)
    s[0] &= 248
    s[31] &= 63
    s[31] |= 64
    return bytes(s)


def expanded_from_seed(seed: bytes) -> bytes:
    """Produce the 64-byte MeshCore private key for a 32-byte seed.

    ``clamp(SHA-512(seed)[:32]) || SHA-512(seed)[32:]``. This is the format
    ``CMD_EXPORT_PRIVATE_KEY`` returns and ``CMD_IMPORT_PRIVATE_KEY`` accepts.
    """
    if len(seed) != SEED_SIZE:
        raise ValueError(f"seed must be {SEED_SIZE} bytes, got {len(seed)}")
    digest = hashlib.sha512(seed).digest()
    return clamp_scalar(digest[:32]) + digest[32:]


def derive_public_key(expanded_private_key: bytes) -> bytes:
    """Derive the Ed25519 public key from an expanded private key."""
    if len(expanded_private_key) != PRV_KEY_SIZE:
        raise ValueError(
            f"expanded private key must be {PRV_KEY_SIZE} bytes, got {len(expanded_private_key)}"
        )
    scalar = int.from_bytes(clamp_scalar(expanded_private_key[:32]), "little")
    return _encode(_scalar_mult(scalar))


def sign(expanded_private_key: bytes, public_key: bytes, message: bytes) -> bytes:
    """Sign ``message``, returning a 64-byte Ed25519 signature.

    Standard RFC 8032 §5.1.6 with the key-expansion step already done:

        r = SHA-512(prefix || M) mod L
        R = r * B
        k = SHA-512(R || A || M) mod L
        S = (r + k * a) mod L
    """
    if len(expanded_private_key) != PRV_KEY_SIZE:
        raise ValueError(
            f"expanded private key must be {PRV_KEY_SIZE} bytes, got {len(expanded_private_key)}"
        )
    if len(public_key) != PUB_KEY_SIZE:
        raise ValueError(f"public key must be {PUB_KEY_SIZE} bytes, got {len(public_key)}")

    scalar = int.from_bytes(clamp_scalar(expanded_private_key[:32]), "little")
    prefix = expanded_private_key[32:]

    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    big_r = _encode(_scalar_mult(r))
    k = int.from_bytes(hashlib.sha512(big_r + public_key + message).digest(), "little") % L
    s = (r + k * scalar) % L
    return big_r + s.to_bytes(32, "little")
