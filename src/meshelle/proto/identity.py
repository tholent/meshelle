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

"""Room identities: Ed25519 key material, and the key files that hold it.

A room *is* its key pair. Clients address the room by the first byte of its
public key and add it to their contacts by the full key, so losing or changing a
room's identity means every client must re-add it.

Two flavours of private key exist, and the difference is load-bearing:

* **Seed-backed** (what ``generate`` produces) — we keep the 32-byte seed, so
  signing goes through ``cryptography``/OpenSSL, the audited implementation.
* **Expanded-only** (imported from MeshCore or meshcore-pi) — only the 64-byte
  ``(a, prefix)`` pair survives; the seed is unrecoverable. Signing then uses
  ``ed25519_expanded``, which the tests hold byte-identical to OpenSSL.

Both expose the same interface, so nothing above this module cares which it has.
"""

from __future__ import annotations

import os
import secrets
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from meshelle.proto import crypto, ed25519_expanded
from meshelle.proto.constants import PRV_KEY_SIZE, PUB_KEY_SIZE, SEED_SIZE

KEY_FILE_MODE = 0o600


class IdentityError(Exception):
    """The key material or key file is unusable."""


def _raw_public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def is_reserved_public_key(public_key: bytes) -> bool:
    """Whether a public key starts with a reserved node hash.

    Firmware reserves node hashes 0x00 and 0xFF (``validatePrivateKey`` in
    src/Identity.cpp), so a key with either prefix must not be used.
    """
    return public_key[0] in (0x00, 0xFF)


@dataclass(frozen=True, slots=True)
class LocalIdentity:
    """A key pair meshelle holds the private half of.

    ``private_key`` is always the 64-byte MeshCore expanded form, so it can be
    exported to firmware verbatim. ``seed`` is present only when we generated
    the key (or loaded a file that recorded it).
    """

    public_key: bytes
    private_key: bytes
    seed: bytes | None = None

    def __post_init__(self) -> None:
        if len(self.public_key) != PUB_KEY_SIZE:
            raise IdentityError(f"public key must be {PUB_KEY_SIZE} bytes")
        if len(self.private_key) != PRV_KEY_SIZE:
            raise IdentityError(f"private key must be {PRV_KEY_SIZE} bytes")
        if self.seed is not None and len(self.seed) != SEED_SIZE:
            raise IdentityError(f"seed must be {SEED_SIZE} bytes")

        derived = ed25519_expanded.derive_public_key(self.private_key)
        if derived != self.public_key:
            raise IdentityError(
                "public key does not match the private key "
                f"(derived {derived.hex()[:16]}…, stored {self.public_key.hex()[:16]}…)"
            )
        if self.seed is not None and ed25519_expanded.expanded_from_seed(self.seed) != (
            self.private_key
        ):
            raise IdentityError("seed does not expand to the stored private key")

    # -- construction --------------------------------------------------------

    @classmethod
    def generate(cls) -> Self:
        """Create a new identity, avoiding the reserved 0x00/0xFF node hashes."""
        while True:
            seed = secrets.token_bytes(SEED_SIZE)
            public_key = _raw_public_bytes(Ed25519PrivateKey.from_private_bytes(seed))
            if not is_reserved_public_key(public_key):
                return cls(
                    public_key=public_key,
                    private_key=ed25519_expanded.expanded_from_seed(seed),
                    seed=seed,
                )

    @classmethod
    def from_seed(cls, seed: bytes) -> Self:
        if len(seed) != SEED_SIZE:
            raise IdentityError(f"seed must be {SEED_SIZE} bytes, got {len(seed)}")
        return cls(
            public_key=_raw_public_bytes(Ed25519PrivateKey.from_private_bytes(seed)),
            private_key=ed25519_expanded.expanded_from_seed(seed),
            seed=seed,
        )

    @classmethod
    def from_expanded(cls, private_key: bytes) -> Self:
        """Import a MeshCore 64-byte expanded private key. The seed is lost."""
        if len(private_key) != PRV_KEY_SIZE:
            raise IdentityError(
                f"expanded private key must be {PRV_KEY_SIZE} bytes, got {len(private_key)}"
            )
        return cls(
            public_key=ed25519_expanded.derive_public_key(private_key),
            private_key=private_key,
        )

    @classmethod
    def from_hex(cls, private_key_hex: str) -> Self:
        """Import from hex: 64 chars is a seed, 128 is an expanded private key."""
        cleaned = private_key_hex.strip().replace(" ", "")
        try:
            raw = bytes.fromhex(cleaned)
        except ValueError as exc:
            raise IdentityError(f"private key is not valid hex: {exc}") from exc

        if len(raw) == SEED_SIZE:
            return cls.from_seed(raw)
        if len(raw) == PRV_KEY_SIZE:
            return cls.from_expanded(raw)
        raise IdentityError(
            f"private key hex must be {SEED_SIZE * 2} chars (seed) or "
            f"{PRV_KEY_SIZE * 2} chars (expanded), got {len(cleaned)}"
        )

    # -- use -----------------------------------------------------------------

    @property
    def node_hash(self) -> int:
        """The first byte of the public key, used to address packets."""
        return self.public_key[0]

    def sign(self, message: bytes) -> bytes:
        """Sign with OpenSSL when the seed is known, else the expanded signer."""
        if self.seed is not None:
            return Ed25519PrivateKey.from_private_bytes(self.seed).sign(message)
        return ed25519_expanded.sign(self.private_key, self.public_key, message)

    def shared_secret(self, peer_public_key: bytes) -> bytes:
        return crypto.shared_secret(self.private_key, peer_public_key)


def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature, returning False rather than raising.

    Used on adverts from the mesh, where a bad signature is an ordinary event
    (corruption, a spoof attempt) and not an exception-worthy one.
    """
    if len(public_key) != PUB_KEY_SIZE or len(signature) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


# ---------------------------------------------------------------------------
# Key files
# ---------------------------------------------------------------------------


def save_identity(path: Path, identity: LocalIdentity, *, overwrite: bool = False) -> None:
    """Write a key file with mode 0600.

    The file is created with restrictive permissions from the outset rather than
    chmod'ed afterwards, so the key is never briefly world-readable.
    """
    if path.exists() and not overwrite:
        raise IdentityError(f"refusing to overwrite existing key file: {path}")

    lines = [
        "# meshelle room identity -- SECRET. Keep this file mode 0600.",
        "#",
        "# public_key is recorded so a corrupted file is detected on load; it is",
        "# derived from private_key, never trusted over it.",
        "",
        f'public_key = "{identity.public_key.hex()}"',
        f'private_key = "{identity.private_key.hex()}"  # MeshCore expanded format',
    ]
    if identity.seed is not None:
        lines.append(f'seed = "{identity.seed.hex()}"')
    body = "\n".join(lines) + "\n"

    path.parent.mkdir(parents=True, exist_ok=True)
    # O_EXCL unless overwriting, so a concurrent writer cannot be clobbered.
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    fd = os.open(path, flags, KEY_FILE_MODE)
    try:
        os.write(fd, body.encode("utf-8"))
    finally:
        os.close(fd)


def load_identity(path: Path) -> LocalIdentity:
    """Read a key file, validating its permissions and internal consistency."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise IdentityError(f"cannot read key file {path}: {exc}") from exc

    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise IdentityError(
            f"key file {path} is group/world accessible (mode {mode:04o}); "
            f"fix with: chmod 600 {path}"
        )

    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise IdentityError(f"key file {path} is malformed: {exc}") from exc

    if "private_key" not in data:
        raise IdentityError(f"key file {path} has no private_key")

    expanded_hex = str(data["private_key"]).strip()

    if "seed" in data:
        # Prefer the seed (it enables the OpenSSL signing path) but only after
        # confirming it expands to the recorded private key. Taking the seed on
        # faith would silently ignore a mismatch.
        identity = LocalIdentity.from_hex(str(data["seed"]))
        if identity.private_key.hex() != expanded_hex.lower():
            raise IdentityError(
                f"key file {path} is inconsistent: seed expands to "
                f"{identity.private_key.hex()[:16]}… but private_key is "
                f"{expanded_hex[:16]}…"
            )
    else:
        identity = LocalIdentity.from_hex(expanded_hex)

    if "public_key" in data:
        recorded = str(data["public_key"])
        if recorded != identity.public_key.hex():
            raise IdentityError(
                f"key file {path} is inconsistent: recorded public_key {recorded[:16]}… "
                f"but private_key derives {identity.public_key.hex()[:16]}…"
            )
    return identity


def load_or_create_identity(path: Path) -> tuple[LocalIdentity, bool]:
    """Load the key file, generating one if absent.

    Returns the identity and whether it was newly created, so callers can log
    a new room key exactly once.
    """
    if path.exists():
        return load_identity(path), False
    identity = LocalIdentity.generate()
    save_identity(path, identity)
    return identity, True
