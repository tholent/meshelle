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

"""Validate the expanded-key signer against OpenSSL and the firmware's vectors.

The risky claim in ``ed25519_expanded`` is that hand-rolled curve arithmetic
agrees with a real Ed25519 implementation. These tests pin that down rather than
trusting it, which is the only reason the module is allowed to exist.
"""

from __future__ import annotations

import hashlib
import secrets

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from meshelle.proto.ed25519_expanded import (
    clamp_scalar,
    derive_public_key,
    expanded_from_seed,
    sign,
)

# From MeshCore src/Identity.cpp, LocalIdentity::validatePrivateKey. The firmware
# ships this pair to self-test its own crypto, which makes it an ideal vector:
# if our derivation disagrees, we are not MeshCore-compatible.
FIRMWARE_TEST_PRV = bytes.fromhex(
    "7065e18fd9fabb70c1ed90dca19907de698c88b709ea146eafd93d9b830c7b60"
    "c4681193c79bbc39945ba8064104bb618f8fd7a84a0af6f57033d6e8ddcd6471"
)
FIRMWARE_TEST_PUB = bytes.fromhex(
    "1ec77175b0918ed206f9ae04ec136d6d5d4315bb26305427f645b492e9350c10"
)


def _seed_to_pub(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def test_derives_the_firmware_test_public_key() -> None:
    """The firmware's own self-test vector must round-trip through our code."""
    assert derive_public_key(FIRMWARE_TEST_PRV) == FIRMWARE_TEST_PUB


def test_firmware_test_key_is_already_clamped() -> None:
    """MeshCore stores the clamped scalar, not the raw SHA-512 output.

    If this were false, ``expanded_from_seed`` would have to stop clamping to
    stay byte-compatible with exported keys.
    """
    assert clamp_scalar(FIRMWARE_TEST_PRV[:32]) == FIRMWARE_TEST_PRV[:32]


@pytest.mark.parametrize("iteration", range(8))
def test_expanded_from_seed_matches_openssl_public_key(iteration: int) -> None:
    """Our seed expansion must yield the same public key as a real Ed25519 impl."""
    seed = secrets.token_bytes(32)
    assert derive_public_key(expanded_from_seed(seed)) == _seed_to_pub(seed)


def test_expanded_from_seed_is_clamped_sha512() -> None:
    seed = bytes(range(32))
    digest = hashlib.sha512(seed).digest()
    expanded = expanded_from_seed(seed)
    assert expanded[:32] == clamp_scalar(digest[:32])
    assert expanded[32:] == digest[32:]


@pytest.mark.parametrize(
    "message",
    [
        b"",
        b"a",
        bytes(range(32)),
        b"advert payload with a name and lat/lon" * 4,
        secrets.token_bytes(200),
    ],
    ids=["empty", "one-byte", "32-bytes", "repeated", "random-200"],
)
def test_signature_is_byte_identical_to_openssl(message: bytes) -> None:
    """The whole justification for this module: same key, same signature.

    A seed gives both a ``cryptography`` key and, via SHA-512, the expanded form.
    Signing is deterministic in Ed25519, so the two must agree exactly.
    """
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    reference = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = _seed_to_pub(seed)

    ours = sign(expanded_from_seed(seed), public_key, message)

    assert ours == reference.sign(message)
    # And it really verifies, so a matching-but-wrong pair cannot slip through.
    reference.public_key().verify(ours, message)


@pytest.mark.parametrize("iteration", range(4))
def test_signature_matches_openssl_for_random_keys(iteration: int) -> None:
    seed = secrets.token_bytes(32)
    reference = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = _seed_to_pub(seed)
    message = secrets.token_bytes(64)

    assert sign(expanded_from_seed(seed), public_key, message) == reference.sign(message)


def test_rejects_wrong_length_inputs() -> None:
    with pytest.raises(ValueError, match="64 bytes"):
        derive_public_key(b"\x00" * 32)
    with pytest.raises(ValueError, match="32 bytes"):
        expanded_from_seed(b"\x00" * 64)
    with pytest.raises(ValueError, match="public key must be 32 bytes"):
        sign(FIRMWARE_TEST_PRV, b"\x00" * 31, b"msg")
