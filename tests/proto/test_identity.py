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

"""Identity construction, signing paths, and key file handling."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from meshelle.proto.constants import PRV_KEY_SIZE, PUB_KEY_SIZE, SEED_SIZE
from meshelle.proto.ed25519_expanded import expanded_from_seed
from meshelle.proto.identity import (
    KEY_FILE_MODE,
    IdentityError,
    LocalIdentity,
    is_reserved_public_key,
    load_identity,
    load_or_create_identity,
    save_identity,
    verify_signature,
)

FIRMWARE_TEST_PRV = bytes.fromhex(
    "7065e18fd9fabb70c1ed90dca19907de698c88b709ea146eafd93d9b830c7b60"
    "c4681193c79bbc39945ba8064104bb618f8fd7a84a0af6f57033d6e8ddcd6471"
)
FIRMWARE_TEST_PUB = bytes.fromhex(
    "1ec77175b0918ed206f9ae04ec136d6d5d4315bb26305427f645b492e9350c10"
)
SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")


class TestConstruction:
    def test_generate_produces_a_usable_seed_backed_identity(self) -> None:
        identity = LocalIdentity.generate()

        assert len(identity.public_key) == PUB_KEY_SIZE
        assert len(identity.private_key) == PRV_KEY_SIZE
        assert identity.seed is not None
        assert len(identity.seed) == SEED_SIZE

    def test_generate_never_returns_a_reserved_node_hash(self) -> None:
        """0x00 and 0xFF are reserved; firmware rejects such keys outright."""
        for _ in range(50):
            assert not is_reserved_public_key(LocalIdentity.generate().public_key)

    def test_generate_is_unique(self) -> None:
        keys = {LocalIdentity.generate().public_key for _ in range(10)}
        assert len(keys) == 10

    def test_from_expanded_recovers_the_firmware_test_key(self) -> None:
        identity = LocalIdentity.from_expanded(FIRMWARE_TEST_PRV)

        assert identity.public_key == FIRMWARE_TEST_PUB
        assert identity.seed is None, "an imported expanded key has no recoverable seed"

    def test_from_seed_and_from_expanded_agree_on_the_same_key(self) -> None:
        from_seed = LocalIdentity.from_seed(SEED)
        from_expanded = LocalIdentity.from_expanded(expanded_from_seed(SEED))

        assert from_seed.public_key == from_expanded.public_key
        assert from_seed.private_key == from_expanded.private_key

    @pytest.mark.parametrize(
        ("hex_in", "has_seed"),
        [(SEED.hex(), True), (expanded_from_seed(SEED).hex(), False)],
        ids=["seed-64-chars", "expanded-128-chars"],
    )
    def test_from_hex_dispatches_on_length(self, hex_in: str, has_seed: bool) -> None:
        identity = LocalIdentity.from_hex(hex_in)
        assert (identity.seed is not None) is has_seed
        assert identity.public_key == LocalIdentity.from_seed(SEED).public_key

    def test_from_hex_tolerates_whitespace_and_case(self) -> None:
        assert LocalIdentity.from_hex(f"  {SEED.hex().upper()}  ").seed == SEED

    @pytest.mark.parametrize(
        ("bad", "match"),
        [
            ("00" * 31, "must be 64 chars"),
            ("zz" * 32, "not valid hex"),
            ("", "must be 64 chars"),
        ],
    )
    def test_from_hex_rejects_bad_input(self, bad: str, match: str) -> None:
        with pytest.raises(IdentityError, match=match):
            LocalIdentity.from_hex(bad)

    def test_rejects_mismatched_public_key(self) -> None:
        with pytest.raises(IdentityError, match="does not match"):
            LocalIdentity(public_key=bytes(32), private_key=FIRMWARE_TEST_PRV)

    def test_rejects_seed_that_does_not_expand_to_private_key(self) -> None:
        with pytest.raises(IdentityError, match="does not expand"):
            LocalIdentity(
                public_key=FIRMWARE_TEST_PUB,
                private_key=FIRMWARE_TEST_PRV,
                seed=bytes(32),
            )

    def test_node_hash_is_the_first_public_key_byte(self) -> None:
        assert LocalIdentity.from_expanded(FIRMWARE_TEST_PRV).node_hash == 0x1E


class TestSigning:
    def test_both_signing_paths_agree(self) -> None:
        """The seed-backed (OpenSSL) and expanded-only paths must be identical.

        This is what lets the rest of the codebase ignore which kind it holds.
        """
        seed_backed = LocalIdentity.from_seed(SEED)
        expanded_only = LocalIdentity.from_expanded(expanded_from_seed(SEED))
        assert expanded_only.seed is None

        message = b"\x04advert payload"
        assert seed_backed.sign(message) == expanded_only.sign(message)

    def test_signature_verifies(self) -> None:
        identity = LocalIdentity.generate()
        message = b"room advert"
        assert verify_signature(identity.public_key, message, identity.sign(message))

    def test_verify_rejects_tampered_message(self) -> None:
        identity = LocalIdentity.generate()
        signature = identity.sign(b"original")
        assert not verify_signature(identity.public_key, b"tampered", signature)

    def test_verify_rejects_wrong_key(self) -> None:
        signer, other = LocalIdentity.generate(), LocalIdentity.generate()
        assert not verify_signature(other.public_key, b"msg", signer.sign(b"msg"))

    @pytest.mark.parametrize(
        ("public_key", "signature"),
        [(bytes(31), bytes(64)), (bytes(32), bytes(63)), (bytes(32), b"")],
        ids=["short-key", "short-sig", "empty-sig"],
    )
    def test_verify_returns_false_on_malformed_input(
        self, public_key: bytes, signature: bytes
    ) -> None:
        """Malformed adverts are ordinary mesh noise, not exceptions."""
        assert not verify_signature(public_key, b"msg", signature)

    def test_shared_secret_is_symmetric_between_identities(self) -> None:
        a, b = LocalIdentity.generate(), LocalIdentity.generate()
        assert a.shared_secret(b.public_key) == b.shared_secret(a.public_key)


class TestKeyFiles:
    def test_round_trips_a_generated_identity(self, tmp_path: Path) -> None:
        original = LocalIdentity.generate()
        path = tmp_path / "lobby.key"

        save_identity(path, original)
        loaded = load_identity(path)

        assert loaded == original
        assert loaded.seed is not None, "a generated key keeps its seed through the file"

    def test_round_trips_an_imported_expanded_identity(self, tmp_path: Path) -> None:
        original = LocalIdentity.from_expanded(FIRMWARE_TEST_PRV)
        path = tmp_path / "imported.key"

        save_identity(path, original)
        loaded = load_identity(path)

        assert loaded == original
        assert loaded.seed is None

    def test_file_is_created_with_mode_0600(self, tmp_path: Path) -> None:
        path = tmp_path / "lobby.key"
        save_identity(path, LocalIdentity.generate())

        assert stat.S_IMODE(path.stat().st_mode) == KEY_FILE_MODE

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        path = tmp_path / "nested" / "deeper" / "lobby.key"
        save_identity(path, LocalIdentity.generate())
        assert path.exists()

    def test_refuses_to_overwrite_without_being_asked(self, tmp_path: Path) -> None:
        path = tmp_path / "lobby.key"
        save_identity(path, LocalIdentity.generate())

        with pytest.raises(IdentityError, match="refusing to overwrite"):
            save_identity(path, LocalIdentity.generate())

    def test_overwrites_when_asked(self, tmp_path: Path) -> None:
        path = tmp_path / "lobby.key"
        save_identity(path, LocalIdentity.generate())
        replacement = LocalIdentity.generate()

        save_identity(path, replacement, overwrite=True)

        assert load_identity(path) == replacement

    def test_rejects_a_world_readable_key_file(self, tmp_path: Path) -> None:
        """A leaked room key lets anyone impersonate the room."""
        path = tmp_path / "lobby.key"
        save_identity(path, LocalIdentity.generate())
        path.chmod(0o644)

        with pytest.raises(IdentityError, match="group/world accessible"):
            load_identity(path)

    def test_rejects_a_seed_that_disagrees_with_private_key(self, tmp_path: Path) -> None:
        """Corruption detection: the two fields must describe the same key."""
        path = tmp_path / "tampered.key"
        other = LocalIdentity.generate()
        assert other.seed is not None
        path.write_text(
            f'public_key = "{other.public_key.hex()}"\n'
            f'private_key = "{FIRMWARE_TEST_PRV.hex()}"\n'
            f'seed = "{other.seed.hex()}"\n'
        )
        path.chmod(KEY_FILE_MODE)

        with pytest.raises(IdentityError, match="seed expands to"):
            load_identity(path)

    def test_rejects_a_public_key_that_disagrees_with_private_key(self, tmp_path: Path) -> None:
        path = tmp_path / "tampered.key"
        path.write_text(
            f'public_key = "{bytes(32).hex()}"\nprivate_key = "{FIRMWARE_TEST_PRV.hex()}"\n'
        )
        path.chmod(KEY_FILE_MODE)

        with pytest.raises(IdentityError, match="inconsistent"):
            load_identity(path)

    def test_rejects_a_file_with_no_private_key(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.key"
        path.write_text("# nothing here\n")
        path.chmod(KEY_FILE_MODE)

        with pytest.raises(IdentityError, match="no private_key"):
            load_identity(path)

    def test_rejects_malformed_toml(self, tmp_path: Path) -> None:
        path = tmp_path / "broken.key"
        path.write_text("this is not = = toml\n")
        path.chmod(KEY_FILE_MODE)

        with pytest.raises(IdentityError, match="malformed"):
            load_identity(path)

    def test_reports_a_missing_file_clearly(self, tmp_path: Path) -> None:
        with pytest.raises(IdentityError, match="cannot read key file"):
            load_identity(tmp_path / "absent.key")

    def test_load_or_create_generates_once_then_reuses(self, tmp_path: Path) -> None:
        path = tmp_path / "lobby.key"

        first, created = load_or_create_identity(path)
        assert created is True

        second, created_again = load_or_create_identity(path)
        assert created_again is False
        assert second == first, "a restart must not change a room's identity"
