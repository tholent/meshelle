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

"""Config schema: value parsing and the invariants each model enforces."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from meshelle.config.model import (
    CompanionSettings,
    LogSettings,
    Member,
    Passwords,
    Role,
    RoomSettings,
    Settings,
    TransportKind,
    UnknownPolicy,
    parse_duration,
    parse_public_key,
    resolve_secret,
)
from meshelle.proto.constants import Permission

KEY_A = "a1" + "00" * 31
KEY_B = "b0" + "00" * 31

SERIAL = {"port": "/dev/ttyUSB0"}


def room_data(**overrides: object) -> dict[str, object]:
    """A room that is reachable, so tests exercise one invariant at a time."""
    return {"name": "Lobby", "allow_unknown": "guest"} | overrides


def make_room(**overrides: object) -> RoomSettings:
    """Build via model_validate, the same path the loader uses.

    Keyword construction would need a type: ignore on every dict-shaped value,
    which is noise that hides real type errors.
    """
    return RoomSettings.model_validate(room_data(**overrides))


def make_settings(**overrides: object) -> Settings:
    return Settings.model_validate({"companion": SERIAL} | overrides)


class TestParseDuration:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (90, 90),
            ("90", 90),
            ("30s", 30),
            ("30m", 1800),
            ("6h", 21600),
            ("30d", 2592000),
            ("2w", 1209600),
            ("1h30m", 5400),
            ("1d12h", 129600),
            ("  6h  ", 21600),
            ("6H", 21600),
        ],
    )
    def test_accepts_unit_forms_and_bare_seconds(self, value: object, expected: int) -> None:
        assert parse_duration(value) == expected

    @pytest.mark.parametrize("word", ["never", "off", "none", "disabled", "forever", "unlimited"])
    def test_disabling_words_become_none(self, word: str) -> None:
        """None must be distinguishable from zero: 'never advertise' is not the
        same as 'advertise once at startup'."""
        assert parse_duration(word) is None

    def test_zero_is_preserved(self) -> None:
        assert parse_duration("0") == 0
        assert parse_duration(0) == 0

    @pytest.mark.parametrize("value", ["", "soon", "6 parsecs", "h6", "6x", "1h nonsense"])
    def test_rejects_nonsense(self, value: str) -> None:
        with pytest.raises(ValueError, match=r"duration|empty"):
            parse_duration(value)

    def test_passes_none_through(self) -> None:
        assert parse_duration(None) is None


class TestParsePublicKey:
    def test_accepts_64_hex_characters(self) -> None:
        assert parse_public_key(KEY_A) == bytes.fromhex(KEY_A)

    @pytest.mark.parametrize(
        "value",
        [
            "A1" + "00" * 31,
            "a1:" + ":".join(["00"] * 31),
            "  " + KEY_A + "  ",
        ],
        ids=["uppercase", "colon-separated", "whitespace"],
    )
    def test_tolerates_common_formatting(self, value: str) -> None:
        assert parse_public_key(value) == bytes.fromhex(KEY_A)

    def test_rejects_wrong_length(self) -> None:
        with pytest.raises(ValueError, match="64 hex characters"):
            parse_public_key("a1" * 16)

    def test_rejects_non_hex(self) -> None:
        with pytest.raises(ValueError, match="not valid hex"):
            parse_public_key("z" * 64)


class TestResolveSecret:
    def test_passes_a_literal_through(self) -> None:
        assert resolve_secret("hunter2") == "hunter2"

    def test_reads_an_environment_variable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MESHELLE_TEST_PW", "from-env")
        assert resolve_secret("env:MESHELLE_TEST_PW") == "from-env"

    def test_reports_a_missing_variable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("MESHELLE_ABSENT_PW", raising=False)
        with pytest.raises(ValueError, match="is not set"):
            resolve_secret("env:MESHELLE_ABSENT_PW")

    def test_reports_an_empty_variable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MESHELLE_EMPTY_PW", "")
        with pytest.raises(ValueError, match="is empty"):
            resolve_secret("env:MESHELLE_EMPTY_PW")

    def test_reads_a_file(self, tmp_path: Path) -> None:
        secret = tmp_path / "pw"
        secret.write_text("from-file\n")

        assert resolve_secret(f"file:{secret}") == "from-file", "trailing newline stripped"

    def test_reports_a_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="cannot read secret"):
            resolve_secret(f"file:{tmp_path / 'absent'}")

    def test_reports_an_empty_file(self, tmp_path: Path) -> None:
        secret = tmp_path / "pw"
        secret.write_text("\n  \n")

        with pytest.raises(ValueError, match="is empty"):
            resolve_secret(f"file:{secret}")

    @pytest.mark.parametrize("value", ["env:", "file:"])
    def test_rejects_an_indirection_with_no_target(self, value: str) -> None:
        with pytest.raises(ValueError, match="needs a"):
            resolve_secret(value)


class TestRole:
    @pytest.mark.parametrize(
        ("role", "permission"),
        [
            (Role.GUEST, Permission.GUEST),
            (Role.READ_ONLY, Permission.READ_ONLY),
            (Role.READ_WRITE, Permission.READ_WRITE),
            (Role.ADMIN, Permission.ADMIN),
        ],
    )
    def test_maps_to_the_wire_permission(self, role: Role, permission: Permission) -> None:
        assert role.permission == permission

    @pytest.mark.parametrize(
        ("role", "may_post"),
        [
            (Role.GUEST, False),
            (Role.READ_ONLY, False),
            (Role.READ_WRITE, True),
            (Role.ADMIN, True),
        ],
    )
    def test_read_only_may_not_post(self, role: Role, may_post: bool) -> None:
        """Stricter than firmware, which only refuses GUEST and so lets a
        'read only' client post. We honour the name we give the role."""
        assert role.may_post is may_post


class TestUnknownPolicy:
    def test_reject_grants_no_role(self) -> None:
        assert UnknownPolicy.REJECT.role is None

    @pytest.mark.parametrize(
        ("policy", "role"),
        [
            (UnknownPolicy.GUEST, Role.GUEST),
            (UnknownPolicy.READ_ONLY, Role.READ_ONLY),
            (UnknownPolicy.READ_WRITE, Role.READ_WRITE),
        ],
    )
    def test_other_policies_map_to_a_role(self, policy: UnknownPolicy, role: Role) -> None:
        assert policy.role == role


class TestCompanionSettings:
    def test_defaults_to_serial(self) -> None:
        settings = CompanionSettings(port="/dev/ttyUSB0")
        assert settings.transport is TransportKind.SERIAL
        assert settings.baud_rate == 115200

    @pytest.mark.parametrize(
        ("transport", "field"),
        [("serial", "port"), ("tcp", "host"), ("ble", "address")],
    )
    def test_each_transport_requires_its_own_field(self, transport: str, field: str) -> None:
        with pytest.raises(ValidationError, match=f"companion.{field} is required"):
            CompanionSettings.model_validate({"transport": transport})

    def test_accepts_tcp_with_a_host(self) -> None:
        settings = CompanionSettings.model_validate({"transport": "tcp", "host": "node.local"})
        assert settings.tcp_port == 5000

    def test_rejects_an_unknown_transport(self) -> None:
        with pytest.raises(ValidationError):
            CompanionSettings.model_validate({"transport": "carrier-pigeon"})

    def test_rejects_an_unknown_key(self) -> None:
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            CompanionSettings.model_validate({"port": "/dev/x", "serial_port": "/dev/y"})


class TestPasswords:
    def test_none_declared_is_an_empty_list(self) -> None:
        assert Passwords().as_pairs() == []

    def test_orders_strongest_first(self) -> None:
        """If one string is set for two roles, the stronger must win rather than
        the outcome depending on iteration order."""
        passwords = Passwords.model_validate(
            {"admin": "same", "read_write": "same", "read_only": "same"}
        )

        assert [role for role, _ in passwords.as_pairs()] == [
            Role.ADMIN,
            Role.READ_WRITE,
            Role.READ_ONLY,
        ]

    def test_secrets_are_not_in_the_repr(self) -> None:
        """So a config dump or traceback does not leak the room password."""
        assert "hunter2" not in repr(Passwords.model_validate({"admin": "hunter2"}))


class TestRoomSettings:
    def test_inherits_the_default_intervals(self) -> None:
        room = make_room()
        assert room.advert_flood_interval == 6 * 3600
        assert room.advert_local_interval == 30 * 60

    def test_rejects_both_key_sources(self) -> None:
        with pytest.raises(ValidationError, match="not both"):
            make_room(key_file="a.key", private_key="ab" * 32)

    def test_rejects_a_duplicate_member(self) -> None:
        with pytest.raises(ValidationError, match="listed twice"):
            make_room(
                members=[
                    {"pubkey": KEY_A, "role": "admin"},
                    {"pubkey": KEY_A, "role": "guest"},
                ]
            )

    def test_rejects_a_room_nobody_can_enter(self) -> None:
        """No members, no passwords, and reject-by-default is a mistake."""
        with pytest.raises(ValidationError, match="no client could ever log in"):
            RoomSettings.model_validate({"name": "Lobby"})

    @pytest.mark.parametrize(
        "reachable",
        [
            {"members": [{"pubkey": KEY_A, "role": "admin"}]},
            {"passwords": {"admin": "pw"}},
            {"allow_unknown": "guest"},
        ],
        ids=["a-member", "a-password", "open-policy"],
    )
    def test_any_one_route_in_is_enough(self, reachable: dict[str, object]) -> None:
        assert RoomSettings.model_validate({"name": "Lobby"} | reachable) is not None

    def test_location_needs_both_halves(self) -> None:
        with pytest.raises(ValidationError, match="must be set together"):
            make_room(latitude=51.5)

    def test_looks_up_a_member_role(self) -> None:
        room = make_room(members=[{"pubkey": KEY_A, "role": "admin"}])

        assert room.role_for_member(bytes.fromhex(KEY_A)) is Role.ADMIN
        assert room.role_for_member(bytes.fromhex(KEY_B)) is None

    def test_member_note_is_optional_and_free_text(self) -> None:
        member = Member.model_validate({"pubkey": KEY_A, "role": "admin", "note": "chris's phone"})
        assert member.note == "chris's phone"


class TestSettings:
    def test_requires_a_companion_section(self) -> None:
        """Nothing can run without a node; saying so beats a phantom default."""
        with pytest.raises(ValidationError, match="companion"):
            Settings.model_validate({"rooms": {"lobby": room_data()}})

    def test_requires_at_least_one_room(self) -> None:
        with pytest.raises(ValidationError, match="no rooms are configured"):
            make_settings()

    def test_rejects_duplicate_room_names(self) -> None:
        """Indistinguishable in an app, and the likely cause is 'name' in
        [defaults] applying to every room."""
        with pytest.raises(ValidationError, match="must be distinct"):
            make_settings(rooms={"lobby": room_data(name="Same"), "ops": room_data(name="Same")})

    def test_rejects_two_rooms_sharing_a_key_file(self) -> None:
        """Two state machines answering one destination hash corrupt each other."""
        with pytest.raises(ValidationError, match="share the same key_file"):
            make_settings(
                rooms={
                    "lobby": room_data(name="Lobby", key_file="shared.key"),
                    "ops": room_data(name="Ops", key_file="shared.key"),
                }
            )

    def test_rejects_two_rooms_sharing_a_private_key(self) -> None:
        with pytest.raises(ValidationError, match="share the same private_key"):
            make_settings(
                rooms={
                    "lobby": room_data(name="Lobby", private_key="ab" * 32),
                    "ops": room_data(name="Ops", private_key="ab" * 32),
                }
            )

    def test_distinct_identities_are_fine(self) -> None:
        settings = make_settings(
            rooms={
                "lobby": room_data(name="Lobby", key_file="lobby.key"),
                "ops": room_data(name="Ops", key_file="ops.key"),
            }
        )
        assert set(settings.rooms) == {"lobby", "ops"}

    def test_database_path_sits_under_the_data_dir(self) -> None:
        settings = make_settings(
            node={"data_dir": "/var/lib/meshelle"}, rooms={"lobby": room_data()}
        )
        assert settings.node.database_path == Path("/var/lib/meshelle/meshelle.db")

    def test_logging_defaults_to_stderr_text(self) -> None:
        """A file sink is opt-in. meshcore-pi's basicConfig(filename=...) is why
        raising its log level appears to do nothing."""
        log = LogSettings()
        assert log.file is None
        assert log.format.value == "text"
