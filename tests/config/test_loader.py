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

"""Loading, merging, and the error messages an operator actually sees."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from meshelle.config.loader import (
    ConfigError,
    build_settings,
    deep_merge,
    env_overrides,
    load_settings,
    read_config_file,
)
from meshelle.config.model import Role, TransportKind, UnknownPolicy

KEY_A = "a1" + "00" * 31

MINIMAL_TOML = """
[companion]
port = "/dev/ttyUSB0"

[room.lobby]
allow_unknown = "guest"
"""


def write_config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "meshelle.toml"
    path.write_text(text)
    return path


class TestDeepMerge:
    def test_overlay_wins_on_scalars(self) -> None:
        assert deep_merge({"a": 1}, {"a": 2}) == {"a": 2}

    def test_merges_nested_tables(self) -> None:
        merged = deep_merge({"x": {"a": 1, "b": 2}}, {"x": {"b": 3}})
        assert merged == {"x": {"a": 1, "b": 3}}

    def test_leaves_the_inputs_untouched(self) -> None:
        base = {"x": {"a": 1}}
        deep_merge(base, {"x": {"a": 2}})
        assert base == {"x": {"a": 1}}

    def test_lists_replace_rather_than_append(self) -> None:
        """Appending would make it impossible to *remove* a member via an
        override, and an ACL that silently grows is the worse failure."""
        merged = deep_merge({"members": [{"a": 1}]}, {"members": [{"b": 2}]})
        assert merged == {"members": [{"b": 2}]}

    def test_a_scalar_can_replace_a_table(self) -> None:
        assert deep_merge({"x": {"a": 1}}, {"x": "flat"}) == {"x": "flat"}


class TestEnvOverrides:
    def test_ignores_unprefixed_variables(self) -> None:
        assert env_overrides({"PATH": "/usr/bin", "HOME": "/root"}) == {}

    def test_maps_a_single_level(self) -> None:
        assert env_overrides({"MESHELLE_COMPANION__PORT": "/dev/ttyACM0"}) == {
            "companion": {"port": "/dev/ttyACM0"}
        }

    def test_single_underscores_stay_inside_names(self) -> None:
        """So baud_rate and data_dir are reachable at all."""
        assert env_overrides({"MESHELLE_COMPANION__BAUD_RATE": "9600"}) == {
            "companion": {"baud_rate": "9600"}
        }

    def test_reaches_into_a_room(self) -> None:
        assert env_overrides({"MESHELLE_ROOM__LOBBY__WELCOME": "hi"}) == {
            "room": {"lobby": {"welcome": "hi"}}
        }

    def test_merges_several_variables(self) -> None:
        overrides = env_overrides(
            {
                "MESHELLE_COMPANION__PORT": "/dev/ttyACM0",
                "MESHELLE_COMPANION__BAUD_RATE": "9600",
                "MESHELLE_LOG__LEVEL": "debug",
            }
        )
        assert overrides == {
            "companion": {"port": "/dev/ttyACM0", "baud_rate": "9600"},
            "log": {"level": "debug"},
        }

    def test_ignores_the_bare_prefix(self) -> None:
        assert env_overrides({"MESHELLE_": "nonsense"}) == {}


class TestPrecedence:
    def test_file_supplies_the_base(self) -> None:
        settings = build_settings(
            {"companion": {"port": "/dev/from-file"}, "room": {"lobby": {"allow_unknown": "guest"}}}
        )
        assert settings.companion.port == "/dev/from-file"

    def test_env_beats_the_file(self) -> None:
        settings = build_settings(
            {
                "companion": {"port": "/dev/from-file"},
                "room": {"lobby": {"allow_unknown": "guest"}},
            },
            environ={"MESHELLE_COMPANION__PORT": "/dev/from-env"},
        )
        assert settings.companion.port == "/dev/from-env"

    def test_cli_beats_env_and_file(self) -> None:
        settings = build_settings(
            {
                "companion": {"port": "/dev/from-file"},
                "room": {"lobby": {"allow_unknown": "guest"}},
            },
            environ={"MESHELLE_COMPANION__PORT": "/dev/from-env"},
            overrides={"companion": {"port": "/dev/from-cli"}},
        )
        assert settings.companion.port == "/dev/from-cli"

    def test_layers_combine_rather_than_replace_wholesale(self) -> None:
        """An override of one key must not discard its siblings."""
        settings = build_settings(
            {
                "companion": {"port": "/dev/from-file", "baud_rate": 9600},
                "room": {"lobby": {"allow_unknown": "guest"}},
            },
            overrides={"companion": {"port": "/dev/from-cli"}},
        )
        assert settings.companion.port == "/dev/from-cli"
        assert settings.companion.baud_rate == 9600

    def test_defaults_apply_where_nothing_sets_a_value(self) -> None:
        settings = build_settings(
            {"companion": {"port": "/dev/x"}, "room": {"lobby": {"allow_unknown": "guest"}}}
        )
        assert settings.log.level.value == "info"
        assert settings.node.data_dir == Path("data")


class TestFileShapes:
    def test_room_sections_become_the_rooms_mapping(self) -> None:
        settings = build_settings(
            {
                "companion": {"port": "/dev/x"},
                "room": {"lobby": {"allow_unknown": "guest"}, "ops": {"allow_unknown": "guest"}},
            }
        )
        assert set(settings.rooms) == {"lobby", "ops"}

    def test_member_arrays_become_members(self) -> None:
        """TOML spells an array of tables singular: [[room.lobby.member]]."""
        settings = build_settings(
            {
                "companion": {"port": "/dev/x"},
                "room": {"lobby": {"member": [{"pubkey": KEY_A, "role": "admin"}]}},
            }
        )
        assert settings.rooms["lobby"].members[0].role is Role.ADMIN

    def test_a_room_name_defaults_to_its_section_name(self) -> None:
        settings = build_settings(
            {"companion": {"port": "/dev/x"}, "room": {"lobby": {"allow_unknown": "guest"}}}
        )
        assert settings.rooms["lobby"].name == "lobby"

    def test_an_explicit_name_is_kept(self) -> None:
        settings = build_settings(
            {
                "companion": {"port": "/dev/x"},
                "room": {"lobby": {"name": "The Lobby", "allow_unknown": "guest"}},
            }
        )
        assert settings.rooms["lobby"].name == "The Lobby"

    def test_rejects_a_room_table_that_is_not_a_section(self) -> None:
        with pytest.raises(ConfigError, match="must be a section"):
            build_settings({"companion": {"port": "/dev/x"}, "room": {"lobby": "oops"}})

    def test_rejects_room_that_is_not_a_table(self) -> None:
        with pytest.raises(ConfigError, match="named room sections"):
            build_settings({"companion": {"port": "/dev/x"}, "room": "oops"})


class TestRoomDefaults:
    def test_defaults_are_inherited(self) -> None:
        settings = build_settings(
            {
                "companion": {"port": "/dev/x"},
                "defaults": {"allow_unknown": "read_write", "advert_flood_interval": "2h"},
                "room": {"lobby": {}, "ops": {}},
            }
        )
        for room in settings.rooms.values():
            assert room.allow_unknown is UnknownPolicy.READ_WRITE
            assert room.advert_flood_interval == 7200

    def test_a_room_overrides_the_default(self) -> None:
        settings = build_settings(
            {
                "companion": {"port": "/dev/x"},
                "defaults": {"allow_unknown": "read_write"},
                "room": {"lobby": {}, "ops": {"allow_unknown": "guest"}},
            }
        )
        assert settings.rooms["lobby"].allow_unknown is UnknownPolicy.READ_WRITE
        assert settings.rooms["ops"].allow_unknown is UnknownPolicy.GUEST

    def test_defaults_does_not_leak_into_the_top_level(self) -> None:
        """It is folded into rooms and removed, not passed to Settings."""
        settings = build_settings(
            {
                "companion": {"port": "/dev/x"},
                "defaults": {"allow_unknown": "guest"},
                "room": {"lobby": {}},
            }
        )
        assert not hasattr(settings, "defaults")

    def test_rejects_a_non_table_defaults(self) -> None:
        with pytest.raises(ConfigError, match=r"\[defaults\] must be a section"):
            build_settings(
                {"companion": {"port": "/dev/x"}, "defaults": "oops", "room": {"lobby": {}}}
            )

    def test_a_name_in_defaults_is_caught_as_duplicate_names(self) -> None:
        """Otherwise every room silently advertises the same name."""
        with pytest.raises(ConfigError, match="must be distinct"):
            build_settings(
                {
                    "companion": {"port": "/dev/x"},
                    "defaults": {"name": "Shared", "allow_unknown": "guest"},
                    "room": {"lobby": {}, "ops": {}},
                }
            )


class TestErrorMessages:
    def _error(self, data: dict[str, Any]) -> str:
        with pytest.raises(ConfigError) as excinfo:
            build_settings(data, source="meshelle.toml")
        return str(excinfo.value)

    def test_names_the_source_file(self) -> None:
        assert "meshelle.toml" in self._error({"companion": {"port": "/dev/x"}})

    def test_names_an_unknown_top_level_key(self) -> None:
        message = self._error(
            {"companion": {"port": "/dev/x"}, "room": {"lobby": {}}, "nonsense": 1}
        )
        assert "unknown key 'nonsense'" in message
        assert "top level" in message

    def test_suggests_the_nearest_key(self) -> None:
        """The fix for the whole class of bug: a near-miss spelling is reported
        with the key that was meant, instead of being silently ignored."""
        message = self._error(
            {"companion": {"prot": "/dev/x", "port": "/dev/x"}, "room": {"lobby": {}}}
        )
        assert "unknown key 'prot'" in message
        assert "Did you mean 'port'" in message

    def test_lists_valid_keys_when_nothing_is_close(self) -> None:
        message = self._error({"companion": {"port": "/dev/x", "zzzzzz": 1}, "room": {"lobby": {}}})
        assert "Valid keys here" in message
        assert "baud_rate" in message

    def test_uses_the_files_spelling_for_locations(self) -> None:
        """A message must never mention a key the user did not write: the file
        says 'room' and 'member', not 'rooms' and 'members'."""
        message = self._error(
            {
                "companion": {"port": "/dev/x"},
                "room": {"lobby": {"allow_unknown": "guest", "nonsense": 1}},
            }
        )
        assert "[room.lobby]" in message
        assert "[rooms.lobby]" not in message

    def test_points_at_member_entries_by_index(self) -> None:
        message = self._error(
            {
                "companion": {"port": "/dev/x"},
                "room": {
                    "lobby": {
                        "member": [
                            {"pubkey": KEY_A, "role": "admin"},
                            {"pubkey": "too-short", "role": "guest"},
                        ]
                    }
                },
            }
        )
        assert "room.lobby.member.[1].pubkey" in message

    @pytest.mark.parametrize(
        ("key", "expected"),
        [
            ("admin", "passwords.admin"),
            ("guest", "allow_unknown"),
            ("writer", "passwords.read_write"),
            ("readonly", "read_only"),
            ("advert", "advert_flood_interval"),
            ("privatekey", "private_key"),
        ],
    )
    def test_explains_meshcore_pi_keys(self, key: str, expected: str) -> None:
        """Someone porting a meshcore-pi config gets a pointer, not a dead end."""
        message = self._error(
            {
                "companion": {"port": "/dev/x"},
                "room": {"lobby": {"allow_unknown": "guest", key: "whatever"}},
            }
        )
        assert f"unknown key '{key}'" in message
        assert expected in message

    def test_reports_a_bad_value_with_its_location(self) -> None:
        message = self._error(
            {
                "companion": {"port": "/dev/x"},
                "room": {"lobby": {"allow_unknown": "guest", "advert_flood_interval": "soon"}},
            }
        )
        assert "room.lobby.advert_flood_interval" in message
        assert "is not a duration" in message

    def test_strips_pydantics_value_error_prefix(self) -> None:
        message = self._error(
            {"companion": {"port": "/dev/x"}, "room": {"lobby": {"latitude": 10.0}}}
        )
        assert "Value error," not in message
        assert "must be set together" in message

    def test_reports_several_problems_at_once(self) -> None:
        """An operator should not have to fix errors one restart at a time."""
        message = self._error(
            {
                "companion": {"port": "/dev/x", "bogus": 1},
                "room": {"lobby": {"allow_unknown": "guest", "alsobogus": 2}},
            }
        )
        assert "bogus" in message
        assert "alsobogus" in message


class TestReadConfigFile:
    def test_reads_valid_toml(self, tmp_path: Path) -> None:
        path = write_config(tmp_path, MINIMAL_TOML)
        assert read_config_file(path)["companion"]["port"] == "/dev/ttyUSB0"

    def test_reports_a_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="cannot read config file"):
            read_config_file(tmp_path / "absent.toml")

    def test_reports_invalid_toml(self, tmp_path: Path) -> None:
        path = write_config(tmp_path, "this is = = not toml")
        with pytest.raises(ConfigError, match="not valid TOML"):
            read_config_file(path)

    def test_reports_invalid_utf8(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.toml"
        path.write_bytes(b"port = '\xff\xfe'")
        with pytest.raises(ConfigError, match="not valid UTF-8"):
            read_config_file(path)


class TestLoadSettings:
    def test_loads_a_complete_config(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LOBBY_ADMIN_PW", "from-env-secret")
        secret_file = tmp_path / "rw.secret"
        secret_file.write_text("rw-secret\n")

        path = write_config(
            tmp_path,
            f"""
[companion]
transport = "tcp"
host = "node.local"

[node]
data_dir = "{tmp_path}/state"

[log]
level = "debug"

[defaults]
advert_flood_interval = "3h"
allow_unknown = "reject"

[room.lobby]
name = "The Lobby"
welcome = "Welcome!"
key_file = "lobby.key"
latitude = 51.5074
longitude = -0.1278
passwords = {{ admin = "env:LOBBY_ADMIN_PW", read_write = "file:{secret_file}" }}

[[room.lobby.member]]
pubkey = "{KEY_A}"
role = "admin"
note = "chris"

[room.ops]
name = "Ops"
key_file = "ops.key"
allow_unknown = "read_only"
advert_flood_interval = "never"
""",
        )

        settings = load_settings(path, environ={})

        assert settings.companion.transport is TransportKind.TCP
        assert settings.companion.host == "node.local"
        assert settings.log.level.value == "debug"
        assert settings.node.database_path == tmp_path / "state" / "meshelle.db"

        lobby = settings.rooms["lobby"]
        assert lobby.name == "The Lobby"
        assert lobby.advert_flood_interval == 3 * 3600, "inherited from [defaults]"
        assert lobby.latitude == pytest.approx(51.5074)
        assert lobby.members[0].note == "chris"
        assert lobby.passwords.admin is not None
        assert lobby.passwords.admin.get_secret_value() == "from-env-secret"
        assert lobby.passwords.read_write is not None
        assert lobby.passwords.read_write.get_secret_value() == "rw-secret"

        ops = settings.rooms["ops"]
        assert ops.allow_unknown is UnknownPolicy.READ_ONLY
        assert ops.advert_flood_interval is None, "'never' disables it entirely"

    def test_environment_overrides_the_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = write_config(tmp_path, MINIMAL_TOML)

        settings = load_settings(path, environ={"MESHELLE_LOG__LEVEL": "warning"})

        assert settings.log.level.value == "warning"

    def test_cli_overrides_everything(self, tmp_path: Path) -> None:
        path = write_config(tmp_path, MINIMAL_TOML)

        settings = load_settings(
            path,
            environ={"MESHELLE_COMPANION__PORT": "/dev/from-env"},
            overrides={"companion": {"port": "/dev/from-cli"}},
        )

        assert settings.companion.port == "/dev/from-cli"

    def test_loads_with_no_file_at_all(self) -> None:
        """Everything can come from the environment, for containerised runs."""
        settings = load_settings(
            None,
            environ={
                "MESHELLE_COMPANION__PORT": "/dev/ttyUSB0",
                "MESHELLE_ROOM__LOBBY__ALLOW_UNKNOWN": "guest",
            },
        )
        assert settings.rooms["lobby"].allow_unknown is UnknownPolicy.GUEST
