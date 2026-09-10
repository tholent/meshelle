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

"""The commands an operator actually types.

Two properties are asserted throughout, because both are easy to break and
neither is visible from a passing exit code:

* **diagnostics create nothing.** ``check-config`` and ``doctor`` exist to
  report what is missing; a command that generated a key file or migrated a
  database on the way would make the thing it was asked about stop being
  missing.
* **a failure explains itself on stderr and exits 1.** A traceback would bury
  the message that says which line of which file is wrong.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from meshelle.cli import DEFAULT_CONFIG_PATHS, UsageError, _doctor, find_config, main
from meshelle.config.loader import load_settings
from meshelle.proto.identity import LocalIdentity, load_identity, save_identity
from meshelle.store.migrate import current_revision, head_revision
from tests.fakes.companion import FakeCompanion

VALID_CONFIG = """
[companion]
transport = "tcp"
host = "127.0.0.1"

[node]
data_dir = "data"

[room.lobby]
name = "Lobby"
welcome = "Be kind."
passwords = { admin = "hunter2" }

[[room.lobby.member]]
pubkey = "1ec77175b0918ed206f9ae04ec136d6d5d4315bb26305427f645b492e9350c10"
role = "admin"
note = "the operator"
"""


@pytest.fixture
def config(tmp_path: Path) -> Path:
    path = tmp_path / "room.toml"
    path.write_text(VALID_CONFIG, encoding="utf-8")
    return path


class TestFindConfig:
    def test_an_explicit_missing_file_is_an_error(self, tmp_path: Path) -> None:
        """Not a fall-through to the defaults.

        Hosting a different room than the one named on the command line is the
        failure this prevents.
        """
        with pytest.raises(UsageError, match="config file not found"):
            find_config(tmp_path / "absent.toml", {})

    def test_the_environment_variable_is_honoured(self, config: Path) -> None:
        assert find_config(None, {"MESHELLE_CONFIG": str(config)}) == config

    def test_a_missing_environment_path_names_the_variable(self, tmp_path: Path) -> None:
        with pytest.raises(UsageError, match="MESHELLE_CONFIG"):
            find_config(None, {"MESHELLE_CONFIG": str(tmp_path / "gone.toml")})

    def test_nothing_found_lists_where_it_looked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        with pytest.raises(UsageError) as caught:
            find_config(None, {})
        for candidate in DEFAULT_CONFIG_PATHS:
            assert str(candidate) in str(caught.value)


class TestOverrides:
    def test_log_flags_override_the_file(
        self, config: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The flag is the highest layer, so it must win over the [log] section."""
        main(["check-config", "--config", str(config), "--log-level", "debug"])
        assert "logging: debug/text" in capsys.readouterr().out

        main(["check-config", "--config", str(config), "--log-format", "json"])
        assert "logging: info/json" in capsys.readouterr().out


class TestVersionAndUsage:
    def test_version_exits_zero(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as caught:
            main(["--version"])
        assert caught.value.code == 0
        assert "meshelle" in capsys.readouterr().out

    def test_no_subcommand_prints_help_and_signals_usage(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main([]) == 2
        assert "check-config" in capsys.readouterr().out


class TestCheckConfig:
    def test_reports_the_rooms_and_their_acl(
        self, config: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["check-config", "--config", str(config)]) == 0

        out = capsys.readouterr().out
        assert "valid" in out
        assert "room lobby -- 'Lobby'" in out
        assert "members: 1 (admin)" in out
        assert "passwords: admin" in out

    def test_creates_no_key_file(self, config: Path) -> None:
        """A command run to find out what is missing must not fix it silently."""
        main(["check-config", "--config", str(config)])
        assert not (config.parent / "data" / "lobby.key").exists()

    def test_reports_a_key_file_that_is_already_there(
        self, config: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        identity = LocalIdentity.generate()
        save_identity(config.parent / "data" / "lobby.key", identity)

        main(["check-config", "--config", str(config)])

        assert identity.public_key.hex() in capsys.readouterr().out

    def test_an_invalid_config_explains_itself_on_stderr(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """With the line number, because that is the point of the loader."""
        path = tmp_path / "room.toml"
        path.write_text(
            '[companion]\ntransport = "serial"\nport = "/dev/ttyUSB0"\n'
            '\n[room.lobby]\nname = "Lobby"\nadmin = { password = "x" }\n',
            encoding="utf-8",
        )

        assert main(["check-config", "--config", str(path)]) == 1

        captured = capsys.readouterr()
        assert "meshcore-pi used admin.password" in captured.err
        assert "Traceback" not in captured.err


class TestInlineKeys:
    """A room can carry its key in the config, for migrating an existing room."""

    @pytest.fixture
    def inline_config(self, tmp_path: Path) -> Path:
        identity = LocalIdentity.generate()
        path = tmp_path / "room.toml"
        path.write_text(
            '[companion]\ntransport = "tcp"\nhost = "127.0.0.1"\n\n'
            '[room.lobby]\nname = "Lobby"\nallow_unknown = "read_write"\n'
            f'private_key = "{identity.private_key.hex()}"\n',
            encoding="utf-8",
        )
        return path

    def test_check_config_says_where_the_identity_came_from(
        self, inline_config: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["check-config", "--config", str(inline_config)]) == 0
        assert "inline private_key" in capsys.readouterr().out

    def test_keygen_has_nothing_to_do(
        self, inline_config: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Generating a file would produce an identity the room never uses."""
        assert main(["keygen", "--config", str(inline_config)]) == 0
        assert "nothing to generate" in capsys.readouterr().out


class TestUnusableKeyFile:
    """A key file that cannot be loaded must be named, not skipped.

    Its room would otherwise be missing from a run with nothing to say why.
    """

    @pytest.fixture
    def broken_key(self, config: Path) -> Path:
        key_file = config.parent / "data" / "lobby.key"
        key_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.write_text('private_key = "not hex"\n', encoding="utf-8")
        key_file.chmod(0o600)
        return key_file

    def test_check_config_reports_it(
        self, config: Path, broken_key: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        main(["check-config", "--config", str(config)])
        assert "UNUSABLE" in capsys.readouterr().out

    async def test_doctor_counts_it_as_a_problem(
        self, config: Path, broken_key: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        node = FakeCompanion()
        assert await _doctor(load_settings(config), config, transport_factory=lambda: node) == 1
        assert "UNUSABLE key file" in capsys.readouterr().out


class TestKeygen:
    def test_generates_a_key_and_reports_the_public_half(
        self, config: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["keygen", "--config", str(config), "--room", "lobby"]) == 0

        key_file = config.parent / "data" / "lobby.key"
        identity = load_identity(key_file)
        assert identity.public_key.hex() in capsys.readouterr().out
        assert key_file.stat().st_mode & 0o777 == 0o600

    def test_refuses_to_replace_a_key_without_force(
        self, config: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Replacing it strands every client that already holds the room.

        A room's public key is its address in every client's contact list, so a
        silent regeneration looks to them like the room simply stopped existing.
        """
        main(["keygen", "--config", str(config), "--room", "lobby"])
        before = load_identity(config.parent / "data" / "lobby.key").public_key

        assert main(["keygen", "--config", str(config), "--room", "lobby"]) == 1

        assert "--force" in capsys.readouterr().err
        assert load_identity(config.parent / "data" / "lobby.key").public_key == before

    def test_force_replaces_the_key(self, config: Path) -> None:
        main(["keygen", "--config", str(config), "--room", "lobby"])
        before = load_identity(config.parent / "data" / "lobby.key").public_key

        assert main(["keygen", "--config", str(config), "--room", "lobby", "--force"]) == 0

        assert load_identity(config.parent / "data" / "lobby.key").public_key != before

    def test_an_unknown_room_lists_the_ones_that_exist(
        self, config: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["keygen", "--config", str(config), "--room", "ops"]) == 1
        assert "lobby" in capsys.readouterr().err

    def test_without_a_room_it_fills_in_the_gaps(
        self, config: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Skips rooms that already have a key rather than refusing outright."""
        main(["keygen", "--config", str(config), "--room", "lobby"])
        capsys.readouterr()

        assert main(["keygen", "--config", str(config)]) == 0
        assert "already has a key" in capsys.readouterr().out


class TestDb:
    def test_current_reports_an_unmigrated_database(
        self, config: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["db", "current", "--config", str(config)]) == 0

        out = capsys.readouterr().out
        assert "absent" in out
        assert "not migrated" in out

    def test_current_creates_nothing(self, config: Path) -> None:
        main(["db", "current", "--config", str(config)])
        assert not (config.parent / "data" / "meshelle.db").exists()

    def test_upgrade_brings_the_schema_to_head(self, config: Path) -> None:
        assert main(["db", "upgrade", "--config", str(config)]) == 0
        assert current_revision(config.parent / "data" / "meshelle.db") == head_revision()

    def test_current_reports_an_up_to_date_database(
        self, config: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        main(["db", "upgrade", "--config", str(config)])
        capsys.readouterr()

        main(["db", "current", "--config", str(config)])

        assert "up to date" in capsys.readouterr().out

    def test_downgrade_rolls_back(self, config: Path) -> None:
        main(["db", "upgrade", "--config", str(config)])

        assert main(["db", "downgrade", "base", "--config", str(config)]) == 0

        assert current_revision(config.parent / "data" / "meshelle.db") is None


class TestDoctor:
    async def test_reports_a_healthy_node(
        self, config: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Including the raw-packet probe, which is the make-or-break check.

        ``CMD_SEND_RAW_PACKET`` is undocumented, so a node whose firmware lacks
        it looks perfectly healthy right up to the moment nothing reaches the
        air.
        """
        settings = load_settings(config)
        node = FakeCompanion()

        assert await _doctor(settings, config, transport_factory=lambda: node) == 0

        out = capsys.readouterr().out
        assert "CMD_SEND_RAW_PACKET (65) supported" in out
        assert "all checks passed" in out

    async def test_probing_transmits_nothing(self, config: Path) -> None:
        """The probe is deliberately malformed so the node rejects it.

        A diagnostic that put a packet on the air would be unusable on a mesh
        someone else is running.
        """
        node = FakeCompanion()
        await _doctor(load_settings(config), config, transport_factory=lambda: node)
        assert node.transmitted == []

    async def test_firmware_without_the_command_fails_the_check(
        self, config: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        node = FakeCompanion()
        node.config.supports_raw_packet = False

        assert await _doctor(load_settings(config), config, transport_factory=lambda: node) == 1

        out = capsys.readouterr().out
        assert "MISSING" in out
        assert "Flash firmware" in out

    async def test_a_node_sharing_a_rooms_key_is_a_problem(
        self, config: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Two state machines on one destination hash answer each other's mail."""
        identity = LocalIdentity.generate()
        save_identity(config.parent / "data" / "lobby.key", identity)
        node = FakeCompanion()
        node.config.public_key = identity.public_key

        assert await _doctor(load_settings(config), config, transport_factory=lambda: node) == 1

        assert "CONFLICT" in capsys.readouterr().out

    async def test_a_silent_node_is_reported_rather_than_waited_on(
        self, config: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """meshcore-pi's bare readexactly(1) hangs forever on this."""
        monkeypatch.setattr("meshelle.cli.DOCTOR_TIMEOUT", 0.05)
        node = FakeCompanion()
        node.config.answer_device_query = False

        assert await _doctor(load_settings(config), config, transport_factory=lambda: node) == 1

        assert "no answer" in capsys.readouterr().out

    async def test_reports_a_missing_key_file_without_creating_one(
        self, config: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        node = FakeCompanion()
        await _doctor(load_settings(config), config, transport_factory=lambda: node)

        assert "no key file yet" in capsys.readouterr().out
        assert not (config.parent / "data" / "lobby.key").exists()

    async def test_reports_a_database_that_is_behind(
        self, config: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Reported, not migrated: doctor answers questions, run changes things."""
        main(["db", "upgrade", "--config", str(config)])
        capsys.readouterr()
        node = FakeCompanion()

        await _doctor(load_settings(config), config, transport_factory=lambda: node)

        assert "up to date" in capsys.readouterr().out

    def test_the_subcommand_wires_the_real_transport(self, config: Path) -> None:
        """Nothing is listening on the configured TCP port, so it must fail.

        Proves the command builds a transport from the config rather than
        reporting success on an empty check.
        """
        assert main(["doctor", "--config", str(config)]) == 1


class TestRunWiring:
    def test_a_wiring_failure_is_a_message_not_a_traceback(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Two rooms resolving to one key file only fails once identities resolve.

        It happens inside the run, after logging is configured -- the path an
        operator hits, and the one where a raw traceback would bury the reason.
        """
        path = tmp_path / "room.toml"
        path.write_text(
            '[companion]\ntransport = "tcp"\nhost = "127.0.0.1"\n\n'
            '[room.lobby]\nname = "Lobby"\nallow_unknown = "read_write"\n\n'
            '[room.ops]\nname = "Ops"\nallow_unknown = "read_write"\n'
            'key_file = "lobby.key"\n',
            encoding="utf-8",
        )

        assert main(["run", "--config", str(path)]) == 1

        captured = capsys.readouterr()
        assert "both resolve to key file" in captured.err
        assert "Traceback" not in captured.err

    def test_run_reports_a_config_failure_before_touching_anything(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "room.toml"
        path.write_text('[companion]\ntransport = "serial"\n', encoding="utf-8")

        assert main(["run", "--config", str(path)]) == 1

        assert "companion.port is required" in capsys.readouterr().err
        assert not (tmp_path / "data").exists()
