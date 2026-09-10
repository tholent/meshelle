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

"""The wiring: does a configured meshelle actually host a room?

Phases 2-6 each tested one layer against fakes at its own boundary. Nothing
before this file proves that a config file plus a companion node produces a
room a client can log into, which is the only claim the project actually makes.

The tests here therefore run the **real** ``Application`` -- real database, real
migrations, real dispatcher, real room server -- against
:class:`tests.fakes.companion.FakeCompanion`, which speaks the node's side of
the companion protocol properly. Only two things are compressed: the protocol's
reply delays (injected :class:`Timings`, per the project's testing rules) and
the advert intervals, so an interval test does not cost its interval.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
from pathlib import Path
from typing import Any

import pytest

from meshelle.app import AppError, Application, make_transport_factory, plan_rooms, room_key_path
from meshelle.config.loader import load_settings
from meshelle.config.model import (
    CompanionSettings,
    RoomSettings,
    Settings,
    TransportKind,
)
from meshelle.mesh.scheduler import Timings
from meshelle.proto.constants import PayloadType, Permission
from meshelle.proto.identity import LocalIdentity, save_identity
from meshelle.proto.packet import Packet
from meshelle.store import repo
from meshelle.store.db import Store
from meshelle.store.migrate import head_revision
from tests.fakes.client import FakeClient, PathReceived, assert_login_grants
from tests.fakes.companion import DEFAULT_PUBLIC_KEY, FakeCompanion

STARTUP_TIMEOUT = 5.0
"""Any of these tests reaching this has hung, not been slow."""

FAST = Timings(
    server_response_delay=0.0,
    txt_ack_delay=0.0,
    reply_delay=0.0,
    push_notify_delay=0.0,
    sync_push_interval=0.02,
)
"""The protocol's delays, compressed. The ordering between them is exercised
against real values in the room tests; here they only slow the wiring down."""


def write_config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "room.toml"
    path.write_text(body, encoding="utf-8")
    return path


def minimal_config(**room_lines: str) -> str:
    extra = "\n".join(f"{key} = {value}" for key, value in room_lines.items())
    return f"""
[companion]
transport = "tcp"
host = "127.0.0.1"

[node]
data_dir = "data"

[room.lobby]
name = "Lobby"
allow_unknown = "read_write"
advert_flood_interval = "never"
advert_local_interval = "never"
{extra}
"""


def settings_for(tmp_path: Path, **room_overrides: Any) -> Settings:
    room: dict[str, Any] = {
        "name": "Lobby",
        "allow_unknown": "read_write",
        "advert_flood_interval": None,
        "advert_local_interval": None,
    }
    room.update(room_overrides)
    return Settings.model_validate(
        {
            "companion": {"transport": "tcp", "host": "127.0.0.1"},
            "node": {"data_dir": str(tmp_path / "data")},
            "rooms": {"lobby": room},
        }
    )


class TestTransportFactory:
    """The link reconnects by calling the factory again, so it must build anew."""

    def test_serial_factory_builds_a_fresh_transport_each_time(self) -> None:
        """A closed StreamTransport refuses to be reconnected.

        Handing the link one instance would make the first disconnect
        permanent, which is exactly what the reconnect supervisor exists to
        prevent.
        """
        factory = make_transport_factory(
            CompanionSettings(transport=TransportKind.SERIAL, port="/dev/ttyUSB0")
        )
        first, second = factory(), factory()
        assert first is not second
        assert first.description.startswith("serial /dev/ttyUSB0")

    def test_tcp_factory_carries_host_and_port(self) -> None:
        factory = make_transport_factory(
            CompanionSettings(transport=TransportKind.TCP, host="node.local", tcp_port=5123)
        )
        assert factory().description == "tcp node.local:5123"

    def test_ble_factory_does_not_need_bleak_to_be_installed(self) -> None:
        """Constructing must not import bleak; only connecting may.

        Otherwise a serial-only install cannot even parse a config that
        mentions BLE, and the "install the ble extra" message never gets shown.
        """
        factory = make_transport_factory(
            CompanionSettings(transport=TransportKind.BLE, address="AA:BB:CC:DD:EE:FF")
        )
        assert factory().description == "ble AA:BB:CC:DD:EE:FF"


class TestRoomKeyPaths:
    def test_a_room_without_a_key_file_gets_one_named_for_its_slug(self, tmp_path: Path) -> None:
        """Derived from the slug, which the config guarantees is unique.

        Two rooms therefore cannot land on one identity merely by both omitting
        ``key_file`` -- which would put two state machines on one destination
        hash (trap #12).
        """
        room = RoomSettings(name="Lobby", allow_unknown="read_write")  # type: ignore[arg-type]
        assert room_key_path("lobby", room, tmp_path) == tmp_path / "lobby.key"

    def test_an_explicit_key_file_is_relative_to_the_data_directory(self, tmp_path: Path) -> None:
        room = RoomSettings(
            name="Lobby",
            allow_unknown="read_write",  # type: ignore[arg-type]
            key_file=Path("keys/lobby.key"),
        )
        assert room_key_path("lobby", room, tmp_path) == tmp_path / "keys" / "lobby.key"

    def test_an_inline_private_key_has_no_file(self, tmp_path: Path) -> None:
        room = RoomSettings(
            name="Lobby",
            allow_unknown="read_write",  # type: ignore[arg-type]
            private_key=LocalIdentity.generate().private_key.hex(),
        )
        assert room_key_path("lobby", room, tmp_path) is None


class TestPlanRooms:
    def test_generates_a_key_file_and_reuses_it_next_time(self, tmp_path: Path) -> None:
        """A restart must not mint a new identity: clients hold the old one."""
        settings = settings_for(tmp_path)
        data_dir = tmp_path / "data"

        first = plan_rooms(settings, data_dir)
        assert first[0].created is True

        second = plan_rooms(settings, data_dir)
        assert second[0].created is False
        assert second[0].identity.public_key == first[0].identity.public_key

    def test_the_generated_key_file_is_not_readable_by_others(self, tmp_path: Path) -> None:
        plan_rooms(settings_for(tmp_path), tmp_path / "data")
        mode = (tmp_path / "data" / "lobby.key").stat().st_mode & 0o777
        assert mode == 0o600

    def test_refuses_two_rooms_resolving_to_one_key_file(self, tmp_path: Path) -> None:
        """The config validator only sees the literal values.

        Here ``ops`` names ``lobby.key`` explicitly and ``lobby`` arrives at the
        same path by default, so the collision is only visible after resolution
        -- and both rooms would answer for one destination hash.
        """
        settings = Settings.model_validate(
            {
                "companion": {"transport": "tcp", "host": "127.0.0.1"},
                "node": {"data_dir": str(tmp_path)},
                "rooms": {
                    "lobby": {"name": "Lobby", "allow_unknown": "read_write"},
                    "ops": {
                        "name": "Ops",
                        "allow_unknown": "read_write",
                        "key_file": "lobby.key",
                    },
                },
            }
        )
        with pytest.raises(AppError, match="both resolve to key file"):
            plan_rooms(settings, tmp_path)

    def test_refuses_two_rooms_resolving_to_one_public_key(self, tmp_path: Path) -> None:
        """A seed and its expanded form are different strings, one identity."""
        identity = LocalIdentity.generate()
        assert identity.seed is not None
        settings = Settings.model_validate(
            {
                "companion": {"transport": "tcp", "host": "127.0.0.1"},
                "node": {"data_dir": str(tmp_path)},
                "rooms": {
                    "lobby": {
                        "name": "Lobby",
                        "allow_unknown": "read_write",
                        "private_key": identity.seed.hex(),
                    },
                    "ops": {
                        "name": "Ops",
                        "allow_unknown": "read_write",
                        "private_key": identity.private_key.hex(),
                    },
                },
            }
        )
        with pytest.raises(AppError, match="same public key"):
            plan_rooms(settings, tmp_path)


class RunningApp:
    """An ``Application`` running in the background, with its fake node."""

    def __init__(self, app: Application, node: FakeCompanion) -> None:
        self.app = app
        self.node = node
        self.task: asyncio.Task[int] | None = None

    async def __aenter__(self) -> RunningApp:
        self.task = asyncio.create_task(self.app.run())
        async with asyncio.timeout(STARTUP_TIMEOUT):
            await self.app.wait_started()
            # Every room floods one advert as soon as the link is up, so this
            # is the point at which the node has finished its handshake. A
            # packet delivered before that is discarded by the handshake's own
            # frame reader -- exactly as it would be by real firmware -- and a
            # test that raced it would fail for the wrong reason.
            await self.node.wait_for_transmit(len(self.app.rooms))
        return self

    async def __aexit__(self, *_: object) -> None:
        assert self.task is not None
        if not self.task.done():
            self.app.request_stop()
        async with asyncio.timeout(STARTUP_TIMEOUT):
            await self.task

    @property
    def exit_code(self) -> int:
        assert self.task is not None
        return self.task.result()

    async def deliver(self, packet: Packet) -> None:
        self.node.deliver_packet(packet.encode())

    async def wait_for_transmit(self, count: int) -> None:
        async with asyncio.timeout(STARTUP_TIMEOUT):
            await self.node.wait_for_transmit(count)

    def transmitted(self) -> list[Packet]:
        return [Packet.decode(raw) for raw in self.node.transmitted_packets]

    def replies(self) -> list[Packet]:
        """Everything but the adverts.

        Every room floods one advert the moment it starts, so the first packet
        on the air is never the answer to whatever the test just sent.
        """
        return [p for p in self.transmitted() if p.payload_type is not PayloadType.ADVERT]


def build_app(
    tmp_path: Path,
    *,
    config_path: Path | None = None,
    node: FakeCompanion | None = None,
    settings: Settings | None = None,
    **room_overrides: Any,
) -> RunningApp:
    companion = node or FakeCompanion()
    resolved = settings or settings_for(tmp_path, **room_overrides)
    app = Application(
        resolved,
        config_path=config_path,
        transport_factory=lambda: companion,
        timings=FAST,
        # Signal handlers are process-global; installing them here would leave
        # the suite's SIGINT bound to a dead Application.
        handle_signals=False,
    )
    return RunningApp(app, companion)


class TestStartup:
    async def test_creates_and_migrates_the_database(self, tmp_path: Path) -> None:
        async with build_app(tmp_path):
            assert (tmp_path / "data" / "meshelle.db").exists()

        store = Store(tmp_path / "data" / "meshelle.db")
        try:
            rooms = await store.run(repo.list_rooms)
            version = await store.run(lambda s: repo.get_meta(s, "created_by"))
        finally:
            await store.aclose()

        assert [room.slug for room in rooms] == ["lobby"]
        assert version is not None
        assert head_revision() is not None

    async def test_a_room_advertises_itself_on_startup(self, tmp_path: Path) -> None:
        """The advert is how a client discovers the room at all.

        meshcore-pi sends its first advert before its link is up, so it is lost
        and the room stays invisible until the next interval hours later.
        """
        async with build_app(
            tmp_path, advert_flood_interval=3600, advert_local_interval=None
        ) as running:
            await running.wait_for_transmit(1)
            advert = running.transmitted()[0]

        assert advert.payload_type is PayloadType.ADVERT
        assert advert.route_type.is_flood

    async def test_stops_cleanly_and_reports_success(self, tmp_path: Path) -> None:
        async with build_app(tmp_path) as running:
            running.app.request_stop()
        assert running.exit_code == 0

    async def test_refuses_to_share_the_nodes_own_identity(self, tmp_path: Path) -> None:
        """Two state machines on one destination hash answer each other's mail.

        The config cannot catch this: the node's key is only known once it has
        answered the handshake.
        """
        node_identity = LocalIdentity.generate()
        key_file = tmp_path / "data" / "lobby.key"
        key_file.parent.mkdir(parents=True)
        save_identity(key_file, node_identity)

        node = FakeCompanion()
        node.config.public_key = node_identity.public_key

        running = build_app(tmp_path, node=node)
        # Run to completion rather than stopping it: the point is that meshelle
        # gives up on its own, without being asked.
        async with asyncio.timeout(STARTUP_TIMEOUT):
            assert await running.app.run() == 1


class TestOnTheAir:
    """One client, one node, the whole stack -- the claim the project makes."""

    async def test_a_client_logs_in_and_is_granted_a_permission(self, tmp_path: Path) -> None:
        """Byte 7 of the login response, end to end.

        Every layer below has been tested in isolation; this is the first proof
        that a *configured* meshelle grants a permission over a real node link.
        A zero here is the meshcore-pi bug: the room appears read-only in every
        app, with nothing in the logs to say so.
        """
        async with build_app(tmp_path) as running:
            client = FakeClient(running.app.identities["lobby"].public_key)

            await running.deliver(client.login(timestamp=1_800_000_000))
            await running.wait_for_transmit(2)

            # A flooded login is answered with a PATH carrying the response, so
            # the client learns the route here as well as its permission.
            reply = client.receive(running.replies()[0])

        assert isinstance(reply, PathReceived)
        assert_login_grants(reply.response, Permission.READ_WRITE)

    async def test_a_post_is_stored_and_acknowledged(self, tmp_path: Path) -> None:
        async with build_app(tmp_path) as running:
            client = FakeClient(running.app.identities["lobby"].public_key)

            await running.deliver(client.login(timestamp=1_800_000_000))
            await running.wait_for_transmit(2)
            client.receive(running.replies()[0])

            await running.deliver(client.post("hello room", timestamp=1_800_000_001))
            await running.wait_for_transmit(3)

        acked = [p for p in running.transmitted() if p.payload_type is PayloadType.ACK]
        assert acked, "the room never acknowledged the post"

        store = Store(tmp_path / "data" / "meshelle.db")
        try:
            rooms = await store.run(repo.list_rooms)
            posts = await store.run(lambda s: repo.recent_posts(s, rooms[0].id))
        finally:
            await store.aclose()
        assert [post.text for post in posts] == ["hello room"]


class TestReload:
    """SIGHUP re-resolves the ACL without disturbing anything else."""

    async def test_a_new_member_takes_effect_without_a_restart(self, tmp_path: Path) -> None:
        member = LocalIdentity.generate()
        config = write_config(tmp_path, minimal_config())
        settings = load_settings(config)
        async with build_app(tmp_path, config_path=config, settings=settings) as running:
            config.write_text(
                minimal_config()
                + f'\n[[room.lobby.member]]\npubkey = "{member.public_key.hex()}"\n'
                + 'role = "admin"\n',
                encoding="utf-8",
            )
            running.app.reload()

            room = running.app.settings.rooms["lobby"]
            assert room.role_for_member(member.public_key) is not None
            assert running.app.rooms["lobby"].settings.role_for_member(member.public_key)

    async def test_an_invalid_reload_is_refused_whole(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A typo in one section must not cost a room its ACL.

        The running configuration is kept in full rather than partially
        replaced: losing an ACL to an unrelated edit is the worst outcome of a
        routine change.
        """
        config = write_config(tmp_path, minimal_config())
        settings = load_settings(config)
        async with build_app(tmp_path, config_path=config, settings=settings) as running:
            before = running.app.settings
            config.write_text(minimal_config(nonsense='"boom"'), encoding="utf-8")

            with caplog.at_level(logging.ERROR):
                running.app.reload()

            assert running.app.settings is before
            assert "reload refused" in caplog.text

    async def test_a_new_room_is_reported_as_needing_a_restart(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Silently ignoring it would leave an operator waiting for a room."""
        config = write_config(tmp_path, minimal_config())
        settings = load_settings(config)
        async with build_app(tmp_path, config_path=config, settings=settings) as running:
            config.write_text(
                minimal_config() + '\n[room.ops]\nname = "Ops"\nallow_unknown = "read_only"\n',
                encoding="utf-8",
            )
            with caplog.at_level(logging.WARNING):
                running.app.reload()

            assert "ops" in caplog.text
            assert "restart" in caplog.text
            assert set(running.app.rooms) == {"lobby"}

    async def test_a_removed_room_keeps_running_and_says_so(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Dropping it mid-sync would abandon whatever it still owes its clients.

        The room stays up; the operator is told a restart is what stops it.
        """
        two_rooms = minimal_config() + '\n[room.ops]\nname = "Ops"\nallow_unknown = "read_only"\n'
        config = write_config(tmp_path, two_rooms)
        settings = load_settings(config)

        async with build_app(tmp_path, config_path=config, settings=settings) as running:
            config.write_text(minimal_config(), encoding="utf-8")
            with caplog.at_level(logging.WARNING):
                running.app.reload()

            assert set(running.app.rooms) == {"lobby", "ops"}

        assert "ops" in caplog.text
        assert "still running" in caplog.text

    async def test_a_changed_companion_is_named_rather_than_ignored(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The link is already open; only a restart can point it somewhere else."""
        config = write_config(tmp_path, minimal_config())
        settings = load_settings(config)

        async with build_app(tmp_path, config_path=config, settings=settings) as running:
            config.write_text(
                minimal_config().replace('host = "127.0.0.1"', 'host = "node.local"'),
                encoding="utf-8",
            )
            with caplog.at_level(logging.WARNING):
                running.app.reload()

        assert "companion settings changed" in caplog.text

    async def test_a_changed_room_identity_is_named_and_the_rest_applied(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The room is already on the air under the key it started with.

        Adopting a new one silently would leave every client addressing a
        destination hash nothing answers for.
        """
        config = write_config(tmp_path, minimal_config())
        settings = load_settings(config)

        async with build_app(tmp_path, config_path=config, settings=settings) as running:
            config.write_text(
                minimal_config(key_file='"other.key"', welcome='"Be kind."'),
                encoding="utf-8",
            )
            with caplog.at_level(logging.WARNING):
                running.app.reload()

            # The identity is untouched, but the reloadable half took effect.
            assert running.app.rooms["lobby"].settings.welcome == "Be kind."

        assert "identity changed" in caplog.text

    async def test_a_room_removed_then_restored_does_not_crash_the_reload(
        self, tmp_path: Path
    ) -> None:
        """Two reloads: the second sees a room the running settings no longer name.

        Looking it up unconditionally raises here, and this runs inside the
        reload task -- so a KeyError would take the whole process down over an
        edit that was undone.
        """
        ops = '\n[room.ops]\nname = "Ops"\nallow_unknown = "read_only"\n'
        config = write_config(tmp_path, minimal_config() + ops)
        settings = load_settings(config)

        async with build_app(tmp_path, config_path=config, settings=settings) as running:
            config.write_text(minimal_config(), encoding="utf-8")
            running.app.reload()

            config.write_text(minimal_config() + ops, encoding="utf-8")
            running.app.reload()

            assert "ops" in running.app.settings.rooms

    async def test_the_log_level_can_be_changed_by_a_reload(self, tmp_path: Path) -> None:
        """Turning on debug logging must not require dropping the rooms."""
        config = write_config(tmp_path, minimal_config())
        settings = load_settings(config)

        async with build_app(tmp_path, config_path=config, settings=settings) as running:
            config.write_text('[log]\nlevel = "debug"\n' + minimal_config(), encoding="utf-8")
            running.app.reload()

            assert logging.getLogger().level == logging.DEBUG

    async def test_reload_without_a_config_file_says_so(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        async with build_app(tmp_path) as running:
            with caplog.at_level(logging.WARNING):
                running.app.reload()
        assert "no file" in caplog.text


class LogWatcher(logging.Handler):
    """Waits for a log line to appear, without polling.

    ``caplog`` can only be inspected, so a test that wanted to know when a line
    was written would have to spin on ``asyncio.sleep(0)`` -- which passes for
    the wrong reason as soon as the loop happens to run enough turns.
    """

    def __init__(self, needle: str) -> None:
        super().__init__()
        self._needle = needle
        self.seen = asyncio.Event()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        message = record.getMessage()
        self.lines.append(message)
        if self._needle in message:
            self.seen.set()


class TestNodeIdentity:
    async def test_the_node_is_reported_once_it_answers(self, tmp_path: Path) -> None:
        """The first thing an operator needs when a room does not appear.

        Which node is this, on what frequency, at what power -- none of it is
        knowable from the config, because it lives in the node's own firmware.
        """
        watcher = LogWatcher("companion:")
        logger = logging.getLogger("meshelle.app")
        logger.addHandler(watcher)
        # Without this the record never reaches the handler: the effective level
        # comes from the root logger, which pytest leaves at WARNING.
        logger.setLevel(logging.INFO)
        try:
            async with build_app(tmp_path):
                async with asyncio.timeout(STARTUP_TIMEOUT):
                    await watcher.seen.wait()
        finally:
            logger.removeHandler(watcher)
            logger.setLevel(logging.NOTSET)

        summary = next(line for line in watcher.lines if "companion:" in line)
        assert DEFAULT_PUBLIC_KEY[:4].hex() in summary
        assert "869.618 MHz" in summary


class TestSignals:
    """SIGTERM stops, SIGHUP reloads. Both are the documented operator interface.

    The signals are raised for real, at this process, because the whole point is
    that the handlers are installed on the running loop -- a test that called
    ``request_stop`` directly would pass with no handler installed at all, and
    the first ``systemctl reload`` would be the thing that found out.
    """

    async def test_sigterm_stops_the_process_cleanly(self, tmp_path: Path) -> None:
        node = FakeCompanion()
        app = Application(
            settings_for(tmp_path),
            transport_factory=lambda: node,
            timings=FAST,
        )
        task = asyncio.create_task(app.run())
        async with asyncio.timeout(STARTUP_TIMEOUT):
            await app.wait_started()
            await node.wait_for_transmit(1)

            os.kill(os.getpid(), signal.SIGTERM)

            assert await task == 0

    async def test_sighup_reloads_the_acl(self, tmp_path: Path) -> None:
        member = LocalIdentity.generate()
        config = write_config(tmp_path, minimal_config())
        node = FakeCompanion()
        app = Application(
            load_settings(config),
            config_path=config,
            transport_factory=lambda: node,
            timings=FAST,
        )

        # Event-driven: the signal handler runs on the loop, so the reload has
        # not happened yet when os.kill returns.
        reloaded = LogWatcher("configuration reloaded")
        app_logger = logging.getLogger("meshelle.app")
        app_logger.addHandler(reloaded)
        app_logger.setLevel(logging.INFO)

        task = asyncio.create_task(app.run())
        try:
            async with asyncio.timeout(STARTUP_TIMEOUT):
                await app.wait_started()
                await node.wait_for_transmit(1)

                config.write_text(
                    minimal_config()
                    + f'\n[[room.lobby.member]]\npubkey = "{member.public_key.hex()}"\n'
                    + 'role = "admin"\n',
                    encoding="utf-8",
                )
                os.kill(os.getpid(), signal.SIGHUP)
                await reloaded.seen.wait()
        finally:
            app_logger.removeHandler(reloaded)
            app_logger.setLevel(logging.NOTSET)
            app.request_stop()
            async with asyncio.timeout(STARTUP_TIMEOUT):
                await task

        assert app.rooms["lobby"].settings.role_for_member(member.public_key) is not None
