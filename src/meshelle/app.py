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

"""One process, one companion node, every configured room.

Phases 2-6 built parts that never construct each other. This is where they are
wired together, and the shape is fixed by what is shared and what is not:

* **one** :class:`~meshelle.store.db.Store` -- one SQLite file, one DB thread;
* **one** :class:`~meshelle.companion.link.CompanionLink` -- there is one radio;
* **one** :class:`~meshelle.mesh.dedupe.SeenTable` and one
  :class:`~meshelle.room.stats.RadioStats` -- both describe the *node*, not a
  room. A per-room seen-table would let one room reprocess a packet another
  room's reply had already put on the air;
* **one** :class:`~meshelle.mesh.scheduler.Scheduler` and one clock, so every
  delay in the process is measured on the same timeline;
* **one** :class:`~meshelle.room.server.RoomServer` per configured room, all
  behind a single :class:`~meshelle.mesh.dispatcher.Dispatcher`.

Everything then runs under one ``asyncio.TaskGroup``. That is what makes a
failure anywhere -- the serial port vanishing, a room raising -- stop the whole
process cleanly instead of leaving a half-live server that still answers logins
but never pushes a post. It is also trap #1: the group wraps a child's exception
in an ``ExceptionGroup``, so the failure is unwrapped with
:func:`~meshelle.companion.link.first_leaf` before it reaches the operator.

Signals:

* ``SIGTERM`` / ``SIGINT`` -- graceful shutdown.
* ``SIGHUP`` -- re-read the config file and re-resolve every ACL, **keeping
  sync cursors and live sessions**. A reload that dropped them would re-push
  every post in the room to everyone.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from meshelle import __version__
from meshelle.companion.link import CompanionInfo, CompanionLink, first_leaf
from meshelle.config.dotenv import DotenvError, DotenvResult, load_dotenv
from meshelle.config.loader import ConfigError, load_settings
from meshelle.config.model import (
    CompanionSettings,
    RoomSettings,
    Settings,
    TransportKind,
)
from meshelle.logs import configure_logging
from meshelle.mesh.clock import Clock, UniqueClock
from meshelle.mesh.dedupe import SeenTable
from meshelle.mesh.dispatcher import Dispatcher
from meshelle.mesh.scheduler import Scheduler, Timings
from meshelle.paths import anchor, config_base
from meshelle.proto.identity import LocalIdentity, load_or_create_identity
from meshelle.room.server import RoomServer
from meshelle.room.stats import RadioStats
from meshelle.store import repo
from meshelle.store.db import Store
from meshelle.store.migrate import upgrade_to_head
from meshelle.transport.base import Transport

logger = logging.getLogger(__name__)

DEFAULT_KEY_SUFFIX = ".key"
"""A room without an explicit ``key_file`` gets ``<slug>.key`` in the data dir.
Derived from the slug, which the config already guarantees is unique, so two
rooms cannot land on one identity by omission (trap #12)."""


class AppError(Exception):
    """The application cannot run as configured. The message is for the operator."""


@dataclass(frozen=True, slots=True)
class RoomPlan:
    """A room resolved down to the things the server needs to exist."""

    slug: str
    settings: RoomSettings
    identity: LocalIdentity
    key_path: Path | None
    """Where the key lives, or ``None`` when it was given inline as ``private_key``."""
    created: bool
    """Whether the key file was generated just now, so it is logged exactly once."""


# ---------------------------------------------------------------------------
# Resolving the configuration into objects
# ---------------------------------------------------------------------------


def make_transport_factory(companion: CompanionSettings) -> Callable[[], Transport]:
    """A factory the link calls on every (re)connect.

    A factory rather than an instance because reconnecting means opening a *new*
    transport: a closed ``StreamTransport`` refuses to be reused, and the whole
    point of the supervisor is to survive a node being unplugged.

    Imports are local so that a serial-only install never imports ``bleak``, and
    a BLE user gets the "install the extra" message from
    :class:`~meshelle.transport.ble.BleTransport` rather than at import time.
    """
    match companion.transport:
        case TransportKind.SERIAL:
            from meshelle.transport.serial import SerialTransport

            port = companion.port
            if port is None:  # pragma: no cover - the model requires it
                raise AppError("companion.port is required for the serial transport")
            baud = companion.baud_rate
            return lambda: SerialTransport(port, baud)

        case TransportKind.TCP:
            from meshelle.transport.tcp import TcpTransport

            host = companion.host
            if host is None:  # pragma: no cover - the model requires it
                raise AppError("companion.host is required for the tcp transport")
            tcp_port = companion.tcp_port
            return lambda: TcpTransport(host, tcp_port)

        case TransportKind.BLE:
            from meshelle.transport.ble import BleTransport

            address = companion.address
            if address is None:  # pragma: no cover - the model requires it
                raise AppError("companion.address is required for the ble transport")
            return lambda: BleTransport(address)


def room_key_path(slug: str, room: RoomSettings, data_dir: Path) -> Path | None:
    """Where a room's key file lives, or ``None`` if its key is inline.

    Separate from :func:`plan_rooms` because ``check-config`` and ``doctor`` need
    to *report* on a key file without creating one -- a diagnostic that generated
    an identity as a side effect would make "the key is missing" unobservable.
    """
    if room.private_key is not None:
        return None
    return anchor(room.key_file or Path(f"{slug}{DEFAULT_KEY_SUFFIX}"), data_dir)


def plan_rooms(settings: Settings, data_dir: Path) -> list[RoomPlan]:
    """Resolve every room's identity, generating key files that do not exist yet.

    Raises:
        AppError: two rooms resolved to the same key file or the same public
            key. The config validator catches the literal cases; this catches
            the ones only visible after resolution -- a default path colliding
            with another room's explicit ``key_file``, or a seed and its own
            expanded form given to two rooms as different-looking strings.
            Either way both rooms would answer for one destination hash.
    """
    plans: list[RoomPlan] = []
    by_key_path: dict[Path, str] = {}
    by_public_key: dict[bytes, str] = {}

    for slug, room in settings.rooms.items():
        path = room_key_path(slug, room, data_dir)
        if path is None:
            assert room.private_key is not None  # noqa: S101 - room_key_path's contract
            identity = LocalIdentity.from_hex(room.private_key)
            created = False
        else:
            resolved = path.resolve()
            if resolved in by_key_path:
                raise AppError(
                    f"rooms {by_key_path[resolved]!r} and {slug!r} both resolve to key file "
                    f"{path}. Each room needs its own identity, or both will answer for one "
                    f"destination hash and corrupt each other's state."
                )
            by_key_path[resolved] = slug
            identity, created = load_or_create_identity(path)

        if identity.public_key in by_public_key:
            raise AppError(
                f"rooms {by_public_key[identity.public_key]!r} and {slug!r} resolve to the "
                f"same public key {identity.public_key.hex()[:16]}…. Each room needs its own "
                f"identity; clients address both by the same destination hash."
            )
        by_public_key[identity.public_key] = slug

        plans.append(
            RoomPlan(
                slug=slug,
                settings=room,
                identity=identity,
                key_path=path,
                created=created,
            )
        )
    return plans


# ---------------------------------------------------------------------------
# The application
# ---------------------------------------------------------------------------


class Application:
    """Everything meshelle runs, for as long as it runs."""

    def __init__(
        self,
        settings: Settings,
        *,
        config_path: Path | None = None,
        overrides: Mapping[str, Any] | None = None,
        env_file: DotenvResult | None = None,
        transport_factory: Callable[[], Transport] | None = None,
        clock: Clock | None = None,
        timings: Timings | None = None,
        version: str = __version__,
        handle_signals: bool = True,
    ) -> None:
        self._settings = settings
        self._config_path = config_path
        self._overrides = dict(overrides) if overrides else {}
        self._env_file = env_file if env_file is not None else DotenvResult()
        self._base = config_base(config_path)
        self._clock: Clock = clock if clock is not None else UniqueClock()
        self._timings = timings if timings is not None else Timings()
        self._version = version
        self._handle_signals = handle_signals
        self._transport_factory = (
            transport_factory
            if transport_factory is not None
            else make_transport_factory(settings.companion)
        )

        self._rooms: dict[str, RoomServer] = {}
        self._identities: dict[str, LocalIdentity] = {}
        self._stop = asyncio.Event()
        self._reload_requested = asyncio.Event()
        self._started = asyncio.Event()

    # -- resolved locations --------------------------------------------------

    @property
    def data_dir(self) -> Path:
        return anchor(self._settings.node.data_dir, self._base)

    @property
    def database_path(self) -> Path:
        return anchor(self._settings.node.database_path, self._base)

    @property
    def rooms(self) -> Mapping[str, RoomServer]:
        """The live room servers, for tests and diagnostics."""
        return self._rooms

    @property
    def identities(self) -> Mapping[str, LocalIdentity]:
        """Each room's resolved identity, keyed by slug.

        Exposed because a room's public key is the one thing an operator needs
        to hand out and the one thing a log line abbreviates.
        """
        return self._identities

    @property
    def settings(self) -> Settings:
        """The configuration currently in effect, which a reload replaces."""
        return self._settings

    async def wait_started(self) -> None:
        """Block until every room is running. Only the tests need this."""
        await self._started.wait()

    # -- control -------------------------------------------------------------

    def request_stop(self) -> None:
        if self._stop.is_set():
            logger.info("already shutting down")
            return
        self._stop.set()

    def request_reload(self) -> None:
        self._reload_requested.set()

    # -- the run ------------------------------------------------------------

    async def run(self) -> int:
        """Host every configured room until stopped. Returns a process exit code."""
        plans = plan_rooms(self._settings, self.data_dir)
        for plan in plans:
            if plan.created:
                # Logged once, and loudly: this is the moment a room acquires
                # the identity every client will store in its contact list.
                logger.warning(
                    "room %s: generated a new identity %s in %s",
                    plan.slug,
                    plan.identity.public_key.hex(),
                    plan.key_path,
                )

        result = upgrade_to_head(self.database_path)
        logger.info("database %s: %s", self.database_path, result.describe())

        store = Store(self.database_path)
        try:
            await store.run(lambda s: repo.record_version(s, self._version))
            return await self._serve(store, plans)
        finally:
            await store.aclose()

    async def _serve(self, store: Store, plans: list[RoomPlan]) -> int:
        link = CompanionLink(self._transport_factory)
        radio = RadioStats(started_at=self._clock.monotonic())
        scheduler = Scheduler(self._clock)
        dispatcher = Dispatcher(link, [], seen=SeenTable(), radio=radio)

        for plan in plans:
            room_id = await _ensure_room_id(store, plan.slug, plan.identity.public_key)
            server = RoomServer(
                slug=plan.slug,
                settings=plan.settings,
                identity=plan.identity,
                room_id=room_id,
                store=store,
                sink=dispatcher,
                scheduler=scheduler,
                clock=self._clock,
                radio=radio,
                version=self._version,
                timings=self._timings,
            )
            # start() rehydrates known clients from the database, and has to run
            # before the push loop: a loop that started first would see no
            # sessions and idle while owed posts sat unsent.
            await server.start()
            dispatcher.add_room(server)
            self._rooms[plan.slug] = server
            self._identities[plan.slug] = plan.identity
            logger.info(
                "room %s (%s): key %s, hash 0x%02X",
                plan.slug,
                plan.settings.name,
                plan.identity.public_key.hex()[:16],
                plan.identity.node_hash,
            )

        # Held explicitly rather than passed inline, so shutdown can close the
        # async generator. A generator left to garbage collection is reported as
        # "async generator ignored GeneratorExit", which this project's
        # filterwarnings turns into a failure blamed on unrelated code.
        packets = link.packets()

        failure: BaseException | None = None
        with self._signal_handlers():
            try:
                async with asyncio.TaskGroup() as group:
                    tasks = [
                        group.create_task(link.run(), name="companion-link"),
                        group.create_task(dispatcher.run(packets), name="dispatcher"),
                        group.create_task(self._identify_node(link), name="node-identity"),
                        group.create_task(self._reload_loop(), name="reload"),
                    ]
                    for slug, server in self._rooms.items():
                        tasks.append(
                            group.create_task(server.run_push_loop(), name=f"push[{slug}]")
                        )
                        tasks.append(
                            group.create_task(server.run_advert_loop(), name=f"advert[{slug}]")
                        )

                    self._started.set()
                    logger.info("meshelle %s: %d room(s) running", self._version, len(self._rooms))

                    await self._stop.wait()
                    logger.info("shutting down")
                    # stop() first: it interrupts the link's reconnect backoff
                    # and closes the port, so the cancellation below is not
                    # racing an in-flight serial write.
                    await link.stop()
                    for task in tasks:
                        task.cancel()
            # TaskGroup wraps a child failure in an ExceptionGroup, so a plain
            # `except CompanionError` would not match it (trap #1).
            except* Exception as raised:
                failure = first_leaf(raised)
            finally:
                await scheduler.aclose()
                await packets.aclose()

        if failure is not None:
            logger.error("meshelle stopped: %s", failure)
            logger.debug("failure detail", exc_info=failure)
            return 1
        return 0

    @contextlib.contextmanager
    def _signal_handlers(self) -> Iterator[None]:
        """Install SIGTERM/SIGINT/SIGHUP for the life of the run.

        Removed on the way out, because they are process-global: a second
        ``Application`` in the same process would otherwise inherit handlers
        bound to the first one, which has already finished.
        """
        if not self._handle_signals:
            yield
            return

        loop = asyncio.get_running_loop()
        installed: list[signal.Signals] = []
        wanted = (
            (signal.SIGTERM, self.request_stop),
            (signal.SIGINT, self.request_stop),
            (signal.SIGHUP, self.request_reload),
        )
        for sig, handler in wanted:
            try:
                loop.add_signal_handler(sig, handler)
            except (NotImplementedError, RuntimeError, ValueError):  # pragma: no cover
                logger.debug("cannot install a handler for %s here", sig.name)
                continue
            installed.append(sig)
        try:
            yield
        finally:
            for sig in installed:
                with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
                    loop.remove_signal_handler(sig)

    async def _identify_node(self, link: CompanionLink) -> CompanionInfo:
        """Report the node, and refuse to share an identity with it.

        A room using the companion's own key would put two state machines on one
        destination hash: the node would answer logins meant for the room, and
        the room's replies would collide with the node's. The config cannot catch
        this because the node's key is only known once it has answered.
        """
        info = await link.wait_ready()
        logger.info("companion: %s", info.summary())

        for slug, identity in self._identities.items():
            if identity.public_key == info.public_key:
                raise AppError(
                    f"room {slug!r} uses the companion node's own public key "
                    f"{info.public_key.hex()[:16]}…. The node would answer for the room's "
                    f"destination hash as well. Give the room its own key file."
                )
        return info

    # -- reload --------------------------------------------------------------

    async def _reload_loop(self) -> None:
        while True:
            await self._reload_requested.wait()
            self._reload_requested.clear()
            self.reload()

    def reload(self) -> None:
        """Re-read the config file and adopt what can change at runtime.

        A reload that cannot be parsed or validated is **refused**, not applied
        in part: the running rooms keep the configuration they have. Losing a
        room's ACL because of a typo in an unrelated section would be the worst
        possible outcome of a routine edit.
        """
        if self._config_path is None:
            logger.warning("reload requested, but the configuration came from no file")
            return

        logger.info("reloading %s", self._config_path)
        try:
            env_file = self._reload_env_file()
            fresh = load_settings(
                self._config_path, overrides=self._overrides, env_sources=env_file.sources
            )
        except (ConfigError, DotenvError) as exc:
            logger.error("reload refused; keeping the running configuration:\n%s", exc)
            return

        self._env_file = env_file
        self._adopt(fresh)

    def _reload_env_file(self) -> DotenvResult:
        """Re-read the env file, if there was one, before re-reading the config.

        The variables this process took from the file last time are dropped
        first, so a rotated password takes effect and a *deleted* line actually
        revokes -- a value left behind in ``os.environ`` would keep an old
        password working for the life of the process, which is precisely the
        thing an operator reloads to stop.
        """
        if self._env_file.path is None:
            return self._env_file
        return load_dotenv(self._env_file.path, owned=self._env_file.applied)

    def _adopt(self, fresh: Settings) -> None:
        """Apply a validated configuration, naming everything it cannot change."""
        current = self._settings

        if fresh.companion != current.companion:
            logger.warning("companion settings changed; restart meshelle to use them")
        if fresh.node != current.node:
            logger.warning("node.data_dir changed; restart meshelle to use it")

        if fresh.log != current.log:
            configure_logging(fresh.log, base=self._base)
            logger.info("logging reconfigured to %s/%s", fresh.log.level, fresh.log.format)

        added = sorted(fresh.rooms.keys() - current.rooms.keys())
        removed = sorted(current.rooms.keys() - fresh.rooms.keys())
        if added:
            logger.warning("new room(s) %s need a restart to start hosting", ", ".join(added))
        if removed:
            # Left running on purpose: silently dropping a room mid-sync would
            # abandon whatever it still owes its clients.
            logger.warning(
                "room(s) %s were removed from the config but are still running; "
                "restart to stop hosting them",
                ", ".join(removed),
            )

        for slug, server in self._rooms.items():
            room = fresh.rooms.get(slug)
            if room is None:
                continue
            # .get, not [], because a room can be absent from the running
            # settings and present in the fresh ones: removing it and adding it
            # back over two reloads would otherwise raise here and, from inside
            # the reload task, take the whole process down with it.
            was = current.rooms.get(slug)
            if was is not None and (room.key_file, room.private_key) != (
                was.key_file,
                was.private_key,
            ):
                logger.warning(
                    "room %s: its identity changed in the config, which needs a restart. "
                    "Every other setting was applied.",
                    slug,
                )
            # Keeps sessions and sync cursors: only the declarative ACL and the
            # room's own knobs are re-resolved.
            server.apply_settings(room)

        self._settings = fresh
        logger.info("configuration reloaded")


async def _ensure_room_id(store: Store, slug: str, public_key: bytes) -> int:
    """The database id for a room, creating its row on first run.

    A free function taking its arguments by value, because a lambda closing over
    a loop variable would capture the last room for every iteration.
    """
    room = await store.run(lambda session: repo.ensure_room(session, slug, public_key))
    return room.id
