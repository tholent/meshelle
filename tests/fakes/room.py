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

"""Harness for driving a room server without a radio, a node, or real time.

Three pieces, each replacing something the room server would otherwise have to
wait for:

* :class:`ManualClock` -- both clocks the server reads, stepped by the test.
  Nothing here sleeps for a timeout; the test moves the clock instead.
* :class:`CapturingSink` -- stands in for the dispatcher, recording what would
  have gone on the air so a test can assert on the actual packets.
* :func:`drain` -- runs the scheduler's queued sends to completion. Every reply
  is scheduled rather than sent inline, so without this a test would assert on
  an empty sink and pass for the wrong reason.

The room runs against its **real** protocol delays here, not zeroed ones: the
scheduler waits through :class:`ManualClock` too, so a 1.5-second reply delay
costs a test nothing while still being the delay under test.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from meshelle.companion.link import ReceivedPacket
from meshelle.config.model import RoomSettings
from meshelle.mesh.scheduler import Scheduler, Timings
from meshelle.proto.constants import PayloadType
from meshelle.proto.identity import LocalIdentity
from meshelle.proto.packet import Packet
from meshelle.room.server import RoomServer
from meshelle.room.stats import RadioStats
from meshelle.store import repo
from meshelle.store.db import Store

EPOCH = 1_800_000_000
"""An arbitrary but fixed wall-clock start, so timestamps in failures are stable."""

DRAIN_TURNS = 200
"""Event-loop turns :func:`drain` will spend before declaring the scheduler stuck."""


class ManualClock:
    """A clock the test moves. Satisfies :class:`meshelle.mesh.clock.Clock`."""

    def __init__(self, wall: int = EPOCH, monotonic: float = 1000.0) -> None:
        self._wall = wall
        self._monotonic = monotonic
        self._last_unique = 0
        self.sleeps: list[float] = []
        """Every wait the room has asked for, in order."""
        self._slept = asyncio.Event()

    def now(self) -> int:
        return self._wall

    def unique_now(self) -> int:
        self._last_unique = self._wall if self._wall > self._last_unique else self._last_unique + 1
        return self._last_unique

    def monotonic(self) -> float:
        return self._monotonic

    def advance(self, seconds: float) -> None:
        """Move both clocks together, as real time does."""
        self._wall += int(seconds)
        self._monotonic += seconds

    async def wait_for_sleeps(self, count: int) -> None:
        """Block until the room has waited ``count`` times."""
        while len(self.sleeps) < count:
            self._slept.clear()
            await self._slept.wait()

    def advance_monotonic(self, seconds: float) -> None:
        """Move only the monotonic clock, to step past a timeout."""
        self._monotonic += seconds

    async def sleep(self, seconds: float) -> None:
        """Skip straight to the far end of the wait, and count the sleeps.

        A room loop waiting on real time would make every interval test take as
        long as the interval. Recording the durations also lets a test assert on
        the *pacing* -- that an idle round-robin polls faster than a busy one --
        which is otherwise invisible.
        """
        self.sleeps.append(seconds)
        self.advance(seconds)
        self._slept.set()
        await asyncio.sleep(0)


@dataclass
class CapturingSink:
    """Records what the room asked to transmit."""

    sent: list[Packet] = field(default_factory=list)
    descriptions: list[str] = field(default_factory=list)
    _arrived: asyncio.Event = field(default_factory=asyncio.Event)

    async def send(
        self,
        packet: Packet,
        *,
        priority: int = 0,
        ttl: float | None = None,
        description: str = "packet",
    ) -> None:
        self.sent.append(packet)
        self.descriptions.append(description)
        self._arrived.set()

    async def wait_for(self, count: int) -> None:
        """Block until ``count`` packets have been transmitted.

        An event rather than a polling sleep, so a loop that never transmits
        fails on the caller's timeout instead of silently passing after enough
        turns of the event loop.
        """
        while len(self.sent) < count:
            self._arrived.clear()
            await self._arrived.wait()

    def clear(self) -> None:
        self.sent.clear()
        self.descriptions.clear()

    def of_type(self, payload_type: PayloadType) -> list[Packet]:
        return [p for p in self.sent if p.payload_type is payload_type]

    @property
    def last(self) -> Packet:
        if not self.sent:
            raise AssertionError("nothing was transmitted")
        return self.sent[-1]


async def drain(scheduler: Scheduler) -> None:
    """Let every scheduled send run.

    Bounded, because a scheduler that never empties means a job is awaiting
    something the test never provides -- and a bare ``while pending`` would hang
    the suite rather than pointing at it.
    """
    for _ in range(DRAIN_TURNS):
        if not scheduler.pending:
            return
        await asyncio.sleep(0)
    raise AssertionError(f"scheduler still has {scheduler.pending} job(s) after draining")


@dataclass
class RoomHarness:
    """A room server plus everything needed to poke at it."""

    server: RoomServer
    identity: LocalIdentity
    clock: ManualClock
    sink: CapturingSink
    scheduler: Scheduler
    store: Store
    settings: RoomSettings
    room_id: int

    async def deliver(self, packet: Packet) -> bool:
        """Hand the room a packet and let any reply it schedules go out."""
        claimed = await self.server.handle(packet, ReceivedPacket(raw=b"", snr=8.0, rssi=-70))
        await drain(self.scheduler)
        return claimed

    async def aclose(self) -> None:
        await self.scheduler.aclose()


async def build_room(
    store: Store,
    settings: RoomSettings,
    *,
    slug: str = "lobby",
    identity: LocalIdentity | None = None,
    clock: ManualClock | None = None,
    timings: Timings | None = None,
) -> RoomHarness:
    """Create a room server backed by a real database and a fake radio."""
    identity = identity or LocalIdentity.generate()
    clock = clock or ManualClock()
    sink = CapturingSink()
    scheduler = Scheduler(clock)

    room = await store.run(lambda s: repo.ensure_room(s, slug, identity.public_key, now=EPOCH))
    server = RoomServer(
        slug=slug,
        settings=settings,
        identity=identity,
        room_id=room.id,
        store=store,
        sink=sink,
        scheduler=scheduler,
        clock=clock,
        radio=RadioStats(started_at=clock.monotonic()),
        version="0.0.0-test",
        timings=timings if timings is not None else Timings(),
    )
    await server.start()
    return RoomHarness(
        server=server,
        identity=identity,
        clock=clock,
        sink=sink,
        scheduler=scheduler,
        store=store,
        settings=settings,
        room_id=room.id,
    )


def room_settings(**overrides: object) -> RoomSettings:
    """A minimal valid room, with only what a test cares about spelled out."""
    values: dict[str, object] = {"name": "Lobby", "allow_unknown": "read_write"}
    values.update(overrides)
    return RoomSettings.model_validate(values)
