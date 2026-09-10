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

"""Clocks: wall time for the wire, monotonic time for scheduling.

Two clocks, deliberately separate, because they answer different questions and
one of them can jump:

* **Wall time** goes on the wire. Every MeshCore payload carries a 32-bit UTC
  timestamp, and clients compare ours against theirs.
* **Monotonic time** drives ACK timeouts and push intervals. An NTP step
  backwards during a sync must not make a pending ACK look freshly sent, nor
  make one time out instantly.

:class:`UniqueClock` reproduces the firmware's ``getCurrentTimeUnique``
(src/MeshCore.h:108): a strictly increasing wall clock. Two packets built in the
same second would otherwise carry the same timestamp, and since ``packet_hash``
covers the payload, identical timestamps mean identical hashes -- which every
repeater on the mesh suppresses as a duplicate, so the second packet never
arrives.

Waiting belongs here too. A loop that reads an injected clock but sleeps on the
real one is measuring one timeline and waiting on another: under a test clock it
would wait out a twelve-second timeout it had already stepped past. So
:meth:`Clock.sleep` is part of the same interface, and every wait in the room
server goes through it.

Both sources are injectable, so tests drive time directly instead of sleeping.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Protocol


class Clock(Protocol):
    """The time source a room server reads."""

    def now(self) -> int:
        """Wall-clock UTC seconds, as they go on the wire."""
        ...

    def unique_now(self) -> int:
        """Wall-clock seconds, guaranteed strictly greater than the last call."""
        ...

    def monotonic(self) -> float:
        """Seconds from an arbitrary origin, never decreasing."""
        ...

    async def sleep(self, seconds: float) -> None:
        """Wait, on the same timeline :meth:`monotonic` reports."""
        ...


class UniqueClock:
    """A :class:`Clock` whose ``unique_now`` never repeats or goes backwards.

    The high-water mark is per-instance and in memory only. Post timestamps --
    the ones that must survive a restart -- are deliberately *not* generated
    here: they come from ``repo.next_post_ts``, which derives them from the
    room's own maximum, so a restart cannot re-issue one.
    """

    __slots__ = ("_last_unique", "_monotonic", "_wall")

    def __init__(
        self,
        wall: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._wall = wall
        self._monotonic = monotonic
        self._last_unique = 0

    def now(self) -> int:
        return int(self._wall())

    def unique_now(self) -> int:
        current = self.now()
        # Step by one rather than returning `current` when the wall clock has
        # not advanced -- and also when it has gone *backwards*, which an NTP
        # correction can do. Either way the result is strictly increasing.
        self._last_unique = current if current > self._last_unique else self._last_unique + 1
        return self._last_unique

    def monotonic(self) -> float:
        return self._monotonic()

    async def sleep(self, seconds: float) -> None:
        if seconds > 0:
            await asyncio.sleep(seconds)
