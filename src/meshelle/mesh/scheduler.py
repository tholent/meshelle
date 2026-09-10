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

"""Delayed work, and the delays the room protocol is built from.

MeshCore servers do not reply immediately. ``sendDirect(reply, path, len,
SERVER_RESPONSE_DELAY)`` hands the packet to the radio queue with a delay
attached, because a client that has just transmitted is still switching its
radio back to receive: a reply that arrives too soon is simply not heard.

meshelle has no radio queue of its own -- the companion owns that -- so the
delay is applied here, by scheduling the send rather than awaiting it inline.
Awaiting inline would stall the receive loop for the whole delay, during which
every other packet in earshot would be dropped.

:class:`Timings` gathers every protocol delay in one injectable object so tests
can compress the clock to milliseconds instead of waiting out a 12-second flood
ACK timeout.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from meshelle.mesh.clock import Clock, UniqueClock
from meshelle.proto.constants import (
    MAX_PUSH_FAILURES,
    POST_SYNC_DELAY_SECS,
    PUSH_ACK_TIMEOUT_FACTOR_MILLIS,
    PUSH_ACK_TIMEOUT_FLOOD_MILLIS,
    PUSH_NOTIFY_DELAY_MILLIS,
    PUSH_TIMEOUT_BASE_MILLIS,
    REPLY_DELAY_MILLIS,
    SERVER_RESPONSE_DELAY_MILLIS,
    SYNC_PUSH_INTERVAL_MILLIS,
    TXT_ACK_DELAY_MILLIS,
)

logger = logging.getLogger(__name__)

IDLE_PUSH_DIVISOR = 8
"""When a client had nothing owed, poll the next one at ``interval / 8``.
Firmware's ``next_push = futureMillis(SYNC_PUSH_INTERVAL / 8)`` -- an idle
round-robin should not take 1.2 seconds per client to get back to a busy one."""


@dataclass(frozen=True, slots=True)
class Timings:
    """Every protocol delay, in **seconds**.

    The wire constants are milliseconds; they are converted once, here, so no
    call site has to remember which unit it is holding.
    """

    server_response_delay: float = SERVER_RESPONSE_DELAY_MILLIS / 1000
    """Before a REQ/ANON_REQ reply goes out."""
    txt_ack_delay: float = TXT_ACK_DELAY_MILLIS / 1000
    """Before the ACK for a received post."""
    reply_delay: float = REPLY_DELAY_MILLIS / 1000
    """Added on top of the ACK delay before a CLI reply, so the ACK lands first."""
    push_notify_delay: float = PUSH_NOTIFY_DELAY_MILLIS / 1000
    """Pushes pause this long after a login reply or a new post."""
    sync_push_interval: float = SYNC_PUSH_INTERVAL_MILLIS / 1000
    """Between push attempts, one client at a time."""
    push_ack_timeout_flood: float = PUSH_ACK_TIMEOUT_FLOOD_MILLIS / 1000
    """A flooded push has to cross the mesh twice; give it much longer."""
    push_timeout_base: float = PUSH_TIMEOUT_BASE_MILLIS / 1000
    push_ack_timeout_factor: float = PUSH_ACK_TIMEOUT_FACTOR_MILLIS / 1000
    """Direct push timeout is ``base + factor * (hops + 1)``."""
    post_sync_delay: int = POST_SYNC_DELAY_SECS
    """Seconds a post is held before it may be pushed, so the author's ACK
    arrives before we start talking to the author again. Whole seconds because
    it is compared against wall-clock post timestamps, not the monotonic clock."""
    max_push_failures: int = MAX_PUSH_FAILURES
    """Consecutive unacknowledged pushes before a client is left alone."""

    def push_ack_timeout(self, *, is_flood: bool, hop_count: int) -> float:
        """How long to wait for a push ACK (MyMesh.cpp:95-102)."""
        if is_flood:
            return self.push_ack_timeout_flood
        return self.push_timeout_base + self.push_ack_timeout_factor * (hop_count + 1)

    @property
    def idle_push_interval(self) -> float:
        return self.sync_push_interval / IDLE_PUSH_DIVISOR


class Scheduler:
    """Runs callables after a delay, without blocking the caller.

    Every scheduled job is tracked, so :meth:`aclose` can cancel outstanding
    work at shutdown rather than leaving tasks to be garbage-collected -- which
    asyncio reports as "Task was destroyed but it is pending!" and, under this
    project's ``filterwarnings = ["error"]``, fails whichever test runs next.

    Waiting goes through the injected clock, not ``asyncio.sleep`` directly, so
    a scheduled reply is on the same timeline as the ACK timeouts it is paced
    against. A test can then drive the real protocol delays instead of zeroing
    them, which is the only way the ordering between them is actually exercised.
    """

    __slots__ = ("_clock", "_closed", "_tasks")

    def __init__(self, clock: Clock | None = None) -> None:
        self._clock = clock if clock is not None else UniqueClock()
        self._tasks: set[asyncio.Task[None]] = set()
        self._closed = False

    def call_later(
        self,
        delay: float,
        work: Callable[[], Awaitable[None]],
        *,
        description: str = "scheduled work",
    ) -> None:
        """Run ``work`` after ``delay`` seconds. Never raises into the caller."""
        if self._closed:
            logger.debug("scheduler is closed; dropping %s", description)
            return
        task = asyncio.create_task(self._run_later(delay, work, description), name=description)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _run_later(
        self, delay: float, work: Callable[[], Awaitable[None]], description: str
    ) -> None:
        await self._clock.sleep(delay)
        try:
            await work()
        except asyncio.CancelledError:
            raise
        except Exception:
            # One failed reply must not take the room down. The traceback is
            # logged because nothing else will ever see this exception.
            logger.exception("scheduled %s failed", description)

    @property
    def pending(self) -> int:
        return len(self._tasks)

    async def aclose(self) -> None:
        """Cancel every outstanding job and wait for it to finish unwinding."""
        self._closed = True
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
