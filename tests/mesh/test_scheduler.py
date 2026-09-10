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

"""Delayed sends: they must happen, must not block, and must not leak."""

from __future__ import annotations

import asyncio

import pytest

from meshelle.mesh.scheduler import Scheduler, Timings
from meshelle.proto.constants import (
    PUSH_ACK_TIMEOUT_FLOOD_MILLIS,
    SERVER_RESPONSE_DELAY_MILLIS,
)


async def test_work_runs_after_the_delay_without_blocking_the_caller() -> None:
    """The receive loop must keep running while a reply waits its turn.

    Protocol semantics: a reply sent immediately is not heard, because the
    client is still switching its radio back to receive. Awaiting that delay
    inline would drop every other packet in earshot for its duration.
    """
    scheduler = Scheduler()
    done = asyncio.Event()

    scheduler.call_later(0.0, lambda: _set(done))

    assert not done.is_set()  # call_later returned before the work ran
    await asyncio.wait_for(done.wait(), timeout=1.0)


async def test_a_failing_job_does_not_take_the_room_down() -> None:
    """One reply that cannot be built must not stop the next one."""
    scheduler = Scheduler()
    survived = asyncio.Event()

    scheduler.call_later(0.0, _boom)
    scheduler.call_later(0.0, lambda: _set(survived))

    await asyncio.wait_for(survived.wait(), timeout=1.0)
    await scheduler.aclose()


async def test_close_cancels_outstanding_work() -> None:
    """A pending task left to garbage collection is reported by asyncio as
    "Task was destroyed but it is pending!", which this project's
    ``filterwarnings = ["error"]`` turns into a failure in an unrelated test."""
    scheduler = Scheduler()
    never = asyncio.Event()

    scheduler.call_later(30.0, lambda: _set(never))
    assert scheduler.pending == 1

    await scheduler.aclose()

    assert scheduler.pending == 0
    assert not never.is_set()


async def test_a_closed_scheduler_accepts_no_new_work() -> None:
    scheduler = Scheduler()
    await scheduler.aclose()
    ran = asyncio.Event()

    scheduler.call_later(0.0, lambda: _set(ran))
    await asyncio.sleep(0)

    assert not ran.is_set()


def test_flood_push_timeout_ignores_hop_count() -> None:
    """Protocol semantics (MyMesh.cpp:95): a flooded push has to cross the mesh
    and be answered across it, so it gets one long fixed timeout rather than one
    scaled by a path length we do not have."""
    timings = Timings()

    assert timings.push_ack_timeout(is_flood=True, hop_count=0) == pytest.approx(
        PUSH_ACK_TIMEOUT_FLOOD_MILLIS / 1000
    )
    assert timings.push_ack_timeout(is_flood=True, hop_count=5) == pytest.approx(
        PUSH_ACK_TIMEOUT_FLOOD_MILLIS / 1000
    )


def test_direct_push_timeout_scales_with_the_path() -> None:
    """``base + factor * (hops + 1)`` (MyMesh.cpp:100). The +1 counts the final
    hop to the client, which is not in the stored path."""
    timings = Timings()

    zero_hop = timings.push_ack_timeout(is_flood=False, hop_count=0)
    three_hop = timings.push_ack_timeout(is_flood=False, hop_count=3)

    assert zero_hop == pytest.approx(4.0 + 2.0)
    assert three_hop == pytest.approx(4.0 + 2.0 * 4)


def test_timings_are_seconds_not_milliseconds() -> None:
    """The wire constants are milliseconds; everything above this is seconds.
    Mixing them up would make every delay a thousand times too long."""
    assert Timings().server_response_delay == pytest.approx(SERVER_RESPONSE_DELAY_MILLIS / 1000)


def test_idle_polling_is_faster_than_a_real_push() -> None:
    """Firmware polls the next client at ``SYNC_PUSH_INTERVAL / 8`` when the
    current one had nothing owed, so an idle room does not take more than a
    second per client to reach one that is waiting."""
    timings = Timings()

    assert timings.idle_push_interval == pytest.approx(timings.sync_push_interval / 8)


async def _set(event: asyncio.Event) -> None:
    event.set()


async def _boom() -> None:
    raise RuntimeError("a reply that could not be built")
