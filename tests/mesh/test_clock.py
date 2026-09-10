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

"""Clock behaviour that the wire protocol depends on."""

from __future__ import annotations

from meshelle.mesh.clock import UniqueClock


def test_unique_now_never_repeats_within_a_second() -> None:
    """Two packets built in one second must not share a timestamp.

    ``packet_hash`` covers the payload, and the timestamp is in the payload, so
    identical timestamps produce identical hashes -- which every repeater
    suppresses as a duplicate. The second packet would simply never arrive.
    """
    frozen = UniqueClock(wall=lambda: 1_700_000_000.0)

    stamps = [frozen.unique_now() for _ in range(5)]

    assert stamps == [1_700_000_000 + n for n in range(5)]


def test_unique_now_survives_a_clock_step_backwards() -> None:
    """An NTP correction must not let a timestamp be reissued.

    Protocol semantics: a client uses our timestamps to order what it receives,
    and firmware's replay guards compare timestamps for monotonicity. A repeated
    value looks like a replay to the peer.
    """
    wall = [1_700_000_100.0]
    clock = UniqueClock(wall=lambda: wall[0])

    first = clock.unique_now()
    wall[0] = 1_700_000_000.0  # NTP steps the host back 100 seconds
    after_step = clock.unique_now()

    assert after_step == first + 1


def test_unique_now_follows_the_wall_clock_forward() -> None:
    """It is a real clock, not a counter: it tracks wall time when it can."""
    wall = [1_700_000_000.0]
    clock = UniqueClock(wall=lambda: wall[0])

    clock.unique_now()
    wall[0] = 1_700_000_500.0

    assert clock.unique_now() == 1_700_000_500


def test_now_truncates_rather_than_rounds() -> None:
    """The wire carries whole seconds; 1.9 is second 1, not second 2."""
    assert UniqueClock(wall=lambda: 1_700_000_001.9).now() == 1_700_000_001


def test_monotonic_is_separate_from_the_wall_clock() -> None:
    """Timeouts must not move when the wall clock is corrected."""
    wall = [1_700_000_000.0]
    clock = UniqueClock(wall=lambda: wall[0], monotonic=lambda: 42.0)

    wall[0] = 1.0

    assert clock.monotonic() == 42.0


async def test_sleeping_waits_on_the_real_loop() -> None:
    """A room paces its replies through the clock, so the production clock must
    actually wait -- otherwise every delay in the protocol becomes a busy spin."""
    clock = UniqueClock()

    before = clock.monotonic()
    await clock.sleep(0.01)

    assert clock.monotonic() - before >= 0.005


async def test_sleeping_for_nothing_returns_immediately() -> None:
    """A zero delay is the common case for an already-due deadline; it must not
    cost an event-loop round trip on every push-loop iteration."""
    await UniqueClock().sleep(0)
