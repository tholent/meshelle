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

"""The seen-table, which is what stops us answering our own packets."""

from __future__ import annotations

import pytest

from meshelle.mesh.dedupe import SeenTable


def test_first_sighting_is_not_a_duplicate() -> None:
    table = SeenTable()

    assert table.check_and_mark(b"\x01" * 8) is False
    assert table.check_and_mark(b"\x01" * 8) is True


def test_marking_before_transmit_suppresses_our_own_echo() -> None:
    """Protocol semantics: a repeater re-broadcasts what we send, and the node
    mirrors that back to us as an ordinary received packet.

    ``packet_hash`` excludes the path, so the echo hashes identically to what we
    sent. Marking at transmit time (as ``Mesh::sendFlood`` does) is what makes
    the echo recognisable -- without it a room would process its own login reply
    as an inbound packet.
    """
    table = SeenTable()
    our_packet = b"\xab" * 8

    table.mark(our_packet)  # what Dispatcher.send does before transmitting

    assert table.check_and_mark(our_packet) is True


def test_entries_expire_so_the_table_cannot_grow_forever() -> None:
    now = [100.0]
    table = SeenTable(ttl=10.0, monotonic=lambda: now[0])

    table.mark(b"old!!!!!")
    now[0] = 111.0

    assert table.check_and_mark(b"old!!!!!") is False
    assert len(table) == 1


def test_a_packet_still_circulating_keeps_its_entry_alive() -> None:
    """Re-hearing a hash refreshes it, so a long flood cannot outlive the TTL
    and come back around as a fresh packet."""
    now = [100.0]
    table = SeenTable(ttl=10.0, monotonic=lambda: now[0])

    table.mark(b"circling")
    now[0] = 105.0
    table.check_and_mark(b"circling")  # heard again from another repeater
    now[0] = 112.0  # past the original TTL, but not past the refreshed one

    assert table.check_and_mark(b"circling") is True


def test_capacity_evicts_the_oldest_entry() -> None:
    """A busy mesh must not be able to exhaust memory on a Pi."""
    table = SeenTable(capacity=2)

    table.mark(b"first---")
    table.mark(b"second--")
    table.mark(b"third---")

    assert len(table) == 2
    assert table.check_and_mark(b"first---") is False
    assert table.check_and_mark(b"third---") is True


@pytest.mark.parametrize(("ttl", "capacity"), [(0, 10), (-1, 10), (10, 0)])
def test_nonsense_limits_are_rejected_at_construction(ttl: float, capacity: int) -> None:
    with pytest.raises(ValueError, match="must be positive"):
        SeenTable(ttl=ttl, capacity=capacity)
