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

"""The seen-packet table: duplicate suppression, including of our own echoes.

Every packet carries an 8-byte ``packet_hash`` over its payload type and payload
but **not** its path, so the same packet arriving by two routes hashes
identically. That property does two jobs here:

1. A flood packet reaches us once per repeater in earshot. Handling it more than
   once would double-post a message and send duplicate ACKs.
2. **Our own transmissions come back to us.** The companion node hears the
   repeater re-broadcasting what we just sent and mirrors it to us over
   ``PUSH_CODE_LOG_RX_DATA`` like any other packet. Firmware avoids this with
   ``_tables->markSeen(packet)`` at send time (Mesh::sendFlood); meshelle does
   the same by marking every outbound packet before handing it to the link.

Entries expire so the table cannot grow without bound on a busy mesh, and it is
additionally capped: a flood of unique packets evicts the oldest rather than
exhausting memory on a Pi.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable

DEFAULT_TTL_SECONDS = 900.0
"""15 minutes. Comfortably longer than any flood takes to die out, and longer
than the 12s flood ACK timeout, so a late duplicate is still recognised."""

DEFAULT_CAPACITY = 2048
"""Bounded because this runs on a Pi and the mesh is not under our control."""


class SeenTable:
    """A bounded, expiring set of packet hashes.

    Not thread-safe: it is touched only from the event loop.
    """

    __slots__ = ("_capacity", "_entries", "_monotonic", "_ttl")

    def __init__(
        self,
        *,
        ttl: float = DEFAULT_TTL_SECONDS,
        capacity: int = DEFAULT_CAPACITY,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl <= 0:
            raise ValueError(f"ttl must be positive, got {ttl}")
        if capacity <= 0:
            raise ValueError(f"capacity must be positive, got {capacity}")
        self._ttl = ttl
        self._capacity = capacity
        self._monotonic = monotonic
        # Insertion-ordered, so the oldest entry is always the first one.
        self._entries: OrderedDict[bytes, float] = OrderedDict()

    def __len__(self) -> int:
        return len(self._entries)

    def mark(self, packet_hash: bytes) -> None:
        """Record a hash as seen, refreshing it if it already was.

        Called both on receive and immediately before every transmit.
        """
        self._expire()
        # Re-inserting at the end refreshes the TTL of a hash we keep hearing,
        # so a packet still circulating never falls out of the table and gets
        # processed a second time on its way back.
        self._entries.pop(packet_hash, None)
        self._entries[packet_hash] = self._monotonic()
        while len(self._entries) > self._capacity:
            self._entries.popitem(last=False)

    def check_and_mark(self, packet_hash: bytes) -> bool:
        """Whether this hash was already known. Marks it either way.

        The test and the insert are one operation on purpose: two callers doing
        ``if not seen: mark()`` around an await is exactly how a duplicate slips
        through.
        """
        self._expire()
        already_seen = packet_hash in self._entries
        self.mark(packet_hash)
        return already_seen

    def _expire(self) -> None:
        cutoff = self._monotonic() - self._ttl
        while self._entries:
            oldest_hash, stamped = next(iter(self._entries.items()))
            if stamped > cutoff:
                return
            del self._entries[oldest_hash]
