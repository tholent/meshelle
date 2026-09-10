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

"""The 52-byte ``ServerStats`` struct returned by ``REQ_TYPE_GET_STATUS``.

Layout is the C struct at ``simple_room_server/MyMesh.cpp:24``, little-endian
with no padding -- every field is naturally aligned at its offset, so the packed
and native layouts coincide and ``<`` is exact rather than lucky.

Half of these fields describe *radio hardware* that meshelle does not own: the
companion node does. Those are reported as zero rather than invented, and
:class:`RadioStats` carries the ones meshelle can actually observe from the
packets it is handed. The two kinds are kept apart on purpose:

* **node-wide** (packets seen, floods forwarded, duplicates) -- one radio serves
  every hosted room, so these cannot honestly be attributed per room;
* **per-room** (posts made, posts pushed) -- these live in the ``counters``
  table and survive a restart, unlike the firmware's, which are RAM only.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, fields

STATS_FORMAT = "<HHhhIIIIIIIIHhHHHH"
"""batt_mv, tx_queue, noise_floor, last_rssi, 8 x uint32 counters,
err_events, last_snr(x4), direct_dups, flood_dups, n_posted, n_post_push."""

STATS_LEN = struct.calcsize(STATS_FORMAT)
assert STATS_LEN == 52, STATS_LEN  # noqa: S101 - the wire size is not negotiable

COUNTER_POSTED = "posted"
COUNTER_POST_PUSH = "post_push"

UINT16_MAX = 0xFFFF
UINT32_MAX = 0xFFFF_FFFF

STATS_FIELDS = (
    "batt_milli_volts",
    "curr_tx_queue_len",
    "noise_floor",
    "last_rssi",
    "n_packets_recv",
    "n_packets_sent",
    "total_air_time_secs",
    "total_up_time_secs",
    "n_sent_flood",
    "n_sent_direct",
    "n_recv_flood",
    "n_recv_direct",
    "err_events",
    "last_snr",
    "n_direct_dups",
    "n_flood_dups",
    "n_posted",
    "n_post_push",
)
"""Field order, which is the struct's field order. Used to decode."""


def _clamp(value: int, limit: int) -> int:
    """Saturate rather than wrap.

    ``struct.pack`` raises on overflow, and a long-running room *will* exceed
    65535 posts. A stats reply that fails to encode would take out the reply
    path; a saturated counter merely stops being interesting.
    """
    return max(0, min(value, limit))


@dataclass(slots=True)
class RadioStats:
    """Node-wide counters, shared by every room on one companion.

    In memory only. These describe this process's view of the radio since it
    started, which is what ``total_up_time_secs`` is relative to anyway.
    """

    started_at: float = 0.0
    """Monotonic reading at startup, for uptime."""

    packets_recv: int = 0
    packets_sent: int = 0
    sent_flood: int = 0
    sent_direct: int = 0
    recv_flood: int = 0
    recv_direct: int = 0
    direct_dups: int = 0
    flood_dups: int = 0
    err_events: int = 0
    last_rssi: int = 0
    last_snr_quarters: int = 0
    """SNR times four, as the wire carries it -- no float round-trip."""

    def reset(self) -> None:
        """Zero the counters, keeping ``started_at`` so uptime stays honest.

        ``clear stats`` from one room's CLI clears these for every room on the
        node, because there is only one radio. Said so in the CLI's reply.
        """
        for spec in fields(self):
            if spec.name != "started_at":
                setattr(self, spec.name, 0)

    def uptime_seconds(self, monotonic_now: float) -> int:
        return max(0, int(monotonic_now - self.started_at))


@dataclass(frozen=True, slots=True)
class ServerStats:
    """One decoded ``ServerStats`` struct."""

    batt_milli_volts: int = 0
    """Zero: meshelle runs on mains or a UPS the node knows nothing about."""
    curr_tx_queue_len: int = 0
    noise_floor: int = 0
    last_rssi: int = 0
    n_packets_recv: int = 0
    n_packets_sent: int = 0
    total_air_time_secs: int = 0
    """Zero: only the node's radio driver can measure air time."""
    total_up_time_secs: int = 0
    n_sent_flood: int = 0
    n_sent_direct: int = 0
    n_recv_flood: int = 0
    n_recv_direct: int = 0
    err_events: int = 0
    last_snr: int = 0
    """Times four, matching the firmware field."""
    n_direct_dups: int = 0
    n_flood_dups: int = 0
    n_posted: int = 0
    n_post_push: int = 0

    def encode(self) -> bytes:
        return struct.pack(
            STATS_FORMAT,
            _clamp(self.batt_milli_volts, UINT16_MAX),
            _clamp(self.curr_tx_queue_len, UINT16_MAX),
            self.noise_floor,
            self.last_rssi,
            _clamp(self.n_packets_recv, UINT32_MAX),
            _clamp(self.n_packets_sent, UINT32_MAX),
            _clamp(self.total_air_time_secs, UINT32_MAX),
            _clamp(self.total_up_time_secs, UINT32_MAX),
            _clamp(self.n_sent_flood, UINT32_MAX),
            _clamp(self.n_sent_direct, UINT32_MAX),
            _clamp(self.n_recv_flood, UINT32_MAX),
            _clamp(self.n_recv_direct, UINT32_MAX),
            _clamp(self.err_events, UINT16_MAX),
            self.last_snr,
            _clamp(self.n_direct_dups, UINT16_MAX),
            _clamp(self.n_flood_dups, UINT16_MAX),
            _clamp(self.n_posted, UINT16_MAX),
            _clamp(self.n_post_push, UINT16_MAX),
        )

    @classmethod
    def decode(cls, raw: bytes) -> ServerStats:
        """Parse a stats reply. Used by the tests and, later, by ``doctor``."""
        if len(raw) < STATS_LEN:
            raise ValueError(f"server stats must be {STATS_LEN} bytes, got {len(raw)}")
        values = struct.unpack_from(STATS_FORMAT, raw, 0)
        return cls(**dict(zip(STATS_FIELDS, values, strict=True)))

    @classmethod
    def build(
        cls,
        radio: RadioStats,
        *,
        monotonic_now: float,
        posted: int,
        post_pushes: int,
        tx_queue_len: int = 0,
    ) -> ServerStats:
        return cls(
            curr_tx_queue_len=tx_queue_len,
            last_rssi=radio.last_rssi,
            n_packets_recv=radio.packets_recv,
            n_packets_sent=radio.packets_sent,
            total_up_time_secs=radio.uptime_seconds(monotonic_now),
            n_sent_flood=radio.sent_flood,
            n_sent_direct=radio.sent_direct,
            n_recv_flood=radio.recv_flood,
            n_recv_direct=radio.recv_direct,
            err_events=radio.err_events,
            last_snr=radio.last_snr_quarters,
            n_direct_dups=radio.direct_dups,
            n_flood_dups=radio.flood_dups,
            n_posted=posted,
            n_post_push=post_pushes,
        )
