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

"""The ServerStats struct, which apps parse byte-for-byte."""

from __future__ import annotations

import struct

import pytest

from meshelle.room.stats import (
    STATS_FIELDS,
    STATS_FORMAT,
    STATS_LEN,
    RadioStats,
    ServerStats,
)


def test_the_struct_is_exactly_52_bytes() -> None:
    """Protocol semantics: the layout is a C struct an app reads by offset
    (MyMesh.cpp:24). A byte of drift shifts every field after it."""
    assert STATS_LEN == 52
    assert len(ServerStats().encode()) == 52


def test_every_field_round_trips_at_its_own_offset() -> None:
    """Distinct values per field, so a transposed pair cannot pass."""
    original = ServerStats(**{name: index + 1 for index, name in enumerate(STATS_FIELDS)})

    assert ServerStats.decode(original.encode()) == original


def test_signed_fields_stay_signed() -> None:
    """RSSI, SNR and the noise floor are all negative in normal operation. If
    they were packed unsigned, an app would show -70 dBm as 186."""
    stats = ServerStats(last_rssi=-108, last_snr=-30, noise_floor=-120)

    decoded = ServerStats.decode(stats.encode())

    assert (decoded.last_rssi, decoded.last_snr, decoded.noise_floor) == (-108, -30, -120)


def test_a_counter_past_its_field_width_saturates_rather_than_failing() -> None:
    """A room that has carried more than 65535 posts must still answer a status
    request. ``struct.pack`` would raise, taking the whole reply path down."""
    stats = ServerStats(n_posted=70_000, n_packets_recv=2**33)

    decoded = ServerStats.decode(stats.encode())

    assert decoded.n_posted == 0xFFFF
    assert decoded.n_packets_recv == 0xFFFF_FFFF


def test_decoding_a_short_reply_is_refused() -> None:
    with pytest.raises(ValueError, match="52 bytes"):
        ServerStats.decode(b"\x00" * 51)


def test_hardware_fields_are_zero_rather_than_invented() -> None:
    """meshelle does not own the radio: the companion node does. Battery
    voltage and air time are unknowable here, and a plausible-looking made-up
    number is worse than an obvious zero."""
    stats = ServerStats.build(
        RadioStats(started_at=0.0), monotonic_now=60.0, posted=1, post_pushes=2
    )

    assert stats.batt_milli_volts == 0
    assert stats.total_air_time_secs == 0


def test_build_reports_uptime_from_the_monotonic_clock() -> None:
    stats = ServerStats.build(
        RadioStats(started_at=1000.0), monotonic_now=1123.9, posted=0, post_pushes=0
    )

    assert stats.total_up_time_secs == 123


def test_resetting_the_radio_keeps_uptime_running() -> None:
    """`clear stats` zeroes counters. Restarting the uptime clock as well would
    make the room look like it had just rebooted."""
    radio = RadioStats(started_at=500.0, packets_recv=99, flood_dups=4)

    radio.reset()

    assert radio.packets_recv == 0
    assert radio.flood_dups == 0
    assert radio.uptime_seconds(560.0) == 60


def test_the_format_string_matches_the_field_list() -> None:
    """The two are edited separately, and a mismatch would silently misdecode."""
    assert len(STATS_FIELDS) == len(struct.unpack(STATS_FORMAT, b"\x00" * STATS_LEN))
