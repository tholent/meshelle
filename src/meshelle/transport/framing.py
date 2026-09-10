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

"""Frame codec for the companion serial/TCP protocol.

Frames are length-prefixed in both directions, with a direction marker::

    app -> node:  b'<' + uint16le length + payload
    node -> app:  b'>' + uint16le length + payload

The WiFi/TCP interface reuses this exact header -- ``SerialWifiInterface.cpp``
says so in a comment, "use same header as serial interface so client can delimit
frames" -- so one codec covers both. BLE does not: there a frame is one GATT
notification, with no header at all.

Resynchronisation matters in practice. USB serial hands us whatever the node
emitted before the app attached: boot banners, CLI output, a partial frame from a
previous session. The reader therefore scans for the marker rather than assuming
the stream starts clean, and sanity-checks the declared length so a stray 0x3E
byte inside junk is not mistaken for a frame header.
"""

from __future__ import annotations

import asyncio
import logging
import struct

from meshelle.proto.constants import FRAME_START_RX, FRAME_START_TX, MAX_FRAME_SIZE

logger = logging.getLogger(__name__)

FRAME_HEADER_LEN = 3
"""Marker byte plus a 16-bit little-endian length."""

MAX_FRAME_LEN = MAX_FRAME_SIZE
"""Frames larger than the node's own buffer cannot be genuine."""

HEADER_READ_TIMEOUT = 2.0
"""Once a marker is seen the rest of the frame is already in flight."""

BODY_READ_TIMEOUT = 5.0

JUNK_LOG_THRESHOLD = 256
"""Report accumulating junk this often, so a babbling port is visible promptly."""


class FramingError(Exception):
    """The stream could not be parsed as frames."""


def encode_frame(payload: bytes) -> bytes:
    """Wrap ``payload`` for transmission to the companion."""
    if not payload:
        raise FramingError("refusing to send an empty frame")
    if len(payload) > MAX_FRAME_LEN:
        raise FramingError(
            f"frame of {len(payload)} bytes exceeds the node's {MAX_FRAME_LEN}-byte buffer"
        )
    return FRAME_START_TX + struct.pack("<H", len(payload)) + payload


async def read_frame(reader: asyncio.StreamReader) -> bytes:
    """Read one frame, scanning past junk as needed.

    A single flat loop: accumulate non-marker bytes as junk, and on seeing a
    marker try to read a header and body. An implausible length means we locked
    onto a marker byte inside junk, so that byte joins the junk and the scan
    continues -- a desynchronised stream recovers rather than dropping the link.

    Raises:
        asyncio.IncompleteReadError: the stream ended.
        TimeoutError: a frame header or body stalled mid-transfer.
    """
    junk = bytearray()
    next_junk_report = JUNK_LOG_THRESHOLD

    while True:
        byte = await reader.readexactly(1)

        if byte != FRAME_START_RX:
            junk += byte
            if len(junk) >= next_junk_report:
                logger.warning(
                    "discarded %d bytes of non-frame data from the companion: %s…",
                    len(junk),
                    junk[:32].hex(),
                )
                next_junk_report = len(junk) + JUNK_LOG_THRESHOLD
            continue

        async with asyncio.timeout(HEADER_READ_TIMEOUT):
            length = struct.unpack("<H", await reader.readexactly(2))[0]

        if length == 0 or length > MAX_FRAME_LEN:
            logger.debug(
                "implausible frame length %d (max %d); treating the marker as junk",
                length,
                MAX_FRAME_LEN,
            )
            junk += byte
            continue

        async with asyncio.timeout(BODY_READ_TIMEOUT):
            payload = await reader.readexactly(length)

        if junk:
            logger.warning("resynchronised after %d bytes of junk: %s…", len(junk), junk[:32].hex())
        return payload
