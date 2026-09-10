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

"""Frame codec: encoding, resynchronisation, and truncation."""

from __future__ import annotations

import asyncio
import struct

import pytest

from meshelle.proto.constants import FRAME_START_RX, FRAME_START_TX
from meshelle.transport.framing import (
    MAX_FRAME_LEN,
    FramingError,
    encode_frame,
    read_frame,
)
from tests.fakes.companion import FakeStream


def framed(payload: bytes) -> bytes:
    """The node's outbound framing: b'>' + uint16le length + payload."""
    return FRAME_START_RX + struct.pack("<H", len(payload)) + payload


class TestEncodeFrame:
    def test_prefixes_marker_and_little_endian_length(self) -> None:
        assert encode_frame(b"abc") == FRAME_START_TX + b"\x03\x00" + b"abc"

    def test_length_is_two_bytes_little_endian(self) -> None:
        payload = bytes(170)
        encoded = encode_frame(payload)
        assert struct.unpack_from("<H", encoded, 1)[0] == 170

    def test_rejects_empty_payload(self) -> None:
        with pytest.raises(FramingError, match="empty frame"):
            encode_frame(b"")

    def test_rejects_payload_over_the_node_buffer(self) -> None:
        with pytest.raises(FramingError, match="exceeds the node"):
            encode_frame(bytes(MAX_FRAME_LEN + 1))

    def test_accepts_a_payload_exactly_at_the_limit(self) -> None:
        assert len(encode_frame(bytes(MAX_FRAME_LEN))) == MAX_FRAME_LEN + 3


class TestReadFrame:
    async def test_reads_a_single_frame(self) -> None:
        stream = FakeStream(framed(b"hello"))
        assert await read_frame(stream.reader) == b"hello"

    async def test_reads_consecutive_frames(self) -> None:
        stream = FakeStream(framed(b"one") + framed(b"two") + framed(b"three"))

        assert await read_frame(stream.reader) == b"one"
        assert await read_frame(stream.reader) == b"two"
        assert await read_frame(stream.reader) == b"three"

    async def test_skips_a_boot_banner_before_the_first_frame(self) -> None:
        """A freshly attached USB port often hands us the node's startup text."""
        stream = FakeStream(b"MeshCore v1.17.1 starting\r\n" + framed(b"frame"))

        assert await read_frame(stream.reader) == b"frame"

    async def test_recovers_when_junk_contains_the_marker_byte(self) -> None:
        """A 0x3E inside junk must not be mistaken for a frame header.

        Here '>' is followed by a length of 0xFFFF, which is impossible, so the
        scan treats it as junk and finds the real frame after it.
        """
        stream = FakeStream(b"noise>" + b"\xff\xff" + framed(b"real"))

        assert await read_frame(stream.reader) == b"real"

    async def test_rejects_a_zero_length_frame_and_keeps_scanning(self) -> None:
        stream = FakeStream(FRAME_START_RX + b"\x00\x00" + framed(b"after"))

        assert await read_frame(stream.reader) == b"after"

    async def test_handles_a_frame_arriving_in_pieces(self) -> None:
        """Serial delivers bytes whenever it feels like it."""
        stream = FakeStream()
        task = asyncio.create_task(read_frame(stream.reader))

        stream.feed(FRAME_START_RX)
        await asyncio.sleep(0)
        stream.feed(b"\x05\x00")
        await asyncio.sleep(0)
        stream.feed(b"par")
        await asyncio.sleep(0)
        stream.feed(b"ts")

        assert await task == b"parts"

    async def test_raises_on_eof(self) -> None:
        stream = FakeStream()
        stream.eof()

        with pytest.raises(asyncio.IncompleteReadError):
            await read_frame(stream.reader)

    async def test_raises_on_eof_midway_through_a_frame(self) -> None:
        stream = FakeStream(FRAME_START_RX + b"\x10\x00" + b"only four")
        stream.eof()

        with pytest.raises(asyncio.IncompleteReadError):
            await read_frame(stream.reader)

    async def test_times_out_if_a_body_never_arrives(self) -> None:
        """A header with no body must not block forever."""
        stream = FakeStream(FRAME_START_RX + b"\x10\x00")

        with pytest.raises(TimeoutError):
            async with asyncio.timeout(0.2):
                await read_frame(stream.reader)

    async def test_reads_a_maximum_length_frame(self) -> None:
        payload = bytes(range(256)) * 1
        payload = payload[:MAX_FRAME_LEN]
        stream = FakeStream(framed(payload))

        assert await read_frame(stream.reader) == payload

    async def test_reads_a_one_byte_frame(self) -> None:
        """RESP_CODE_OK is a single byte and must parse cleanly."""
        stream = FakeStream(framed(b"\x00"))
        assert await read_frame(stream.reader) == b"\x00"
