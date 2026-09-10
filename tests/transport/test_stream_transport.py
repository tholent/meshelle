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

"""Exercise StreamTransport and TcpTransport against a loopback server.

``FakeCompanion`` implements :class:`Transport` directly, which leaves the real
stream plumbing -- the reader task, the bounded queue, draining on disconnect,
write failures -- untested. A loopback TCP server speaking the frame protocol
covers that plumbing with genuine ``StreamReader``/``StreamWriter`` objects, and
covers :class:`TcpTransport` at the same time, since the node's WiFi interface
uses exactly this framing.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
from collections.abc import AsyncIterator, Awaitable, Callable

import pytest

from meshelle.proto.constants import FRAME_START_RX
from meshelle.transport.base import TransportClosedError, TransportError
from meshelle.transport.tcp import TcpTransport

Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


def framed(payload: bytes) -> bytes:
    return FRAME_START_RX + struct.pack("<H", len(payload)) + payload


class LoopbackNode:
    """A TCP server that speaks the companion frame protocol."""

    def __init__(self) -> None:
        self.received: list[bytes] = []
        self.port = 0
        self._server: asyncio.Server | None = None
        self._writer: asyncio.StreamWriter | None = None
        # Every writer ever handed out, so none is garbage collected while still
        # open. A leaked StreamWriter raises from __del__, and filterwarnings=error
        # turns that into a confusing failure in an unrelated test.
        self._writers: list[asyncio.StreamWriter] = []
        self._connected = asyncio.Event()
        self._got_frame = asyncio.Event()

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.append(writer)
        self._writer = writer
        self._connected.set()
        try:
            while True:
                header = await reader.readexactly(3)
                length = struct.unpack("<H", header[1:])[0]
                self.received.append(await reader.readexactly(length))
                self._got_frame.set()
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        finally:
            writer.close()

    async def wait_connected(self) -> None:
        await self._connected.wait()

    async def wait_for_frames(self, count: int) -> None:
        while len(self.received) < count:
            self._got_frame.clear()
            await self._got_frame.wait()

    def send(self, payload: bytes) -> None:
        assert self._writer is not None
        self._writer.write(framed(payload))

    def send_raw(self, data: bytes) -> None:
        """Write bytes directly, for junk and partial-frame cases."""
        assert self._writer is not None
        self._writer.write(data)

    def hang_up(self) -> None:
        assert self._writer is not None
        self._writer.close()

    async def stop(self) -> None:
        for writer in self._writers:
            writer.close()
        for writer in self._writers:
            with contextlib.suppress(OSError, ConnectionResetError):
                await writer.wait_closed()
        self._writers.clear()
        self._writer = None

        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


@pytest.fixture
async def node() -> AsyncIterator[LoopbackNode]:
    server = LoopbackNode()
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


class TestConnect:
    async def test_connects_and_describes_itself(self, node: LoopbackNode) -> None:
        transport = TcpTransport("127.0.0.1", node.port)
        async with transport:
            await node.wait_connected()
            assert transport.description == f"tcp 127.0.0.1:{node.port}"

    async def test_reports_a_refused_connection_clearly(self) -> None:
        # Port 1 on loopback is not listening and needs privileges to bind.
        transport = TcpTransport("127.0.0.1", 1)
        with pytest.raises(TransportError, match="cannot connect"):
            await transport.connect()

    async def test_refuses_to_connect_twice(self, node: LoopbackNode) -> None:
        transport = TcpTransport("127.0.0.1", node.port)
        async with transport:
            with pytest.raises(TransportError, match="already connected"):
                await transport.connect()


class TestSendFrame:
    async def test_sends_a_framed_payload(self, node: LoopbackNode) -> None:
        async with TcpTransport("127.0.0.1", node.port) as transport:
            await transport.send_frame(b"\x16\x03")
            await node.wait_for_frames(1)

            assert node.received == [b"\x16\x03"]

    async def test_sends_several_frames_in_order(self, node: LoopbackNode) -> None:
        async with TcpTransport("127.0.0.1", node.port) as transport:
            for index in range(5):
                await transport.send_frame(bytes([index]))
            await node.wait_for_frames(5)

            assert node.received == [bytes([i]) for i in range(5)]

    async def test_sending_before_connect_is_refused(self, node: LoopbackNode) -> None:
        transport = TcpTransport("127.0.0.1", node.port)
        with pytest.raises(TransportClosedError, match="not connected"):
            await transport.send_frame(b"\x16")


class TestReadFrame:
    async def test_reads_a_frame(self, node: LoopbackNode) -> None:
        async with TcpTransport("127.0.0.1", node.port) as transport:
            await node.wait_connected()
            node.send(b"\x0dhello")

            async with asyncio.timeout(2):
                assert await transport.read_frame() == b"\x0dhello"

    async def test_reads_a_one_byte_frame(self, node: LoopbackNode) -> None:
        """RESP_CODE_OK arrives as a single byte on every successful transmit."""
        async with TcpTransport("127.0.0.1", node.port) as transport:
            await node.wait_connected()
            node.send(b"\x00")

            async with asyncio.timeout(2):
                assert await transport.read_frame() == b"\x00"

    async def test_skips_junk_before_a_frame(self, node: LoopbackNode) -> None:
        async with TcpTransport("127.0.0.1", node.port) as transport:
            await node.wait_connected()
            node.send_raw(b"boot banner gibberish\r\n" + framed(b"\x05real"))

            async with asyncio.timeout(2):
                assert await transport.read_frame() == b"\x05real"

    async def test_reassembles_a_frame_split_across_writes(self, node: LoopbackNode) -> None:
        async with TcpTransport("127.0.0.1", node.port) as transport:
            await node.wait_connected()
            node.send_raw(FRAME_START_RX + b"\x05\x00")
            await asyncio.sleep(0.05)
            node.send_raw(b"spl")
            await asyncio.sleep(0.05)
            node.send_raw(b"it")

            async with asyncio.timeout(2):
                assert await transport.read_frame() == b"split"

    async def test_queues_frames_that_arrive_before_they_are_read(self, node: LoopbackNode) -> None:
        """The reader task runs continuously, so a burst is not lost."""
        async with TcpTransport("127.0.0.1", node.port) as transport:
            await node.wait_connected()
            for index in range(4):
                node.send(bytes([index]))
            await asyncio.sleep(0.1)

            async with asyncio.timeout(2):
                for index in range(4):
                    assert await transport.read_frame() == bytes([index])

    async def test_raises_once_the_peer_hangs_up(self, node: LoopbackNode) -> None:
        async with TcpTransport("127.0.0.1", node.port) as transport:
            await node.wait_connected()
            node.hang_up()

            with pytest.raises(TransportClosedError, match="closed"):
                async with asyncio.timeout(2):
                    await transport.read_frame()

    async def test_drains_queued_frames_before_reporting_the_close(
        self, node: LoopbackNode
    ) -> None:
        """A burst that landed just before a disconnect must still be delivered.

        Otherwise a packet the node really did hear is discarded because the
        cable was pulled a millisecond later.
        """
        async with TcpTransport("127.0.0.1", node.port) as transport:
            await node.wait_connected()
            node.send(b"\x01first")
            node.send(b"\x02second")
            await asyncio.sleep(0.05)
            node.hang_up()
            await asyncio.sleep(0.05)

            async with asyncio.timeout(2):
                assert await transport.read_frame() == b"\x01first"
                assert await transport.read_frame() == b"\x02second"
                with pytest.raises(TransportClosedError):
                    await transport.read_frame()

    async def test_reading_before_connect_is_refused(self, node: LoopbackNode) -> None:
        transport = TcpTransport("127.0.0.1", node.port)
        with pytest.raises(TransportClosedError, match="not connected"):
            await transport.read_frame()


class TestClose:
    async def test_close_is_idempotent(self, node: LoopbackNode) -> None:
        transport = TcpTransport("127.0.0.1", node.port)
        await transport.connect()
        await transport.close()
        await transport.close()

    async def test_can_reconnect_after_close(self, node: LoopbackNode) -> None:
        """The link's reconnect loop builds a fresh transport, but closing and
        reopening the same object must not leave stale state behind either."""
        transport = TcpTransport("127.0.0.1", node.port)
        await transport.connect()
        await transport.close()

        await transport.connect()
        try:
            await transport.send_frame(b"\x16")
            await node.wait_for_frames(1)
            assert node.received == [b"\x16"]
        finally:
            await transport.close()
