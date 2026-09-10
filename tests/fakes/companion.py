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

"""An in-memory companion node that speaks the real frame protocol.

This is the substrate for every link and room test. It implements the node side
of the companion protocol faithfully enough that the production code cannot tell
the difference, and it can be told to misbehave in each of the specific ways real
hardware does:

* go silent mid-session (a node that needs a replug)
* reject ``CMD_SEND_RAW_PACKET`` (firmware without the command)
* drop the connection

This fake is frame-oriented, so it cannot model byte-level stream damage. Junk
and truncation are covered against the framing codec directly, using
:class:`FakeStream`.

Frames it is handed are parsed, and raw packets it is asked to transmit are
recorded in :attr:`transmitted` so tests can assert on what went on the air.
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field

from meshelle.proto.constants import (
    MAX_FRAME_SIZE,
    Cmd,
    ErrCode,
    PushCode,
    RespCode,
)
from meshelle.transport.base import Transport, TransportClosedError

DEFAULT_PUBLIC_KEY = bytes.fromhex(
    "1ec77175b0918ed206f9ae04ec136d6d5d4315bb26305427f645b492e9350c10"
)


@dataclass(slots=True)
class SentPacket:
    """A raw packet the link asked us to transmit."""

    raw: bytes
    priority: int


@dataclass
class FakeCompanionConfig:
    """How this fake node should behave."""

    node_name: str = "Test Node"
    public_key: bytes = DEFAULT_PUBLIC_KEY
    firmware_version: str = "v1.17.1"
    build_date: str = "14 Aug 2026"
    manufacturer: str = "Test Mfr"
    firmware_version_code: int = 10
    path_hash_mode: int = 0
    tx_power_dbm: int = 20
    max_tx_power_dbm: int = 22
    frequency_khz: int = 869618
    bandwidth_hz: int = 250000
    spreading_factor: int = 10
    coding_rate: int = 5

    supports_raw_packet: bool = True
    """When False, CMD_SEND_RAW_PACKET answers ERR_CODE_UNSUPPORTED_CMD."""

    answer_device_query: bool = True
    """When False the node never replies, as if it had wedged."""

    answer_heartbeat: bool = True
    """When False, CMD_GET_DEVICE_TIME is ignored so the heartbeat times out."""

    device_info_override: bytes | None = None
    """Replace the DEVICE_INFO frame entirely, to test short/garbled replies."""


class FakeCompanion(Transport):
    """A :class:`Transport` whose far end is a simulated companion node."""

    def __init__(self, config: FakeCompanionConfig | None = None) -> None:
        self.config = config or FakeCompanionConfig()
        self.transmitted: list[SentPacket] = []
        self.commands: list[int] = []

        self._to_app: asyncio.Queue[bytes] = asyncio.Queue()
        self._closed = asyncio.Event()
        self._connected = False
        self._transmitted = asyncio.Event()

    # -- Transport ------------------------------------------------------------

    @property
    def description(self) -> str:
        return "fake companion"

    async def connect(self) -> None:
        self._connected = True
        self._closed.clear()

    async def close(self) -> None:
        self._connected = False
        self._closed.set()

    async def send_frame(self, payload: bytes) -> None:
        if not self._connected:
            raise TransportClosedError("fake companion is not connected")
        if len(payload) > MAX_FRAME_SIZE:
            raise AssertionError(
                f"link sent a {len(payload)}-byte frame, over the node's {MAX_FRAME_SIZE} limit"
            )
        self._handle_command(payload)

    async def read_frame(self) -> bytes:
        get = asyncio.create_task(self._to_app.get())
        closed = asyncio.create_task(self._closed.wait())
        try:
            done, _ = await asyncio.wait({get, closed}, return_when=asyncio.FIRST_COMPLETED)
            if get in done:
                return await get
            try:
                return self._to_app.get_nowait()
            except asyncio.QueueEmpty:
                raise TransportClosedError("fake companion closed") from None
        finally:
            for task in (get, closed):
                if not task.done():
                    task.cancel()

    # -- node behaviour -------------------------------------------------------

    def _reply(self, frame: bytes) -> None:
        self._to_app.put_nowait(frame)

    def _handle_command(self, payload: bytes) -> None:
        command = payload[0]
        self.commands.append(command)

        if command == Cmd.DEVICE_QUERY:
            if self.config.answer_device_query:
                self._reply(self.config.device_info_override or self._device_info())
            return

        if command == Cmd.APP_START:
            self._reply(self._self_info())
            return

        if command == Cmd.GET_DEVICE_TIME:
            if self.config.answer_heartbeat:
                self._reply(bytes([RespCode.CURR_TIME]) + struct.pack("<I", 1700000000))
            return

        if command == Cmd.SEND_RAW_PACKET:
            self._handle_raw_packet(payload)
            return

        self._reply(bytes([RespCode.ERR, ErrCode.UNSUPPORTED_CMD]))

    def _handle_raw_packet(self, payload: bytes) -> None:
        if not self.config.supports_raw_packet:
            self._reply(bytes([RespCode.ERR, ErrCode.UNSUPPORTED_CMD]))
            return

        # Firmware requires len >= 4 before it even considers the command.
        if len(payload) < 4:
            self._reply(bytes([RespCode.ERR, ErrCode.UNSUPPORTED_CMD]))
            return

        priority = payload[1]
        raw = payload[2:]

        # Mirror tryParsePacket's minimum: header + path_len + at least one
        # payload byte. Anything shorter is rejected without transmitting, which
        # is exactly what probe_raw_packet_support relies on.
        if len(raw) < 3:
            self._reply(bytes([RespCode.ERR, ErrCode.ILLEGAL_ARG]))
            return

        self.transmitted.append(SentPacket(raw=raw, priority=priority))
        self._transmitted.set()
        self._reply(bytes([RespCode.OK]))

    def _device_info(self) -> bytes:
        frame = bytearray(82)
        frame[0] = RespCode.DEVICE_INFO
        frame[1] = self.config.firmware_version_code
        frame[2] = 50
        frame[3] = 32
        struct.pack_into("<I", frame, 4, 0)
        frame[8:20] = self.config.build_date.encode().ljust(12, b"\x00")[:12]
        frame[20:60] = self.config.manufacturer.encode().ljust(40, b"\x00")[:40]
        frame[60:80] = self.config.firmware_version.encode().ljust(20, b"\x00")[:20]
        frame[80] = 0
        frame[81] = self.config.path_hash_mode
        return bytes(frame)

    def _self_info(self) -> bytes:
        frame = bytearray(58)
        frame[0] = RespCode.SELF_INFO
        frame[1] = 1  # ADV_TYPE_CHAT
        frame[2] = self.config.tx_power_dbm
        frame[3] = self.config.max_tx_power_dbm
        frame[4:36] = self.config.public_key
        struct.pack_into("<ii", frame, 36, 0, 0)
        frame[44] = 0
        frame[45] = 0
        frame[46] = 0
        frame[47] = 0
        struct.pack_into("<II", frame, 48, self.config.frequency_khz, self.config.bandwidth_hz)
        frame[56] = self.config.spreading_factor
        frame[57] = self.config.coding_rate
        return bytes(frame) + self.config.node_name.encode()

    # -- test helpers ---------------------------------------------------------

    def deliver_packet(self, raw: bytes, *, snr: float = 10.0, rssi: int = -80) -> None:
        """Make the node report having heard ``raw`` on the air."""
        self._to_app.put_nowait(
            bytes([PushCode.LOG_RX_DATA]) + struct.pack("<bb", int(snr * 4), rssi) + raw
        )

    def push(self, frame: bytes) -> None:
        """Inject an arbitrary frame, for exercising unexpected node output."""
        self._to_app.put_nowait(frame)

    def drop_connection(self) -> None:
        """Simulate the link vanishing without a clean close."""
        self._connected = False
        self._closed.set()

    @property
    def transmitted_packets(self) -> list[bytes]:
        return [packet.raw for packet in self.transmitted]

    async def wait_for_transmit(self, count: int = 1) -> None:
        """Block until at least ``count`` packets have been transmitted.

        Event-driven rather than sleep-polling, so tests are deterministic and
        do not trade flakiness against wall-clock time.
        """
        while len(self.transmitted) < count:
            self._transmitted.clear()
            await self._transmitted.wait()


class NodeFactory:
    """Hands out fake nodes and records them, so reconnects can be awaited.

    :class:`CompanionLink` builds a fresh transport per connection attempt, so
    the number of nodes created is exactly the number of connection attempts.
    """

    def __init__(self, config: FakeCompanionConfig | None = None) -> None:
        self._config = config
        self.nodes: list[FakeCompanion] = []
        self._created = asyncio.Event()

    def __call__(self) -> FakeCompanion:
        node = FakeCompanion(self._config)
        self.nodes.append(node)
        self._created.set()
        return node

    async def wait_for_node(self, count: int) -> FakeCompanion:
        """Block until ``count`` nodes have been created, and return the last."""
        while len(self.nodes) < count:
            self._created.clear()
            await self._created.wait()
        return self.nodes[count - 1]


@dataclass
class FakeStream:
    """A minimal ``asyncio.StreamReader``-compatible source of bytes.

    Used to exercise the framing codec directly, including junk and truncation,
    without a real serial port.
    """

    data: bytes = b""
    _reader: asyncio.StreamReader = field(default_factory=asyncio.StreamReader)

    def __post_init__(self) -> None:
        if self.data:
            self._reader.feed_data(self.data)

    @property
    def reader(self) -> asyncio.StreamReader:
        return self._reader

    def feed(self, data: bytes) -> None:
        self._reader.feed_data(data)

    def eof(self) -> None:
        self._reader.feed_eof()
