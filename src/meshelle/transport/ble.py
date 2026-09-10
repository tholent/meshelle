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

"""BLE transport: a companion node over Bluetooth Low Energy.

BLE is frame-oriented at the protocol level -- ``SerialBLEInterface`` sets the TX
characteristic to the whole frame and notifies, with no length prefix, so one
notification is exactly one frame. That makes this transport simpler than the
stream ones, and it does not use the framing codec at all.

``bleak`` is an optional dependency (``pip install 'meshelle[ble]'``), imported
lazily so a serial-only deployment need not carry it.

BLE is the least reliable option for an always-on server: notifications can be
dropped under load, and adapters on Linux periodically need a stack restart.
Prefer serial or TCP where the choice exists.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Final

from meshelle.transport.base import (
    RX_QUEUE_SIZE,
    Transport,
    TransportClosedError,
    TransportError,
)

if TYPE_CHECKING:
    from bleak import BleakClient

logger = logging.getLogger(__name__)

SERVICE_UUID: Final = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
RX_CHAR_UUID: Final = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
"""App writes commands here."""
TX_CHAR_UUID: Final = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"
"""Node notifies frames here."""

CONNECT_TIMEOUT = 20.0


class BleTransport(Transport):
    """Frames over BLE GATT notifications."""

    def __init__(self, address: str) -> None:
        self._address = address
        self._client: BleakClient | None = None
        self._frames: asyncio.Queue[bytes] = asyncio.Queue(maxsize=RX_QUEUE_SIZE)
        self._disconnected = asyncio.Event()

    @property
    def description(self) -> str:
        return f"ble {self._address}"

    def _on_notify(self, _characteristic: object, data: bytearray) -> None:
        """One notification is one frame."""
        try:
            self._frames.put_nowait(bytes(data))
        except asyncio.QueueFull:
            logger.error(
                "receive queue full (%d frames); dropping a frame from %s",
                RX_QUEUE_SIZE,
                self.description,
            )

    def _on_disconnect(self, _client: object) -> None:
        self._disconnected.set()

    async def connect(self) -> None:
        try:
            from bleak import BleakClient
        except ImportError as exc:  # pragma: no cover - depends on install extras
            raise TransportError("BLE support needs the 'ble' extra: uv sync --extra ble") from exc

        self._disconnected.clear()
        client = BleakClient(
            self._address,
            disconnected_callback=self._on_disconnect,
            timeout=CONNECT_TIMEOUT,
        )
        try:
            await client.connect()
            await client.start_notify(TX_CHAR_UUID, self._on_notify)
        except Exception as exc:
            raise TransportError(f"cannot connect to BLE device {self._address}: {exc}") from exc

        self._client = client

    async def send_frame(self, payload: bytes) -> None:
        if self._client is None or self._disconnected.is_set():
            raise TransportClosedError(f"{self.description} is not connected")
        try:
            # response=True so a full node buffer surfaces as an error rather
            # than a silently dropped command.
            await self._client.write_gatt_char(RX_CHAR_UUID, payload, response=True)
        except Exception as exc:
            raise TransportClosedError(f"write to {self.description} failed: {exc}") from exc

    async def read_frame(self) -> bytes:
        if self._client is None:
            raise TransportClosedError(f"{self.description} is not connected")

        get = asyncio.create_task(self._frames.get())
        gone = asyncio.create_task(self._disconnected.wait())
        try:
            done, _ = await asyncio.wait({get, gone}, return_when=asyncio.FIRST_COMPLETED)
            if get in done:
                return await get
            # Disconnected: hand over anything already queued before failing.
            try:
                return self._frames.get_nowait()
            except asyncio.QueueEmpty:
                raise TransportClosedError(f"{self.description} disconnected") from None
        finally:
            for task in (get, gone):
                if not task.done():
                    task.cancel()

    async def close(self) -> None:
        if self._client is not None:
            try:
                await self._client.disconnect()
            except Exception as exc:
                logger.debug("error disconnecting %s: %r", self.description, exc)
            self._client = None
        self._disconnected.set()
