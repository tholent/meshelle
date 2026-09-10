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

"""Serial transport: a companion node on USB or a UART.

This is the primary link. ``pyserial-asyncio-fast`` is used rather than plain
``pyserial`` because it integrates with the event loop and avoids the polling
thread the original library uses.
"""

from __future__ import annotations

import asyncio

import serial_asyncio_fast

from meshelle.proto.constants import DEFAULT_BAUD_RATE
from meshelle.transport.base import StreamTransport, TransportError


class SerialTransport(StreamTransport):
    """Frames over a serial port."""

    def __init__(self, port: str, baud_rate: int = DEFAULT_BAUD_RATE) -> None:
        super().__init__()
        self._port = port
        self._baud_rate = baud_rate

    @property
    def description(self) -> str:
        return f"serial {self._port}@{self._baud_rate}"

    async def _open(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        try:
            return await serial_asyncio_fast.open_serial_connection(
                url=self._port, baudrate=self._baud_rate
            )
        except Exception as exc:  # pyserial raises its own SerialException tree
            raise TransportError(
                f"cannot open serial port {self._port}: {exc}. "
                f"Check the device path and that your user can access it "
                f"(often the 'dialout' group)."
            ) from exc
