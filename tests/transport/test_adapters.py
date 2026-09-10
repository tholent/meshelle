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

"""Serial and BLE adapters: the parts testable without hardware.

Both are thin wrappers around a third-party open call, so what matters here is
that a failure to open becomes an actionable :class:`TransportError` rather than
a raw library exception, and that the descriptions are right. The happy paths
need real hardware and are exercised by ``meshelle doctor``, not by unit tests.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from meshelle.proto.constants import DEFAULT_BAUD_RATE
from meshelle.transport.base import TransportClosedError, TransportError
from meshelle.transport.ble import RX_CHAR_UUID, SERVICE_UUID, TX_CHAR_UUID, BleTransport
from meshelle.transport.serial import SerialTransport
from meshelle.transport.tcp import DEFAULT_TCP_PORT, TcpTransport


class TestSerialTransport:
    def test_describes_port_and_baud_rate(self) -> None:
        transport = SerialTransport("/dev/ttyUSB0")
        assert transport.description == f"serial /dev/ttyUSB0@{DEFAULT_BAUD_RATE}"

    def test_honours_a_custom_baud_rate(self) -> None:
        assert "@9600" in SerialTransport("/dev/ttyS0", 9600).description

    async def test_a_missing_port_gives_an_actionable_error(self) -> None:
        """The message should point at the two things that are actually wrong:
        the path, or permissions on it."""
        transport = SerialTransport("/dev/definitely-not-a-serial-port")

        with pytest.raises(TransportError, match="cannot open serial port") as excinfo:
            await transport.connect()

        assert "dialout" in str(excinfo.value), "should hint at the usual permission fix"

    async def test_a_directory_is_not_a_serial_port(self, tmp_path: Path) -> None:
        """The failure mode behind "[Errno 21] Is a directory": Docker created an
        empty directory where /dev/ttyUSB0 was expected. It must be reported as a
        port that cannot be opened, not as an obscure OSError."""
        transport = SerialTransport(str(tmp_path))

        with pytest.raises(TransportError, match="cannot open serial port"):
            await transport.connect()


class TestTcpTransportDefaults:
    def test_defaults_to_the_firmware_port(self) -> None:
        assert DEFAULT_TCP_PORT == 5000
        assert TcpTransport("node.local").description == "tcp node.local:5000"


class TestBleTransport:
    def test_uses_the_documented_nordic_uart_uuids(self) -> None:
        """From docs/companion_protocol.md; getting these wrong means no device
        is ever found."""
        assert SERVICE_UUID == "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
        assert RX_CHAR_UUID == "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
        assert TX_CHAR_UUID == "6e400003-b5a3-f393-e0a9-e50e24dcca9e"

    def test_describes_its_address(self) -> None:
        assert BleTransport("AA:BB:CC:DD:EE:FF").description == "ble AA:BB:CC:DD:EE:FF"

    async def test_sending_before_connect_is_refused(self) -> None:
        with pytest.raises(TransportClosedError, match="not connected"):
            await BleTransport("AA:BB:CC:DD:EE:FF").send_frame(b"\x16")

    async def test_reading_before_connect_is_refused(self) -> None:
        with pytest.raises(TransportClosedError, match="not connected"):
            await BleTransport("AA:BB:CC:DD:EE:FF").read_frame()

    async def test_close_is_safe_before_connect(self) -> None:
        await BleTransport("AA:BB:CC:DD:EE:FF").close()

    async def test_connecting_to_a_nonexistent_device_is_reported(self) -> None:
        transport = BleTransport("00:00:00:00:00:00")
        with pytest.raises(TransportError, match="cannot connect to BLE device"):
            await transport.connect()
