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

"""TCP transport: a companion node reachable over WiFi.

The node's ``SerialWifiInterface`` listens on a TCP port (5000 by default) and
uses the same length-prefixed framing as the serial link, so this transport only
differs in how the stream is opened.

One caveat from the firmware: a new connection *displaces* the existing one
(``checkRecvFrame`` stops the old client when a new one arrives). Two meshelle
instances pointed at one node will therefore fight, each silently killing the
other's link.
"""

from __future__ import annotations

import asyncio

from meshelle.transport.base import StreamTransport, TransportError

DEFAULT_TCP_PORT = 5000
"""``TCP_PORT`` in examples/companion_radio/main.cpp."""

CONNECT_TIMEOUT = 10.0


class TcpTransport(StreamTransport):
    """Frames over a TCP connection."""

    def __init__(self, host: str, port: int = DEFAULT_TCP_PORT) -> None:
        super().__init__()
        self._host = host
        self._port = port

    @property
    def description(self) -> str:
        return f"tcp {self._host}:{self._port}"

    async def _open(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        try:
            async with asyncio.timeout(CONNECT_TIMEOUT):
                return await asyncio.open_connection(self._host, self._port)
        except TimeoutError as exc:
            raise TransportError(
                f"timed out connecting to {self._host}:{self._port} after {CONNECT_TIMEOUT}s"
            ) from exc
        except OSError as exc:
            raise TransportError(f"cannot connect to {self._host}:{self._port}: {exc}") from exc
