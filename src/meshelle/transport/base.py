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

"""Transport abstraction for talking to a companion node.

Transports are **frame oriented**, because that is the level at which all three
physical links agree: serial and TCP carry length-prefixed frames over a byte
stream, while BLE delivers one frame per GATT notification. Everything above
this layer deals only in whole frames.

Reads never apply a timeout to the underlying stream. A cancelled read partway
through a frame would leave the stream desynchronised, so instead a background
task parses frames continuously into a queue and callers time out waiting on the
*queue*. That keeps "the radio went quiet" recoverable and cheap to detect --
the failure mode that hangs meshcore-pi's bare ``readexactly(1)`` forever.
"""

from __future__ import annotations

import abc
import asyncio
import contextlib
import logging
from types import TracebackType
from typing import Self

from meshelle.transport.framing import FramingError, encode_frame, read_frame

logger = logging.getLogger(__name__)

RX_QUEUE_SIZE = 64
"""Bounded so a stalled consumer cannot grow memory without limit."""


class TransportError(Exception):
    """The transport could not be opened or used."""


class TransportClosedError(TransportError):
    """The link went away; the caller should reconnect."""


class Transport(abc.ABC):
    """A frame-oriented link to a companion node."""

    @property
    @abc.abstractmethod
    def description(self) -> str:
        """Human-readable identification, for logs and ``doctor`` output."""

    @abc.abstractmethod
    async def connect(self) -> None: ...

    @abc.abstractmethod
    async def close(self) -> None: ...

    @abc.abstractmethod
    async def send_frame(self, payload: bytes) -> None: ...

    @abc.abstractmethod
    async def read_frame(self) -> bytes:
        """Await the next frame.

        Raises:
            TransportClosedError: the link ended or failed.
        """

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()


class StreamTransport(Transport):
    """Shared implementation for stream links (serial, TCP).

    Subclasses only provide :meth:`_open`; framing, the reader task, and teardown
    are handled here.
    """

    def __init__(self) -> None:
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._frames: asyncio.Queue[bytes] = asyncio.Queue(maxsize=RX_QUEUE_SIZE)
        self._reader_task: asyncio.Task[None] | None = None
        self._failure: BaseException | None = None

    @abc.abstractmethod
    async def _open(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Open the underlying stream, raising :class:`TransportError` on failure."""

    async def connect(self) -> None:
        if self._reader_task is not None:
            raise TransportError(f"{self.description} is already connected")

        self._failure = None
        self._reader, self._writer = await self._open()
        self._reader_task = asyncio.create_task(
            self._pump(), name=f"transport-rx[{self.description}]"
        )

    async def _pump(self) -> None:
        """Parse frames into the queue until the stream ends or fails."""
        assert self._reader is not None  # noqa: S101 - set by connect()
        try:
            while True:
                frame = await read_frame(self._reader)
                try:
                    self._frames.put_nowait(frame)
                except asyncio.QueueFull:
                    # Dropping is better than unbounded growth, and says so.
                    logger.error(
                        "receive queue full (%d frames); dropping a frame from %s",
                        RX_QUEUE_SIZE,
                        self.description,
                    )
        except asyncio.CancelledError:
            raise
        except (
            asyncio.IncompleteReadError,
            ConnectionResetError,
            FramingError,
            OSError,
            TimeoutError,
        ) as exc:
            self._failure = exc
            logger.debug("reader for %s stopped: %r", self.description, exc)

    async def send_frame(self, payload: bytes) -> None:
        if self._writer is None:
            raise TransportClosedError(f"{self.description} is not connected")
        try:
            self._writer.write(encode_frame(payload))
            await self._writer.drain()
        except (OSError, ConnectionResetError) as exc:
            raise TransportClosedError(f"write to {self.description} failed: {exc}") from exc

    async def read_frame(self) -> bytes:
        """Await the next frame, or raise once the reader has stopped.

        Queued frames are drained before the failure surfaces, so a burst that
        arrived just before a disconnect is not thrown away.
        """
        get = asyncio.create_task(self._frames.get())
        reader_task = self._reader_task
        if reader_task is None:
            get.cancel()
            raise TransportClosedError(f"{self.description} is not connected")

        done, _ = await asyncio.wait({get, reader_task}, return_when=asyncio.FIRST_COMPLETED)

        if get in done:
            return await get

        # The reader finished. Drain anything it already queued first.
        get.cancel()
        try:
            return self._frames.get_nowait()
        except asyncio.QueueEmpty:
            pass

        raise TransportClosedError(
            f"{self.description} closed"
            + (f": {self._failure!r}" if self._failure is not None else "")
        )

    async def close(self) -> None:
        if self._reader_task is not None:
            self._reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._reader_task
            self._reader_task = None

        if self._writer is not None:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except (OSError, ConnectionResetError) as exc:
                logger.debug("error closing %s: %r", self.description, exc)
            self._writer = None

        self._reader = None
