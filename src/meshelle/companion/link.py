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

"""The companion link: a MeshCore node driven as a bare radio modem.

meshelle owns the mesh endpoint, so the node is used only to get bytes on and off
the air:

* **Transmit** — ``CMD_SEND_RAW_PACKET`` (65), frame ``[65][priority][packet]``.
* **Receive** — ``PUSH_CODE_LOG_RX_DATA`` (0x88), frame
  ``[0x88][snr*4: int8][rssi: int8][packet]``, which the node emits
  unconditionally for every packet it hears (``Dispatcher::checkRecv``).

Four deliberate design choices, each fixing a failure mode seen in meshcore-pi:

1. **The outbound queue lives here and survives reconnects.** ``send_packet``
   enqueues and never silently drops; a room's startup advert sent before the
   handshake completes goes out once the link is up instead of vanishing into a
   log line. Entries carry a TTL so a stale push is discarded rather than
   transmitted minutes late.
2. **Every read has a deadline.** The handshake is bounded, and liveness is
   checked by an explicit heartbeat rather than by waiting for traffic -- an idle
   mesh legitimately produces no frames at all, so silence is not a fault.
3. **One-byte frames are normal.** ``RESP_CODE_OK`` is a single byte; treating
   anything under three bytes as malformed logs a warning on every successful
   transmit.
4. **An unsupported CMD 65 fails loudly.** After the handshake the only commands
   we send are 65 and ``GET_DEVICE_TIME`` (5, ancient), so an
   ``UNSUPPORTED_CMD`` error is unambiguous and actionable.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import struct
import time
from collections import deque
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field

from meshelle.proto.constants import (
    COMPANION_API_VERSION,
    MAX_RAW_TX_PACKET,
    Cmd,
    ErrCode,
    PushCode,
    RespCode,
)
from meshelle.transport.base import Transport, TransportClosedError, TransportError

logger = logging.getLogger(__name__)

HANDSHAKE_TIMEOUT = 10.0
"""A node that does not answer CMD_DEVICE_QUERY in this long needs a replug."""

HEARTBEAT_INTERVAL = 60.0
HEARTBEAT_TIMEOUT = 10.0

RECONNECT_MIN_DELAY = 1.0
RECONNECT_MAX_DELAY = 60.0

DEFAULT_SEND_TTL = 30.0
"""Long enough to ride out a brief reconnect, short enough that a stale post
push is dropped rather than arriving after the client gave up waiting."""

ADVERT_SEND_TTL = 600.0
"""Adverts stay useful far longer than acknowledged traffic."""

PACKET_QUEUE_SIZE = 256

DEVICE_INFO_MIN_LEN = 60
SELF_INFO_MIN_LEN = 58


def _first_leaf(exc: BaseException) -> BaseException:
    """The first non-group exception inside a possibly nested ExceptionGroup."""
    while isinstance(exc, BaseExceptionGroup):
        exc = exc.exceptions[0]
    return exc


class CompanionError(Exception):
    """The companion node cannot be used as a modem."""


class RawPacketUnsupportedError(CompanionError):
    """The node's firmware does not implement ``CMD_SEND_RAW_PACKET``."""


@dataclass(frozen=True, slots=True)
class CompanionInfo:
    """What the node told us about itself during the handshake."""

    firmware_version_code: int
    firmware_version: str
    build_date: str
    manufacturer: str
    path_hash_mode: int
    public_key: bytes
    node_name: str
    tx_power_dbm: int
    max_tx_power_dbm: int
    frequency_khz: int
    bandwidth_hz: int
    spreading_factor: int
    coding_rate: int

    def summary(self) -> str:
        return (
            f"{self.node_name or '(unnamed)'} [{self.public_key[:4].hex()}] "
            f"{self.manufacturer} fw {self.firmware_version} ({self.build_date}), "
            f"{self.frequency_khz / 1000:.3f} MHz "
            f"bw {self.bandwidth_hz / 1000:.0f} kHz sf{self.spreading_factor} "
            f"cr{self.coding_rate} tx {self.tx_power_dbm}/{self.max_tx_power_dbm} dBm"
        )


@dataclass(frozen=True, slots=True)
class ReceivedPacket:
    """A raw packet the node heard, with its radio metadata."""

    raw: bytes
    snr: float
    rssi: int


@dataclass(slots=True)
class _Outbound:
    payload: bytes
    expires_at: float
    description: str


@dataclass(slots=True)
class _LinkState:
    """Per-connection state, discarded on every reconnect."""

    info: CompanionInfo | None = None
    time_responses: asyncio.Queue[int] = field(default_factory=lambda: asyncio.Queue(maxsize=4))


def parse_device_info(frame: bytes) -> tuple[int, str, str, str, int]:
    """Decode ``RESP_CODE_DEVICE_INFO``.

    Layout (MyMesh.cpp:1026)::

        [0]=13 [1]=ver_code [2]=max_contacts/2 [3]=max_channels [4:8]=ble_pin
        [8:20]=build_date [20:60]=manufacturer [60:80]=firmware_version
        [80]=repeater_enabled (v9+) [81]=path_hash_mode (v10+)

    The trailing fields are version-gated, so older firmware sends a shorter
    frame and we fall back rather than failing.
    """
    if len(frame) < DEVICE_INFO_MIN_LEN:
        raise CompanionError(
            f"device info frame too short: {len(frame)} bytes "
            f"(need {DEVICE_INFO_MIN_LEN}); is this a MeshCore companion node?"
        )

    version_code = frame[1]
    build_date = frame[8:20].split(b"\x00")[0].decode("utf-8", errors="replace")
    manufacturer = frame[20:60].split(b"\x00")[0].decode("utf-8", errors="replace")
    firmware_version = (
        frame[60:80].split(b"\x00")[0].decode("utf-8", errors="replace") if len(frame) >= 80 else ""
    )
    path_hash_mode = frame[81] if len(frame) >= 82 else 0
    return version_code, firmware_version, build_date, manufacturer, path_hash_mode


def parse_self_info(frame: bytes) -> tuple[bytes, str, int, int, int, int, int, int]:
    """Decode ``RESP_CODE_SELF_INFO``.

    Layout (MyMesh.cpp:1052)::

        [0]=5 [1]=adv_type [2]=tx_power [3]=max_tx_power [4:36]=public_key
        [36:40]=lat [40:44]=lon [44]=multi_acks [45]=advert_loc_policy
        [46]=telemetry_modes [47]=manual_add_contacts
        [48:52]=freq(kHz) [52:56]=bw(Hz) [56]=sf [57]=cr [58:]=node_name
    """
    if len(frame) < SELF_INFO_MIN_LEN:
        raise CompanionError(
            f"self info frame too short: {len(frame)} bytes (need {SELF_INFO_MIN_LEN})"
        )

    tx_power, max_tx_power = frame[2], frame[3]
    public_key = frame[4:36]
    frequency_khz, bandwidth_hz = struct.unpack_from("<II", frame, 48)
    spreading_factor, coding_rate = frame[56], frame[57]
    node_name = frame[58:].split(b"\x00")[0].decode("utf-8", errors="replace")
    return (
        public_key,
        node_name,
        tx_power,
        max_tx_power,
        frequency_khz,
        bandwidth_hz,
        spreading_factor,
        coding_rate,
    )


class CompanionLink:
    """Keeps a companion node connected and usable as a modem.

    :meth:`run` supervises the connection forever, reconnecting with capped
    exponential backoff. Callers use :meth:`wait_ready`, :meth:`send_packet` and
    :meth:`packets`, none of which care whether the link is currently up.
    """

    def __init__(
        self,
        transport_factory: Callable[[], Transport],
        *,
        app_name: str = "meshelle",
        heartbeat_interval: float = HEARTBEAT_INTERVAL,
        heartbeat_timeout: float = HEARTBEAT_TIMEOUT,
        reconnect_min_delay: float = RECONNECT_MIN_DELAY,
        reconnect_max_delay: float = RECONNECT_MAX_DELAY,
    ) -> None:
        self._make_transport = transport_factory
        self._app_name = app_name
        self._heartbeat_interval = heartbeat_interval
        self._heartbeat_timeout = heartbeat_timeout
        self._reconnect_min_delay = reconnect_min_delay
        self._reconnect_max_delay = reconnect_max_delay

        self._outbound: deque[_Outbound] = deque()
        self._outbound_ready = asyncio.Event()
        self._packets: asyncio.Queue[ReceivedPacket] = asyncio.Queue(maxsize=PACKET_QUEUE_SIZE)

        self._ready = asyncio.Event()
        self._state = _LinkState()
        self._transport: Transport | None = None
        self._stop = asyncio.Event()

    # -- public API ----------------------------------------------------------

    @property
    def info(self) -> CompanionInfo | None:
        """What the node reported, or None while disconnected."""
        return self._state.info

    @property
    def is_connected(self) -> bool:
        return self._ready.is_set()

    async def wait_ready(self) -> CompanionInfo:
        """Block until the node has completed its handshake.

        Rooms await this before sending their first advert, so the advert is
        never handed to a link that cannot carry it. Bound the wait at the call
        site with ``asyncio.timeout`` if you need one.
        """
        await self._ready.wait()
        info = self._state.info
        if info is None:  # pragma: no cover - set before _ready by design
            raise CompanionError("link reported ready without device info")
        return info

    async def send_packet(
        self,
        raw: bytes,
        *,
        priority: int = 0,
        ttl: float = DEFAULT_SEND_TTL,
        description: str = "packet",
    ) -> None:
        """Queue a raw packet for transmission.

        Returns as soon as it is queued. If the link is down the packet waits,
        which is the point: nothing is dropped merely because the serial port
        happened to be reconnecting.
        """
        if len(raw) > MAX_RAW_TX_PACKET:
            raise CompanionError(
                f"packet of {len(raw)} bytes exceeds the {MAX_RAW_TX_PACKET}-byte limit "
                f"imposed by the node's {MAX_RAW_TX_PACKET + 2}-byte frame buffer"
            )
        if not 0 <= priority <= 0xFF:
            raise CompanionError(f"priority must fit in a byte, got {priority}")

        self._outbound.append(
            _Outbound(
                payload=bytes([Cmd.SEND_RAW_PACKET, priority]) + raw,
                expires_at=time.monotonic() + ttl,
                description=description,
            )
        )
        self._outbound_ready.set()

    async def packets(self) -> AsyncIterator[ReceivedPacket]:
        """Yield every packet the node hears, for as long as the link runs."""
        while True:
            yield await self._packets.get()

    async def run(self) -> None:
        """Supervise the link forever, reconnecting on failure."""
        delay = self._reconnect_min_delay
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                # _session runs its loops in a TaskGroup, which wraps any child
                # failure in an ExceptionGroup. `except*` is what matches through
                # that wrapper -- a plain `except CompanionError` does not, and
                # would let every ordinary disconnect escape the supervisor
                # instead of reconnecting.
                await self._session()
            except* RawPacketUnsupportedError as group:
                # Reconnecting cannot conjure up a command the firmware lacks.
                # Re-raise the leaf, not the group: callers want an actionable
                # error, not an ExceptionGroup they have to unwrap.
                raise _first_leaf(group) from None
            except* (CompanionError, TransportError) as group:
                for exc in group.exceptions:
                    logger.error("companion link failed: %s", exc)
            finally:
                self._ready.clear()
                self._state = _LinkState()

            if self._stop.is_set():
                break

            # A connection that lasted a while is not a backoff-worthy failure.
            if time.monotonic() - started > 2 * self._reconnect_max_delay:
                delay = self._reconnect_min_delay

            logger.info("reconnecting to the companion in %.1fs", delay)
            # Sleep on the stop event rather than the clock, so shutdown is
            # prompt instead of waiting out a backoff of up to a minute.
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(delay):
                    await self._stop.wait()
            delay = min(delay * 2, self._reconnect_max_delay)

    async def stop(self) -> None:
        """Ask :meth:`run` to exit, interrupting any reconnect backoff."""
        self._stop.set()
        if self._transport is not None:
            await self._transport.close()

    # -- one connection ------------------------------------------------------

    async def _session(self) -> None:
        transport = self._make_transport()
        self._transport = transport
        try:
            await transport.connect()
            logger.info("connected to companion via %s", transport.description)

            info = await self._handshake(transport)
            self._state.info = info
            logger.info("companion: %s", info.summary())
            self._ready.set()

            async with asyncio.TaskGroup() as group:
                group.create_task(self._receive_loop(transport), name="companion-rx")
                group.create_task(self._send_loop(transport), name="companion-tx")
                group.create_task(self._heartbeat_loop(transport), name="companion-heartbeat")
        finally:
            self._ready.clear()
            with contextlib.suppress(Exception):
                await transport.close()
            self._transport = None

    async def _handshake(self, transport: Transport) -> CompanionInfo:
        """Identify the node and learn its radio settings.

        Bounded by :data:`HANDSHAKE_TIMEOUT` in total. meshcore-pi's equivalent
        does a bare ``readexactly(1)`` here, so a node that has stopped answering
        hangs the process instead of triggering a reconnect.
        """
        async with asyncio.timeout(HANDSHAKE_TIMEOUT):
            await transport.send_frame(bytes([Cmd.DEVICE_QUERY, COMPANION_API_VERSION]))
            device_frame = await self._expect(transport, RespCode.DEVICE_INFO)
            (
                version_code,
                firmware_version,
                build_date,
                manufacturer,
                path_hash_mode,
            ) = parse_device_info(device_frame)

            await transport.send_frame(
                bytes([Cmd.APP_START, 1]) + bytes(6) + self._app_name.encode("utf-8")
            )
            self_frame = await self._expect(transport, RespCode.SELF_INFO)
            (
                public_key,
                node_name,
                tx_power,
                max_tx_power,
                frequency_khz,
                bandwidth_hz,
                spreading_factor,
                coding_rate,
            ) = parse_self_info(self_frame)

        return CompanionInfo(
            firmware_version_code=version_code,
            firmware_version=firmware_version,
            build_date=build_date,
            manufacturer=manufacturer,
            path_hash_mode=path_hash_mode,
            public_key=public_key,
            node_name=node_name,
            tx_power_dbm=tx_power,
            max_tx_power_dbm=max_tx_power,
            frequency_khz=frequency_khz,
            bandwidth_hz=bandwidth_hz,
            spreading_factor=spreading_factor,
            coding_rate=coding_rate,
        )

    async def _expect(self, transport: Transport, code: RespCode) -> bytes:
        """Read frames until the expected response arrives.

        Unsolicited pushes can interleave with handshake replies -- the node may
        already be hearing adverts -- so anything unexpected is skipped rather
        than treated as a protocol error.
        """
        while True:
            frame = await transport.read_frame()
            if not frame:
                continue
            if frame[0] == code:
                return frame
            if frame[0] == RespCode.ERR:
                raise CompanionError(
                    f"companion rejected the handshake: {self._describe_error(frame)}"
                )
            logger.debug(
                "skipping frame 0x%02X while awaiting 0x%02X during handshake", frame[0], code
            )

    @staticmethod
    def _describe_error(frame: bytes) -> str:
        if len(frame) < 2:
            return "error with no code"
        try:
            return ErrCode(frame[1]).name
        except ValueError:
            return f"unknown error code {frame[1]}"

    async def _receive_loop(self, transport: Transport) -> None:
        while True:
            frame = await transport.read_frame()
            self._dispatch(frame)

    def _dispatch(self, frame: bytes) -> None:
        if not frame:
            logger.debug("ignoring empty frame from companion")
            return

        code = frame[0]

        if code == PushCode.LOG_RX_DATA:
            # [0x88][snr*4 int8][rssi int8][raw packet]
            if len(frame) < 4:
                logger.debug("rx-log frame carries no packet: %s", frame.hex())
                return
            snr_quarters, rssi = struct.unpack_from("<bb", frame, 1)
            packet = ReceivedPacket(raw=frame[3:], snr=snr_quarters / 4, rssi=rssi)
            try:
                self._packets.put_nowait(packet)
            except asyncio.QueueFull:
                logger.error(
                    "packet queue full (%d); dropping a received packet", PACKET_QUEUE_SIZE
                )
            return

        if code == RespCode.OK:
            # A bare one-byte ack for our last CMD_SEND_RAW_PACKET. Expected on
            # every successful transmit, and emphatically not a short frame.
            return

        if code == RespCode.CURR_TIME and len(frame) >= 5:
            with contextlib.suppress(asyncio.QueueFull):
                self._state.time_responses.put_nowait(struct.unpack_from("<I", frame, 1)[0])
            return

        if code == RespCode.ERR:
            if len(frame) >= 2 and frame[1] == ErrCode.UNSUPPORTED_CMD:
                raise RawPacketUnsupportedError(
                    "the companion firmware does not support CMD_SEND_RAW_PACKET (65), "
                    "so meshelle cannot transmit. Update the node to current MeshCore "
                    "firmware; the obsolete meshcore-pi 0xC0 patch is not what this uses."
                )
            logger.warning("companion reported an error: %s", self._describe_error(frame))
            return

        try:
            logger.debug("ignoring %s from companion", PushCode(code).name)
        except ValueError:
            logger.debug("ignoring unknown frame 0x%02X from companion", code)

    async def _send_loop(self, transport: Transport) -> None:
        """Drain the outbound queue while the link is up."""
        while True:
            if not self._outbound:
                self._outbound_ready.clear()
                await self._outbound_ready.wait()
                continue

            item = self._outbound[0]
            now = time.monotonic()
            if now > item.expires_at:
                self._outbound.popleft()
                logger.warning("dropping %s: queued too long to still be useful", item.description)
                continue

            try:
                await transport.send_frame(item.payload)
            except TransportClosedError:
                # Leave it queued; the next connection will carry it.
                raise
            self._outbound.popleft()
            logger.debug("sent %s (%d bytes)", item.description, len(item.payload) - 2)

    async def _heartbeat_loop(self, transport: Transport) -> None:
        """Probe liveness explicitly.

        Silence is not evidence of a dead link -- an idle mesh produces no
        frames at all -- so the node is asked for its clock instead. Any reply
        proves the serial path is alive in both directions.
        """
        while True:
            await asyncio.sleep(self._heartbeat_interval)

            while not self._state.time_responses.empty():
                self._state.time_responses.get_nowait()

            await transport.send_frame(bytes([Cmd.GET_DEVICE_TIME]))
            try:
                async with asyncio.timeout(self._heartbeat_timeout):
                    await self._state.time_responses.get()
            except TimeoutError as exc:
                raise CompanionError(
                    f"companion stopped answering (no clock reply in {self._heartbeat_timeout}s)"
                ) from exc

    # -- diagnostics ---------------------------------------------------------

    async def probe_raw_packet_support(self, transport: Transport) -> bool:
        """Check for ``CMD_SEND_RAW_PACKET`` **without transmitting anything**.

        Sends a deliberately malformed 2-byte packet (a header and path length
        with no payload). ``tryParsePacket`` rejects it, so the node answers
        ``ERR_CODE_ILLEGAL_ARG`` and nothing reaches the air. Firmware lacking
        the command falls through to ``ERR_CODE_UNSUPPORTED_CMD`` instead, which
        is exactly the distinction ``doctor`` needs.
        """
        await transport.send_frame(bytes([Cmd.SEND_RAW_PACKET, 0, 0x01, 0x00]))

        async with asyncio.timeout(HEARTBEAT_TIMEOUT):
            while True:
                frame = await transport.read_frame()
                if not frame or frame[0] != RespCode.ERR or len(frame) < 2:
                    continue
                if frame[1] == ErrCode.UNSUPPORTED_CMD:
                    return False
                if frame[1] == ErrCode.ILLEGAL_ARG:
                    return True
                logger.debug("unexpected probe error %s", self._describe_error(frame))
