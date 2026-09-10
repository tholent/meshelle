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

"""Demultiplexing packets across the rooms hosted on one companion node.

Everything the node hears arrives here: traffic for our rooms, traffic for other
people's nodes, and our own packets echoed back by repeaters. The dispatcher's
job is to work out which of those a packet is, cheaply, and hand the survivors
to a room.

**Addressing is one byte.** A datagram names its destination by
``public_key[0]``, so 256 destinations share a namespace with every node on the
mesh. That means:

* a packet addressed to ``0x7A`` may be for our room, for someone else's node,
  or for two of our own rooms at once;
* the only way to tell is to try the decryption -- a matching 2-byte MAC is the
  proof, and a mismatch is the *normal* case, not an error.

So the dispatcher gathers every room whose hash matches and offers the packet to
each in turn until one claims it. Firmware does exactly this
(``searchPeersByHash`` returns up to four candidates), and it is why
:class:`meshelle.proto.crypto.DecryptionError` is logged at debug and no higher.

The dispatcher is also the only place that transmits, which is deliberate: it
lets every outbound packet be marked in the seen-table before it goes out, so
the repeater's re-broadcast of our own packet is recognised and dropped rather
than being processed as an inbound message.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from typing import Protocol

from meshelle.companion.link import ReceivedPacket
from meshelle.mesh.dedupe import SeenTable
from meshelle.proto.constants import PayloadType
from meshelle.proto.packet import AnonRequest, Datagram, Packet, PacketError
from meshelle.room.stats import RadioStats

logger = logging.getLogger(__name__)

ADDRESSED_TYPES = frozenset(
    {
        PayloadType.REQ,
        PayloadType.RESPONSE,
        PayloadType.TXT_MSG,
        PayloadType.PATH,
    }
)
"""Payload types carrying a ``[dest_hash][src_hash]`` datagram header."""


class PacketSender(Protocol):
    """The half of :class:`~meshelle.companion.link.CompanionLink` we transmit through."""

    async def send_packet(
        self,
        raw: bytes,
        *,
        priority: int = 0,
        ttl: float = ...,
        description: str = ...,
    ) -> None: ...


class PacketSink(Protocol):
    """What a room server transmits through. Implemented by :class:`Dispatcher`."""

    async def send(
        self,
        packet: Packet,
        *,
        priority: int = 0,
        ttl: float | None = None,
        description: str = "packet",
    ) -> None: ...


class RoomHandler(Protocol):
    """The dispatcher's view of a room server.

    Structural, so :mod:`meshelle.mesh` never imports :mod:`meshelle.room` --
    the room imports :class:`PacketSink` from here, and a cycle would be the
    price of naming the concrete class.
    """

    @property
    def slug(self) -> str: ...

    @property
    def node_hash(self) -> int:
        """The first byte of this room's public key: its address on the mesh."""
        ...

    async def handle(self, packet: Packet, received: ReceivedPacket) -> bool:
        """Try to claim a packet. ``True`` means it decrypted and was handled."""
        ...


class Dispatcher:
    """Routes inbound packets to rooms, and outbound packets to the node."""

    def __init__(
        self,
        sender: PacketSender,
        rooms: list[RoomHandler],
        *,
        seen: SeenTable | None = None,
        radio: RadioStats | None = None,
    ) -> None:
        self._sender = sender
        self._rooms = list(rooms)
        self._seen = seen if seen is not None else SeenTable()
        self.radio = radio if radio is not None else RadioStats()

        # Rooms indexed by their node hash. A list per hash, because two of our
        # own rooms can collide on one byte just as easily as strangers do.
        self._by_hash: dict[int, list[RoomHandler]] = {}
        for room in self._rooms:
            self._by_hash.setdefault(room.node_hash, []).append(room)

    def add_room(self, room: RoomHandler) -> None:
        """Attach a room after construction.

        The two objects need each other: a room transmits through the
        dispatcher, and the dispatcher routes to the room. One of them has to be
        attachable afterwards, and it is this one -- a room handed a sink it
        could not yet use would be a room whose first advert goes nowhere.
        """
        self._rooms.append(room)
        self._by_hash.setdefault(room.node_hash, []).append(room)

    # -- transmit ------------------------------------------------------------

    async def send(
        self,
        packet: Packet,
        *,
        priority: int = 0,
        ttl: float | None = None,
        description: str = "packet",
    ) -> None:
        """Mark a packet as seen, then queue it for transmission.

        Marking before sending, not after, because the echo can arrive while
        ``send_packet`` is still awaiting the serial write.
        """
        self._seen.mark(packet.packet_hash)

        self.radio.packets_sent += 1
        if packet.route_type.is_flood:
            self.radio.sent_flood += 1
        else:
            self.radio.sent_direct += 1

        raw = packet.encode()
        if ttl is None:
            await self._sender.send_packet(raw, priority=priority, description=description)
        else:
            await self._sender.send_packet(raw, priority=priority, ttl=ttl, description=description)

    # -- receive -------------------------------------------------------------

    async def dispatch(self, received: ReceivedPacket) -> bool:
        """Handle one packet off the air. ``True`` if a room claimed it."""
        try:
            packet = Packet.decode(received.raw)
        except (PacketError, ValueError) as exc:
            # Radio bit errors reach us as malformed packets, and so does every
            # protocol meshelle does not implement. Neither is an error here.
            logger.debug("undecodable packet (%s): %s", exc, received.raw[:16].hex())
            self.radio.err_events += 1
            return False

        self.radio.packets_recv += 1
        self.radio.last_rssi = received.rssi
        self.radio.last_snr_quarters = int(received.snr * 4)
        is_flood = packet.route_type.is_flood
        if is_flood:
            self.radio.recv_flood += 1
        else:
            self.radio.recv_direct += 1

        if self._seen.check_and_mark(packet.packet_hash):
            # Either a genuine duplicate from a second repeater, or our own
            # transmission coming back. Both are counted, neither is handled.
            if is_flood:
                self.radio.flood_dups += 1
            else:
                self.radio.direct_dups += 1
            logger.debug("duplicate %s packet, ignored", packet.payload_type.name)
            return False

        return await self._route(packet, received)

    async def _route(self, packet: Packet, received: ReceivedPacket) -> bool:
        candidates = self._candidates(packet)
        if candidates is None:
            return False

        for room in candidates:
            if await room.handle(packet, received):
                return True

        logger.debug(
            "no room claimed a %s packet (%d candidate(s))",
            packet.payload_type.name,
            len(candidates),
        )
        return False

    def _candidates(self, packet: Packet) -> list[RoomHandler] | None:
        """Rooms worth offering this packet to, or ``None`` to drop it."""
        if packet.payload_type is PayloadType.ACK:
            # An ACK carries no destination at all -- just a 4-byte hash -- so
            # every room has to check it against what it is waiting for.
            return self._rooms

        if packet.payload_type is PayloadType.ANON_REQ:
            try:
                dest_hash = AnonRequest.decode(packet.payload).dest_hash
            except PacketError as exc:
                logger.debug("malformed anon request: %s", exc)
                return None
            return self._by_hash.get(dest_hash, [])

        if packet.payload_type in ADDRESSED_TYPES:
            try:
                dest_hash = Datagram.decode(packet.payload).dest_hash
            except PacketError as exc:
                logger.debug("malformed datagram: %s", exc)
                return None
            return self._by_hash.get(dest_hash, [])

        # ADVERT above all: a room learns a client's public key from the login
        # itself, so it keeps no contact book and an advert tells it nothing.
        # Our own room adverts come back to us here too (the node auto-adds
        # them as contacts), which is why this is debug and not a warning.
        logger.debug("ignoring %s packet", packet.payload_type.name)
        return None

    async def run(self, packets: AsyncIterator[ReceivedPacket]) -> None:
        """Consume received packets until the stream ends.

        Nothing is awaited between packets other than ``dispatch`` itself, and
        ``dispatch`` never waits on a reply -- delayed sends go to the
        scheduler. A room that blocked here would drop everything else in
        earshot for the length of the delay.
        """
        async for received in packets:
            await self.dispatch(received)
