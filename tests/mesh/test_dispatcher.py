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

"""Demultiplexing: which room, if any, gets a packet off the air."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass, field

from meshelle.companion.link import ReceivedPacket
from meshelle.mesh.dedupe import SeenTable
from meshelle.mesh.dispatcher import Dispatcher
from meshelle.proto.constants import PayloadType, RouteType
from meshelle.proto.packet import Ack, AnonRequest, Datagram, Packet
from meshelle.room.stats import RadioStats


@dataclass
class RecordingRoom:
    """A room that claims packets on demand and remembers what it was offered."""

    slug: str
    node_hash: int
    claims: bool = True
    offered: list[Packet] = field(default_factory=list)

    async def handle(self, packet: Packet, received: ReceivedPacket) -> bool:
        self.offered.append(packet)
        return self.claims


@dataclass
class RecordingSender:
    frames: list[bytes] = field(default_factory=list)

    async def send_packet(
        self,
        raw: bytes,
        *,
        priority: int = 0,
        ttl: float = 30.0,
        description: str = "packet",
    ) -> None:
        self.frames.append(raw)


def heard(packet: Packet) -> ReceivedPacket:
    return ReceivedPacket(raw=packet.encode(), snr=6.5, rssi=-71)


def datagram_packet(dest_hash: int, *, src_hash: int = 0x11) -> Packet:
    payload = Datagram(dest_hash=dest_hash, src_hash=src_hash, sealed=b"\x00" * 18).encode()
    return Packet(route_type=RouteType.FLOOD, payload_type=PayloadType.TXT_MSG, payload=payload)


def anon_packet(dest_hash: int, public_key: bytes) -> Packet:
    payload = AnonRequest(
        dest_hash=dest_hash, sender_public_key=public_key, sealed=b"\x00" * 18
    ).encode()
    return Packet(route_type=RouteType.FLOOD, payload_type=PayloadType.ANON_REQ, payload=payload)


async def test_a_packet_reaches_the_room_it_is_addressed_to() -> None:
    lobby, den = RecordingRoom("lobby", 0x7A), RecordingRoom("den", 0x1B)
    dispatcher = Dispatcher(RecordingSender(), [lobby, den])

    await dispatcher.dispatch(heard(datagram_packet(0x1B)))

    assert not lobby.offered
    assert len(den.offered) == 1


async def test_two_rooms_sharing_a_destination_hash_are_both_offered_it() -> None:
    """Protocol semantics: a destination is one byte, so two of our own rooms
    can collide on it just as easily as strangers do. The MAC is what
    disambiguates, so the packet must reach the second room when the first
    cannot decrypt it -- otherwise the colliding room is silently unreachable.
    """
    first = RecordingRoom("first", 0x7A, claims=False)
    second = RecordingRoom("second", 0x7A, claims=True)
    dispatcher = Dispatcher(RecordingSender(), [first, second])

    claimed = await dispatcher.dispatch(heard(datagram_packet(0x7A)))

    assert claimed is True
    assert len(first.offered) == 1
    assert len(second.offered) == 1


async def test_an_anon_request_is_routed_by_its_own_destination_byte() -> None:
    """ANON_REQ has a different payload shape -- the sender's whole public key
    sits where a datagram's source hash would be -- so its destination must be
    read with the right decoder, not the datagram one."""
    lobby = RecordingRoom("lobby", 0x33)
    dispatcher = Dispatcher(RecordingSender(), [lobby])

    await dispatcher.dispatch(heard(anon_packet(0x33, bytes(range(32)))))

    assert len(lobby.offered) == 1


async def test_an_ack_is_offered_to_every_room() -> None:
    """Protocol semantics: an ACK payload is a bare 4-byte hash with no
    addressing at all, so the only way to find its owner is to ask everyone what
    they are waiting for."""
    lobby = RecordingRoom("lobby", 0x7A, claims=False)
    den = RecordingRoom("den", 0x1B, claims=True)
    dispatcher = Dispatcher(RecordingSender(), [lobby, den])

    ack = Packet(
        route_type=RouteType.DIRECT,
        payload_type=PayloadType.ACK,
        payload=Ack(checksum=b"\xde\xad\xbe\xef").encode(),
    )
    claimed = await dispatcher.dispatch(heard(ack))

    assert claimed is True
    assert len(lobby.offered) == 1
    assert len(den.offered) == 1


async def test_our_own_transmission_is_not_handled_when_it_echoes_back() -> None:
    """The node hears the repeater re-broadcasting what we just sent and mirrors
    it to us. Marking at send time is what makes that recognisable."""
    lobby = RecordingRoom("lobby", 0x7A)
    dispatcher = Dispatcher(RecordingSender(), [lobby])
    ours = datagram_packet(0x7A)

    await dispatcher.send(ours)
    await dispatcher.dispatch(heard(ours))

    assert lobby.offered == []


async def test_a_duplicate_from_a_second_repeater_is_dropped_and_counted() -> None:
    lobby = RecordingRoom("lobby", 0x7A)
    radio = RadioStats()
    dispatcher = Dispatcher(RecordingSender(), [lobby], radio=radio)
    packet = datagram_packet(0x7A)

    await dispatcher.dispatch(heard(packet))
    await dispatcher.dispatch(heard(packet))

    assert len(lobby.offered) == 1
    assert radio.flood_dups == 1
    assert radio.packets_recv == 2


async def test_a_packet_for_nobody_here_is_dropped_without_a_candidate() -> None:
    lobby = RecordingRoom("lobby", 0x7A)
    dispatcher = Dispatcher(RecordingSender(), [lobby])

    claimed = await dispatcher.dispatch(heard(datagram_packet(0xC4)))

    assert claimed is False
    assert lobby.offered == []


async def test_adverts_are_ignored_entirely() -> None:
    """A room learns a client's public key from the login itself, so it keeps no
    contact book and an advert tells it nothing. Our own room adverts come back
    here too, since the node auto-adds them as contacts."""
    lobby = RecordingRoom("lobby", 0x7A)
    dispatcher = Dispatcher(RecordingSender(), [lobby])
    advert = Packet(
        route_type=RouteType.FLOOD, payload_type=PayloadType.ADVERT, payload=b"\x00" * 100
    )

    assert await dispatcher.dispatch(heard(advert)) is False
    assert lobby.offered == []


async def test_radio_noise_is_counted_not_raised() -> None:
    """Bit errors reach us as undecodable packets. One must not escape into the
    receive loop and stop the room hearing anything else."""
    radio = RadioStats()
    dispatcher = Dispatcher(RecordingSender(), [], radio=radio)

    claimed = await dispatcher.dispatch(ReceivedPacket(raw=b"\x04", snr=1.0, rssi=-99))

    assert claimed is False
    assert radio.err_events == 1


async def test_sending_records_route_and_marks_the_packet_seen() -> None:
    sender = RecordingSender()
    seen = SeenTable()
    radio = RadioStats()
    dispatcher = Dispatcher(sender, [], seen=seen, radio=radio)
    packet = datagram_packet(0x7A)

    await dispatcher.send(packet)

    assert sender.frames == [packet.encode()]
    assert radio.packets_sent == 1
    assert radio.sent_flood == 1
    assert seen.check_and_mark(packet.packet_hash) is True


async def test_radio_metadata_follows_the_most_recent_packet() -> None:
    radio = RadioStats()
    dispatcher = Dispatcher(RecordingSender(), [], radio=radio)

    await dispatcher.dispatch(
        ReceivedPacket(raw=datagram_packet(0x01).encode(), snr=-2.5, rssi=-108)
    )

    assert radio.last_rssi == -108
    # SNR travels as a signed byte of quarter-dB, so it is stored that way
    # rather than round-tripped through a float.
    assert radio.last_snr_quarters == -10


async def test_a_truncated_datagram_names_no_candidate_room() -> None:
    """A payload too short to hold a MAC cannot be addressed to anyone. Letting
    the decode error escape would stop the receive loop."""
    lobby = RecordingRoom("lobby", 0x7A)
    dispatcher = Dispatcher(RecordingSender(), [lobby])
    runt = Packet(
        route_type=RouteType.FLOOD, payload_type=PayloadType.TXT_MSG, payload=b"\x7a\x11\x00"
    )

    assert await dispatcher.dispatch(heard(runt)) is False
    assert lobby.offered == []


async def test_a_truncated_anon_request_names_no_candidate_room() -> None:
    lobby = RecordingRoom("lobby", 0x7A)
    dispatcher = Dispatcher(RecordingSender(), [lobby])
    runt = Packet(
        route_type=RouteType.FLOOD, payload_type=PayloadType.ANON_REQ, payload=b"\x7a\x00"
    )

    assert await dispatcher.dispatch(heard(runt)) is False
    assert lobby.offered == []


async def test_a_send_with_a_ttl_passes_it_through() -> None:
    """Adverts are queued with a much longer TTL than acknowledged traffic, so
    one waiting out a reconnect is still worth transmitting when the link
    returns."""
    sender = TtlRecordingSender()
    dispatcher = Dispatcher(sender, [])

    await dispatcher.send(datagram_packet(0x7A), ttl=600.0, description="advert")

    assert sender.ttls == [600.0]


async def test_run_consumes_the_stream_until_it_ends() -> None:
    """The dispatcher owns the link's packet iterator: nothing else drains it,
    so a packet not consumed here is a packet nobody ever sees."""
    lobby = RecordingRoom("lobby", 0x7A)
    dispatcher = Dispatcher(RecordingSender(), [lobby])
    packets = [datagram_packet(0x7A, src_hash=n) for n in range(3)]

    async def stream() -> AsyncIterator[ReceivedPacket]:
        for packet in packets:
            yield heard(packet)

    await dispatcher.run(stream())

    assert len(lobby.offered) == 3


@dataclass
class TtlRecordingSender:
    ttls: list[float] = field(default_factory=list)

    async def send_packet(
        self,
        raw: bytes,
        *,
        priority: int = 0,
        ttl: float = 30.0,
        description: str = "packet",
    ) -> None:
        self.ttls.append(ttl)
