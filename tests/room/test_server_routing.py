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

"""One-byte addressing, adverts, restarts, and configuration reloads."""

from __future__ import annotations

from meshelle.companion.link import ReceivedPacket
from meshelle.config.model import Role
from meshelle.mesh.dispatcher import Dispatcher
from meshelle.proto.advert import Advert
from meshelle.proto.constants import AdvertType, PayloadType, Permission, RouteType
from meshelle.proto.identity import LocalIdentity
from meshelle.store.db import Store
from tests.fakes.client import FakeClient, PathReceived, PushedPost, assert_login_grants
from tests.fakes.room import build_room, drain, room_settings


def with_first_byte(byte: int) -> LocalIdentity:
    """An identity whose public key starts with a chosen byte.

    Generating until it matches is how a colliding pair is obtained honestly:
    a handcrafted key would not have a usable private half.
    """
    while True:
        identity = LocalIdentity.generate()
        if identity.node_hash == byte:
            return identity


# -- hash collisions --------------------------------------------------------


async def test_two_rooms_sharing_a_destination_hash_stay_independent(
    store: Store,
) -> None:
    """Protocol semantics: a destination is one byte, so two rooms on one node
    can collide -- and with 256 buckets the birthday bound bites at about 20.

    The MAC is what disambiguates. A dispatcher that stopped at the first room
    whose hash matched would make the second room permanently unreachable, and
    the symptom would be a room that simply never answers.
    """
    first_identity = with_first_byte(0x5A)
    second_identity = with_first_byte(0x5A)
    lobby = await build_room(
        store, room_settings(name="Lobby"), slug="lobby", identity=first_identity
    )
    den = await build_room(store, room_settings(name="Den"), slug="den", identity=second_identity)
    assert lobby.server.node_hash == den.server.node_hash

    dispatcher = Dispatcher(_NullSender(), [lobby.server, den.server])
    client = FakeClient(den.identity.public_key)

    login = client.login(timestamp=1000)
    await dispatcher.dispatch(ReceivedPacket(raw=login.encode(), snr=5.0, rssi=-70))
    await drain(den.scheduler)

    assert lobby.sink.sent == []
    path = client.receive(den.sink.last)
    assert isinstance(path, PathReceived)
    assert_login_grants(path.response, Permission.READ_WRITE)
    await lobby.aclose()
    await den.aclose()


async def test_two_clients_sharing_a_source_hash_are_told_apart(store: Store) -> None:
    """The same collision on the way in: a room picks the sender by trying each
    candidate's shared secret. Taking the first hash match would attribute one
    client's post to another, and encrypt the reply so only the wrong one could
    read it.
    """
    room = await build_room(store, room_settings())
    alice = FakeClient(room.identity.public_key, with_first_byte(0x3C), path_to_room=b"\x0a")
    bob = FakeClient(room.identity.public_key, with_first_byte(0x3C), path_to_room=b"\x0b")
    assert alice.node_hash == bob.node_hash

    for index, client in enumerate((alice, bob)):
        await room.deliver(client.login(timestamp=1000 + index))
        await room.deliver(client.path_return())
    room.sink.clear()

    await room.deliver(bob.post("this is bob", timestamp=1100))

    ack = room.sink.of_type(PayloadType.ACK)[0]
    assert ack.path == b"\x0b", "the ACK went to bob's route, not alice's"
    await room.aclose()


# -- adverts ----------------------------------------------------------------


async def test_a_flood_advert_carries_the_rooms_name_and_type(store: Store) -> None:
    """This is how a client discovers the room at all: an app adds a contact
    from an advert, and ADV_TYPE_ROOM is what makes it appear as a room rather
    than as a chat peer."""
    room = await build_room(store, room_settings(name="The Lobby"))

    await room.server.send_advert(flood=True)

    packet = room.sink.last
    assert packet.payload_type is PayloadType.ADVERT
    assert packet.route_type is RouteType.FLOOD
    advert = Advert.decode(packet.payload)
    assert advert.is_valid, "a client verifies the signature before adding a contact"
    assert advert.public_key == room.identity.public_key
    assert advert.data.node_type is AdvertType.ROOM
    assert advert.data.name == "The Lobby"
    await room.aclose()


async def test_a_zero_hop_advert_is_a_direct_packet_with_no_path(store: Store) -> None:
    """Protocol semantics (``Mesh::sendZeroHop``): "zero hop" is DIRECT with an
    empty path, not a flood with a hop limit. Sending it as a flood would put a
    mesh-wide advert on the air every thirty minutes."""
    room = await build_room(store, room_settings())

    await room.server.send_advert(flood=False)

    packet = room.sink.last
    assert packet.route_type is RouteType.DIRECT
    assert packet.path == b""
    await room.aclose()


async def test_two_adverts_in_one_second_are_distinct_packets(store: Store) -> None:
    """An advert's signature covers its timestamp, so a repeated timestamp gives
    a byte-identical packet that every repeater suppresses as a duplicate."""
    room = await build_room(store, room_settings())

    await room.server.send_advert(flood=True)
    await room.server.send_advert(flood=False)

    assert room.sink.sent[0].packet_hash != room.sink.sent[1].packet_hash
    await room.aclose()


# -- restarts and reloads ---------------------------------------------------


async def test_a_restart_restores_clients_so_pushes_resume(store: Store) -> None:
    """Without rehydration a restart would leave every client's owed posts
    unsent until it happened to log in again -- and a client with a working
    return path may not log in for hours."""
    room = await build_room(store, room_settings())
    alice = FakeClient(room.identity.public_key, path_to_room=b"\x0a")
    bob = FakeClient(room.identity.public_key, path_to_room=b"\x0b")
    for index, client in enumerate((alice, bob)):
        await room.deliver(client.login(timestamp=1000 + index))
        await room.deliver(client.path_return())
    await room.deliver(alice.post("before the restart", timestamp=1100))
    await room.aclose()

    restarted = await build_room(store, room.settings, identity=room.identity, clock=room.clock)
    restarted.clock.advance(7)

    assert set(restarted.server.sessions) == {alice.public_key, bob.public_key}
    # The stored return path survives, so the resumed push goes direct.
    assert restarted.server.sessions[bob.public_key].out_path == b"\x0b"
    for _ in range(6):
        if await restarted.server.push_once():
            await drain(restarted.scheduler)
            if isinstance(bob.receive(restarted.sink.last), PushedPost):
                break
    else:
        raise AssertionError("the resumed room never pushed to bob")
    await restarted.aclose()


async def test_a_restart_does_not_restore_a_password_earned_role(store: Store) -> None:
    """The password a client used is never recorded, so a restart cannot
    re-verify it. Restoring the role anyway would mean removing a password from
    the config achieved nothing until every client happened to log in again.
    """
    settings = room_settings(passwords={"admin": "hunter2"}, allow_unknown="reject")
    room = await build_room(store, settings)
    client = FakeClient(room.identity.public_key, path_to_room=b"\x0c")
    await room.deliver(client.login(timestamp=1000, password="hunter2"))
    assert room.server.sessions[client.public_key].role is Role.ADMIN
    await room.aclose()

    restarted = await build_room(store, settings, identity=room.identity, clock=room.clock)

    assert restarted.server.sessions[client.public_key].role is Role.GUEST
    await restarted.aclose()


async def test_a_reload_demotes_a_member_removed_from_the_config(store: Store) -> None:
    """SIGHUP re-resolves declared members immediately. A revoked role that
    survived until the next login would make the reload look like it worked
    while the room kept honouring the old one."""
    member = LocalIdentity.generate()
    room = await build_room(
        store,
        room_settings(members=[{"pubkey": member.public_key.hex(), "role": "admin"}]),
    )
    client = FakeClient(room.identity.public_key, member, path_to_room=b"\x0c")
    await room.deliver(client.login(timestamp=1000))
    assert room.server.sessions[client.public_key].role is Role.ADMIN

    room.server.apply_settings(room_settings(allow_unknown="read_only"))

    assert room.server.sessions[client.public_key].role is Role.READ_ONLY
    await room.aclose()


async def test_a_reload_keeps_the_sync_cursor(store: Store) -> None:
    """A reload must not cost a client its place, or every client would be sent
    the whole room again after an unrelated config change."""
    room = await build_room(store, room_settings())
    client = FakeClient(room.identity.public_key, path_to_room=b"\x0c")
    await room.deliver(client.login(timestamp=1000, sync_since=4242))

    room.server.apply_settings(room_settings(name="Renamed"))

    assert room.server.sessions[client.public_key].sync_since == 4242
    await room.aclose()


class _NullSender:
    async def send_packet(
        self,
        raw: bytes,
        *,
        priority: int = 0,
        ttl: float = 30.0,
        description: str = "packet",
    ) -> None:
        return None
