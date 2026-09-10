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

"""Login: the 13 bytes that decide whether a room is usable at all."""

from __future__ import annotations

from meshelle.proto.constants import PayloadType, Permission, RouteType
from meshelle.proto.identity import LocalIdentity
from meshelle.store import repo
from meshelle.store.db import Store
from tests.fakes.client import FakeClient, LoginOk, PathReceived, assert_login_grants
from tests.fakes.room import build_room, room_settings


async def test_a_read_write_client_is_told_it_may_post(store: Store) -> None:
    """Protocol semantics: byte 7 of the login response is the client's
    permission level (MyMesh.cpp:381), and an app shows a compose box only when
    it reads READ_WRITE or better.

    meshcore-pi hardcodes a zero here, which is why every room it hosts is
    read-only in current apps. This assertion is the reason this project exists,
    and it cannot be checked any other way -- the byte is invisible in logs.
    """
    room = await build_room(store, room_settings(allow_unknown="read_write"))
    client = FakeClient(room.identity.public_key)

    await room.deliver(client.login(timestamp=1000))

    path = client.receive(room.sink.last)
    assert isinstance(path, PathReceived)
    reply = assert_login_grants(path.response, Permission.READ_WRITE)
    assert reply.may_post is True
    await room.aclose()


async def test_an_admin_member_is_granted_admin(store: Store) -> None:
    admin = LocalIdentity.generate()
    room = await build_room(
        store,
        room_settings(members=[{"pubkey": admin.public_key.hex(), "role": "admin"}]),
    )
    client = FakeClient(room.identity.public_key, admin)

    await room.deliver(client.login(timestamp=1000))

    path = client.receive(room.sink.last)
    assert isinstance(path, PathReceived)
    reply = assert_login_grants(path.response, Permission.ADMIN)
    # Byte 6 is the legacy admin flag older apps read before byte 7 existed.
    assert reply.legacy_admin == 1
    await room.aclose()


async def test_a_guest_gets_the_legacy_flag_that_marks_a_zero_permission(
    store: Store,
) -> None:
    """Firmware sets byte 6 to 2 when the whole permissions byte is zero
    (MyMesh.cpp:380), which is how an older app tells "guest" from "unknown"."""
    room = await build_room(store, room_settings(allow_unknown="guest"))
    client = FakeClient(room.identity.public_key)

    await room.deliver(client.login(timestamp=1000))

    path = client.receive(room.sink.last)
    assert isinstance(path, PathReceived)
    reply = assert_login_grants(path.response, Permission.GUEST)
    assert reply.legacy_admin == 2
    assert reply.may_post is False
    await room.aclose()


async def test_a_refused_login_gets_no_reply_at_all(store: Store) -> None:
    """Protocol semantics: an error packet would confirm the room exists and
    that the password was wrong. Silence makes a refusal indistinguishable from
    being out of range, which is what denies an attacker a password oracle.
    """
    room = await build_room(
        store, room_settings(passwords={"admin": "hunter2"}, allow_unknown="reject")
    )
    client = FakeClient(room.identity.public_key)

    claimed = await room.deliver(client.login(timestamp=1000, password="wrong"))

    assert claimed is True  # it was ours: the MAC verified
    assert room.sink.sent == []
    await room.aclose()


async def test_a_flooded_login_is_answered_with_a_path_return(store: Store) -> None:
    """Protocol semantics (MyMesh.cpp:389): a flooded login is answered with a
    PAYLOAD_TYPE_PATH packet carrying the response inside it. That is not an
    optimisation -- it is how the client learns the route here. A plain RESPONSE
    would answer the question and leave the client flooding forever.
    """
    room = await build_room(store, room_settings())
    client = FakeClient(room.identity.public_key, path_to_room=b"\xaa\xbb")

    await room.deliver(client.login(timestamp=1000, flood=True))

    sent = room.sink.last
    assert sent.payload_type is PayloadType.PATH
    assert sent.route_type is RouteType.FLOOD
    path = client.receive(sent)
    assert isinstance(path, PathReceived)
    # The path the client is handed is the one its own packet accumulated, so it
    # can replay it verbatim -- no reversal happens anywhere in MeshCore.
    assert path.path == b"\xaa\xbb"
    assert isinstance(path.response, LoginOk)
    await room.aclose()


async def test_a_direct_login_is_answered_with_a_plain_response(store: Store) -> None:
    room = await build_room(store, room_settings())
    client = FakeClient(room.identity.public_key)

    await room.deliver(client.login(timestamp=1000, flood=True))
    room.sink.clear()
    client.out_path = b"\x0c"
    await room.deliver(client.path_return())
    room.sink.clear()

    await room.deliver(client.login(timestamp=2000, flood=False))

    sent = room.sink.last
    assert sent.payload_type is PayloadType.RESPONSE
    assert sent.route_type is RouteType.DIRECT
    assert_login_grants(client.receive(sent), Permission.READ_WRITE)
    await room.aclose()


async def test_a_flooded_login_discards_a_known_return_path(store: Store) -> None:
    """Protocol semantics (MyMesh.cpp:377): a login that arrived the long way
    round proves the stored route is no longer working. Replying over it would
    send the answer down a path the client is no longer reachable on.
    """
    room = await build_room(store, room_settings())
    client = FakeClient(room.identity.public_key, path_to_room=b"\x0c")

    await room.deliver(client.login(timestamp=1000, flood=True))
    await room.deliver(client.path_return())
    session = room.server.sessions[client.public_key]
    assert session.has_out_path

    await room.deliver(client.login(timestamp=2000, flood=True))

    assert not room.server.sessions[client.public_key].has_out_path
    await room.aclose()


async def test_a_replayed_login_is_refused(store: Store) -> None:
    """Protocol semantics (MyMesh.cpp:355): a login must carry a strictly newer
    timestamp than anything already seen from that key, so a captured ANON_REQ
    cannot be replayed to re-enter the room."""
    room = await build_room(store, room_settings())
    client = FakeClient(room.identity.public_key)
    replayed = client.login(timestamp=1000)

    await room.deliver(replayed)
    room.sink.clear()
    await room.deliver(replayed)

    assert room.sink.sent == []
    await room.aclose()


async def test_the_login_records_the_clients_sync_position(store: Store) -> None:
    """The client tells us the newest post it holds, so we push only what it is
    missing rather than replaying the whole room."""
    room = await build_room(store, room_settings())
    client = FakeClient(room.identity.public_key)

    await room.deliver(client.login(timestamp=1000, sync_since=4242))

    stored = await store.run(lambda s: repo.get_client(s, room.room_id, client.public_key))
    assert stored is not None
    assert stored.sync_since == 4242
    assert room.server.sessions[client.public_key].sync_since == 4242
    await room.aclose()


async def test_two_logins_in_one_second_produce_different_packets(store: Store) -> None:
    """Protocol semantics: packet_hash covers the payload, so two identical
    replies would hash identically and every repeater would suppress the second
    as a duplicate. The random blob and the unique timestamp prevent that.
    """
    room = await build_room(store, room_settings())
    first = FakeClient(room.identity.public_key)
    second = FakeClient(room.identity.public_key)

    await room.deliver(first.login(timestamp=1000))
    await room.deliver(second.login(timestamp=1000))

    hashes = {packet.packet_hash for packet in room.sink.sent}
    assert len(hashes) == len(room.sink.sent) == 2
    await room.aclose()
