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

"""Keep-alives, status and access-list requests, and the over-the-air console."""

from __future__ import annotations

import struct

from meshelle.proto.constants import PayloadType, Permission, ReqType, RouteType
from meshelle.proto.identity import LocalIdentity
from meshelle.proto.packet import Datagram
from meshelle.room.stats import ServerStats
from meshelle.store import repo
from meshelle.store.db import Store
from tests.fakes.client import AckFrame, CliReply, FakeClient, PathReceived
from tests.fakes.room import RoomHarness, build_room, room_settings


async def with_admin(store: Store, **settings: object) -> tuple[RoomHarness, FakeClient]:
    admin = LocalIdentity.generate()
    members = [{"pubkey": admin.public_key.hex(), "role": "admin"}]
    room = await build_room(store, room_settings(members=members, **settings))
    client = FakeClient(room.identity.public_key, admin, path_to_room=b"\x0c")
    await room.deliver(client.login(timestamp=1000))
    await room.deliver(client.path_return())
    room.sink.clear()
    return room, client


# -- keep-alive -------------------------------------------------------------


async def test_a_keep_alive_is_answered_with_the_unsynced_count(store: Store) -> None:
    """Protocol semantics (MyMesh.cpp:576): the room appends a count byte to the
    ACK, which is how an app shows "3 messages waiting" without waiting for
    them to arrive."""
    room, admin = await with_admin(store)
    poster = FakeClient(room.identity.public_key, path_to_room=b"\x0a")
    await room.deliver(poster.login(timestamp=1001))
    for index in range(3):
        await room.deliver(poster.post(f"post {index}", timestamp=1100 + index))
    room.sink.clear()

    await room.deliver(admin.keep_alive(timestamp=1200))

    reply = admin.receive(room.sink.last)
    assert isinstance(reply, AckFrame)
    assert reply.checksum == admin.expected_keep_alive_ack(timestamp=1200)
    assert reply.unsynced_count == 3
    await room.aclose()


async def test_a_flooded_keep_alive_is_not_answered(store: Store) -> None:
    """Protocol semantics (MyMesh.cpp:568): keep-alives are answered DIRECT
    only. A keep-alive exists to prove the stored return path still works, so
    answering one that arrived by flood would confirm a path that was not used
    -- and would put a flood on the air every interval, for every client.
    """
    room, admin = await with_admin(store)

    await room.deliver(
        admin.request(ReqType.KEEP_ALIVE, timestamp=1200, data=struct.pack("<I", 0), flood=True)
    )

    assert room.sink.sent == []
    await room.aclose()


async def test_a_keep_alive_ack_covers_nine_bytes_even_when_four_were_padding(
    store: Store,
) -> None:
    """Protocol semantics (MyMesh.cpp:565): the hash is over exactly nine bytes
    whether or not the client sent the last four. Cipher padding means they are
    always present as zeros, and firmware zero-fills them for this reason.
    Hashing only five would produce an ACK the client never recognises.
    """
    room, admin = await with_admin(store)

    await room.deliver(admin.keep_alive(timestamp=1200))  # no force_since sent

    reply = admin.receive(room.sink.last)
    assert isinstance(reply, AckFrame)
    assert reply.checksum == admin.expected_keep_alive_ack(timestamp=1200, force_since=0)
    await room.aclose()


async def test_a_keep_alive_can_rewind_the_sync_cursor(store: Store) -> None:
    """A client that has lost history is entitled to ask for it again, so this
    force-set deliberately bypasses the forward-only guard that protects against
    a late ACK undoing progress."""
    room, admin = await with_admin(store)
    await room.deliver(admin.keep_alive(timestamp=1200, force_since=9000))
    assert room.server.sessions[admin.public_key].sync_since == 9000

    await room.deliver(admin.keep_alive(timestamp=1300, force_since=100))

    assert room.server.sessions[admin.public_key].sync_since == 100
    await room.aclose()


async def test_a_keep_alive_clears_a_stuck_pending_push(store: Store) -> None:
    """Firmware clears pending_ack on a keep-alive (MyMesh.cpp:563): the client
    has clearly not received the push it was sent, so holding the slot open for
    an ACK that is not coming would stall its sync."""
    room, admin = await with_admin(store)
    room.server.sessions[admin.public_key].pending_ack = b"\x01\x02\x03\x04"

    await room.deliver(admin.keep_alive(timestamp=1200))

    assert room.server.sessions[admin.public_key].pending_ack is None
    await room.aclose()


# -- status -----------------------------------------------------------------


async def test_a_status_request_returns_the_52_byte_struct(store: Store) -> None:
    room, admin = await with_admin(store)
    await room.deliver(admin.post("counted", timestamp=1100))
    room.sink.clear()

    await room.deliver(admin.request(ReqType.GET_STATUS, timestamp=1200))

    payload = _open_response(room, admin)
    assert len(payload) >= 4 + 52
    # The reflected timestamp is the correlation tag a client matches on.
    assert struct.unpack_from("<I", payload, 0)[0] == 1200
    stats = ServerStats.decode(payload[4:])
    assert stats.n_posted == 1
    await room.aclose()


async def test_a_flooded_request_is_answered_with_a_path_return(store: Store) -> None:
    """Same rule as a login: a flooded request teaches the client the route back
    at the same time as it answers."""
    room, admin = await with_admin(store)
    room.server.sessions[admin.public_key].forget_path()

    await room.deliver(admin.request(ReqType.GET_STATUS, timestamp=1200, flood=True))

    sent = room.sink.last
    assert sent.payload_type is PayloadType.PATH
    assert sent.route_type is RouteType.FLOOD
    received = admin.receive(sent)
    assert isinstance(received, PathReceived)
    assert isinstance(received.response, bytes)
    assert struct.unpack_from("<I", received.response, 0)[0] == 1200
    await room.aclose()


# -- access list ------------------------------------------------------------


async def test_an_admin_gets_the_access_list(store: Store) -> None:
    """Protocol semantics (MyMesh.cpp:207): a 6-byte public key prefix and a
    permissions byte per entry, after the reflected timestamp."""
    other = LocalIdentity.generate()
    room, admin = await with_admin(store)
    room.server.apply_settings(
        room_settings(
            members=[
                {"pubkey": admin.public_key.hex(), "role": "admin"},
                {"pubkey": other.public_key.hex(), "role": "read_only"},
            ]
        )
    )

    await room.deliver(admin.request(ReqType.GET_ACCESS_LIST, timestamp=1200, data=bytes(2)))

    payload = _open_response(room, admin)
    entries = payload[4:]
    assert entries[0:6] == admin.public_key[:6]
    assert entries[6] == Permission.ADMIN
    assert entries[7:13] == other.public_key[:6]
    assert entries[13] == Permission.READ_ONLY
    await room.aclose()


async def test_a_non_admin_gets_no_access_list(store: Store) -> None:
    room = await build_room(store, room_settings(allow_unknown="read_write"))
    client = FakeClient(room.identity.public_key, path_to_room=b"\x0c")
    await room.deliver(client.login(timestamp=1000))
    await room.deliver(client.path_return())
    room.sink.clear()

    await room.deliver(client.request(ReqType.GET_ACCESS_LIST, timestamp=1200, data=bytes(2)))

    assert room.sink.sent == []
    await room.aclose()


async def test_a_reserved_query_byte_is_not_answered_with_the_plain_list(
    store: Store,
) -> None:
    """The two reserved bytes are for future query parameters. A non-zero value
    means a question we do not understand, and answering it with the unfiltered
    list would be answering something else (MyMesh.cpp:203)."""
    room, admin = await with_admin(store)

    await room.deliver(admin.request(ReqType.GET_ACCESS_LIST, timestamp=1200, data=b"\x01\x00"))

    assert room.sink.sent == []
    await room.aclose()


async def test_an_unknown_request_type_gets_no_reply(store: Store) -> None:
    room, admin = await with_admin(store)

    await room.deliver(admin.request(0x7E, timestamp=1200))

    assert room.sink.sent == []
    await room.aclose()


async def test_a_replayed_request_is_dropped(store: Store) -> None:
    room, admin = await with_admin(store)
    await room.deliver(admin.request(ReqType.GET_STATUS, timestamp=2000))
    room.sink.clear()

    await room.deliver(admin.request(ReqType.GET_STATUS, timestamp=1500))

    assert room.sink.sent == []
    await room.aclose()


# -- the console ------------------------------------------------------------


async def test_an_admin_console_command_is_answered(store: Store) -> None:
    room, admin = await with_admin(store)

    await room.deliver(admin.cli("a1|ver", timestamp=1200))

    reply = admin.receive(room.sink.last)
    assert isinstance(reply, CliReply)
    # The XX| prefix is reflected so the app can match reply to request.
    assert reply.text.startswith("a1|meshelle")
    await room.aclose()


async def test_a_console_command_is_not_acknowledged(store: Store) -> None:
    """Firmware sends no ACK for CLI data (MyMesh.cpp:473): the console is
    request/response, and the reply is the acknowledgement."""
    room, admin = await with_admin(store)

    await room.deliver(admin.cli("ver", timestamp=1200))

    assert room.sink.of_type(PayloadType.ACK) == []
    await room.aclose()


async def test_a_non_admin_console_command_is_ignored_entirely(store: Store) -> None:
    room = await build_room(store, room_settings(allow_unknown="read_write"))
    client = FakeClient(room.identity.public_key, path_to_room=b"\x0c")
    await room.deliver(client.login(timestamp=1000))
    await room.deliver(client.path_return())
    room.sink.clear()

    await room.deliver(client.cli("room.post sneaky", timestamp=1200))

    assert room.sink.sent == []
    await room.aclose()


async def test_a_retried_console_command_is_not_run_twice(store: Store) -> None:
    """Re-running would repeat the side effect: two posts, or an extra advert.
    The app already showed the first reply."""
    room, admin = await with_admin(store)

    await room.deliver(admin.cli("room.post notice", timestamp=1200))
    room.sink.clear()
    await room.deliver(admin.cli("room.post notice", timestamp=1200, attempt=1))

    assert room.sink.sent == []
    stored = await store.run(lambda s: repo.recent_posts(s, room.room_id))
    assert len(stored) == 1
    await room.aclose()


async def test_the_console_can_trigger_an_advert(store: Store) -> None:
    room, admin = await with_admin(store)

    await room.deliver(admin.cli("advert", timestamp=1200))

    adverts = room.sink.of_type(PayloadType.ADVERT)
    assert len(adverts) == 1
    assert adverts[0].route_type is RouteType.FLOOD
    await room.aclose()


async def test_a_cli_reply_never_shares_the_requests_timestamp(store: Store) -> None:
    """Firmware's workaround (MyMesh.cpp:518): an app shows the request and the
    reply side by side, and identical timestamps make them indistinguishable."""
    room, admin = await with_admin(store)
    room.clock.advance(0)

    await room.deliver(admin.cli("ver", timestamp=room.clock.now()))

    reply = admin.receive(room.sink.last)
    assert isinstance(reply, CliReply)
    assert reply.timestamp != room.clock.now()
    await room.aclose()


def _open_response(room: RoomHarness, client: FakeClient) -> bytes:
    packet = room.sink.last
    assert packet.payload_type is PayloadType.RESPONSE
    return Datagram.decode(packet.payload).open(client.secret)
