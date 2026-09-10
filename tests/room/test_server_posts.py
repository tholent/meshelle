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

"""Posting: who may, what gets acknowledged, and what is never double-stored."""

from __future__ import annotations

from meshelle.config.model import RoomSettings
from meshelle.proto.constants import PayloadType
from meshelle.proto.identity import LocalIdentity
from meshelle.proto.packet import Ack
from meshelle.store import repo
from meshelle.store.db import Store
from tests.fakes.client import FakeClient
from tests.fakes.room import RoomHarness, build_room, room_settings


async def logged_in(
    store: Store,
    settings: RoomSettings | None = None,
    *,
    identity: LocalIdentity | None = None,
) -> tuple[RoomHarness, FakeClient]:
    """A room with one client that has logged in and taught it a return path."""
    room = await build_room(store, settings if settings is not None else room_settings())
    client = FakeClient(room.identity.public_key, identity, path_to_room=b"\x0c")
    await room.deliver(client.login(timestamp=1000))
    await room.deliver(client.path_return())
    room.sink.clear()
    return room, client


async def posts_in(room: RoomHarness) -> list[str]:
    stored = await room.store.run(lambda s: repo.recent_posts(s, room.room_id))
    return [post.text for post in stored]


async def test_a_post_is_stored_and_acknowledged(store: Store) -> None:
    room, client = await logged_in(store)

    await room.deliver(client.post("first light", timestamp=1100))

    assert await posts_in(room) == ["first light"]
    ack = room.sink.of_type(PayloadType.ACK)
    assert len(ack) == 1
    assert Ack.decode(ack[0].payload).checksum == client.expected_post_ack(
        "first light", timestamp=1100
    )
    await room.aclose()


async def test_a_retried_post_is_re_acknowledged_but_not_stored_twice(
    store: Store,
) -> None:
    """Protocol semantics (MyMesh.cpp:449): an identical timestamp means the
    client did not hear our ACK. It must be acknowledged again and must not be
    posted again -- that is the whole difference between a lost ACK and a
    duplicated message.
    """
    room, client = await logged_in(store)
    message = client.post("say again", timestamp=1100)

    await room.deliver(message)
    room.sink.clear()
    # A retry is a different packet (the client picks a fresh attempt), so the
    # seen-table cannot be what suppresses the duplicate.
    await room.deliver(client.post("say again", timestamp=1100, attempt=1))

    assert await posts_in(room) == ["say again"]
    assert len(room.sink.of_type(PayloadType.ACK)) == 1
    await room.aclose()


async def test_an_older_timestamp_is_a_replay_and_is_dropped(store: Store) -> None:
    room, client = await logged_in(store)

    await room.deliver(client.post("current", timestamp=1100))
    room.sink.clear()
    await room.deliver(client.post("captured earlier", timestamp=1050))

    assert await posts_in(room) == ["current"]
    assert room.sink.sent == []
    await room.aclose()


async def test_a_read_only_client_gets_neither_a_post_nor_an_ack(store: Store) -> None:
    """Protocol semantics: no ACK means the app shows the message as
    undelivered, rather than silently swallowing it. Firmware would accept this
    post -- it refuses only PERM_ACL_GUEST (MyMesh.cpp:480) -- but meshelle
    honours the name it gave the role.
    """
    reader = LocalIdentity.generate()
    room, client = await logged_in(
        store,
        room_settings(members=[{"pubkey": reader.public_key.hex(), "role": "read_only"}]),
        identity=reader,
    )

    await room.deliver(client.post("let me in", timestamp=1100))

    assert await posts_in(room) == []
    assert room.sink.sent == []
    await room.aclose()


async def test_a_guest_gets_neither_a_post_nor_an_ack(store: Store) -> None:
    room, client = await logged_in(store, room_settings(allow_unknown="guest"))

    await room.deliver(client.post("hello?", timestamp=1100))

    assert await posts_in(room) == []
    assert room.sink.sent == []
    await room.aclose()


async def test_the_ack_hash_covers_the_trimmed_text_not_the_padding(
    store: Store,
) -> None:
    """Protocol semantics (MyMesh.cpp:461): the hash is over
    ``5 + strlen(text)`` bytes. Hashing the cipher-padded plaintext instead
    would produce an ACK the client never recognises, so it would retry forever.
    """
    room, client = await logged_in(store)
    # 3 bytes of text: the plaintext is padded from 8 to 16 before encryption.
    await room.deliver(client.post("hi!", timestamp=1100))

    ack = room.sink.of_type(PayloadType.ACK)[0]

    assert Ack.decode(ack.payload).checksum == client.expected_post_ack("hi!", timestamp=1100)
    await room.aclose()


async def test_a_post_is_acknowledged_over_the_stored_path(store: Store) -> None:
    room, client = await logged_in(store)

    await room.deliver(client.post("routed", timestamp=1100))

    ack = room.sink.of_type(PayloadType.ACK)[0]
    assert ack.route_type.is_direct
    assert ack.path == b"\x0c"
    await room.aclose()


async def test_a_post_from_a_client_with_no_path_is_acknowledged_by_flood(
    store: Store,
) -> None:
    """Falling back to a flood is not a failure: it is how the first reply after
    a restart reaches a client whose PATH we have not re-learned."""
    room = await build_room(store, room_settings())
    client = FakeClient(room.identity.public_key)
    await room.deliver(client.login(timestamp=1000))
    room.sink.clear()

    await room.deliver(client.post("no path yet", timestamp=1100))

    assert room.sink.of_type(PayloadType.ACK)[0].route_type.is_flood
    await room.aclose()


async def test_an_over_long_post_is_truncated_on_a_character_boundary(
    store: Store,
) -> None:
    room, client = await logged_in(store)

    # 152 bytes: over the 151-byte post limit, but still a packet a real client
    # could build, so this is a truncation the room must do rather than a
    # message it could never receive.
    await room.deliver(client.post("é" * 76, timestamp=1100))

    stored = (await posts_in(room))[0]
    assert len(stored.encode("utf-8")) <= 151
    assert "�" not in stored
    await room.aclose()


async def test_retention_cannot_delete_a_post_a_client_has_not_received(
    store: Store,
) -> None:
    """The least-synced client is a floor on what retention may remove.

    Deleting a post someone has not yet been sent would silently lose a message
    for them, which no retention policy is worth. So a strict ``max_posts`` does
    nothing at all while a client is still behind -- that is the guard working,
    not retention failing.
    """
    room, client = await logged_in(store, room_settings(max_posts=1))

    for index in range(3):
        await room.deliver(client.post(f"post {index}", timestamp=1100 + index))

    assert len(await posts_in(room)) == 3
    await room.aclose()


async def test_retention_prunes_once_every_client_has_caught_up(store: Store) -> None:
    """Applied at post time and in the same transaction, so the database never
    holds more than the policy allows for longer than one post."""
    room, client = await logged_in(store, room_settings(max_posts=2))

    for index in range(4):
        await room.deliver(client.post(f"post {index}", timestamp=1100 + index))
    caught_up = max(
        post.post_ts for post in await room.store.run(lambda s: repo.recent_posts(s, room.room_id))
    )
    await room.deliver(client.keep_alive(timestamp=1200, force_since=caught_up))

    await room.deliver(client.post("post 4", timestamp=1300))

    assert await posts_in(room) == ["post 4", "post 3"]
    await room.aclose()


async def test_a_posted_message_updates_the_room_statistic(store: Store) -> None:
    room, client = await logged_in(store)

    await room.deliver(client.post("counted", timestamp=1100))

    counters = await store.run(lambda s: repo.get_counters(s, room.room_id))
    assert counters["posted"] == 1
    await room.aclose()
