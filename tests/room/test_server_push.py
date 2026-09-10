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

"""The push loop: getting stored posts to the clients that are owed them."""

from __future__ import annotations

from meshelle.proto.constants import PayloadType
from meshelle.store import repo
from meshelle.store.db import Store
from tests.fakes.client import FakeClient, PushedPost
from tests.fakes.room import RoomHarness, build_room, drain, room_settings


async def two_clients(
    store: Store, **settings: object
) -> tuple[RoomHarness, FakeClient, FakeClient]:
    room = await build_room(store, room_settings(**settings))
    alice = FakeClient(room.identity.public_key, path_to_room=b"\x0a")
    bob = FakeClient(room.identity.public_key, path_to_room=b"\x0b")
    for index, client in enumerate((alice, bob)):
        await room.deliver(client.login(timestamp=1000 + index))
        await room.deliver(client.path_return())
    room.sink.clear()
    return room, alice, bob


async def settle(room: RoomHarness) -> None:
    """Move past POST_SYNC_DELAY_SECS, after which a post may be pushed.

    Protocol semantics (MyMesh.cpp:1013): a post is held for six seconds so the
    author's own ACK has landed before the room starts transmitting again.
    """
    room.clock.advance(7)


async def test_a_post_reaches_the_other_client_but_not_its_author(
    store: Store,
) -> None:
    """Protocol semantics: nobody needs their own post back, and sending it
    would cost airtime and confuse the author's message list."""
    room, alice, bob = await two_clients(store)
    await room.deliver(alice.post("hello room", timestamp=1100))
    room.sink.clear()
    await settle(room)

    pushed = []
    for _ in range(4):
        if await room.server.push_once():
            pushed.append(room.sink.last)

    assert len(pushed) == 1
    received = bob.receive(pushed[0])
    assert isinstance(received, PushedPost)
    assert received.text == "hello room"
    assert received.author_prefix == alice.public_key[:4]
    await room.aclose()


async def test_a_push_is_not_repeated_until_it_is_acknowledged(store: Store) -> None:
    """Strictly one outstanding push per client. Two in flight would race: both
    ACKs match on a 4-byte hash, and the cursor would advance past a post whose
    push was never acknowledged."""
    room, alice, _bob = await two_clients(store)
    await room.deliver(alice.post("one", timestamp=1100))
    await room.deliver(alice.post("two", timestamp=1101))
    room.sink.clear()
    await settle(room)

    for _ in range(6):
        await room.server.push_once()

    assert len(room.sink.of_type(PayloadType.TXT_MSG)) == 1
    await room.aclose()


async def test_an_ack_advances_the_cursor_and_releases_the_next_post(
    store: Store,
) -> None:
    room, alice, bob = await two_clients(store)
    await room.deliver(alice.post("one", timestamp=1100))
    await room.deliver(alice.post("two", timestamp=1101))
    room.sink.clear()
    await settle(room)

    await _push_to(room, bob)
    first = bob.receive(room.sink.last)
    assert isinstance(first, PushedPost)
    await room.deliver(bob.acknowledge(first))
    room.sink.clear()

    await _push_to(room, bob)
    second = bob.receive(room.sink.last)

    assert isinstance(second, PushedPost)
    assert (first.text, second.text) == ("one", "two")
    stored = await store.run(lambda s: repo.get_client(s, room.room_id, bob.public_key))
    assert stored is not None
    assert stored.sync_since == first.timestamp
    await room.aclose()


async def test_a_restart_resumes_the_sync_without_re_sending(store: Store) -> None:
    """The end-to-end requirement: kill mid-sync, restart, and the client
    receives the missed post exactly once.

    ``sync_since`` only advances on an acknowledged push, so a restart simply
    re-pushes from the last post that was actually confirmed -- which is why
    there is no pending-push table to drift out of step with the durable record.
    """
    room, alice, bob = await two_clients(store)
    await room.deliver(alice.post("one", timestamp=1100))
    await room.deliver(alice.post("two", timestamp=1101))
    room.sink.clear()
    await settle(room)

    await _push_to(room, bob)
    first = bob.receive(room.sink.last)
    assert isinstance(first, PushedPost)
    await room.deliver(bob.acknowledge(first))
    await room.aclose()

    # The second push was in flight and never acknowledged when we died.
    await _push_to(room, bob)
    restarted = await build_room(store, room.settings, identity=room.identity, clock=room.clock)
    restarted.clock.advance(7)

    delivered = []
    for _ in range(8):
        if await restarted.server.push_once():
            received = bob.receive(restarted.sink.last)
            if isinstance(received, PushedPost):
                delivered.append(received.text)
                await restarted.deliver(bob.acknowledge(received))

    assert delivered == ["two"]
    await restarted.aclose()


async def test_a_push_that_is_never_acknowledged_eventually_stops(
    store: Store,
) -> None:
    """Protocol semantics (MyMesh.cpp:1019): after three unacknowledged pushes a
    client is left alone until it talks to us again. Otherwise a client that has
    gone out of range costs the whole room airtime for as long as it stays away.
    """
    room, alice, bob = await two_clients(store)
    await room.deliver(alice.post("anyone there?", timestamp=1100))
    room.sink.clear()
    await settle(room)

    attempts = 0
    for _ in range(20):
        if await room.server.push_once():
            attempts += 1
        # Step past the ACK timeout without waiting for it.
        room.clock.advance_monotonic(30)

    assert attempts == 3
    assert room.server.sessions[bob.public_key].push_failures == 3
    await room.aclose()


async def test_a_silent_client_resumes_when_it_speaks_again(store: Store) -> None:
    """The failure counter resets on any inbound packet, which is what makes a
    client that comes back into range start receiving again."""
    room, alice, bob = await two_clients(store)
    await room.deliver(alice.post("still here?", timestamp=1100))
    room.sink.clear()
    await settle(room)

    for _ in range(20):
        await room.server.push_once()
        room.clock.advance_monotonic(30)
    assert room.server.sessions[bob.public_key].push_failures == 3

    await room.deliver(bob.keep_alive(timestamp=2000))
    room.sink.clear()
    await _push_to(room, bob)

    assert isinstance(bob.receive(room.sink.last), PushedPost)
    await room.aclose()


async def test_a_post_is_held_before_being_pushed(store: Store) -> None:
    """Protocol semantics: a post younger than POST_SYNC_DELAY_SECS is not
    pushed, so the author's ACK is not competing with a push for airtime."""
    room, alice, bob = await two_clients(store)
    await room.deliver(alice.post("too soon", timestamp=1100))
    room.sink.clear()

    for _ in range(4):
        await room.server.push_once()

    assert room.sink.of_type(PayloadType.TXT_MSG) == []

    await settle(room)
    await _push_to(room, bob)
    assert isinstance(bob.receive(room.sink.last), PushedPost)
    await room.aclose()


async def test_clients_are_served_round_robin(store: Store) -> None:
    """One busy client must not starve another: firmware advances the
    round-robin index whether or not it pushed."""
    room, alice, bob = await two_clients(store)
    charlie = FakeClient(room.identity.public_key, path_to_room=b"\x0c")
    await room.deliver(charlie.login(timestamp=1002))
    await room.deliver(charlie.path_return())
    await room.deliver(alice.post("for everyone", timestamp=1100))
    room.sink.clear()
    await settle(room)

    recipients = set()
    for _ in range(6):
        if await room.server.push_once():
            for client in (bob, charlie):
                if isinstance(client.receive(room.sink.last), PushedPost):
                    recipients.add(client.public_key)

    assert recipients == {bob.public_key, charlie.public_key}
    await room.aclose()


async def test_a_flooded_push_is_acknowledged_inside_a_path_return(
    store: Store,
) -> None:
    """Protocol semantics (BaseChatMesh.cpp:277): a client with no path back
    answers a flooded push with a PATH return carrying the ACK, so the room
    learns the route at the same time as it learns the post arrived.
    """
    room = await build_room(store, room_settings())
    alice = FakeClient(room.identity.public_key, path_to_room=b"\x0a")
    bob = FakeClient(room.identity.public_key, path_to_room=b"\x0b")
    await room.deliver(alice.login(timestamp=1000))
    await room.deliver(alice.path_return())
    await room.deliver(bob.login(timestamp=1001))  # bob never sends a PATH
    await room.deliver(alice.post("find me", timestamp=1100))
    room.sink.clear()
    await settle(room)

    await _push_to(room, bob)
    push = room.sink.last
    assert push.route_type.is_flood
    received = bob.receive(push)
    assert isinstance(received, PushedPost)

    await room.deliver(bob.acknowledge(received, flood=True))

    session = room.server.sessions[bob.public_key]
    assert session.pending_ack is None
    assert session.out_path == b"\x0b"
    await room.aclose()


async def test_a_welcome_is_pushed_on_a_first_sync(store: Store) -> None:
    """A client that says it holds no posts gets the welcome before anything
    else, so it arrives as the first thing the room ever says."""
    room = await build_room(store, room_settings(welcome="Be excellent to each other."))
    client = FakeClient(room.identity.public_key, path_to_room=b"\x0c")
    await room.deliver(client.login(timestamp=1000, sync_since=0))
    await room.deliver(client.path_return())
    room.sink.clear()

    await _push_to(room, client)

    received = client.receive(room.sink.last)
    assert isinstance(received, PushedPost)
    assert received.text == "Be excellent to each other."
    assert received.author_prefix == room.identity.public_key[:4]
    await room.aclose()


async def test_acknowledging_a_welcome_does_not_move_the_sync_cursor(
    store: Store,
) -> None:
    """A welcome is per-client and is not in the post table, so treating its ACK
    as a post ACK would advance the cursor past posts never sent."""
    room = await build_room(store, room_settings(welcome="hello"))
    client = FakeClient(room.identity.public_key, path_to_room=b"\x0c")
    await room.deliver(client.login(timestamp=1000, sync_since=0))
    await room.deliver(client.path_return())
    room.sink.clear()

    await _push_to(room, client)
    welcome = client.receive(room.sink.last)
    assert isinstance(welcome, PushedPost)
    await room.deliver(client.acknowledge(welcome))

    assert room.server.sessions[client.public_key].sync_since == 0
    assert not room.server.sessions[client.public_key].welcome
    await room.aclose()


async def test_a_returning_client_is_not_welcomed_again(store: Store) -> None:
    room = await build_room(store, room_settings(welcome="hello"))
    client = FakeClient(room.identity.public_key, path_to_room=b"\x0c")

    await room.deliver(client.login(timestamp=1000, sync_since=500))

    assert not room.server.sessions[client.public_key].welcome
    await room.aclose()


async def test_pushing_updates_the_room_statistic(store: Store) -> None:
    room, alice, bob = await two_clients(store)
    await room.deliver(alice.post("counted", timestamp=1100))
    await settle(room)

    await _push_to(room, bob)

    counters = await store.run(lambda s: repo.get_counters(s, room.room_id))
    assert counters["post_push"] == 1
    await room.aclose()


async def _push_to(room: RoomHarness, client: FakeClient) -> None:
    """Run the round-robin until it reaches ``client`` and pushes something."""
    for _ in range(8):
        if await room.server.push_once():
            await drain(room.scheduler)
            if isinstance(client.receive(room.sink.last), PushedPost):
                return
    raise AssertionError(f"nothing was pushed to {client.public_key[:4].hex()}")
