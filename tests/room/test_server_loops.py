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

"""The long-running loops, and the paths that keep a bad packet from stopping them."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Coroutine
from contextlib import suppress
from itertools import pairwise

import pytest
from sqlalchemy.orm import Session

from meshelle.companion.link import ReceivedPacket
from meshelle.config.model import Role
from meshelle.proto.constants import PayloadType, RouteType, TxtType
from meshelle.proto.identity import LocalIdentity
from meshelle.proto.packet import Datagram, Packet, TextMessage
from meshelle.store import repo
from meshelle.store.db import Store
from tests.fakes.client import FakeClient, PushedPost
from tests.fakes.room import EPOCH, build_room, drain, room_settings


async def run_until(
    loop: Coroutine[None, None, None], reached: Awaitable[None], *, deadline: float = 5.0
) -> None:
    """Run a forever-loop until ``reached`` resolves, then stop it.

    The loops never return on their own, so something has to end them. Waiting
    on an event the loop itself sets -- a packet transmitted, a wait taken --
    rather than counting turns of the event loop means a loop that silently does
    nothing fails on the timeout instead of passing once the turns run out.
    """
    task = asyncio.ensure_future(loop)
    try:
        async with asyncio.timeout(deadline):
            await reached
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


# -- the push loop ----------------------------------------------------------


async def test_the_push_loop_delivers_and_then_settles(store: Store) -> None:
    room = await build_room(store, room_settings())
    alice = FakeClient(room.identity.public_key, path_to_room=b"\x0a")
    bob = FakeClient(room.identity.public_key, path_to_room=b"\x0b")
    for index, client in enumerate((alice, bob)):
        await room.deliver(client.login(timestamp=1000 + index))
        await room.deliver(client.path_return())
    await room.deliver(alice.post("through the loop", timestamp=1100))
    room.sink.clear()
    room.clock.advance(7)

    await run_until(room.server.run_push_loop(), room.sink.wait_for(1))
    await drain(room.scheduler)

    pushes = room.sink.of_type(PayloadType.TXT_MSG)
    assert len(pushes) == 1
    assert isinstance(bob.receive(pushes[0]), PushedPost)
    await room.aclose()


async def test_an_idle_round_robin_polls_faster_than_a_busy_one(store: Store) -> None:
    """Firmware polls the next client at ``SYNC_PUSH_INTERVAL / 8`` when the
    current one had nothing owed (MyMesh.cpp:1039). Waiting the full interval
    per idle client would make a room with a dozen of them take fifteen seconds
    to reach the one that is actually waiting.
    """
    from meshelle.mesh.scheduler import Timings

    timings = Timings()
    room = await build_room(store, room_settings(), timings=timings)
    client = FakeClient(room.identity.public_key, path_to_room=b"\x0c")
    await room.deliver(client.login(timestamp=1000))
    room.clock.sleeps.clear()

    await run_until(room.server.run_push_loop(), room.clock.wait_for_sleeps(4))

    # The first wait is the post-login pause; the rest are the idle poll.
    assert room.clock.sleeps[1:] == pytest.approx([timings.idle_push_interval] * 3)
    assert timings.sync_push_interval not in room.clock.sleeps
    await room.aclose()


# -- the advert loop --------------------------------------------------------


async def test_the_advert_loop_advertises_at_startup(store: Store) -> None:
    """meshcore-pi sends its first advert before its link is up, so it is lost
    and the room stays invisible until the next interval. Advertising once at
    startup is what makes a restarted room reachable again immediately.
    """
    room = await build_room(
        store, room_settings(advert_flood_interval=None, advert_local_interval=None)
    )

    await run_until(room.server.run_advert_loop(), room.sink.wait_for(1))

    adverts = room.sink.of_type(PayloadType.ADVERT)
    assert len(adverts) == 1
    assert adverts[0].route_type is RouteType.FLOOD
    await room.aclose()


async def test_the_advert_loop_alternates_flood_and_zero_hop(store: Store) -> None:
    """Two independent timers, and the cheap one must fire far more often than
    the mesh-wide one -- otherwise the room floods every thirty minutes."""
    room = await build_room(
        store,
        room_settings(advert_flood_interval="6h", advert_local_interval="30m"),
    )

    await run_until(room.server.run_advert_loop(), room.sink.wait_for(6))

    routes = [packet.route_type for packet in room.sink.of_type(PayloadType.ADVERT)]
    assert routes.count(RouteType.DIRECT) > routes.count(RouteType.FLOOD)
    assert RouteType.FLOOD in routes
    await room.aclose()


async def test_a_flood_advert_rearms_the_local_timer_too(store: Store) -> None:
    """Otherwise the two would stack up when they coincide and put two adverts
    on the air back to back, for no benefit."""
    room = await build_room(
        store,
        room_settings(advert_flood_interval="1h", advert_local_interval="1h"),
    )

    await run_until(room.server.run_advert_loop(), room.sink.wait_for(4))

    adverts = room.sink.of_type(PayloadType.ADVERT)
    assert all(
        first.route_type is not second.route_type or first.route_type is RouteType.FLOOD
        for first, second in pairwise(adverts)
    )
    assert adverts.count(adverts[0]) == 1
    await room.aclose()


# -- robustness -------------------------------------------------------------


async def test_a_client_whose_stored_key_is_unusable_is_skipped(store: Store) -> None:
    """A corrupt row loses one client, not the whole room: every other client's
    sync would otherwise stop at startup."""
    identity = LocalIdentity.generate()
    await store.run(lambda s: repo.ensure_room(s, "lobby", identity.public_key, now=EPOCH))
    room_row = await store.run(lambda s: repo.get_room_by_slug(s, "lobby"))
    assert room_row is not None
    good = LocalIdentity.generate()

    def remember(key: bytes) -> Callable[[Session], object]:
        return lambda s: repo.record_login(
            s,
            room_row.id,
            key,
            role=Role.READ_WRITE.permission,
            sender_timestamp=1,
            sync_since=0,
            # EPOCH, not 1: these clients are current as far as the room's clock
            # is concerned, so client_retention is not what this test measures.
            now=EPOCH,
            reset_out_path=False,
        )

    for key in (bytes(32), good.public_key):  # an all-zero key is degenerate
        await store.run(remember(key))

    room = await build_room(store, room_settings(), identity=identity)

    assert set(room.server.sessions) == {good.public_key}
    await room.aclose()


# -- client retention -------------------------------------------------------


async def test_a_client_idle_past_retention_is_not_rehydrated(store: Store) -> None:
    """Nothing else removes a client row.

    A room whose ``allow_unknown`` grants a role gains one per stranger that
    ever logs in, keeps it forever, and derives a shared secret for every one of
    them at each start. Slow, because radio bandwidth is the limit -- but it
    never recovers on its own, which is what makes it a policy question.
    """
    identity = LocalIdentity.generate()
    await store.run(lambda s: repo.ensure_room(s, "lobby", identity.public_key, now=EPOCH))
    room_row = await store.run(lambda s: repo.get_room_by_slug(s, "lobby"))
    assert room_row is not None
    stale, live = LocalIdentity.generate(), LocalIdentity.generate()

    def remember(key: bytes, when: int) -> Callable[[Session], object]:
        return lambda s: repo.record_login(
            s,
            room_row.id,
            key,
            role=Role.READ_WRITE.permission,
            sender_timestamp=1,
            sync_since=0,
            now=when,
            reset_out_path=False,
        )

    await store.run(remember(stale.public_key, EPOCH - 200 * 86400))
    await store.run(remember(live.public_key, EPOCH - 86400))

    room = await build_room(store, room_settings(client_retention="90d"), identity=identity)

    assert set(room.server.sessions) == {live.public_key}
    remaining = await store.run(lambda s: repo.list_clients(s, room_row.id))
    assert [c.public_key for c in remaining] == [live.public_key], "the row must go too"
    await room.aclose()


async def test_retention_off_keeps_every_client(store: Store) -> None:
    """``client_retention = "forever"`` has to actually mean it: an operator who
    turns the policy off must not find rows disappearing anyway."""
    identity = LocalIdentity.generate()
    await store.run(lambda s: repo.ensure_room(s, "lobby", identity.public_key, now=EPOCH))
    room_row = await store.run(lambda s: repo.get_room_by_slug(s, "lobby"))
    assert room_row is not None
    ancient = LocalIdentity.generate()
    await store.run(
        lambda s: repo.record_login(
            s,
            room_row.id,
            ancient.public_key,
            role=Role.READ_WRITE.permission,
            sender_timestamp=1,
            sync_since=0,
            now=1,
            reset_out_path=False,
        )
    )

    room = await build_room(store, room_settings(client_retention="forever"), identity=identity)

    assert set(room.server.sessions) == {ancient.public_key}
    await room.aclose()


async def test_a_forgotten_client_loses_its_live_session_too(store: Store) -> None:
    """Memory and database have to agree.

    A live session whose row has been deleted re-creates that row on the
    client's next packet, carrying the sync position with it -- so the policy
    would delete the same row forever and never make progress.
    """
    room = await build_room(store, room_settings(client_retention="30d"))
    gone = FakeClient(room.identity.public_key, path_to_room=b"\x0d")
    stays = FakeClient(room.identity.public_key, path_to_room=b"\x0e")
    for index, client in enumerate((gone, stays)):
        await room.deliver(client.login(timestamp=1000 + index))
    assert len(room.server.sessions) == 2

    # Far enough that both are idle, then only `stays` is heard from again.
    room.clock.advance(40 * 86400)
    await room.deliver(stays.login(timestamp=2000))

    # A post is the room's live maintenance point, the same one that prunes posts.
    await room.deliver(stays.post("triggers maintenance", timestamp=2100))

    assert set(room.server.sessions) == {stays.identity.public_key}
    await room.aclose()


async def test_a_malformed_body_is_claimed_and_logged_not_raised(store: Store) -> None:
    """The MAC already proved the packet was ours, so a body we cannot parse is
    a protocol mismatch -- but letting it raise would stop the receive loop and
    take every other room on the node down with it.
    """
    room = await build_room(store, room_settings())
    client = FakeClient(room.identity.public_key, path_to_room=b"\x0c")
    await room.deliver(client.login(timestamp=1000))
    room.sink.clear()

    truncated = Datagram.seal(room.server.node_hash, client.node_hash, client.secret, b"\x01\x02")
    packet = Packet(
        route_type=RouteType.DIRECT,
        payload_type=PayloadType.TXT_MSG,
        payload=truncated.encode(),
    )

    assert await room.deliver(packet) is True
    assert room.sink.sent == []
    await room.aclose()


async def test_an_unsupported_text_type_is_ignored(store: Store) -> None:
    """Protocol semantics (MyMesh.cpp:446): a room accepts PLAIN and CLI_DATA
    only. A SIGNED_PLAIN message is one client trying to sync another, and
    treating it as a post would let anyone forge an author prefix."""
    room = await build_room(store, room_settings())
    client = FakeClient(room.identity.public_key, path_to_room=b"\x0c")
    await room.deliver(client.login(timestamp=1000))
    await room.deliver(client.path_return())
    room.sink.clear()

    plaintext = TextMessage(
        timestamp=1100, txt_type=TxtType.SIGNED_PLAIN, attempt=0, text=b"\x00" * 4 + b"forged"
    ).encode()
    sealed = Datagram.seal(room.server.node_hash, client.node_hash, client.secret, plaintext)
    packet = Packet(
        route_type=RouteType.DIRECT,
        payload_type=PayloadType.TXT_MSG,
        payload=sealed.encode(),
        path=b"\x0c",
    )

    await room.deliver(packet)

    assert room.sink.sent == []
    assert await store.run(lambda s: repo.recent_posts(s, room.room_id)) == []
    await room.aclose()


async def test_a_response_from_a_client_is_claimed_but_not_answered(
    store: Store,
) -> None:
    """Nothing asks a client for a RESPONSE, so this is a confused peer. It must
    not be answered, or two confused peers would talk forever."""
    room = await build_room(store, room_settings())
    client = FakeClient(room.identity.public_key)
    await room.deliver(client.login(timestamp=1000))
    room.sink.clear()

    sealed = Datagram.seal(room.server.node_hash, client.node_hash, client.secret, b"\x00" * 13)
    packet = Packet(
        route_type=RouteType.DIRECT,
        payload_type=PayloadType.RESPONSE,
        payload=sealed.encode(),
    )

    assert await room.deliver(packet) is True
    assert room.sink.sent == []
    await room.aclose()


async def test_a_keep_alive_from_a_client_with_no_path_is_not_answered(
    store: Store,
) -> None:
    """The rule is direct-only, and there is nothing to send a direct reply
    over. Flooding one would defeat the point of a keep-alive."""
    room = await build_room(store, room_settings())
    client = FakeClient(room.identity.public_key)
    await room.deliver(client.login(timestamp=1000))
    room.sink.clear()

    await room.deliver(client.keep_alive(timestamp=1100))

    assert room.sink.sent == []
    await room.aclose()


async def test_an_empty_post_is_acknowledged_without_being_stored(
    store: Store,
) -> None:
    """A client that sends nothing still needs its ACK, or it retries forever."""
    room = await build_room(store, room_settings())
    client = FakeClient(room.identity.public_key, path_to_room=b"\x0c")
    await room.deliver(client.login(timestamp=1000))
    await room.deliver(client.path_return())
    room.sink.clear()

    await room.deliver(client.post("", timestamp=1100))

    assert len(room.sink.of_type(PayloadType.ACK)) == 1
    assert await store.run(lambda s: repo.recent_posts(s, room.room_id)) == []
    await room.aclose()


async def test_the_access_list_is_capped_at_one_packet(store: Store) -> None:
    """A reply is one message. Building a longer one would produce a packet the
    node's frame buffer cannot carry, so it would be dropped entirely."""
    from meshelle.proto.constants import ReqType

    members = [
        {"pubkey": LocalIdentity.generate().public_key.hex(), "role": "read_write"}
        for _ in range(40)
    ]
    admin = LocalIdentity.generate()
    members.append({"pubkey": admin.public_key.hex(), "role": "admin"})
    room = await build_room(store, room_settings(members=members))
    client = FakeClient(room.identity.public_key, admin, path_to_room=b"\x0c")
    await room.deliver(client.login(timestamp=1000))
    await room.deliver(client.path_return())
    room.sink.clear()

    await room.deliver(client.request(ReqType.GET_ACCESS_LIST, timestamp=1100, data=bytes(2)))

    payload = Datagram.decode(room.sink.last.payload).open(client.secret)
    assert 0 < len(payload) - 4 <= 160
    await room.aclose()


@pytest.mark.parametrize("raw", [b"", b"\x04", b"\xff" * 4])
async def test_radio_noise_never_reaches_a_room(store: Store, raw: bytes) -> None:
    """Bit errors arrive as undecodable packets constantly. One escaping into
    the receive loop would stop the node hearing anything else."""
    from meshelle.mesh.dispatcher import Dispatcher

    room = await build_room(store, room_settings())

    class _Sender:
        async def send_packet(
            self,
            raw: bytes,
            *,
            priority: int = 0,
            ttl: float = 30.0,
            description: str = "packet",
        ) -> None:
            return None

    dispatcher = Dispatcher(_Sender(), [room.server])

    assert await dispatcher.dispatch(ReceivedPacket(raw=raw, snr=0.0, rssi=-120)) is False
    await room.aclose()
