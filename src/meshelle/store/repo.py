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

"""Repository functions: the only place that writes SQL-ish logic.

Plain synchronous functions taking a ``Session``, so they unit-test without async
fixtures and compose inside a single transaction. Call them through
:meth:`meshelle.store.db.Store.run`, which supplies the session and the thread.

Flat functions rather than classes: there is no per-repository state worth
holding, and ``next_unsynced_post(session, ...)`` reads better than a namespace
of static methods.
"""

from __future__ import annotations

import logging
import time

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.orm import Session

from meshelle.proto.constants import OUT_PATH_UNKNOWN, Permission
from meshelle.store.models import Client, Counter, Meta, Post, Room

logger = logging.getLogger(__name__)

META_CREATED_BY = "created_by"
META_LAST_OPENED_BY = "last_opened_by"


class StoreError(Exception):
    """The database contradicts what the caller asked for."""


# ---------------------------------------------------------------------------
# Rooms
# ---------------------------------------------------------------------------


def ensure_room(session: Session, slug: str, public_key: bytes, *, now: int | None = None) -> Room:
    """Fetch or create the row for a configured room.

    Raises:
        StoreError: the slug already exists under a *different* public key.
            That means the key file changed, which is not a routine event: every
            client has the old key in its contacts and would have to re-add the
            room. Failing loudly beats silently orphaning them.
    """
    room = session.scalar(select(Room).where(Room.slug == slug))
    if room is not None:
        if room.public_key != public_key:
            raise StoreError(
                f"room {slug!r} is recorded with public key {room.public_key.hex()[:16]}… "
                f"but the key file provides {public_key.hex()[:16]}…. Clients have the old "
                f"key in their contacts and cannot reach the new one. Restore the original "
                f"key file, or choose a new room slug to start fresh."
            )
        return room

    room = Room(slug=slug, public_key=public_key, created_at=now or int(time.time()))
    session.add(room)
    session.flush()
    return room


def get_room_by_slug(session: Session, slug: str) -> Room | None:
    return session.scalar(select(Room).where(Room.slug == slug))


def list_rooms(session: Session) -> list[Room]:
    return list(session.scalars(select(Room).order_by(Room.slug)))


# ---------------------------------------------------------------------------
# Posts
# ---------------------------------------------------------------------------


def next_post_ts(session: Session, room_id: int, now: int) -> int:
    """The timestamp to give the next post in this room.

    ``post_ts`` is the sync cursor, so it must be strictly increasing per room.
    Deriving it from the room's own maximum -- rather than from a stored global
    counter -- means it is self-healing after a restore and needs no coordination
    between rooms. Equivalent in intent to the firmware's
    ``getCurrentTimeUnique()``.
    """
    latest = session.scalar(select(func.max(Post.post_ts)).where(Post.room_id == room_id))
    if latest is None:
        return now
    return max(now, latest + 1)


def add_post(
    session: Session,
    room_id: int,
    author_public_key: bytes,
    text: str,
    post_ts: int,
) -> Post:
    """Record a post. ``post_ts`` should come from :func:`next_post_ts`."""
    post = Post(
        room_id=room_id,
        author_public_key=author_public_key,
        text=text,
        post_ts=post_ts,
    )
    session.add(post)
    session.flush()
    return post


def next_unsynced_post(
    session: Session,
    room_id: int,
    client_public_key: bytes,
    sync_since: int,
    *,
    not_newer_than: int,
) -> Post | None:
    """The oldest post this client is still owed.

    Three conditions, all mirroring the firmware's push loop:

    * newer than the client's ``sync_since``,
    * not authored by the client -- nobody needs their own post back,
    * settled for ``POST_SYNC_DELAY_SECS``, expressed here as ``not_newer_than``,
      so the author's own ACK has time to land before we start pushing.
    """
    return session.scalar(
        select(Post)
        .where(
            Post.room_id == room_id,
            Post.post_ts > sync_since,
            Post.post_ts <= not_newer_than,
            Post.author_public_key != client_public_key,
        )
        .order_by(Post.post_ts)
        .limit(1)
    )


def count_unsynced_posts(
    session: Session, room_id: int, client_public_key: bytes, sync_since: int
) -> int:
    """How many posts the client is owed, for the keep-alive ACK trailer.

    No settle-time filter here: the client is being told what is waiting, which
    is a different question from what we are ready to push this instant.
    """
    count = session.scalar(
        select(func.count())
        .select_from(Post)
        .where(
            Post.room_id == room_id,
            Post.post_ts > sync_since,
            Post.author_public_key != client_public_key,
        )
    )
    return count or 0


def recent_posts(session: Session, room_id: int, limit: int = 20) -> list[Post]:
    """Newest posts first, for operator inspection."""
    return list(
        session.scalars(
            select(Post).where(Post.room_id == room_id).order_by(Post.post_ts.desc()).limit(limit)
        )
    )


def prune_posts(
    session: Session,
    room_id: int,
    *,
    older_than: int | None = None,
    keep_newest: int | None = None,
) -> int:
    """Apply the retention policy, returning how many posts were removed.

    The two policies are independent reasons to delete, combined with **OR**: a
    post goes if it is too old *or* if it is past the count. Requiring both would
    make ``max_posts`` a dead letter whenever ``post_retention`` is also set --
    which it is by default -- so a busy room would grow without limit until its
    posts aged out, and the documented "keep at most N" would never hold.

    Never prunes a post a connected client has not yet been sent: the minimum
    ``sync_since`` across the room's clients is a floor on what can be deleted,
    and it is ANDed with everything else. Dropping an unsynced post would
    silently lose a message for someone, which no retention policy is worth.
    """
    floor = session.scalar(select(func.min(Client.sync_since)).where(Client.room_id == room_id))

    policies = []
    if older_than is not None:
        policies.append(Post.post_ts < older_than)

    if keep_newest is not None:
        kept = (
            select(Post.id)
            .where(Post.room_id == room_id)
            .order_by(Post.post_ts.desc())
            .limit(keep_newest)
        )
        policies.append(Post.id.not_in(kept))

    if not policies:
        return 0

    doomed = select(Post.id).where(Post.room_id == room_id, or_(*policies))

    if floor is not None:
        doomed = doomed.where(Post.post_ts <= floor)

    ids = list(session.scalars(doomed))
    if not ids:
        return 0

    session.execute(delete(Post).where(Post.id.in_(ids)))
    return len(ids)


# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------


def get_client(session: Session, room_id: int, public_key: bytes) -> Client | None:
    return session.get(Client, {"room_id": room_id, "public_key": public_key})


def record_login(
    session: Session,
    room_id: int,
    public_key: bytes,
    *,
    role: Permission,
    sender_timestamp: int,
    sync_since: int,
    now: int,
    reset_out_path: bool,
) -> Client:
    """Create or update a client's row on a successful login.

    ``sync_since`` comes from the client, which is how a returning client resumes
    where it left off (and how a client asking for history gets it).

    ``reset_out_path`` is set when the login arrived by flood: the route we had is
    no longer known to be good, so replies must flood until a path comes back.
    """
    client = get_client(session, room_id, public_key)
    if client is None:
        client = Client(
            room_id=room_id,
            public_key=public_key,
            first_seen=now,
        )
        session.add(client)

    client.last_role = int(role)
    client.last_timestamp = sender_timestamp
    client.sync_since = sync_since
    client.last_activity = now
    if reset_out_path:
        client.out_path = b""
        client.out_path_len = OUT_PATH_UNKNOWN

    session.flush()
    return client


def set_out_path(
    session: Session, room_id: int, public_key: bytes, path: bytes, path_len: int
) -> None:
    """Record the route back to a client, learned from a PATH packet."""
    session.execute(
        update(Client)
        .where(Client.room_id == room_id, Client.public_key == public_key)
        .values(out_path=path, out_path_len=path_len)
    )


def advance_sync(session: Session, room_id: int, public_key: bytes, post_ts: int) -> None:
    """Move a client's cursor forward after an acknowledged push.

    Guarded against going backwards: a late ACK for an older push must not undo
    progress, which would re-send posts the client already has.
    """
    session.execute(
        update(Client)
        .where(
            Client.room_id == room_id,
            Client.public_key == public_key,
            Client.sync_since < post_ts,
        )
        .values(sync_since=post_ts)
    )


def force_sync_since(session: Session, room_id: int, public_key: bytes, sync_since: int) -> None:
    """Set a client's cursor to exactly what it asked for, backwards or not.

    Deliberately not :func:`advance_sync`. That function's forward-only guard
    exists to stop a *late ACK* undoing progress, which is a race. This is a
    client explicitly saying "the newest post I hold is X" in a keep-alive
    (MyMesh.cpp:557), and a client that has lost history is entitled to ask for
    it again. Applying the forward-only guard here would make re-syncing after a
    client-side restore impossible.
    """
    session.execute(
        update(Client)
        .where(Client.room_id == room_id, Client.public_key == public_key)
        .values(sync_since=sync_since)
    )


def touch_client(
    session: Session,
    room_id: int,
    public_key: bytes,
    *,
    now: int,
    last_timestamp: int | None = None,
) -> None:
    """Mark activity, and optionally raise the replay guard.

    ``last_timestamp`` only ever increases, so an out-of-order packet cannot
    lower the bar for a subsequent replay.
    """
    values: dict[str, int] = {"last_activity": now}
    if last_timestamp is not None:
        values["last_timestamp"] = last_timestamp
        session.execute(
            update(Client)
            .where(
                Client.room_id == room_id,
                Client.public_key == public_key,
                Client.last_timestamp < last_timestamp,
            )
            .values(**values)
        )
        return

    session.execute(
        update(Client)
        .where(Client.room_id == room_id, Client.public_key == public_key)
        .values(**values)
    )


def list_clients(session: Session, room_id: int) -> list[Client]:
    return list(
        session.scalars(select(Client).where(Client.room_id == room_id).order_by(Client.first_seen))
    )


def list_admin_clients(session: Session, room_id: int) -> list[Client]:
    """Admins only, for REQ_TYPE_GET_ACCESS_LIST."""
    return list(
        session.scalars(
            select(Client)
            .where(Client.room_id == room_id, Client.last_role == int(Permission.ADMIN))
            .order_by(Client.first_seen)
        )
    )


# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------


def increment_counter(session: Session, room_id: int, name: str, by: int = 1) -> int:
    """Bump a statistic, creating it if absent. Returns the new value."""
    counter = session.get(Counter, {"room_id": room_id, "name": name})
    if counter is None:
        counter = Counter(room_id=room_id, name=name, value=0)
        session.add(counter)
    counter.value += by
    session.flush()
    return counter.value


def get_counters(session: Session, room_id: int) -> dict[str, int]:
    return {
        counter.name: counter.value
        for counter in session.scalars(select(Counter).where(Counter.room_id == room_id))
    }


def reset_counters(session: Session, room_id: int) -> None:
    """Zero every statistic for a room, for the `clear stats` CLI command."""
    session.execute(delete(Counter).where(Counter.room_id == room_id))


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------


def get_meta(session: Session, key: str) -> str | None:
    row = session.get(Meta, key)
    return None if row is None else row.value


def set_meta(session: Session, key: str, value: str) -> None:
    row = session.get(Meta, key)
    if row is None:
        session.add(Meta(key=key, value=value))
    else:
        row.value = value


def record_version(session: Session, version: str) -> None:
    """Note which meshelle version created and last opened this database.

    Cheap, and the first thing worth knowing when someone reports that an
    upgrade broke their room.
    """
    if get_meta(session, META_CREATED_BY) is None:
        set_meta(session, META_CREATED_BY, version)
    set_meta(session, META_LAST_OPENED_BY, version)
