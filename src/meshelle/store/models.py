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

"""SQLAlchemy models for room state.

Five tables, deliberately small. The design notes that matter:

``posts.post_ts`` is our own clock and is strictly increasing per room, which
makes it the sync cursor as well as the timestamp. A client tells us the newest
post it holds and we send everything after it, so this column carries protocol
meaning and must never be rewritten.

``clients.last_timestamp`` is the *client's* clock, used only as a replay guard.
The two are never compared to each other.

There is deliberately **no** ``shared_secret`` column: it is derivable from our
private key and the client's public key, so persisting it would add secret-at-rest
exposure for nothing. It is cached in memory instead.

There is likewise **no** ``pending_push`` table. ``sync_since`` only advances on an
acknowledged push, so a restart simply re-pushes from the last acknowledged post.
In-memory pending state is sufficient and cannot drift from the durable record.
"""

from __future__ import annotations

from sqlalchemy import (
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from meshelle.proto.constants import OUT_PATH_UNKNOWN, PUB_KEY_SIZE


class Base(DeclarativeBase):
    """Declarative base. Alembic compares against ``Base.metadata``."""


class Room(Base):
    """A hosted room, keyed by the identity it advertises under."""

    __tablename__ = "rooms"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    slug: Mapped[str] = mapped_column(String(64), unique=True)
    """The config section name, e.g. ``lobby``. Stable across restarts."""

    public_key: Mapped[bytes] = mapped_column(LargeBinary(PUB_KEY_SIZE), unique=True)
    created_at: Mapped[int] = mapped_column(Integer)

    def __repr__(self) -> str:
        return f"<Room {self.slug} {self.public_key[:4].hex()}>"


class Post(Base):
    """One message posted to a room.

    Unlike the firmware's 32-entry cyclic buffer, history is unbounded here and
    pruned by policy rather than by overwriting.
    """

    __tablename__ = "posts"
    __table_args__ = (
        # post_ts is the sync cursor, so duplicates within a room would make
        # "everything after X" ambiguous.
        UniqueConstraint("room_id", "post_ts", name="uq_posts_room_ts"),
        Index("ix_posts_room_ts", "room_id", "post_ts"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    room_id: Mapped[int] = mapped_column(ForeignKey("rooms.id", ondelete="CASCADE"))
    author_public_key: Mapped[bytes] = mapped_column(LargeBinary(PUB_KEY_SIZE))
    text: Mapped[str] = mapped_column(Text)
    post_ts: Mapped[int] = mapped_column(Integer)
    """Our clock, strictly increasing per room. Doubles as the sync cursor."""

    def __repr__(self) -> str:
        return f"<Post room={self.room_id} ts={self.post_ts} {self.text[:24]!r}>"


class Client(Base):
    """A client known to a room, and where its sync has reached."""

    __tablename__ = "clients"

    room_id: Mapped[int] = mapped_column(
        ForeignKey("rooms.id", ondelete="CASCADE"), primary_key=True
    )
    public_key: Mapped[bytes] = mapped_column(LargeBinary(PUB_KEY_SIZE), primary_key=True)

    last_role: Mapped[int] = mapped_column(Integer, default=0)
    """Cache of the last resolved ACL role, for `get acl` output and logging.

    Never authoritative: roles are resolved from config on every login.
    """

    last_timestamp: Mapped[int] = mapped_column(Integer, default=0)
    """Highest timestamp seen from this client, by THEIR clock. Replay guard."""

    sync_since: Mapped[int] = mapped_column(Integer, default=0)
    """Posts newer than this are owed to the client. Advances only on an ACK."""

    out_path: Mapped[bytes] = mapped_column(LargeBinary(64), default=b"")
    out_path_len: Mapped[int] = mapped_column(Integer, default=OUT_PATH_UNKNOWN)
    """``OUT_PATH_UNKNOWN`` (0xFF) means we must flood rather than send direct."""

    first_seen: Mapped[int] = mapped_column(Integer, default=0)
    last_activity: Mapped[int] = mapped_column(Integer, default=0)

    @property
    def has_out_path(self) -> bool:
        return self.out_path_len != OUT_PATH_UNKNOWN

    def __repr__(self) -> str:
        return f"<Client room={self.room_id} {self.public_key[:4].hex()} since={self.sync_since}>"


class Counter(Base):
    """Per-room statistics, reported via REQ_TYPE_GET_STATUS.

    A table rather than columns on ``rooms`` so a new statistic needs no
    migration -- these are append-only counters, not schema.
    """

    __tablename__ = "counters"

    room_id: Mapped[int] = mapped_column(
        ForeignKey("rooms.id", ondelete="CASCADE"), primary_key=True
    )
    name: Mapped[str] = mapped_column(String(32), primary_key=True)
    value: Mapped[int] = mapped_column(Integer, default=0)

    def __repr__(self) -> str:
        return f"<Counter room={self.room_id} {self.name}={self.value}>"


class Meta(Base):
    """Server-wide key/value state that is not per-room.

    Currently the high-water mark for unique timestamp generation, so post
    timestamps stay strictly increasing across a restart.
    """

    __tablename__ = "meta"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)

    def __repr__(self) -> str:
        return f"<Meta {self.key}={self.value!r}>"
