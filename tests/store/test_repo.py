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

"""Repository behaviour.

These functions carry the protocol's state machine, so the tests are about
semantics rather than SQL: a sync cursor that only moves forward, a replay guard
that only rises, a post that is never pushed back to its author, and retention
that cannot delete a message somebody has not been sent yet.
"""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from meshelle.proto.constants import OUT_PATH_UNKNOWN, Permission
from meshelle.store import repo
from meshelle.store.models import Post, Room

ALICE = bytes([0xA1]) + bytes(31)
BOB = bytes([0xB0]) + bytes(31)
CAROL = bytes([0xC0]) + bytes(31)
ROOM_KEY = bytes([0x1E]) + bytes(31)
OTHER_ROOM_KEY = bytes([0x2E]) + bytes(31)


@pytest.fixture
def room_id(session: Session) -> int:
    return repo.ensure_room(session, "lobby", ROOM_KEY, now=1000).id


class TestRooms:
    def test_creates_then_returns_the_same_room(self, session: Session) -> None:
        first = repo.ensure_room(session, "lobby", ROOM_KEY, now=1000)
        second = repo.ensure_room(session, "lobby", ROOM_KEY, now=2000)

        assert first.id == second.id
        assert second.created_at == 1000, "creation time is not rewritten"

    def test_rejects_a_changed_public_key(self, session: Session) -> None:
        """A room's identity is how clients address it. Silently accepting a new
        key would orphan every client that has the old one in its contacts."""
        repo.ensure_room(session, "lobby", ROOM_KEY)

        with pytest.raises(repo.StoreError, match="cannot reach the new one"):
            repo.ensure_room(session, "lobby", OTHER_ROOM_KEY)

    def test_separate_slugs_coexist(self, session: Session) -> None:
        repo.ensure_room(session, "lobby", ROOM_KEY)
        repo.ensure_room(session, "ops", OTHER_ROOM_KEY)

        assert [r.slug for r in repo.list_rooms(session)] == ["lobby", "ops"]

    def test_lookup_by_slug(self, session: Session) -> None:
        repo.ensure_room(session, "lobby", ROOM_KEY)

        assert repo.get_room_by_slug(session, "lobby") is not None
        assert repo.get_room_by_slug(session, "absent") is None


class TestPostTimestamps:
    def test_first_post_uses_the_current_time(self, session: Session, room_id: int) -> None:
        assert repo.next_post_ts(session, room_id, now=5000) == 5000

    def test_advances_past_the_latest_post(self, session: Session, room_id: int) -> None:
        """post_ts is the sync cursor, so two posts must never share one."""
        repo.add_post(session, room_id, ALICE, "first", 5000)

        assert repo.next_post_ts(session, room_id, now=5000) == 5001

    def test_survives_a_clock_that_went_backwards(self, session: Session, room_id: int) -> None:
        """An NTP step backwards must not produce a duplicate or lower cursor."""
        repo.add_post(session, room_id, ALICE, "first", 9000)

        assert repo.next_post_ts(session, room_id, now=100) == 9001

    def test_is_per_room(self, session: Session, room_id: int) -> None:
        other = repo.ensure_room(session, "ops", OTHER_ROOM_KEY).id
        repo.add_post(session, room_id, ALICE, "lobby post", 9000)

        assert repo.next_post_ts(session, other, now=5000) == 5000

    def test_duplicate_timestamps_are_rejected_by_the_database(
        self, session: Session, room_id: int
    ) -> None:
        from sqlalchemy.exc import IntegrityError

        repo.add_post(session, room_id, ALICE, "first", 5000)

        with pytest.raises(IntegrityError):
            repo.add_post(session, room_id, BOB, "clash", 5000)


class TestUnsyncedPosts:
    def test_returns_the_oldest_owed_post(self, session: Session, room_id: int) -> None:
        repo.add_post(session, room_id, ALICE, "older", 100)
        repo.add_post(session, room_id, ALICE, "newer", 200)

        owed = repo.next_unsynced_post(session, room_id, BOB, 0, not_newer_than=1000)

        assert owed is not None
        assert owed.text == "older"

    def test_respects_the_sync_cursor(self, session: Session, room_id: int) -> None:
        repo.add_post(session, room_id, ALICE, "seen", 100)
        repo.add_post(session, room_id, ALICE, "unseen", 200)

        owed = repo.next_unsynced_post(session, room_id, BOB, 100, not_newer_than=1000)

        assert owed is not None
        assert owed.text == "unseen"

    def test_never_returns_a_post_to_its_own_author(self, session: Session, room_id: int) -> None:
        repo.add_post(session, room_id, ALICE, "mine", 100)

        assert repo.next_unsynced_post(session, room_id, ALICE, 0, not_newer_than=1000) is None

    def test_withholds_a_post_that_has_not_settled(self, session: Session, room_id: int) -> None:
        """POST_SYNC_DELAY_SECS: the author's ACK should land before we push."""
        repo.add_post(session, room_id, ALICE, "fresh", 1000)

        assert repo.next_unsynced_post(session, room_id, BOB, 0, not_newer_than=999) is None
        assert repo.next_unsynced_post(session, room_id, BOB, 0, not_newer_than=1000) is not None

    def test_returns_none_when_fully_synced(self, session: Session, room_id: int) -> None:
        repo.add_post(session, room_id, ALICE, "only", 100)

        assert repo.next_unsynced_post(session, room_id, BOB, 100, not_newer_than=1000) is None

    def test_ignores_other_rooms(self, session: Session, room_id: int) -> None:
        other = repo.ensure_room(session, "ops", OTHER_ROOM_KEY).id
        repo.add_post(session, other, ALICE, "elsewhere", 100)

        assert repo.next_unsynced_post(session, room_id, BOB, 0, not_newer_than=1000) is None

    def test_counts_what_is_owed_without_the_settle_filter(
        self, session: Session, room_id: int
    ) -> None:
        """The keep-alive trailer tells a client what is waiting, which is a
        different question from what we are ready to push this instant."""
        repo.add_post(session, room_id, ALICE, "one", 100)
        repo.add_post(session, room_id, ALICE, "two", 200)
        repo.add_post(session, room_id, BOB, "bob's own", 300)

        assert repo.count_unsynced_posts(session, room_id, BOB, 0) == 2
        assert repo.count_unsynced_posts(session, room_id, BOB, 100) == 1
        assert repo.count_unsynced_posts(session, room_id, ALICE, 0) == 1


class TestClients:
    def test_records_a_new_login(self, session: Session, room_id: int) -> None:
        client = repo.record_login(
            session,
            room_id,
            ALICE,
            role=Permission.READ_WRITE,
            sender_timestamp=500,
            sync_since=400,
            now=1000,
            reset_out_path=False,
        )

        assert client.last_role == Permission.READ_WRITE
        assert client.sync_since == 400
        assert client.first_seen == 1000
        assert client.out_path_len == OUT_PATH_UNKNOWN

    def test_a_returning_client_keeps_its_first_seen(self, session: Session, room_id: int) -> None:
        repo.record_login(
            session,
            room_id,
            ALICE,
            role=Permission.GUEST,
            sender_timestamp=1,
            sync_since=0,
            now=1000,
            reset_out_path=False,
        )
        again = repo.record_login(
            session,
            room_id,
            ALICE,
            role=Permission.ADMIN,
            sender_timestamp=2,
            sync_since=50,
            now=2000,
            reset_out_path=False,
        )

        assert again.first_seen == 1000
        assert again.last_activity == 2000
        assert again.last_role == Permission.ADMIN, "role is re-resolved on every login"

    def test_a_flood_login_discards_the_known_route(self, session: Session, room_id: int) -> None:
        """Arriving by flood means the route we had is no longer known good."""
        repo.record_login(
            session,
            room_id,
            ALICE,
            role=Permission.GUEST,
            sender_timestamp=1,
            sync_since=0,
            now=1000,
            reset_out_path=False,
        )
        repo.set_out_path(session, room_id, ALICE, b"\x01\x02", 2)

        client = repo.record_login(
            session,
            room_id,
            ALICE,
            role=Permission.GUEST,
            sender_timestamp=2,
            sync_since=0,
            now=2000,
            reset_out_path=True,
        )

        assert client.out_path_len == OUT_PATH_UNKNOWN
        assert client.out_path == b""

    def test_stores_and_reports_a_route(self, session: Session, room_id: int) -> None:
        repo.record_login(
            session,
            room_id,
            ALICE,
            role=Permission.GUEST,
            sender_timestamp=1,
            sync_since=0,
            now=1000,
            reset_out_path=False,
        )
        repo.set_out_path(session, room_id, ALICE, b"\x0a\x0b\x0c", 3)

        client = repo.get_client(session, room_id, ALICE)
        assert client is not None
        assert client.out_path == b"\x0a\x0b\x0c"
        assert client.has_out_path

    def test_sync_cursor_only_moves_forward(self, session: Session, room_id: int) -> None:
        """A late ACK for an older push must not undo progress, which would
        re-send posts the client already has."""
        repo.record_login(
            session,
            room_id,
            ALICE,
            role=Permission.GUEST,
            sender_timestamp=1,
            sync_since=0,
            now=1000,
            reset_out_path=False,
        )

        repo.advance_sync(session, room_id, ALICE, 500)
        repo.advance_sync(session, room_id, ALICE, 200)

        client = repo.get_client(session, room_id, ALICE)
        assert client is not None
        assert client.sync_since == 500

    def test_replay_guard_only_rises(self, session: Session, room_id: int) -> None:
        """An out-of-order packet must not lower the bar for a later replay."""
        repo.record_login(
            session,
            room_id,
            ALICE,
            role=Permission.GUEST,
            sender_timestamp=100,
            sync_since=0,
            now=1000,
            reset_out_path=False,
        )

        repo.touch_client(session, room_id, ALICE, now=1100, last_timestamp=200)
        repo.touch_client(session, room_id, ALICE, now=1200, last_timestamp=50)

        client = repo.get_client(session, room_id, ALICE)
        assert client is not None
        assert client.last_timestamp == 200

    def test_touch_without_a_timestamp_only_marks_activity(
        self, session: Session, room_id: int
    ) -> None:
        repo.record_login(
            session,
            room_id,
            ALICE,
            role=Permission.GUEST,
            sender_timestamp=100,
            sync_since=0,
            now=1000,
            reset_out_path=False,
        )

        repo.touch_client(session, room_id, ALICE, now=9999)

        client = repo.get_client(session, room_id, ALICE)
        assert client is not None
        assert client.last_activity == 9999
        assert client.last_timestamp == 100

    def test_unknown_client_is_none(self, session: Session, room_id: int) -> None:
        assert repo.get_client(session, room_id, CAROL) is None

    def test_lists_only_admins_for_the_access_list(self, session: Session, room_id: int) -> None:
        for key, role in (
            (ALICE, Permission.ADMIN),
            (BOB, Permission.READ_WRITE),
            (CAROL, Permission.ADMIN),
        ):
            repo.record_login(
                session,
                room_id,
                key,
                role=role,
                sender_timestamp=1,
                sync_since=0,
                now=1000,
                reset_out_path=False,
            )

        admins = {c.public_key for c in repo.list_admin_clients(session, room_id)}
        assert admins == {ALICE, CAROL}
        assert len(repo.list_clients(session, room_id)) == 3

    def test_clients_are_scoped_to_their_room(self, session: Session, room_id: int) -> None:
        other = repo.ensure_room(session, "ops", OTHER_ROOM_KEY).id
        repo.record_login(
            session,
            room_id,
            ALICE,
            role=Permission.ADMIN,
            sender_timestamp=1,
            sync_since=0,
            now=1000,
            reset_out_path=False,
        )

        assert repo.get_client(session, other, ALICE) is None
        assert repo.list_clients(session, other) == []


class TestRetention:
    def _posts(self, session: Session, room_id: int, count: int) -> None:
        for index in range(count):
            repo.add_post(session, room_id, ALICE, f"post {index}", 100 + index)

    def test_does_nothing_without_a_policy(self, session: Session, room_id: int) -> None:
        self._posts(session, room_id, 5)
        assert repo.prune_posts(session, room_id) == 0

    def test_prunes_by_age(self, session: Session, room_id: int) -> None:
        self._posts(session, room_id, 5)  # post_ts 100..104

        removed = repo.prune_posts(session, room_id, older_than=102)

        assert removed == 2
        remaining = {p.post_ts for p in repo.recent_posts(session, room_id)}
        assert remaining == {102, 103, 104}

    def test_prunes_by_count(self, session: Session, room_id: int) -> None:
        self._posts(session, room_id, 5)

        removed = repo.prune_posts(session, room_id, keep_newest=2)

        assert removed == 3
        assert {p.post_ts for p in repo.recent_posts(session, room_id)} == {103, 104}

    def test_the_two_policies_are_independent_reasons_to_delete(
        self, session: Session, room_id: int
    ) -> None:
        """OR, not AND.

        Requiring both would make ``max_posts`` a dead letter whenever
        ``post_retention`` is also set -- which it is by default -- so a busy
        room would grow past its declared cap until its posts aged out.
        """
        self._posts(session, room_id, 5)  # post_ts 100..104, none of them old

        removed = repo.prune_posts(session, room_id, older_than=0, keep_newest=2)

        assert removed == 3, "the count policy must bind on its own"
        assert {p.post_ts for p in repo.recent_posts(session, room_id)} == {103, 104}

    def test_never_prunes_a_post_a_client_has_not_been_sent(
        self, session: Session, room_id: int
    ) -> None:
        """Dropping an unsynced post silently loses a message for somebody.

        Bob has only synced to 101, so 102 onwards must survive even though the
        age policy would otherwise take them.
        """
        self._posts(session, room_id, 5)
        repo.record_login(
            session,
            room_id,
            BOB,
            role=Permission.READ_WRITE,
            sender_timestamp=1,
            sync_since=101,
            now=1000,
            reset_out_path=False,
        )

        removed = repo.prune_posts(session, room_id, older_than=999)

        assert removed == 2, "only posts at or below Bob's cursor may go"
        assert {p.post_ts for p in repo.recent_posts(session, room_id)} == {102, 103, 104}

    def test_the_floor_is_the_least_synced_client(self, session: Session, room_id: int) -> None:
        self._posts(session, room_id, 5)
        for key, since in ((ALICE, 104), (BOB, 100)):
            repo.record_login(
                session,
                room_id,
                key,
                role=Permission.READ_WRITE,
                sender_timestamp=1,
                sync_since=since,
                now=1000,
                reset_out_path=False,
            )

        removed = repo.prune_posts(session, room_id, older_than=999)

        assert removed == 1, "Bob's cursor at 100 holds everything above it"

    def test_recent_posts_are_newest_first(self, session: Session, room_id: int) -> None:
        self._posts(session, room_id, 5)

        recent = repo.recent_posts(session, room_id, limit=3)

        assert [p.post_ts for p in recent] == [104, 103, 102]

    def test_deleting_a_room_cascades_to_its_posts(self, session: Session, room_id: int) -> None:
        """Relies on PRAGMA foreign_keys=ON, which SQLite leaves off by default."""
        from sqlalchemy import delete, select

        self._posts(session, room_id, 3)
        session.execute(delete(Room).where(Room.id == room_id))
        session.flush()

        assert list(session.scalars(select(Post))) == []


class TestClientRetention:
    """Forgetting clients, and the two things that must stop it.

    Nothing else removes a client row, so a room whose ``allow_unknown`` grants
    a role gains one per stranger and never loses it. These tests pin the policy
    and, more importantly, the cases it is not allowed to apply to.
    """

    def _seen(self, session: Session, room_id: int, key: bytes, when: int, since: int = 0) -> None:
        repo.record_login(
            session,
            room_id,
            key,
            role=Permission.READ_WRITE,
            sender_timestamp=1,
            sync_since=since,
            now=when,
            reset_out_path=False,
        )

    def test_forgets_a_client_idle_past_the_cutoff(self, session: Session, room_id: int) -> None:
        self._seen(session, room_id, ALICE, when=100)
        self._seen(session, room_id, BOB, when=900)

        assert repo.prune_clients(session, room_id, older_than=500) == [ALICE]
        assert [c.public_key for c in repo.list_clients(session, room_id)] == [BOB]

    def test_the_cutoff_is_exclusive(self, session: Session, room_id: int) -> None:
        """A client seen exactly at the cutoff has not yet been idle that long.

        An inclusive test would forget a client one second early, which matters
        only at the boundary but is the kind of off-by-one that reads as "it
        sometimes forgets people" in a bug report.
        """
        self._seen(session, room_id, ALICE, when=500)

        assert repo.prune_clients(session, room_id, older_than=500) == []

    def test_returns_the_keys_not_a_count(self, session: Session, room_id: int) -> None:
        """The caller holds the matching in-memory sessions and must drop the
        same ones. A count would let the two disagree, and a live session for a
        deleted row re-creates it on the client's next packet -- so the policy
        would never make progress."""
        self._seen(session, room_id, ALICE, when=100)
        self._seen(session, room_id, BOB, when=100)

        assert set(repo.prune_clients(session, room_id, older_than=500)) == {ALICE, BOB}

    def test_an_owed_post_does_not_save_an_idle_client(
        self, session: Session, room_id: int
    ) -> None:
        """Idleness is the whole test, and this is the case that proves it.

        Sparing any client still owed a post sounds prudent and is close to a
        no-op: with a 30-day post retention almost every idle client is owed
        something, so the policy would never fire. It is safe to forget them
        because sync position does not live in this row -- the client's own
        login carries the timestamp of the newest post it holds, and
        ``record_login`` takes that claim verbatim.
        """
        repo.add_post(session, room_id, ALICE, "unread by bob", 700)
        self._seen(session, room_id, BOB, when=100, since=600)

        assert repo.prune_clients(session, room_id, older_than=500) == [BOB]

    def test_keep_spares_a_client_whatever_its_idleness(
        self, session: Session, room_id: int
    ) -> None:
        """``keep`` carries state the database cannot see: a push already on the
        air. Deleting that row now strands the ACK with nothing to advance."""
        self._seen(session, room_id, ALICE, when=100)
        self._seen(session, room_id, BOB, when=100)

        dropped = repo.prune_clients(session, room_id, older_than=500, keep=frozenset({ALICE}))

        assert dropped == [BOB]
        assert [c.public_key for c in repo.list_clients(session, room_id)] == [ALICE]

    def test_leaves_other_rooms_alone(self, session: Session, room_id: int) -> None:
        other = repo.ensure_room(session, "ops", OTHER_ROOM_KEY, now=1000).id
        self._seen(session, room_id, ALICE, when=100)
        self._seen(session, other, ALICE, when=100)

        repo.prune_clients(session, room_id, older_than=500)

        assert [c.public_key for c in repo.list_clients(session, other)] == [ALICE]

    def test_forgetting_a_client_releases_the_posts_it_was_pinning(
        self, session: Session, room_id: int
    ) -> None:
        """The interaction that makes this worth having.

        ``prune_posts`` floors deletion at the lowest ``sync_since`` in the
        room, so a long-dead client pins every post above its cursor and
        ``max_posts`` never binds. Pruning clients first is what releases them.

        Bob is the client that posted and then left. His cursor never moved past
        his first post, so it floors the whole room even though he is long gone.
        """
        for index in range(5):
            repo.add_post(session, room_id, BOB, f"post {index}", 100 + index)
        self._seen(session, room_id, BOB, when=10, since=100)
        self._seen(session, room_id, CAROL, when=900, since=104)

        assert repo.prune_posts(session, room_id, older_than=999) == 1, "Bob pins the rest"

        repo.prune_clients(session, room_id, older_than=500)

        assert repo.prune_posts(session, room_id, older_than=999) == 4


class TestCounters:
    def test_increments_from_nothing(self, session: Session, room_id: int) -> None:
        assert repo.increment_counter(session, room_id, "posted") == 1
        assert repo.increment_counter(session, room_id, "posted") == 2

    def test_increments_by_a_step(self, session: Session, room_id: int) -> None:
        assert repo.increment_counter(session, room_id, "pushed", by=5) == 5

    def test_reports_all_counters(self, session: Session, room_id: int) -> None:
        repo.increment_counter(session, room_id, "posted", by=3)
        repo.increment_counter(session, room_id, "pushed", by=7)

        assert repo.get_counters(session, room_id) == {"posted": 3, "pushed": 7}

    def test_counters_are_per_room(self, session: Session, room_id: int) -> None:
        other = repo.ensure_room(session, "ops", OTHER_ROOM_KEY).id
        repo.increment_counter(session, room_id, "posted")

        assert repo.get_counters(session, other) == {}

    def test_reset_clears_them(self, session: Session, room_id: int) -> None:
        repo.increment_counter(session, room_id, "posted", by=9)

        repo.reset_counters(session, room_id)

        assert repo.get_counters(session, room_id) == {}


class TestMeta:
    def test_round_trips(self, session: Session) -> None:
        assert repo.get_meta(session, "absent") is None

        repo.set_meta(session, "key", "value")
        assert repo.get_meta(session, "key") == "value"

        repo.set_meta(session, "key", "updated")
        assert repo.get_meta(session, "key") == "updated"

    def test_records_the_creating_and_latest_version(self, session: Session) -> None:
        """The first thing worth knowing when an upgrade breaks someone's room."""
        repo.record_version(session, "0.1.0")
        repo.record_version(session, "0.2.0")

        assert repo.get_meta(session, repo.META_CREATED_BY) == "0.1.0"
        assert repo.get_meta(session, repo.META_LAST_OPENED_BY) == "0.2.0"
