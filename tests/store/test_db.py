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

"""The Store's threading model and connection configuration."""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError

from meshelle.store.db import Store, create_db_engine, database_url
from meshelle.store.models import Room


class TestPragmas:
    def test_wal_and_synchronous_normal_are_both_applied(self, db_path: Path) -> None:
        """These two are a pair. WAL makes synchronous=NORMAL safe -- it skips the
        fsync on commit but never corrupts the file. In rollback-journal mode the
        same setting risks real corruption, so seeing one without the other would
        be a data-loss bug rather than a tuning choice.
        """
        engine = create_db_engine(db_path)
        try:
            with engine.connect() as connection:
                journal = connection.execute(text("PRAGMA journal_mode")).scalar()
                synchronous = connection.execute(text("PRAGMA synchronous")).scalar()
        finally:
            engine.dispose()

        assert journal == "wal"
        assert synchronous == 1, "1 is NORMAL; 2 would be FULL, 0 would be OFF"

    def test_foreign_keys_are_enforced(self, db_path: Path) -> None:
        """Off by default in SQLite, so the cascade deletes would not work."""
        engine = create_db_engine(db_path)
        try:
            with engine.connect() as connection:
                assert connection.execute(text("PRAGMA foreign_keys")).scalar() == 1
        finally:
            engine.dispose()

    def test_busy_timeout_is_set(self, db_path: Path) -> None:
        engine = create_db_engine(db_path)
        try:
            with engine.connect() as connection:
                assert connection.execute(text("PRAGMA busy_timeout")).scalar() == 5000
        finally:
            engine.dispose()

    def test_a_corrupt_file_does_not_leak_its_connection(self, tmp_path: Path) -> None:
        """A pragma failing must close the raw connection it opened.

        SQLAlchemy has not adopted it at that point, so nothing else will, and it
        resurfaces as an unraisable ResourceWarning blamed on an unrelated test.
        """
        corrupt = tmp_path / "corrupt.db"
        corrupt.write_bytes(b"not a database")

        engine = create_db_engine(corrupt)
        try:
            with pytest.raises(SQLAlchemyError), engine.connect():
                pass
        finally:
            engine.dispose()


class TestDatabaseUrl:
    def test_builds_a_pysqlite_url(self, tmp_path: Path) -> None:
        url = database_url(tmp_path / "x.db")
        assert url.startswith("sqlite+pysqlite:///")
        assert str(tmp_path / "x.db") in url


class TestStore:
    async def test_runs_work_and_commits(self, store: Store) -> None:
        await store.run(lambda s: s.add(Room(slug="lobby", public_key=bytes(32), created_at=1)))

        slug = await store.run(lambda s: s.scalar(select(Room.slug)))
        assert slug == "lobby"

    async def test_rolls_back_when_work_raises(self, store: Store) -> None:
        """A failed handler must not leave a half-written room behind."""

        def explode(_session: object) -> None:
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            await store.run(explode)

        assert await store.run(lambda s: s.scalar(select(Room.slug))) is None

    async def test_work_never_runs_on_the_event_loop_thread(self, store: Store) -> None:
        """The whole point of the executor: an fsync must not stall the loop."""
        loop_thread = threading.get_ident()

        db_thread = await store.run(lambda _s: threading.get_ident())

        assert db_thread != loop_thread

    async def test_all_work_shares_one_thread(self, store: Store) -> None:
        """A single worker means writes serialise the way SQLite wants anyway."""
        threads = await asyncio.gather(
            *(store.run(lambda _s: threading.get_ident()) for _ in range(8))
        )
        assert len(set(threads)) == 1

    async def test_returned_objects_are_usable_after_the_session_closes(self, store: Store) -> None:
        """expire_on_commit=False, so callers get data rather than detached
        instances that raise on attribute access."""

        def create(session: object) -> Room:
            room = Room(slug="lobby", public_key=bytes(32), created_at=7)
            session.add(room)  # type: ignore[attr-defined]
            session.flush()  # type: ignore[attr-defined]
            return room

        room = await store.run(create)

        assert room.slug == "lobby"
        assert room.created_at == 7

    async def test_concurrent_callers_are_serialised_without_error(self, store: Store) -> None:
        async def insert(index: int) -> None:
            await store.run(
                lambda s: s.add(
                    Room(slug=f"room{index}", public_key=bytes([index]) + bytes(31), created_at=1)
                )
            )

        await asyncio.gather(*(insert(i) for i in range(10)))

        count = await store.run(lambda s: len(list(s.scalars(select(Room)))))
        assert count == 10

    async def test_close_is_idempotent(self, db_path: Path) -> None:
        instance = Store(db_path)
        await instance.aclose()
        await instance.aclose()

    async def test_using_a_closed_store_is_an_error(self, db_path: Path) -> None:
        instance = Store(db_path)
        await instance.aclose()

        with pytest.raises(RuntimeError, match="closed"):
            await instance.run(lambda _s: None)
