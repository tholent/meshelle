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

"""Database access on a dedicated thread.

SQLite has no async disk I/O. ``aiosqlite`` runs the ordinary blocking driver on
a background thread and wraps it in a future, so the choice is not *whether* to
offload but *where*. meshelle uses synchronous SQLAlchemy behind a single-worker
executor: the event loop never blocks on an fsync, database access serialises the
way SQLite wants anyway, the models type cleanly under mypy strict, and Alembic's
stock ``env.py`` works without the async variant or ``greenlet``.

Why the offload matters concretely: this is meant to run on a Pi, a WAL commit
fsyncs, and an SD card fsync can stall for 100ms or more. On the event loop that
would delay the push loop's ACK timing, which the retry logic depends on.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sqlite3
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

logger = logging.getLogger(__name__)

BUSY_TIMEOUT_MS = 5000
"""How long to wait on a lock before erroring. Relevant for a second process --
`meshelle db current` or an sqlite3 shell -- not for our own single writer."""


def _apply_pragmas(dbapi_connection: Any, _record: Any) -> None:
    """Configure each new SQLite connection.

    ``journal_mode=WAL`` and ``synchronous=NORMAL`` are **a pair, and must stay
    one**. In WAL mode NORMAL skips the fsync on commit (only checkpoints sync):
    the last few transactions can be lost to a power cut, but the file is never
    corrupted. In the default rollback-journal mode the same setting risks real
    corruption. Dropping WAL without restoring ``synchronous=FULL`` would quietly
    turn a durability trade-off into a data-loss bug.

    Losing a trailing transaction is benign here: a lost post is simply lost, and
    ``sync_since`` can only ever point at a post that survived, so no client
    desynchronises.

    WAL is orthogonal to the DB thread -- the thread solves event-loop blocking,
    WAL solves reader/writer concurrency (which one connection does not need) and,
    more to the point, halves the fsync cost per commit.
    """
    if not isinstance(dbapi_connection, sqlite3.Connection):  # pragma: no cover
        return

    try:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")  # safe ONLY with WAL, see above
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        finally:
            cursor.close()
    except Exception:
        # A pragma failing means the file is not a usable database. Close the raw
        # connection before re-raising: SQLAlchemy has not taken ownership of it
        # yet, so nothing else ever will, and it surfaces later as an unraisable
        # ResourceWarning attributed to whatever code happened to run next.
        with contextlib.suppress(Exception):
            dbapi_connection.close()
        raise


def database_url(path: Path) -> str:
    """The SQLAlchemy URL for a database file."""
    return f"sqlite+pysqlite:///{path}"


def create_db_engine(path: Path) -> Engine:
    """Build an engine with meshelle's pragmas attached."""
    engine = create_engine(database_url(path), future=True)
    event.listen(engine, "connect", _apply_pragmas)
    return engine


class Store:
    """Runs synchronous database work on one dedicated thread.

    Repository functions are plain synchronous callables taking a ``Session``,
    which makes them trivially unit-testable with no async fixtures. Call sites
    read ``await store.run(lambda s: posts.add(s, room_id, text))``.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._engine = create_db_engine(path)
        self._sessions = sessionmaker(self._engine, expire_on_commit=False)
        # One worker: SQLite serialises writes regardless, and a single thread
        # means no cross-thread connection sharing to reason about.
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="meshelle-db")
        self._closed = False

    async def run[T](self, work: Callable[[Session], T]) -> T:
        """Execute ``work`` in a transaction on the database thread.

        The transaction commits if ``work`` returns and rolls back if it raises.
        ``expire_on_commit=False`` means returned ORM objects stay readable after
        the session closes, so callers get usable data rather than detached
        instances that raise on attribute access.
        """
        if self._closed:
            raise RuntimeError("store is closed")
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self._in_session, work)

    def _in_session[T](self, work: Callable[[Session], T]) -> T:
        with self._sessions.begin() as session:
            return work(session)

    async def aclose(self) -> None:
        """Drain outstanding work, then dispose of the engine."""
        if self._closed:
            return
        self._closed = True
        # wait=True so an in-flight commit is not abandoned mid-transaction.
        await asyncio.to_thread(self._executor.shutdown, wait=True)
        await asyncio.to_thread(self._engine.dispose)
