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

"""Store fixtures.

Databases come from ``alembic upgrade head`` rather than
``Base.metadata.create_all``. That is deliberate: it means the schema under test
is the one migrations actually produce, so models and migrations cannot drift
apart unnoticed.

Migrating once per session and copying the file keeps that property while
amortising the cost -- running Alembic for every test made this directory take
ten seconds on its own. ``tests/store/test_migrations.py`` still drives
``upgrade_to_head`` directly, so the migration machinery itself is exercised for
real.
"""

from __future__ import annotations

import shutil
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from meshelle.store.db import Store, create_db_engine
from meshelle.store.migrate import upgrade_to_head

WAL_SIDECARS = ("-wal", "-shm")


@pytest.fixture(scope="session")
def migrated_template(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One migrated database, built once and copied per test."""
    path = tmp_path_factory.mktemp("template") / "template.db"
    upgrade_to_head(path)
    return path


@pytest.fixture
def db_path(tmp_path: Path, migrated_template: Path) -> Path:
    """A migrated, empty database, private to one test."""
    path = tmp_path / "meshelle.db"
    shutil.copy(migrated_template, path)
    # In WAL mode a commit can still be sitting in the sidecar files, so copy
    # them too rather than assuming the last close checkpointed.
    for suffix in WAL_SIDECARS:
        sidecar = Path(f"{migrated_template}{suffix}")
        if sidecar.exists():
            shutil.copy(sidecar, f"{path}{suffix}")
    return path


@pytest.fixture
def session(db_path: Path) -> Iterator[Session]:
    """A session for testing repository functions directly, no async needed."""
    engine = create_db_engine(db_path)
    factory = sessionmaker(engine, expire_on_commit=False)
    try:
        with factory.begin() as active:
            yield active
    finally:
        engine.dispose()


@pytest.fixture
async def store(db_path: Path) -> AsyncIterator[Store]:
    """A Store with its dedicated database thread, closed on teardown."""
    instance = Store(db_path)
    try:
        yield instance
    finally:
        await instance.aclose()
