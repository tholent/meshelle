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

"""Shared pytest configuration and the database fixtures.

Adds ``scripts/`` to ``sys.path`` so dev tooling under that directory can be
imported by tests without a per-module path hack.

Databases come from ``alembic upgrade head`` rather than
``Base.metadata.create_all``. That is deliberate: it means the schema under test
is the one migrations actually produce, so models and migrations cannot drift
apart unnoticed.

Migrating once per session and copying the file keeps that property while
amortising the cost -- running Alembic for every test made the store directory
take ten seconds on its own. ``tests/store/test_migrations.py`` still drives
``upgrade_to_head`` directly, so the migration machinery itself is exercised for
real.
"""

from __future__ import annotations

import logging
import shutil
import sys
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest

from meshelle.logs import shutdown_logging
from meshelle.store.db import Store
from meshelle.store.migrate import upgrade_to_head

REPO_ROOT = Path(__file__).parent.parent

sys.path.insert(0, str(REPO_ROOT / "scripts"))

WAL_SIDECARS = ("-wal", "-shm")


@pytest.fixture(autouse=True)
def _isolate_logging() -> Iterator[None]:
    """Undo any logging a test configured.

    ``configure_logging`` installs handlers on the *root* logger, so a test that
    runs a CLI command leaves them attached for the rest of the session -- and
    the next test asserting on captured output sees every record two or three
    times. Autouse because the leak is invisible in the test that causes it and
    only fails the ones that come after.
    """
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    shutdown_logging()
    root.handlers[:] = handlers
    root.setLevel(level)


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
async def store(db_path: Path) -> AsyncIterator[Store]:
    """A Store with its dedicated database thread, closed on teardown."""
    instance = Store(db_path)
    try:
        yield instance
    finally:
        await instance.aclose()
