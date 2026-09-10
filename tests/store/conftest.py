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

"""Fixtures for testing repository functions directly.

The database fixtures themselves live in ``tests/conftest.py``, because the room
tests need them too. This adds only the synchronous ``Session`` that repository
tests use to skip the async plumbing entirely.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from meshelle.store.db import create_db_engine


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
