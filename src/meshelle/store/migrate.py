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

"""Schema migrations, driven programmatically.

A room server is an unattended appliance. Refusing to boot after a version bump
is worse than migrating a small SQLite file, so :func:`upgrade_to_head` runs at
startup and logs what it did. ``meshelle db ...`` wraps the same machinery for
manual and development use.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy.exc import SQLAlchemyError

from meshelle.store.db import create_db_engine, database_url

logger = logging.getLogger(__name__)

PACKAGE_DIR = Path(__file__).parent
ALEMBIC_INI = PACKAGE_DIR / "alembic.ini"
MIGRATIONS_DIR = PACKAGE_DIR / "migrations"


class MigrationError(Exception):
    """The schema could not be brought up to date."""


@dataclass(frozen=True, slots=True)
class MigrationResult:
    """What an upgrade actually changed."""

    from_revision: str | None
    to_revision: str | None

    @property
    def changed(self) -> bool:
        return self.from_revision != self.to_revision

    def describe(self) -> str:
        if not self.changed:
            return f"schema already at {self.to_revision or 'base'}"
        return f"schema {self.from_revision or 'empty'} -> {self.to_revision or 'base'}"


def alembic_config(db_path: Path) -> Config:
    """An Alembic config pointed at the in-package migrations and ``db_path``.

    Both options are set here rather than read from alembic.ini, because an
    installed wheel's migration directory is wherever the package landed and the
    database is wherever the user configured it.
    """
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    config.set_main_option("sqlalchemy.url", database_url(db_path))
    return config


def head_revision() -> str | None:
    """The newest revision shipped in this build."""
    script = ScriptDirectory(str(MIGRATIONS_DIR))
    return script.get_current_head()


def current_revision(db_path: Path) -> str | None:
    """The revision a database is stamped with, or None if never migrated.

    Raises:
        MigrationError: the file exists but is not a usable SQLite database.
            Reported here rather than leaking a driver-level DatabaseError,
            because this is also what ``meshelle db current`` surfaces to an
            operator.
    """
    if not db_path.exists():
        return None

    engine = create_db_engine(db_path)
    try:
        with engine.connect() as connection:
            return MigrationContext.configure(connection).get_current_revision()
    except SQLAlchemyError as exc:
        raise MigrationError(
            f"{db_path} exists but is not a usable SQLite database: {exc}"
        ) from exc
    finally:
        engine.dispose()


def upgrade_to_head(db_path: Path) -> MigrationResult:
    """Bring ``db_path`` up to the newest revision, creating it if absent."""
    db_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        before = current_revision(db_path)
        command.upgrade(alembic_config(db_path), "head")
    except MigrationError:
        raise
    except Exception as exc:
        raise MigrationError(f"failed to migrate {db_path}: {exc}") from exc

    result = MigrationResult(from_revision=before, to_revision=current_revision(db_path))
    if result.changed:
        logger.info("db: %s", result.describe())
    else:
        logger.debug("db: %s", result.describe())
    return result


def downgrade(db_path: Path, revision: str) -> MigrationResult:
    """Roll back to ``revision``. Only ever invoked explicitly by an operator."""
    before = current_revision(db_path)
    try:
        command.downgrade(alembic_config(db_path), revision)
    except Exception as exc:
        raise MigrationError(f"failed to downgrade {db_path} to {revision}: {exc}") from exc

    result = MigrationResult(from_revision=before, to_revision=current_revision(db_path))
    logger.info("db: %s", result.describe())
    return result
