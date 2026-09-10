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

"""Migration tests.

These are what make carrying Alembic worthwhile rather than ceremonial:

* the shared DB fixture runs ``alembic upgrade head`` rather than
  ``create_all``, so every other test in the suite exercises the real migration
  path, not a parallel schema definition that can silently drift;
* autogenerate against a migrated database must produce an **empty** diff, which
  catches models edited without a matching revision;
* upgrade -> downgrade -> upgrade must round-trip, so a revision is not a one-way
  door.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext

from meshelle.store.db import create_db_engine
from meshelle.store.migrate import (
    MigrationError,
    alembic_config,
    current_revision,
    downgrade,
    head_revision,
    upgrade_to_head,
)
from meshelle.store.models import Base

EXPECTED_TABLES = {"alembic_version", "clients", "counters", "meta", "posts", "rooms"}


def table_names(db_path: Path) -> set[str]:
    connection = sqlite3.connect(db_path)
    try:
        rows = connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        return {row[0] for row in rows}
    finally:
        connection.close()


class TestUpgrade:
    def test_creates_the_schema_from_nothing(self, tmp_path: Path) -> None:
        db = tmp_path / "new.db"
        assert current_revision(db) is None

        result = upgrade_to_head(db)

        assert result.changed
        assert result.from_revision is None
        assert result.to_revision == head_revision()
        assert table_names(db) == EXPECTED_TABLES

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        db = tmp_path / "nested" / "deeper" / "meshelle.db"
        upgrade_to_head(db)
        assert db.exists()

    def test_is_idempotent(self, tmp_path: Path) -> None:
        """The startup path runs this every boot; it must be a no-op when current."""
        db = tmp_path / "new.db"
        upgrade_to_head(db)

        result = upgrade_to_head(db)

        assert not result.changed
        assert "already at" in result.describe()

    def test_reports_the_revision_transition(self, tmp_path: Path) -> None:
        db = tmp_path / "new.db"
        result = upgrade_to_head(db)

        assert "empty ->" in result.describe()
        assert result.to_revision is not None

    def test_a_corrupt_database_fails_with_context(self, tmp_path: Path) -> None:
        """And without leaking the raw connection opened while finding out.

        A pragma failing on a corrupt file leaves a sqlite3.Connection that
        SQLAlchemy has not adopted, which otherwise resurfaces as an unraisable
        ResourceWarning blamed on an unrelated test.
        """
        db = tmp_path / "garbage.db"
        db.write_bytes(b"this is not a SQLite file at all")

        with pytest.raises(MigrationError, match="not a usable SQLite database"):
            upgrade_to_head(db)

    def test_reading_the_revision_of_a_corrupt_database_is_reported(self, tmp_path: Path) -> None:
        """`meshelle db current` must say what is wrong, not raise a driver error."""
        db = tmp_path / "garbage.db"
        db.write_bytes(b"definitely not SQLite")

        with pytest.raises(MigrationError, match="not a usable SQLite database"):
            current_revision(db)


class TestSchemaMatchesModels:
    def test_autogenerate_finds_nothing_to_change(self, tmp_path: Path) -> None:
        """The drift guard.

        If a model is edited without a matching revision, this diff is non-empty
        and the test names exactly what is missing. Without it, the models and the
        migrations quietly diverge until a fresh deployment gets a schema that
        production never had.
        """
        db = tmp_path / "current.db"
        upgrade_to_head(db)

        engine = create_db_engine(db)
        try:
            with engine.connect() as connection:
                context = MigrationContext.configure(
                    connection,
                    opts={"compare_type": True, "compare_server_default": True},
                )
                diff = compare_metadata(context, Base.metadata)
        finally:
            engine.dispose()

        assert diff == [], f"models have drifted from migrations: {diff}"

    def test_every_model_table_exists(self, tmp_path: Path) -> None:
        db = tmp_path / "current.db"
        upgrade_to_head(db)

        created = table_names(db)
        for table in Base.metadata.tables:
            assert table in created


class TestDowngrade:
    def test_round_trips_to_base_and_back(self, tmp_path: Path) -> None:
        """A revision must not be a one-way door."""
        db = tmp_path / "new.db"
        upgrade_to_head(db)

        downgrade(db, "base")
        assert current_revision(db) is None
        assert "posts" not in table_names(db)

        upgrade_to_head(db)
        assert current_revision(db) == head_revision()
        assert table_names(db) == EXPECTED_TABLES

    def test_reports_a_bad_target(self, tmp_path: Path) -> None:
        db = tmp_path / "new.db"
        upgrade_to_head(db)

        with pytest.raises(MigrationError, match="failed to downgrade"):
            downgrade(db, "nosuchrevision")


class TestConfiguration:
    def test_migrations_ship_inside_the_package(self) -> None:
        """So an installed wheel can migrate, not just a source checkout."""
        config = alembic_config(Path("unused.db"))
        script_location = config.get_main_option("script_location")

        assert script_location is not None
        location = Path(script_location)
        assert location.is_dir()
        assert (location / "env.py").exists()
        assert location.parent.name == "store"

    def test_url_points_at_the_requested_database(self, tmp_path: Path) -> None:
        db = tmp_path / "somewhere.db"
        url = alembic_config(db).get_main_option("sqlalchemy.url")

        assert url is not None
        assert str(db) in url

    def test_env_enables_batch_mode_on_both_paths(self) -> None:
        """SQLite cannot ALTER TABLE in place; without render_as_batch the first
        non-additive migration is simply unwritable.

        Asserted per function body rather than by counting occurrences, so a
        mention in a docstring cannot stand in for the real setting.
        """
        env = (
            Path(alembic_config(Path("unused.db")).get_main_option("script_location") or "")
            / "env.py"
        ).read_text()

        offline = env.split("def run_migrations_offline")[1].split("def run_migrations_online")[0]
        online = env.split("def run_migrations_online")[1]

        assert "render_as_batch=True" in offline
        assert "render_as_batch=True" in online

    def test_revision_template_carries_the_license_header(self) -> None:
        """Generated revisions must inherit the header, or the compliance test
        fails the moment someone runs `db revision`."""
        template = (
            Path(alembic_config(Path("unused.db")).get_main_option("script_location") or "")
            / "script.py.mako"
        ).read_text()

        assert "SPDX-License-Identifier: Apache-2.0" in template

    def test_head_revision_is_known(self) -> None:
        assert head_revision() is not None

    def test_current_revision_of_a_missing_file_is_none(self, tmp_path: Path) -> None:
        assert current_revision(tmp_path / "absent.db") is None
