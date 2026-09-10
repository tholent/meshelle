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

"""Logging behaviour that an operator would otherwise discover the hard way.

The headline case is the meshcore-pi one: ``basicConfig(filename=...)`` sends
every record to a file, so the terminal shows nothing and raising the log level
appears to do nothing at all. stderr must always be a destination.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from meshelle.config.model import LogFormat, LogLevel, LogSettings
from meshelle.logs import LoggingError, configure_logging


def test_stderr_is_always_a_destination(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """A file sink is additional, never a replacement.

    meshcore-pi redirects everything into a file, so an operator watching a
    service start sees silence from a process that is in fact talking.
    """
    log_file = tmp_path / "meshelle.log"
    configure_logging(LogSettings(level=LogLevel.INFO, file=log_file))

    logging.getLogger("meshelle.test").info("room lobby is up")

    assert "room lobby is up" in capsys.readouterr().err
    assert "room lobby is up" in log_file.read_text(encoding="utf-8")


def test_a_missing_log_directory_is_created(tmp_path: Path) -> None:
    path = tmp_path / "logs" / "nested" / "meshelle.log"
    configure_logging(LogSettings(file=path))
    logging.getLogger("meshelle.test").warning("hello")
    assert path.exists()


def test_an_unusable_log_file_refuses_to_start(tmp_path: Path) -> None:
    """Better to fail than to run with the log going nowhere.

    A room that silently stopped writing its log is a room nobody can debug.
    """
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("", encoding="utf-8")

    with pytest.raises(LoggingError, match="cannot open log file"):
        configure_logging(LogSettings(file=blocker / "meshelle.log"))


def test_reconfiguring_does_not_duplicate_records(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """SIGHUP reloads logging; twice-installed handlers write every line twice."""
    settings = LogSettings(file=tmp_path / "meshelle.log")
    configure_logging(settings)
    configure_logging(settings)

    logging.getLogger("meshelle.test").info("once")

    assert capsys.readouterr().err.count("once") == 1
    assert (tmp_path / "meshelle.log").read_text(encoding="utf-8").count("once") == 1


def test_reconfiguring_closes_the_previous_file(tmp_path: Path) -> None:
    """A leaked FileHandler surfaces as a ResourceWarning blamed on later code.

    ``filterwarnings = ["error"]`` then fails whichever unrelated test ran next,
    so the handler is closed rather than dropped.
    """
    first, second = tmp_path / "one.log", tmp_path / "two.log"
    configure_logging(LogSettings(file=first))
    handler = next(
        h
        for h in logging.getLogger().handlers
        if isinstance(h, logging.FileHandler) and h.baseFilename == str(first)
    )
    # Held onto before the reconfigure: FileHandler.close() drops its reference,
    # so the only way to check the descriptor is to have kept one.
    stream = handler.stream
    assert stream is not None

    configure_logging(LogSettings(file=second))

    assert stream.closed


def test_json_format_is_one_object_per_line(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(LogSettings(format=LogFormat.JSON))

    logging.getLogger("meshelle.room").warning("client %s refused", "ab12")

    record = json.loads(capsys.readouterr().err.strip())
    assert record["level"] == "WARNING"
    assert record["logger"] == "meshelle.room"
    assert record["message"] == "client ab12 refused"


def test_json_format_carries_the_traceback(capsys: pytest.CaptureFixture[str]) -> None:
    """An exception logged as JSON must not lose its traceback to the encoder."""
    configure_logging(LogSettings(format=LogFormat.JSON))

    try:
        raise ValueError("no such port")
    except ValueError:
        logging.getLogger("meshelle.test").exception("link failed")

    record = json.loads(capsys.readouterr().err.strip())
    assert "ValueError: no such port" in record["exception"]


def test_level_is_applied_to_the_root_logger(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(LogSettings(level=LogLevel.WARNING))

    logging.getLogger("meshelle.test").info("chatter")
    logging.getLogger("meshelle.test").warning("trouble")

    captured = capsys.readouterr().err
    assert "chatter" not in captured
    assert "trouble" in captured


def test_debug_level_lifts_the_third_party_floor() -> None:
    """Alembic is quietened by default, but 'give me everything' means it."""
    configure_logging(LogSettings(level=LogLevel.INFO))
    assert logging.getLogger("alembic.runtime.migration").level == logging.WARNING

    configure_logging(LogSettings(level=LogLevel.DEBUG))
    assert logging.getLogger("alembic.runtime.migration").level == logging.NOTSET


def test_a_relative_log_file_is_anchored_to_the_config(tmp_path: Path) -> None:
    """Not to the working directory -- see :mod:`meshelle.paths`."""
    configure_logging(LogSettings(file=Path("meshelle.log")), base=tmp_path)
    logging.getLogger("meshelle.test").warning("hello")
    assert (tmp_path / "meshelle.log").exists()
