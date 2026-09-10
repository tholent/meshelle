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

"""Logging setup.

**Records always go to stderr.** A file sink is additional, never a
replacement. meshcore-pi calls ``logging.basicConfig(filename=...)``, which
redirects every record into a file: raising the log level then appears to do
nothing at the terminal, and an operator watching a service start sees silence
from a process that is in fact talking.

:func:`configure_logging` is idempotent. It owns the handlers it installs and
closes them before installing new ones, so a SIGHUP reload cannot leave two
handlers on the root logger writing every line twice -- and cannot leak the
open file, which under this project's ``filterwarnings = ["error"]`` surfaces
as a ResourceWarning blamed on whatever ran next.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Final

from meshelle.config.model import LogFormat, LogLevel, LogSettings
from meshelle.paths import anchor

TEXT_FORMAT: Final = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
TIME_FORMAT: Final = "%Y-%m-%dT%H:%M:%S%z"

LEVELS: Final[dict[LogLevel, int]] = {
    LogLevel.DEBUG: logging.DEBUG,
    LogLevel.INFO: logging.INFO,
    LogLevel.WARNING: logging.WARNING,
    LogLevel.ERROR: logging.ERROR,
}

QUIET_LOGGERS: Final = ("alembic.runtime.migration",)
"""Third-party chatter that duplicates something meshelle already reports.

Alembic announces its dialect and transaction strategy on every upgrade, which
is two lines per start for information ``store.migrate`` already logs in one.
Left alone at debug level, where the operator has asked for everything.
"""

_installed: list[logging.Handler] = []
"""Handlers this module owns. Tracked explicitly rather than by tagging the
handler objects, so a reload removes exactly ours and leaves alone anything a
test or an embedding application attached."""


class LoggingError(Exception):
    """Logging could not be set up. The message is for the operator."""


class JsonFormatter(logging.Formatter):
    """One JSON object per line, for a log shipper rather than a human."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, str] = {
            "ts": self.formatTime(record, TIME_FORMAT),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info is not None:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info is not None:
            payload["stack"] = self.formatStack(record.stack_info)
        # ensure_ascii=False so a room name outside ASCII stays readable rather
        # than becoming a wall of \uXXXX escapes.
        return json.dumps(payload, ensure_ascii=False)


def _build_formatter(log_format: LogFormat) -> logging.Formatter:
    if log_format is LogFormat.JSON:
        return JsonFormatter()
    return logging.Formatter(TEXT_FORMAT, TIME_FORMAT)


def _remove_installed(root: logging.Logger) -> None:
    while _installed:
        handler = _installed.pop()
        root.removeHandler(handler)
        handler.close()


def configure_logging(settings: LogSettings, *, base: Path | None = None) -> None:
    """Install stderr logging, and a file sink if one is configured.

    Args:
        settings: the ``[log]`` section.
        base: directory a relative ``log.file`` is measured from. See
            :mod:`meshelle.paths` for why that is not the working directory.
    """
    root = logging.getLogger()
    _remove_installed(root)

    level = LEVELS[settings.level]
    root.setLevel(level)
    formatter = _build_formatter(settings.format)

    stderr = logging.StreamHandler(sys.stderr)
    stderr.setFormatter(formatter)
    root.addHandler(stderr)
    _installed.append(stderr)

    if settings.file is not None:
        path = anchor(settings.file, base) if base is not None else settings.file.expanduser()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(path, encoding="utf-8")
        except OSError as exc:
            # Refuse to start rather than run with logs going nowhere: a room
            # that silently stopped writing its log is a room nobody can debug.
            raise LoggingError(f"cannot open log file {path}: {exc}") from exc
        file_handler.setFormatter(_build_formatter(settings.format))
        root.addHandler(file_handler)
        _installed.append(file_handler)

    # Reset rather than only raise: a reload that turns debug logging *on*
    # must undo the floor a previous, quieter configuration installed.
    floor = logging.WARNING if level > logging.DEBUG else logging.NOTSET
    for name in QUIET_LOGGERS:
        logging.getLogger(name).setLevel(floor)


def shutdown_logging() -> None:
    """Close the handlers this module installed.

    Only needed by tests and by anything embedding meshelle in a longer-lived
    process; a normal exit closes them on the way out.
    """
    _remove_installed(logging.getLogger())
