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

"""Load and validate configuration.

Precedence is **CLI > environment > file > defaults**, implemented as an explicit
deep merge of plain dicts before a single validation pass. Doing the merge
ourselves rather than layering settings sources keeps the ordering obvious and
makes it directly testable, which matters more here than saving a few lines.

The file uses TOML's natural shapes -- ``[room.lobby]`` and
``[[room.lobby.member]]`` -- which are mapped to the model's ``rooms`` and
``members`` before validation. Error messages translate back, so a message never
mentions a key the user did not write.
"""

from __future__ import annotations

import difflib
import logging
import os
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from meshelle.config.model import (
    CompanionSettings,
    LogSettings,
    Member,
    NodeSettings,
    Passwords,
    RoomSettings,
    Settings,
)

logger = logging.getLogger(__name__)

ENV_PREFIX = "MESHELLE_"
ENV_NESTING = "__"

FILE_ROOMS_KEY = "room"
"""TOML spells it singular, as a table of rooms keyed by name."""
FILE_MEMBERS_KEY = "member"
"""TOML spells an array of tables singular: [[room.lobby.member]]."""

DEFAULTS_SECTION = "defaults"

# Keys a meshcore-pi config would use, and what they became. Someone porting a
# config gets a pointer rather than a bare "unknown key".
MIGRATION_HINTS = {
    "admin": (
        "meshcore-pi used admin.password and admin.pubkeys. Use passwords.admin "
        'and [[room.<name>.member]] entries with role = "admin".'
    ),
    "guest": (
        "meshcore-pi used guest.password, guest.pubkeys and guest.open. Use "
        "passwords.read_write, member entries, and allow_unknown."
    ),
    "writer": (
        "meshcore-pi used writer.password and writer.pubkeys. Use "
        'passwords.read_write or a member entry with role = "read_write".'
    ),
    "readonly": 'use allow_unknown = "read_only", or a member role of "read_only".',
    "advert": "use advert_flood_interval and advert_local_interval.",
    "privatekey": "use private_key (or key_file to have one generated).",
}

# Which model governs each location, so an unknown key can be answered with the
# keys that *are* valid there. An explicit table beats walking annotations: it is
# shorter, and it cannot silently mis-resolve a union or alias.
_MODEL_AT_PATH: tuple[tuple[tuple[str, ...], type[BaseModel]], ...] = (
    ((), Settings),
    (("companion",), CompanionSettings),
    (("node",), NodeSettings),
    (("log",), LogSettings),
    (("rooms", "*"), RoomSettings),
    (("rooms", "*", "passwords"), Passwords),
    (("rooms", "*", "members", "*"), Member),
)


class ConfigError(Exception):
    """Configuration could not be loaded. The message is for the operator."""


def deep_merge(base: Mapping[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    """Recursively merge ``overlay`` onto ``base``, leaving both untouched.

    Lists replace rather than concatenate: appending would make it impossible to
    *remove* a member via an override, and silently growing an ACL is the worse
    failure.
    """
    merged = dict(base)
    for key, value in overlay.items():
        existing = merged.get(key)
        if isinstance(existing, Mapping) and isinstance(value, Mapping):
            merged[key] = deep_merge(existing, value)
        else:
            merged[key] = value
    return merged


def _set_nested(target: dict[str, Any], path: list[str], value: str) -> None:
    cursor = target
    for part in path[:-1]:
        nested = cursor.get(part)
        if not isinstance(nested, dict):
            nested = {}
            cursor[part] = nested
        cursor = nested
    cursor[path[-1]] = value


def env_overrides(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Collect ``MESHELLE_`` variables into a nested dict.

    ``__`` separates levels, so ``MESHELLE_COMPANION__PORT`` sets
    ``companion.port`` and ``MESHELLE_ROOM__LOBBY__WELCOME`` reaches into a room.
    Single underscores stay part of a name, which is why ``BAUD_RATE`` works.
    """
    source = os.environ if environ is None else environ
    overrides: dict[str, Any] = {}

    for name, value in source.items():
        if not name.startswith(ENV_PREFIX) or name == ENV_PREFIX:
            continue
        remainder = name[len(ENV_PREFIX) :]
        path = [part.lower() for part in remainder.split(ENV_NESTING) if part]
        if not path:
            continue
        _set_nested(overrides, path, value)

    return overrides


def _rename_file_keys(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Translate the file's spellings into the model's field names."""
    data = {key: value for key, value in raw.items() if key != FILE_ROOMS_KEY}

    rooms_section = raw.get(FILE_ROOMS_KEY)
    if rooms_section is None:
        return data
    if not isinstance(rooms_section, Mapping):
        raise ConfigError(
            f"[{FILE_ROOMS_KEY}] must contain named room sections, like [{FILE_ROOMS_KEY}.lobby]"
        )

    rooms: dict[str, Any] = {}
    for slug, room in rooms_section.items():
        if not isinstance(room, Mapping):
            raise ConfigError(
                f"[{FILE_ROOMS_KEY}.{slug}] must be a section, got {type(room).__name__}"
            )
        renamed = {key: value for key, value in room.items() if key != FILE_MEMBERS_KEY}
        if FILE_MEMBERS_KEY in room:
            renamed["members"] = room[FILE_MEMBERS_KEY]
        rooms[slug] = renamed

    data["rooms"] = rooms
    return data


def _apply_room_defaults(data: dict[str, Any]) -> dict[str, Any]:
    """Fold the ``[defaults]`` section under each room, with the room winning."""
    defaults = data.pop(DEFAULTS_SECTION, None)
    if defaults is None:
        return data
    if not isinstance(defaults, Mapping):
        raise ConfigError(f"[{DEFAULTS_SECTION}] must be a section")

    rooms = data.get("rooms")
    if not isinstance(rooms, Mapping):
        return data

    data["rooms"] = {
        slug: deep_merge(defaults, room if isinstance(room, Mapping) else {})
        for slug, room in rooms.items()
    }
    return data


def _apply_implicit_names(data: dict[str, Any]) -> dict[str, Any]:
    """Default a room's advertised name to its section name."""
    rooms = data.get("rooms")
    if not isinstance(rooms, Mapping):
        return data

    data["rooms"] = {
        slug: ({**room, "name": slug} if isinstance(room, Mapping) and "name" not in room else room)
        for slug, room in rooms.items()
    }
    return data


def _display_path(location: tuple[int | str, ...]) -> str:
    """Render a pydantic error location using the file's own spellings."""
    parts: list[str] = []
    for index, item in enumerate(location):
        if index == 0 and item == "rooms":
            parts.append(FILE_ROOMS_KEY)
        elif item == "members":
            parts.append(FILE_MEMBERS_KEY)
        elif isinstance(item, int):
            parts.append(f"[{item}]")
        else:
            parts.append(str(item))
    return ".".join(parts)


def _model_for(location: tuple[int | str, ...]) -> type[BaseModel] | None:
    """The model governing a location, for suggesting valid keys."""
    normalised = tuple("*" if isinstance(part, int) else str(part) for part in location)
    for pattern, model in _MODEL_AT_PATH:
        if len(pattern) != len(normalised):
            continue
        if all(
            expected == "*" or expected == actual
            for expected, actual in zip(pattern, normalised, strict=True)
        ):
            return model
    return None


def _describe_unknown_key(location: tuple[int | str, ...]) -> str:
    """Explain an unknown key, suggesting the nearest valid one.

    This is the whole reason for ``extra="forbid"``: meshcore-pi accepts a
    misspelled ACL key, ignores it, and leaves the room with no admins.
    """
    if not location:  # pragma: no cover - pydantic always gives a location here
        return "unknown key"

    key = str(location[-1])
    parent = location[:-1]
    where = _display_path(parent)
    prefix = f"unknown key {key!r}" + (f" in [{where}]" if where else " at the top level")

    hint = MIGRATION_HINTS.get(key.lower())
    if hint is not None:
        return f"{prefix}. {hint}"

    model = _model_for(parent)
    if model is None:
        return prefix

    valid = sorted(model.model_fields)
    display = [FILE_MEMBERS_KEY if name == "members" else name for name in valid]
    close = difflib.get_close_matches(key, display, n=2, cutoff=0.6)
    if close:
        return f"{prefix}. Did you mean {' or '.join(repr(c) for c in close)}?"
    return f"{prefix}. Valid keys here: {', '.join(display)}"


def format_validation_error(error: ValidationError, source: str) -> str:
    """Turn a pydantic error into operator-facing lines."""
    lines = [f"{source}: configuration is invalid:"]
    for detail in error.errors():
        location = detail["loc"]
        if detail["type"] == "extra_forbidden":
            lines.append(f"  - {_describe_unknown_key(location)}")
            continue

        message = detail["msg"]
        # Pydantic prefixes messages raised by our own validators.
        message = message.removeprefix("Value error, ")
        where = _display_path(location)
        lines.append(f"  - {where}: {message}" if where else f"  - {message}")
    return "\n".join(lines)


def read_config_file(path: Path) -> dict[str, Any]:
    """Parse a TOML config file into a raw dict."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc

    try:
        return tomllib.loads(raw.decode("utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path} is not valid TOML: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{path} is not valid UTF-8: {exc}") from exc


def build_settings(
    file_data: Mapping[str, Any] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    overrides: Mapping[str, Any] | None = None,
    source: str = "configuration",
) -> Settings:
    """Merge every layer and validate, in precedence order.

    Args:
        file_data: parsed config file contents.
        environ: environment to read ``MESHELLE_`` variables from.
        overrides: highest-precedence values, normally assembled from CLI flags.
        source: what to name in error messages, usually the config file path.
    """
    merged: dict[str, Any] = dict(file_data or {})
    merged = deep_merge(merged, env_overrides(environ))
    if overrides:
        merged = deep_merge(merged, overrides)

    merged = _rename_file_keys(merged)
    merged = _apply_room_defaults(merged)
    merged = _apply_implicit_names(merged)

    try:
        return Settings.model_validate(merged)
    except ValidationError as exc:
        raise ConfigError(format_validation_error(exc, source)) from exc


def load_settings(
    path: Path | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    overrides: Mapping[str, Any] | None = None,
) -> Settings:
    """Load configuration from ``path``, then environment, then ``overrides``."""
    file_data = read_config_file(path) if path is not None else {}
    return build_settings(
        file_data,
        environ=environ,
        overrides=overrides,
        source=str(path) if path is not None else "configuration",
    )
