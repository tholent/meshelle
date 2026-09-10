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

"""Configuration schema.

Every model sets ``extra="forbid"``. That is the whole point: meshcore-pi
documents ``admin.keys`` while its code reads ``admin.pubkeys``, so the documented
spelling is accepted, ignored, and the room silently has no admins. Here an
unknown key is a startup error that names the key and suggests the nearest valid
one.

The ACL is declarative. Roles come from this file and are re-resolved on every
login, in a fixed order:

1. an explicit member, matched on full public key;
2. a password match against the room's declared passwords;
3. the room's ``allow_unknown`` policy.

``setperm`` over the air is refused, so the file is always the source of truth.
"""

from __future__ import annotations

import os
import re
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Self

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    SecretStr,
    model_validator,
)

from meshelle.proto.constants import DEFAULT_BAUD_RATE, PUB_KEY_SIZE, Permission

DURATION_PATTERN = re.compile(r"(\d+)\s*([smhdw])", re.IGNORECASE)
DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}

NEVER_WORDS = frozenset({"never", "off", "none", "disabled"})
FOREVER_WORDS = frozenset({"forever", "unlimited", "keep"})


class ConfigValueError(ValueError):
    """A configuration value is malformed."""


def parse_duration(value: object) -> object:
    """Accept ``"6h"``, ``"1h30m"``, ``90`` (seconds), or a disabling word.

    Returns seconds as an int, or ``None`` for ``never``/``forever`` so callers
    can distinguish "disabled" from "zero".
    """
    if value is None or isinstance(value, int):
        return value
    if not isinstance(value, str):
        return value

    text = value.strip().lower()
    if not text:
        raise ConfigValueError("duration is empty")
    if text in NEVER_WORDS or text in FOREVER_WORDS:
        return None
    if text.isdigit():
        return int(text)

    matches = DURATION_PATTERN.findall(text)
    if not matches or DURATION_PATTERN.sub("", text).strip():
        raise ConfigValueError(
            f"{value!r} is not a duration. Use a number of seconds, a unit form "
            f"like '30m' or '1h30m' (s/m/h/d/w), or 'never'."
        )
    return sum(int(amount) * DURATION_UNITS[unit.lower()] for amount, unit in matches)


def parse_public_key(value: object) -> object:
    """Accept 64 hex characters and return the 32 raw bytes."""
    if not isinstance(value, str):
        return value

    cleaned = value.strip().replace(" ", "").replace(":", "")
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ConfigValueError(f"{value!r} is not valid hex: {exc}") from exc

    if len(raw) != PUB_KEY_SIZE:
        raise ConfigValueError(
            f"public key must be {PUB_KEY_SIZE * 2} hex characters "
            f"({PUB_KEY_SIZE} bytes), got {len(cleaned)} characters"
        )
    return raw


def resolve_secret(value: object) -> object:
    """Resolve ``env:NAME`` and ``file:/path`` indirection.

    Keeping passwords out of the config file matters when the file is in version
    control or readable by more than the service account.
    """
    if not isinstance(value, str):
        return value

    if value.startswith("env:"):
        name = value[4:].strip()
        if not name:
            raise ConfigValueError("env: needs a variable name, e.g. env:LOBBY_ADMIN_PW")
        resolved = os.environ.get(name)
        if resolved is None:
            raise ConfigValueError(f"environment variable {name} is not set")
        if not resolved:
            raise ConfigValueError(f"environment variable {name} is empty")
        return resolved

    if value.startswith("file:"):
        raw_path = value[5:].strip()
        if not raw_path:
            raise ConfigValueError("file: needs a path, e.g. file:/run/secrets/lobby")
        path = Path(raw_path)
        try:
            # Trailing newline is almost always an artefact of how the file was
            # written, not part of the password.
            contents = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ConfigValueError(f"cannot read secret from {path}: {exc}") from exc
        if not contents:
            raise ConfigValueError(f"secret file {path} is empty")
        return contents

    return value


Duration = Annotated[int | None, BeforeValidator(parse_duration)]
PublicKey = Annotated[bytes, BeforeValidator(parse_public_key)]
Secret = Annotated[SecretStr, BeforeValidator(resolve_secret)]


class StrictModel(BaseModel):
    """Base for every config model: unknown keys are errors, not noise."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class TransportKind(StrEnum):
    SERIAL = "serial"
    TCP = "tcp"
    BLE = "ble"


class Role(StrEnum):
    """A role as written in the config file."""

    GUEST = "guest"
    READ_ONLY = "read_only"
    READ_WRITE = "read_write"
    ADMIN = "admin"

    @property
    def permission(self) -> Permission:
        """The wire value sent as byte 7 of the login response."""
        return {
            Role.GUEST: Permission.GUEST,
            Role.READ_ONLY: Permission.READ_ONLY,
            Role.READ_WRITE: Permission.READ_WRITE,
            Role.ADMIN: Permission.ADMIN,
        }[self]

    @property
    def may_post(self) -> bool:
        """Whether this role may add posts.

        Note this is stricter than the firmware, which only refuses
        ``PERM_ACL_GUEST`` and so lets a "read only" client post
        (simple_room_server/MyMesh.cpp:480). meshelle honours the name it gives
        the role; the wire byte is still 1 so apps label it correctly.
        """
        return self in (Role.READ_WRITE, Role.ADMIN)


class UnknownPolicy(StrEnum):
    """What to do with a client that matches no member entry and no password."""

    REJECT = "reject"
    GUEST = "guest"
    READ_ONLY = "read_only"
    READ_WRITE = "read_write"

    @property
    def role(self) -> Role | None:
        """The role to grant, or None to ignore the login entirely."""
        if self is UnknownPolicy.REJECT:
            return None
        return Role(self.value)


class LogLevel(StrEnum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class LogFormat(StrEnum):
    TEXT = "text"
    JSON = "json"


class CompanionSettings(StrictModel):
    """How to reach the companion node."""

    transport: TransportKind = TransportKind.SERIAL

    port: str | None = None
    """Serial device path, e.g. /dev/ttyUSB0."""
    baud_rate: int = Field(default=DEFAULT_BAUD_RATE, gt=0)

    host: str | None = None
    tcp_port: int = Field(default=5000, gt=0, lt=65536)

    address: str | None = None
    """BLE address."""

    @model_validator(mode="after")
    def _require_the_field_the_transport_needs(self) -> Self:
        required = {
            TransportKind.SERIAL: ("port", self.port, "a device path such as /dev/ttyUSB0"),
            TransportKind.TCP: ("host", self.host, "a hostname or IP address"),
            TransportKind.BLE: ("address", self.address, "a BLE address"),
        }[self.transport]
        field, value, hint = required
        if not value:
            raise ConfigValueError(
                f"companion.transport is {self.transport.value!r}, "
                f"so companion.{field} is required ({hint})"
            )
        return self


class NodeSettings(StrictModel):
    """Where meshelle keeps its state."""

    data_dir: Path = Path("data")

    @property
    def database_path(self) -> Path:
        return self.data_dir / "meshelle.db"


class LogSettings(StrictModel):
    """Logging goes to stderr. A file sink is opt-in, never the default.

    meshcore-pi uses ``logging.basicConfig(filename=...)``, so raising the log
    level appears to do nothing: the terminal only ever shows a few print calls.
    """

    level: LogLevel = LogLevel.INFO
    format: LogFormat = LogFormat.TEXT
    file: Path | None = None


class Member(StrictModel):
    """One declared ACL entry."""

    pubkey: PublicKey
    role: Role
    note: str = ""
    """Free text, so `get acl` output is readable by a human."""


class Passwords(StrictModel):
    """Role-granting passwords. Any may be omitted to disable that route."""

    admin: Secret | None = None
    read_write: Secret | None = None
    read_only: Secret | None = None

    def as_pairs(self) -> list[tuple[Role, SecretStr]]:
        """Declared passwords, strongest first.

        Order matters: if the same string is set for two roles, the stronger one
        wins rather than the result depending on dict iteration.
        """
        candidates = (
            (Role.ADMIN, self.admin),
            (Role.READ_WRITE, self.read_write),
            (Role.READ_ONLY, self.read_only),
        )
        return [(role, secret) for role, secret in candidates if secret is not None]


class RoomDefaults(StrictModel):
    """Settings every room inherits and may override."""

    advert_flood_interval: Duration = 6 * 3600
    """How often to flood an advert across the mesh. None disables it."""
    advert_local_interval: Duration = 30 * 60
    """How often to send a zero-hop advert to immediate neighbours."""

    allow_unknown: UnknownPolicy = UnknownPolicy.REJECT
    post_retention: Duration = 30 * 86400
    """Delete posts older than this. None keeps them forever."""
    max_posts: int | None = Field(default=5000, gt=0)
    """Keep at most this many posts per room. None is unlimited."""

    welcome: str | None = None
    """Sent to a client the first time it syncs. Split across messages if long."""

    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)

    @model_validator(mode="after")
    def _location_needs_both_halves(self) -> Self:
        if (self.latitude is None) != (self.longitude is None):
            raise ConfigValueError("latitude and longitude must be set together")
        return self


class RoomSettings(RoomDefaults):
    """One hosted room. Inherits the defaults section."""

    name: str = Field(min_length=1, max_length=64)
    """The advertised name, trimmed to fit the advert's 32-byte appdata."""

    key_file: Path | None = None
    """Identity file, generated on first run. Relative to node.data_dir."""

    private_key: str | None = None
    """An existing MeshCore key to adopt, as 64 or 128 hex characters.

    For migrating a room that already has clients; they keep their contact entry.
    """

    members: list[Member] = Field(default_factory=list)
    passwords: Passwords = Field(default_factory=Passwords)

    @model_validator(mode="after")
    def _one_source_of_identity(self) -> Self:
        if self.key_file is not None and self.private_key is not None:
            raise ConfigValueError(
                "set either key_file or private_key, not both -- otherwise which "
                "identity the room uses depends on load order"
            )
        return self

    @model_validator(mode="after")
    def _members_are_unique(self) -> Self:
        seen: set[bytes] = set()
        for member in self.members:
            if member.pubkey in seen:
                raise ConfigValueError(
                    f"public key {member.pubkey.hex()[:16]}… is listed twice; "
                    f"its effective role would depend on ordering"
                )
            seen.add(member.pubkey)
        return self

    @model_validator(mode="after")
    def _reachable_by_someone(self) -> Self:
        """A room nobody can enter is a configuration mistake, not a choice."""
        if (
            not self.members
            and not self.passwords.as_pairs()
            and self.allow_unknown is UnknownPolicy.REJECT
        ):
            raise ConfigValueError(
                "this room has no members, no passwords, and allow_unknown = "
                "'reject', so no client could ever log in. Add a member, set a "
                "password, or relax allow_unknown."
            )
        return self

    def role_for_member(self, public_key: bytes) -> Role | None:
        """The declared role for a public key, if it is listed."""
        for member in self.members:
            if member.pubkey == public_key:
                return member.role
        return None


class Settings(StrictModel):
    """The whole configuration."""

    companion: CompanionSettings
    """Required: there is no sensible default for which node to drive, and a
    default that fails its own validation would mask every other error."""

    node: NodeSettings = Field(default_factory=NodeSettings)
    log: LogSettings = Field(default_factory=LogSettings)
    rooms: dict[str, RoomSettings] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _at_least_one_room(self) -> Self:
        if not self.rooms:
            raise ConfigValueError(
                "no rooms are configured; add a [room.<name>] section "
                "(meshelle hosts rooms and does nothing else)"
            )
        return self

    @model_validator(mode="after")
    def _room_names_are_distinct(self) -> Self:
        """Two rooms advertising the same name are indistinguishable in an app.

        Also catches ``name`` set in ``[defaults]``, which would otherwise give
        every room the same name with nothing to flag it.
        """
        by_name: dict[str, list[str]] = {}
        for slug, room in self.rooms.items():
            by_name.setdefault(room.name, []).append(slug)

        clashes = {name: slugs for name, slugs in by_name.items() if len(slugs) > 1}
        if clashes:
            detail = "; ".join(
                f"{name!r} used by {', '.join(sorted(slugs))}" for name, slugs in clashes.items()
            )
            raise ConfigValueError(
                f"room names must be distinct so clients can tell them apart: {detail}. "
                f"If 'name' is set in [defaults], move it into each room."
            )
        return self

    @model_validator(mode="after")
    def _rooms_do_not_share_an_identity(self) -> Self:
        """Each room needs its own key.

        Two rooms on one identity means two independent state machines answering
        for the same destination hash: conflicting replies, duplicate ACKs, and
        sync cursors overwriting each other. The same reason meshelle must never
        reuse the companion node's key.
        """
        for label, values in (
            ("key_file", [(s, r.key_file) for s, r in self.rooms.items()]),
            ("private_key", [(s, r.private_key) for s, r in self.rooms.items()]),
        ):
            seen: dict[object, str] = {}
            for slug, value in values:
                if value is None:
                    continue
                if value in seen:
                    raise ConfigValueError(
                        f"rooms {seen[value]!r} and {slug!r} share the same {label}. "
                        f"Each room needs its own identity, or both will answer for "
                        f"one destination hash and corrupt each other's state."
                    )
                seen[value] = slug
        return self
