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

"""Resolving a login to a role.

The config file is the only source of truth. ``setperm`` over the air is refused
(see :mod:`meshelle.room.admin_cli`), so this function is the whole ACL, and it
runs on **every** login rather than being cached in the database.

Resolution order, first match wins:

1. an explicit ``[[room.x.members]]`` entry, matched on the full public key;
2. a declared password, matched in constant time, strongest role first;
3. the room's ``allow_unknown`` policy.

**A listed member's role is definitive: a password cannot escalate it.** That is
the point of ordering the member check first. Otherwise demoting someone in the
config would achieve nothing while they still remembered the admin password --
the config would say ``read_only`` and the room would keep granting ``admin``.

The firmware's order is the other way around (MyMesh.cpp:337): it consults its
ACL only when the password field is blank. It also has no equivalent of a
demotion, since its ACL is written over the air.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from enum import StrEnum

from meshelle.config.model import Role, RoomSettings


class RoleSource(StrEnum):
    """Which rule granted the role. Logged, so an operator can see why."""

    MEMBER = "member"
    PASSWORD = "password"  # noqa: S105 - a role source, not a credential
    ALLOW_UNKNOWN = "allow_unknown"


@dataclass(frozen=True, slots=True)
class Grant:
    """A successful resolution."""

    role: Role
    source: RoleSource

    def describe(self, public_key: bytes) -> str:
        return f"{public_key[:4].hex()} -> {self.role.value} (via {self.source.value})"


def resolve(room: RoomSettings, public_key: bytes, password: bytes) -> Grant | None:
    """The role to grant this login, or ``None`` to ignore it entirely.

    ``None`` means **no reply at all** -- not an error packet. A rejected login
    is indistinguishable from a room that is out of range, which is what denies
    an attacker a password oracle. The client simply times out.
    """
    member_role = room.role_for_member(public_key)
    if member_role is not None:
        return Grant(role=member_role, source=RoleSource.MEMBER)

    password_role = _match_password(room, password)
    if password_role is not None:
        return Grant(role=password_role, source=RoleSource.PASSWORD)

    unknown_role = room.allow_unknown.role
    if unknown_role is not None:
        return Grant(role=unknown_role, source=RoleSource.ALLOW_UNKNOWN)

    return None


def resolve_without_password(room: RoomSettings, public_key: bytes) -> Role:
    """The role a *known* client holds when no password was offered.

    Used to rehydrate clients from the database at startup. The role a client
    earned by typing a password is deliberately not restored: the password may
    since have been removed from the config, and a restart must not be what
    keeps granting access it no longer authorises.

    Falls back to :attr:`Role.GUEST` rather than refusing, because a rehydrated
    client still needs its pending posts pushed to it. Guest cannot post, so
    it must log in again before it is heard from -- which every app does.
    """
    member_role = room.role_for_member(public_key)
    if member_role is not None:
        return member_role
    return room.allow_unknown.role or Role.GUEST


def _match_password(room: RoomSettings, password: bytes) -> Role | None:
    """Compare against every declared password, strongest role first.

    Always compares against all of them: returning early on the first match
    would make the reply time depend on which password was given.
    """
    if not password:
        # A blank password is what a client sends when it expects to be
        # recognised by key alone. Matching it against an accidentally-empty
        # config value would hand out that role to everyone.
        return None

    matched: Role | None = None
    for role, secret in room.passwords.as_pairs():
        declared = secret.get_secret_value().encode("utf-8")
        if declared and hmac.compare_digest(password, declared) and matched is None:
            matched = role
    return matched
