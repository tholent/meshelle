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

"""Role resolution: the whole ACL, run on every login."""

from __future__ import annotations

from meshelle.config.model import Role, RoomSettings
from meshelle.room import acl

ALICE = bytes([0xA1]) + bytes(31)
BOB = bytes([0xB0]) + bytes(31)


def room(**overrides: object) -> RoomSettings:
    values: dict[str, object] = {"name": "Lobby"}
    values.update(overrides)
    return RoomSettings.model_validate(values)


def test_a_listed_member_gets_their_declared_role() -> None:
    settings = room(
        members=[{"pubkey": ALICE.hex(), "role": "admin"}],
        allow_unknown="guest",
    )

    grant = acl.resolve(settings, ALICE, b"")

    assert grant is not None
    assert grant.role is Role.ADMIN
    assert grant.source is acl.RoleSource.MEMBER


def test_a_password_cannot_escalate_a_listed_member() -> None:
    """The config is the source of truth, so demoting someone in it must
    actually demote them -- even though they still know the admin password.

    This is deliberately the opposite of the firmware, which consults its ACL
    only when the password field is blank (MyMesh.cpp:337) and so would hand
    this login ADMIN back.
    """
    settings = room(
        members=[{"pubkey": ALICE.hex(), "role": "read_only"}],
        passwords={"admin": "hunter2"},
    )

    grant = acl.resolve(settings, ALICE, b"hunter2")

    assert grant is not None
    assert grant.role is Role.READ_ONLY


def test_a_password_grants_its_role_to_an_unlisted_key() -> None:
    settings = room(passwords={"admin": "hunter2", "read_write": "letmein"})

    assert acl.resolve(settings, BOB, b"letmein") == acl.Grant(
        role=Role.READ_WRITE, source=acl.RoleSource.PASSWORD
    )
    assert acl.resolve(settings, BOB, b"hunter2") == acl.Grant(
        role=Role.ADMIN, source=acl.RoleSource.PASSWORD
    )


def test_one_password_set_for_two_roles_grants_the_stronger_one() -> None:
    """Otherwise which role wins would depend on dict iteration order, and the
    same config would behave differently between runs."""
    settings = room(passwords={"admin": "same", "read_only": "same"})

    grant = acl.resolve(settings, BOB, b"same")

    assert grant is not None
    assert grant.role is Role.ADMIN


def test_a_wrong_password_falls_through_to_the_unknown_policy() -> None:
    settings = room(passwords={"admin": "hunter2"}, allow_unknown="read_only")

    grant = acl.resolve(settings, BOB, b"wrong")

    assert grant is not None
    assert grant.role is Role.READ_ONLY
    assert grant.source is acl.RoleSource.ALLOW_UNKNOWN


def test_reject_returns_none_so_the_login_gets_no_reply_at_all() -> None:
    """Protocol semantics: a refused login is answered with silence, not an
    error. A wrong password is then indistinguishable from a room that is out of
    range, which is what denies an attacker a password oracle.
    """
    settings = room(passwords={"admin": "hunter2"}, allow_unknown="reject")

    assert acl.resolve(settings, BOB, b"wrong") is None


def test_a_blank_password_is_never_matched_against_a_declared_one() -> None:
    """A client sending no password expects to be recognised by key alone.
    Matching it against an accidentally-empty config value would hand that role
    to everyone who asked."""
    settings = room(passwords={"read_only": "x"}, allow_unknown="reject")

    assert acl.resolve(settings, BOB, b"") is None


def test_rehydration_does_not_restore_a_password_earned_role() -> None:
    """Protocol semantics: the password a client used is never recorded, so a
    restart cannot re-verify it. Restoring the role anyway would mean removing a
    password from the config achieved nothing until every client re-logged in.
    """
    settings = room(passwords={"admin": "hunter2"}, allow_unknown="reject")

    assert acl.resolve_without_password(settings, BOB) is Role.GUEST


def test_rehydration_keeps_a_declared_member_at_their_role() -> None:
    """A member is re-resolvable from the config alone, so a restart must not
    cost them their role -- their owed posts still need pushing."""
    settings = room(members=[{"pubkey": ALICE.hex(), "role": "read_write"}])

    assert acl.resolve_without_password(settings, ALICE) is Role.READ_WRITE


def test_rehydration_uses_the_unknown_policy_for_a_stranger() -> None:
    settings = room(allow_unknown="read_write")

    assert acl.resolve_without_password(settings, BOB) is Role.READ_WRITE


def test_read_only_may_not_post() -> None:
    """meshelle honours the name it gives the role. Firmware refuses only
    PERM_ACL_GUEST (MyMesh.cpp:480), so a client it labelled "read only" can
    post to it. The wire byte is still 1, so apps still label it correctly."""
    assert Role.READ_ONLY.may_post is False
    assert Role.READ_WRITE.may_post is True
    assert Role.ADMIN.may_post is True
    assert Role.GUEST.may_post is False
