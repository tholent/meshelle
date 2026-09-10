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

"""The over-the-air console, and what it refuses."""

from __future__ import annotations

import pytest

from meshelle.room.admin_cli import CliContext, handle_command, split_prefix

ALICE = bytes([0xA1, 0xA2, 0xA3, 0xA4]) + bytes(28)
BOB = bytes([0xB0, 0xB1, 0xB2, 0xB3]) + bytes(28)


def context(**overrides: object) -> tuple[CliContext, dict[str, list[object]]]:
    calls: dict[str, list[object]] = {"advert": [], "clear": [], "post": []}

    async def send_advert(flood: bool) -> None:
        calls["advert"].append(flood)

    async def clear_stats() -> None:
        calls["clear"].append(True)

    async def post_message(text: str) -> None:
        calls["post"].append(text)

    values: dict[str, object] = {
        "room_slug": "lobby",
        "version": "0.1.0",
        "now": 1_700_000_000,
        "acl_entries": [],
        "send_advert": send_advert,
        "clear_stats": clear_stats,
        "post_message": post_message,
    }
    values.update(overrides)
    return CliContext(**values), calls  # type: ignore[arg-type]


async def run(command: str, **overrides: object) -> tuple[str, dict[str, list[object]]]:
    ctx, calls = context(**overrides)
    return await handle_command(command, ctx), calls


async def test_ver_reports_meshelle_not_a_firmware_string() -> None:
    reply, _ = await run("ver")

    assert reply == "meshelle 0.1.0"


async def test_clock_uses_the_firmware_reply_format() -> None:
    """Apps parse this rather than only displaying it, so the shape matters
    (CommonCLI.cpp:216)."""
    reply, _ = await run("clock", now=1_700_000_000)

    assert reply == "22:13 - 14/11/2023 UTC"


async def test_advert_floods_and_advert_zerohop_does_not() -> None:
    """Protocol semantics: a zero-hop advert is a DIRECT packet with an empty
    path, reaching only immediate neighbours. Confusing the two would either
    flood the mesh every 30 minutes or never reach anyone new."""
    flood_reply, flood_calls = await run("advert")
    local_reply, local_calls = await run("advert.zerohop")

    assert flood_calls["advert"] == [True]
    assert local_calls["advert"] == [False]
    assert flood_reply == "OK - Advert sent"
    assert local_reply == "OK - zerohop advert sent"


async def test_advert_zerohop_is_not_swallowed_by_the_advert_prefix() -> None:
    """``advert.zerohop`` starts with ``advert``; matched in the wrong order it
    would silently flood the mesh instead."""
    _, calls = await run("advert.zerohop")

    assert calls["advert"] == [False]


async def test_room_post_posts_as_the_room() -> None:
    reply, calls = await run("room.post the kitchen is closed")

    assert reply == "OK"
    assert calls["post"] == ["the kitchen is closed"]


async def test_room_post_with_no_message_is_refused() -> None:
    reply, calls = await run("room.post   ")

    assert reply == "ERR empty message"
    assert calls["post"] == []


async def test_clear_stats_says_the_reset_is_node_wide() -> None:
    """One radio serves every room, so the radio counters cannot be cleared for
    one room alone. Saying so beats an operator wondering why another room's
    numbers moved."""
    reply, calls = await run("clear stats")

    assert calls["clear"] == [True]
    assert "node-wide" in reply


async def test_get_acl_answers_over_the_air() -> None:
    """Firmware prints its ACL to the node's serial console and returns an empty
    reply (MyMesh.cpp:965), so an app shows nothing. meshelle has no console to
    print to, so it answers the question it was asked."""
    reply, _ = await run("get acl", acl_entries=[(ALICE, "admin"), (BOB, "read_only")])

    assert "a1a2a3a4 admin" in reply
    assert "b0b1b2b3 read_only" in reply


async def test_get_acl_summarises_a_list_too_long_for_one_message() -> None:
    """A reply is a single text message, so a long ACL must be trimmed rather
    than built into a packet that cannot be transmitted."""
    entries = [(bytes([n]) + bytes(31), "read_write") for n in range(20)]

    reply, _ = await run("get acl", acl_entries=entries)

    assert "more" in reply
    assert len(reply.encode("utf-8")) < 160


async def test_get_acl_with_no_members_explains_the_room_is_not_empty() -> None:
    reply, _ = await run("get acl", acl_entries=[])

    assert "password" in reply


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("setperm aabbcc 3", "config file"),
        ("password newsecret", "config file"),
        ("set advert.interval 30", "config file"),
        ("clock sync", "operating system"),
        ("time 1700000000", "operating system"),
        ("erase", "data directory"),
        ("reboot", "restart it on the host"),
    ],
)
async def test_mutating_commands_are_refused_by_name(command: str, expected: str) -> None:
    """Silently ignoring these is the worst outcome: an operator types
    ``setperm``, sees no error, and believes someone is an admin who is not.
    Each refusal has to say where the setting actually lives.
    """
    reply, _ = await run(command)

    assert reply.startswith("ERR")
    assert expected in reply


async def test_an_unknown_command_names_what_it_did_not_understand() -> None:
    reply, _ = await run("frobnicate the widget")

    assert reply == "ERR - unknown command: frobnicate"


async def test_an_empty_command_is_answered_not_ignored() -> None:
    reply, _ = await run("   ")

    assert reply == "ERR - empty command"


def test_an_app_correlation_prefix_is_split_off_for_reflection() -> None:
    """Protocol semantics: apps prefix a console line with ``XX|`` and match the
    reply by it (MyMesh.cpp:936). A reply without the prefix is not matched to
    its request and the console appears to hang."""
    assert split_prefix("a1|ver") == ("a1|", "ver")


def test_a_short_line_that_merely_contains_a_pipe_is_not_a_prefix() -> None:
    """Firmware's test is ``strlen > 4 && command[2] == '|'``. Matched loosely,
    an ordinary command would be silently reinterpreted."""
    assert split_prefix("ab|c") == ("", "ab|c")
    assert split_prefix("ver") == ("", "ver")
