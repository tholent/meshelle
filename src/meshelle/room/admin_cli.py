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

"""The over-the-air admin CLI (``TXT_TYPE_CLI_DATA``).

MeshCore apps expose a console for any server the user is an admin on. Firmware
routes it through ``CommonCLI`` (src/helpers/CommonCLI.cpp), which can rewrite
almost anything about the node -- radio parameters, passwords, the ACL, the file
system.

meshelle answers a deliberately small subset, and **refuses the mutating ones by
name rather than ignoring them**. A silent no-op is the worst outcome: an
operator types ``setperm <key> 3``, sees no error, and believes someone is an
admin who is not. Each refusal says where the setting actually lives.

The commands that survive are the ones that ask a question or trigger an action
meshelle owns: ``ver``, ``clock``, ``advert``, ``advert.zerohop``,
``clear stats``, ``get acl``, ``room.post``.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime

logger = logging.getLogger(__name__)

CLI_PREFIX_LEN = 3
"""Apps prefix a console line with ``XX|`` to correlate the reply. Reflected
back verbatim (MyMesh.cpp:936), so the app can match reply to request."""

ACL_LINE_LIMIT = 6
"""How many ACL entries fit in one reply before it is summarised. A reply is a
single text message, so this is a hard wire limit, not a display preference."""


@dataclass(frozen=True, slots=True)
class CliContext:
    """Everything a command may read or act on.

    Actions are callables rather than a back-reference to the room server, so
    this module stays testable without building one.
    """

    room_slug: str
    version: str
    now: int
    """Wall-clock seconds, for ``clock``."""
    acl_entries: list[tuple[bytes, str]]
    """``(public_key, role)`` for every declared member."""
    send_advert: Callable[[bool], Awaitable[None]]
    """Called with ``True`` to flood, ``False`` for a zero-hop advert."""
    clear_stats: Callable[[], Awaitable[None]]
    post_message: Callable[[str], Awaitable[None]]


REFUSALS = {
    "setperm": (
        "ERR - roles are declared in the config file, not set over the air. "
        "Add a [[room.{slug}.members]] entry and send SIGHUP."
    ),
    "password": (
        "ERR - passwords live in the config file ([room.{slug}.passwords]). "
        "Change it there and send SIGHUP."
    ),
    "set": "ERR - meshelle has no writable prefs; edit the config file and send SIGHUP.",
    "clock sync": "ERR - the host clock is managed by the operating system, not over the air.",
    "time": "ERR - the host clock is managed by the operating system, not over the air.",
    "erase": "ERR - refused. Stop meshelle and remove its data directory instead.",
    "reboot": "ERR - refused. meshelle is a service; restart it on the host.",
}
"""Commands answered with an explanation instead of an action. The key is
matched as a whole first word (or first two, for ``clock sync``)."""


def split_prefix(command: str) -> tuple[str, str]:
    """Separate an app's ``XX|`` correlation prefix from the command.

    Firmware's test is ``strlen > 4 && command[2] == '|'`` (MyMesh.cpp:936);
    matched exactly, so a message that firmware would treat as a plain command
    is not silently reinterpreted here.
    """
    if len(command) > 4 and command[2] == "|":
        return command[:CLI_PREFIX_LEN], command[CLI_PREFIX_LEN:]
    return "", command


async def handle_command(command: str, context: CliContext) -> str:
    """Run one CLI line and return the reply text (without the prefix).

    An empty reply means "say nothing", which is a real outcome: firmware
    returns no reply for a retried command so the app does not show it twice.
    """
    text = command.strip()
    if not text:
        return "ERR - empty command"

    refusal = _refusal_for(text)
    if refusal is not None:
        logger.info("room %s: refused CLI command %r", context.room_slug, text)
        return refusal.format(slug=context.room_slug)

    if text == "ver":
        return f"meshelle {context.version}"

    if text == "clock":
        stamp = datetime.fromtimestamp(context.now, tz=UTC)
        # Firmware's exact format (CommonCLI.cpp:216), so an app that parses
        # the reply rather than displaying it still works.
        return f"{stamp.hour:02d}:{stamp.minute:02d} - {stamp.day}/{stamp.month}/{stamp.year} UTC"

    if text == "advert.zerohop":
        await context.send_advert(False)
        return "OK - zerohop advert sent"

    if text == "advert":
        await context.send_advert(True)
        return "OK - Advert sent"

    if text == "clear stats":
        await context.clear_stats()
        return "(OK - stats reset, node-wide)"

    if text == "get acl":
        return _format_acl(context)

    if text.startswith("room.post"):
        message = text[len("room.post") :].strip()
        if not message:
            return "ERR empty message"
        await context.post_message(message)
        return "OK"

    return f"ERR - unknown command: {text.split(' ', 1)[0]}"


def _refusal_for(text: str) -> str | None:
    if text.startswith("clock sync"):
        return REFUSALS["clock sync"]
    first_word = text.split(" ", 1)[0]
    return REFUSALS.get(first_word)


def _format_acl(context: CliContext) -> str:
    """The declared ACL, as much of it as fits in one message.

    Firmware's ``get acl`` prints to the node's serial console and returns an
    empty reply, so an app shows nothing at all (MyMesh.cpp:965). meshelle has
    no serial console to print to, so it answers over the air instead.
    """
    entries = context.acl_entries
    if not entries:
        return "(no members declared; access is by password or allow_unknown)"

    shown = entries[:ACL_LINE_LIMIT]
    lines = [f"{key[:4].hex()} {role}" for key, role in shown]
    if len(entries) > len(shown):
        lines.append(f"(+{len(entries) - len(shown)} more; see the config file)")
    return "\n".join(lines)
