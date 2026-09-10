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

"""Map configuration keys back to the line that set them.

``tomllib`` discards position information as soon as it returns a dict, so a
validation error can name ``room.lobby.advert_flood_interval`` but not the line an
operator has to go and edit. For a file edited by hand that line number is the
most useful thing an error carries.

This is a deliberately small, best-effort scanner rather than a second TOML
parser. It recognises section headers, array-of-tables headers, and top-level
assignments, and it tracks multi-line strings and bracket depth so it does not
mistake the contents of a value for a key. When it cannot be confident it returns
nothing and the caller omits the line: **a wrong line number is worse than none**,
because it sends the reader to a line that is fine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

SECTION_RE = re.compile(r"^\s*(\[\[?)\s*([^\]]+?)\s*(\]\]?)\s*(?:#.*)?$")
ASSIGNMENT_RE = re.compile(r"""^\s*(?:"([^"]+)"|'([^']+)'|([A-Za-z0-9_\-]+))\s*(?:\.|\s*=)""")

MULTILINE_DELIMITERS = ('"""', "'''")

type KeyPath = tuple[str | int, ...]


def _split_section(raw: str) -> tuple[str, ...]:
    """Split a section header's dotted name, honouring quoted segments."""
    parts: list[str] = []
    for segment in raw.split("."):
        cleaned = segment.strip()
        if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in "\"'":
            cleaned = cleaned[1:-1]
        parts.append(cleaned)
    return tuple(parts)


@dataclass(frozen=True, slots=True)
class SourceMap:
    """Line numbers for the paths a config file actually mentions."""

    lines: dict[KeyPath, int] = field(default_factory=dict)

    def locate(self, path: KeyPath) -> int | None:
        """The line for ``path``, or for its nearest recorded ancestor.

        Falling back to an ancestor is what makes inline tables work: a bad value
        inside ``passwords = { admin = ... }`` reports the ``passwords`` line,
        which is the line to go and look at.
        """
        for length in range(len(path), 0, -1):
            line = self.lines.get(path[:length])
            if line is not None:
                return line
        return None


def build_source_map(text: str) -> SourceMap:
    """Scan TOML text, recording the line each key and section appears on."""
    lines: dict[KeyPath, int] = {}
    section: KeyPath = ()
    array_counts: dict[tuple[str, ...], int] = {}

    in_multiline: str | None = None
    depth = 0

    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line

        # Inside a multi-line string nothing is a key; look only for the closer.
        if in_multiline is not None:
            if in_multiline in line:
                line = line.split(in_multiline, 1)[1]
                in_multiline = None
            else:
                continue

        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if depth == 0:
            header = SECTION_RE.match(line)
            if header is not None:
                opener, name, closer = header.group(1), header.group(2), header.group(3)
                if len(opener) != len(closer):  # malformed; let tomllib complain
                    continue
                path = _split_section(name)
                if opener == "[[":
                    index = array_counts.get(path, 0)
                    array_counts[path] = index + 1
                    lines[(*path, index)] = number
                    section = (*path, index)
                else:
                    array_counts = {
                        key: value
                        for key, value in array_counts.items()
                        if key[: len(path)] != path
                    }
                    lines[path] = number
                    section = path
                continue

            assignment = ASSIGNMENT_RE.match(line)
            if assignment is not None:
                key = assignment.group(1) or assignment.group(2) or assignment.group(3)
                lines.setdefault((*section, key), number)

        # Track unterminated constructs so continuation lines are not read as keys.
        remaining = line
        for delimiter in MULTILINE_DELIMITERS:
            # An odd number of delimiters leaves the string open at end of line.
            if remaining.count(delimiter) % 2 == 1:
                in_multiline = delimiter
                remaining = remaining.rsplit(delimiter, 1)[0]
                break

        if in_multiline is None:
            scrubbed = _strip_inline_strings(remaining)
            depth += scrubbed.count("[") + scrubbed.count("{")
            depth -= scrubbed.count("]") + scrubbed.count("}")
            depth = max(depth, 0)

    return SourceMap(lines)


def _strip_inline_strings(line: str) -> str:
    """Remove quoted spans and comments so brackets inside them are not counted."""
    out: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(line):
        char = line[index]
        if quote is not None:
            if char == "\\" and quote == '"':
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char in "\"'":
            quote = char
            index += 1
            continue
        if char == "#":
            break
        out.append(char)
        index += 1
    return "".join(out)
