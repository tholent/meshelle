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

"""Read a ``.env`` file into the process environment.

The environment layer already exists -- ``MESHELLE_*`` variables override the
config file, and ``env:NAME`` keeps a password out of it. What was missing is a
place to *put* those variables for a run that is not under systemd, where
``EnvironmentFile=`` does the same job. Exporting them by hand means they live
in one shell and are gone from the next, which is how a room ends up started
without the admin password it had yesterday.

Three rules, each preventing a specific surprise:

* **The real environment wins.** A name already set is left alone, so a
  deliberate ``MESHELLE_LOG__LEVEL=debug meshelle run`` is not silently undone
  by a stale ``.env`` sitting next to the config.
* **No variable interpolation.** ``$`` and ``${}`` are literal. Passwords
  contain ``$`` far more often than a ``.env`` wants substitution, and a
  password quietly truncated at a ``$`` fails as "wrong password", which is
  the hardest kind of failure to trace back to its cause.
* **Nothing is guessed.** A malformed line is an error citing its line number,
  not a silently skipped variable -- a password that never got set is the same
  outage either way, but only one of them says so.

This is a small parser rather than a dependency because the format is small,
and because the two divergences above are exactly the points where the
libraries differ from each other.
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Iterable, MutableMapping
from dataclasses import dataclass, field
from pathlib import Path

NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

EXPORT_PREFIX = re.compile(r"^export\s+")

INLINE_COMMENT = re.compile(r"(?:^|\s)#")
"""A ``#`` only starts a comment at the start of a value or after whitespace, so
``PASSWORD=hunter2#3`` keeps its ``#`` instead of losing half the password."""

ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", '"': '"', "'": "'"}


class DotenvError(Exception):
    """A ``.env`` file could not be read. The message names the line."""


@dataclass(frozen=True, slots=True)
class DotenvEntry:
    """One assignment, with the line it came from so errors can cite it."""

    name: str
    value: str
    line: int


@dataclass(frozen=True, slots=True)
class DotenvFile:
    """A parsed file. Parsing is separate from applying it, so a reload that
    hits a syntax error keeps the environment it already had rather than
    tearing it down half way."""

    path: Path
    entries: tuple[DotenvEntry, ...]
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DotenvResult:
    """What loading actually changed, for the operator-facing summary."""

    path: Path | None = None
    applied: tuple[str, ...] = ()
    shadowed: tuple[str, ...] = ()
    """Names the file set that the real environment had already claimed."""
    warnings: tuple[str, ...] = ()
    sources: dict[str, str] = field(default_factory=dict)
    """Variable name -> ``path:line``, so a validation error can point at the
    line of the ``.env`` rather than only naming the variable."""

    @property
    def detail(self) -> str:
        """What was and was not taken from the file."""
        parts = [f"{len(self.applied)} variable{'' if len(self.applied) == 1 else 's'}"]
        if self.shadowed:
            # Worth saying: it is the explanation for a value that is in the
            # file and yet plainly not the one in effect.
            parts.append(f"{len(self.shadowed)} already set in the environment")
        return ", ".join(parts)

    def describe(self) -> str:
        """One line for ``check-config`` and the startup log."""
        if self.path is None:
            return "env file: none"
        return f"env file: {self.path} ({self.detail})"


def parse_dotenv(text: str, source: str = ".env") -> tuple[DotenvEntry, ...]:
    """Parse ``.env`` text. Pure: no environment is touched."""
    lines = text.splitlines()
    entries: list[DotenvEntry] = []
    seen: dict[str, int] = {}
    index = 0

    while index < len(lines):
        number = index + 1
        stripped = lines[index].strip()
        index += 1

        if not stripped or stripped.startswith("#"):
            continue

        stripped = EXPORT_PREFIX.sub("", stripped)

        name, separator, remainder = stripped.partition("=")
        if not separator:
            raise DotenvError(f"{source}:{number}: expected NAME=VALUE, got {stripped!r}")

        name = name.strip()
        if not NAME_RE.fullmatch(name):
            raise DotenvError(f"{source}:{number}: {name!r} is not a valid variable name")

        # Two assignments to one name is an operator error, and either choice of
        # winner is silent: an edited password sitting under a forgotten older
        # line reads as "the password does not work" with nothing to see.
        if name in seen:
            raise DotenvError(f"{source}:{number}: {name} is already set on line {seen[name]}")
        seen[name] = number

        value, consumed = _read_value(remainder, lines, index, source, number)
        index += consumed
        entries.append(DotenvEntry(name=name, value=value, line=number))

    return tuple(entries)


def _read_value(
    remainder: str, lines: list[str], index: int, source: str, number: int
) -> tuple[str, int]:
    """The value, and how many extra lines a quoted value consumed."""
    body = remainder.strip()
    quote = body[:1]

    if quote not in ('"', "'"):
        # Unquoted values stop at a comment and never span lines.
        comment = INLINE_COMMENT.search(body)
        return (body[: comment.start()] if comment else body).strip(), 0

    buffer = body[1:]
    consumed = 0
    while True:
        end = _closing_quote(buffer, quote)
        if end is not None:
            trailing = buffer[end + 1 :].strip()
            if trailing and not trailing.startswith("#"):
                raise DotenvError(
                    f"{source}:{number}: unexpected text after the closing quote: {trailing!r}"
                )
            raw = buffer[:end]
            # Single quotes are literal, as in the shell: a Windows path or a
            # password full of backslashes survives them unchanged.
            return (_unescape(raw) if quote == '"' else raw), consumed

        if index + consumed >= len(lines):
            raise DotenvError(f"{source}:{number}: unterminated {quote} in the value")
        buffer += "\n" + lines[index + consumed]
        consumed += 1


def _closing_quote(text: str, quote: str) -> int | None:
    position = 0
    while position < len(text):
        char = text[position]
        if quote == '"' and char == "\\":
            position += 2  # an escaped quote does not close the value
            continue
        if char == quote:
            return position
        position += 1
    return None


def _unescape(text: str) -> str:
    out: list[str] = []
    position = 0
    while position < len(text):
        char = text[position]
        if char == "\\" and position + 1 < len(text):
            following = text[position + 1]
            # An unrecognised escape is kept verbatim rather than eaten: the
            # backslash is far more likely to be part of the value than a typo.
            out.append(ESCAPES.get(following, "\\" + following))
            position += 2
            continue
        out.append(char)
        position += 1
    return "".join(out)


def read_dotenv(path: Path) -> DotenvFile:
    """Read and parse ``path``, reporting permissions worth knowing about."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise DotenvError(f"cannot read env file {path}: {exc}") from exc

    try:
        # utf-8-sig: an editor-written BOM would otherwise become part of the
        # first variable's name, which fails as "unknown key" three layers away.
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise DotenvError(f"{path} is not valid UTF-8: {exc}") from exc

    warnings: list[str] = []
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        # A warning, not the hard refusal load_identity makes: a .env may hold
        # nothing secret, and refusing to start over a port number would be
        # absurd. A leaked room key is unrecoverable; a password is rotatable.
        warnings.append(
            f"env file {path} is group/world readable (mode {mode:04o}); "
            f"if it holds passwords, chmod 600 {path}"
        )

    return DotenvFile(path=path, entries=parse_dotenv(text, str(path)), warnings=tuple(warnings))


def apply_dotenv(
    parsed: DotenvFile,
    *,
    environ: MutableMapping[str, str] | None = None,
    owned: Iterable[str] = (),
) -> DotenvResult:
    """Set the parsed variables, leaving names the environment already has.

    ``owned`` names variables a previous load of the same file set. They are
    cleared first, so a reload picks up an edited value and also notices a line
    that was *deleted* -- otherwise a revoked password would stay live in the
    process for as long as it ran.
    """
    target = os.environ if environ is None else environ

    for name in owned:
        target.pop(name, None)

    applied: list[str] = []
    shadowed: list[str] = []
    sources: dict[str, str] = {}

    for entry in parsed.entries:
        if entry.name in target:
            shadowed.append(entry.name)
            continue
        target[entry.name] = entry.value
        applied.append(entry.name)
        sources[entry.name] = f"{parsed.path}:{entry.line}"

    return DotenvResult(
        path=parsed.path,
        applied=tuple(applied),
        shadowed=tuple(shadowed),
        warnings=parsed.warnings,
        sources=sources,
    )


def load_dotenv(
    path: Path,
    *,
    environ: MutableMapping[str, str] | None = None,
    owned: Iterable[str] = (),
) -> DotenvResult:
    """Read ``path`` and apply it to the environment."""
    return apply_dotenv(read_dotenv(path), environ=environ, owned=owned)
