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

"""The ``.env`` reader, and the surprises its rules exist to prevent.

The parser's divergences from the popular libraries are deliberate and each one
is a test here, because "it behaves like python-dotenv" is exactly the
assumption a future edit would make:

* no interpolation, so a ``$`` in a password survives;
* a malformed line raises rather than being skipped;
* a duplicate name raises rather than one of them silently winning;
* the real environment outranks the file.

The reload path (``owned``) has its own class: it is the only part that
*removes* variables, and getting it wrong leaves a revoked password live for as
long as the process runs.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from meshelle.config.dotenv import (
    DotenvError,
    DotenvResult,
    apply_dotenv,
    load_dotenv,
    parse_dotenv,
    read_dotenv,
)


def values(text: str) -> dict[str, str]:
    """The parsed assignments, when the line numbers are not what is asserted."""
    return {entry.name: entry.value for entry in parse_dotenv(text)}


def write_env(tmp_path: Path, text: str, name: str = ".env") -> Path:
    path = tmp_path / name
    path.write_text(text)
    path.chmod(0o600)
    return path


class TestParsing:
    def test_a_plain_assignment(self) -> None:
        assert values("NAME=value") == {"NAME": "value"}

    def test_blank_lines_and_comments_are_skipped(self) -> None:
        assert values("\n# a comment\n\nNAME=value\n") == {"NAME": "value"}

    def test_export_is_accepted(self) -> None:
        """Operators paste lines out of a shell script; refusing the prefix
        would reject a file that is otherwise exactly right."""
        assert values("export NAME=value") == {"NAME": "value"}

    def test_surrounding_whitespace_is_stripped(self) -> None:
        assert values("  NAME = value  ") == {"NAME": "value"}

    def test_an_empty_value_is_kept(self) -> None:
        """Distinct from unset: it is how an operator overrides a config value
        back to empty without deleting the line and losing the reminder."""
        assert values("NAME=") == {"NAME": ""}

    def test_a_value_may_contain_equals_signs(self) -> None:
        """Base64 padding, connection strings and JWTs all end in ``=``."""
        assert values("TOKEN=abc=def==") == {"TOKEN": "abc=def=="}

    def test_line_numbers_are_recorded(self) -> None:
        """They are what an error message cites, so they have to be the line in
        the file rather than the index among the assignments."""
        entries = parse_dotenv("# comment\n\nA=1\nB=2\n")
        assert [(entry.name, entry.line) for entry in entries] == [("A", 3), ("B", 4)]


class TestQuoting:
    def test_double_quotes_are_stripped(self) -> None:
        assert values('NAME="value"') == {"NAME": "value"}

    def test_single_quotes_are_stripped(self) -> None:
        assert values("NAME='value'") == {"NAME": "value"}

    def test_quotes_preserve_surrounding_whitespace(self) -> None:
        assert values('NAME="  padded  "') == {"NAME": "  padded  "}

    def test_double_quotes_honour_escapes(self) -> None:
        assert values('NAME="one\\ntwo"') == {"NAME": "one\ntwo"}

    def test_single_quotes_are_literal(self) -> None:
        r"""As in the shell. A Windows path or a password full of ``\`` is the
        common case, and mangling it fails as "wrong password"."""
        assert values(r"PATH='C:\new\table'") == {"PATH": r"C:\new\table"}

    def test_an_unrecognised_escape_keeps_its_backslash(self) -> None:
        """Eating it would quietly shorten a password by one character."""
        assert values('PW="a\\qb"') == {"PW": "a\\qb"}

    def test_an_escaped_quote_does_not_close_the_value(self) -> None:
        assert values('PW="say \\"hi\\""') == {"PW": 'say "hi"'}

    def test_a_quoted_value_may_span_lines(self) -> None:
        """A PEM key or a multi-line welcome message pasted straight in."""
        assert values('WELCOME="line one\nline two"\nNEXT=x') == {
            "WELCOME": "line one\nline two",
            "NEXT": "x",
        }

    def test_a_multi_line_value_does_not_swallow_later_assignments(self) -> None:
        entries = parse_dotenv('A="one\ntwo"\nB=3\n')
        assert [(entry.name, entry.line) for entry in entries] == [("A", 1), ("B", 3)]

    def test_an_unterminated_quote_is_an_error(self) -> None:
        """Otherwise it silently eats the rest of the file, and the variables
        below it are simply absent with nothing to say so."""
        with pytest.raises(DotenvError, match="unterminated"):
            parse_dotenv('PW="never closed\nOTHER=1\n')

    def test_text_after_the_closing_quote_is_an_error(self) -> None:
        with pytest.raises(DotenvError, match="after the closing quote"):
            parse_dotenv('PW="value" junk')

    def test_a_comment_after_the_closing_quote_is_allowed(self) -> None:
        assert values('PW="value"  # the admin password') == {"PW": "value"}


class TestComments:
    def test_an_unquoted_value_stops_at_a_comment(self) -> None:
        assert values("NAME=value  # trailing") == {"NAME": "value"}

    def test_a_hash_inside_a_word_is_kept(self) -> None:
        """``hunter2#3`` is a plausible password, and truncating it at the
        ``#`` produces a login failure with nothing visibly wrong in the file."""
        assert values("PW=hunter2#3") == {"PW": "hunter2#3"}

    def test_a_quoted_hash_is_kept_whole(self) -> None:
        assert values('PW="hunter2 # not a comment"') == {"PW": "hunter2 # not a comment"}


class TestNoInterpolation:
    def test_a_dollar_is_literal(self) -> None:
        """Substituting would truncate a password at its ``$``, and the result
        reads as "the password is wrong" rather than "the file was rewritten"."""
        assert values("PW=pa$$word") == {"PW": "pa$$word"}

    def test_braces_are_literal(self) -> None:
        assert values("PW=${HOME}") == {"PW": "${HOME}"}

    def test_a_quoted_dollar_is_literal_too(self) -> None:
        assert values('PW="${HOME}"') == {"PW": "${HOME}"}


class TestMalformedLines:
    def test_a_line_without_an_equals_is_an_error(self) -> None:
        with pytest.raises(DotenvError, match="2: expected NAME=VALUE"):
            parse_dotenv("A=1\njust some words\n")

    def test_an_invalid_name_is_an_error(self) -> None:
        with pytest.raises(DotenvError, match="not a valid variable name"):
            parse_dotenv("not-a-name=1")

    def test_a_name_starting_with_a_digit_is_an_error(self) -> None:
        with pytest.raises(DotenvError, match="not a valid variable name"):
            parse_dotenv("9LIVES=1")

    def test_a_duplicate_name_is_an_error(self) -> None:
        """An edited password under a forgotten older line is invisible either
        way it resolves, so neither line may quietly win."""
        with pytest.raises(DotenvError, match="PW is already set on line 1"):
            parse_dotenv("PW=old\nPW=new\n")

    def test_the_error_names_the_file(self) -> None:
        with pytest.raises(DotenvError, match=r"/etc/meshelle/\.env:1"):
            parse_dotenv("oops", source="/etc/meshelle/.env")


class TestApplying:
    def test_variables_reach_the_environment(self, tmp_path: Path) -> None:
        environ: dict[str, str] = {}

        result = load_dotenv(write_env(tmp_path, "PW=hunter2"), environ=environ)

        assert environ["PW"] == "hunter2"
        assert result.applied == ("PW",)

    def test_the_real_environment_wins(self, tmp_path: Path) -> None:
        """``MESHELLE_LOG__LEVEL=debug meshelle run`` must not be undone by a
        stale ``.env`` sitting beside the config."""
        environ = {"PW": "from the shell"}

        result = load_dotenv(write_env(tmp_path, "PW=from the file"), environ=environ)

        assert environ["PW"] == "from the shell"
        assert result.applied == ()
        assert result.shadowed == ("PW",)

    def test_sources_cite_the_file_and_line(self, tmp_path: Path) -> None:
        """So a validation error about ``env:PW`` can send the reader to the
        line that set it, not merely to a variable name their shell lacks."""
        path = write_env(tmp_path, "# comment\nPW=hunter2\n")

        result = load_dotenv(path, environ={})

        assert result.sources == {"PW": f"{path}:2"}

    def test_a_shadowed_variable_has_no_source(self, tmp_path: Path) -> None:
        """Blaming the file for a value it did not supply would send the reader
        to edit a line that is not in effect."""
        result = load_dotenv(write_env(tmp_path, "PW=ignored"), environ={"PW": "wins"})

        assert result.sources == {}


class TestReload:
    def test_owned_variables_are_cleared_first(self, tmp_path: Path) -> None:
        """A rotated password has to take effect; leaving the old value in
        place is a reload that reports success and changes nothing."""
        environ: dict[str, str] = {}
        first = load_dotenv(write_env(tmp_path, "PW=old"), environ=environ)

        load_dotenv(write_env(tmp_path, "PW=new"), environ=environ, owned=first.applied)

        assert environ["PW"] == "new"

    def test_a_deleted_line_actually_revokes(self, tmp_path: Path) -> None:
        """The point of the whole ``owned`` mechanism: a password removed from
        the file must not stay live for the life of the process, which is
        precisely what an operator reloads to stop."""
        environ: dict[str, str] = {}
        first = load_dotenv(write_env(tmp_path, "PW=old\nKEEP=yes\n"), environ=environ)

        load_dotenv(write_env(tmp_path, "KEEP=yes"), environ=environ, owned=first.applied)

        assert "PW" not in environ
        assert environ["KEEP"] == "yes"

    def test_a_variable_the_file_never_set_is_left_alone(self, tmp_path: Path) -> None:
        """Only what this process took from the file is ours to remove."""
        environ = {"SHELL_SET": "untouched"}
        first = load_dotenv(write_env(tmp_path, "PW=old"), environ=environ)

        load_dotenv(write_env(tmp_path, "PW=new"), environ=environ, owned=first.applied)

        assert environ["SHELL_SET"] == "untouched"

    def test_a_shadowed_variable_is_not_owned(self, tmp_path: Path) -> None:
        """Clearing it on the next reload would let the file win a name the
        real environment had claimed -- the precedence rule inverted, one
        reload late."""
        environ = {"PW": "from the shell"}
        first = load_dotenv(write_env(tmp_path, "PW=from the file"), environ=environ)

        load_dotenv(write_env(tmp_path, "PW=from the file"), environ=environ, owned=first.applied)

        assert environ["PW"] == "from the shell"

    def test_a_parse_error_leaves_the_environment_untouched(self, tmp_path: Path) -> None:
        """Parsing happens before anything is removed, so a typo saved into a
        live ``.env`` cannot tear down the running configuration half way."""
        environ: dict[str, str] = {}
        first = load_dotenv(write_env(tmp_path, "PW=old"), environ=environ)

        with pytest.raises(DotenvError):
            load_dotenv(
                write_env(tmp_path, "PW=old\nbroken line\n"), environ=environ, owned=first.applied
            )

        assert environ["PW"] == "old"


class TestFileErrors:
    def test_a_missing_file_is_an_error(self, tmp_path: Path) -> None:
        with pytest.raises(DotenvError, match="cannot read env file"):
            read_dotenv(tmp_path / "absent")

    def test_invalid_utf8_is_an_error(self, tmp_path: Path) -> None:
        path = tmp_path / ".env"
        path.write_bytes(b"PW=\xff\xfe\n")

        with pytest.raises(DotenvError, match="not valid UTF-8"):
            read_dotenv(path)

    def test_a_byte_order_mark_is_stripped(self, tmp_path: Path) -> None:
        """An editor-written BOM would otherwise land inside the first
        variable's name and surface as an unknown key three layers away."""
        path = tmp_path / ".env"
        path.write_bytes("\ufeffPW=hunter2\n".encode())

        assert [entry.name for entry in read_dotenv(path).entries] == ["PW"]

    def test_crlf_line_endings_parse(self, tmp_path: Path) -> None:
        """A file edited on Windows would otherwise give every value a
        trailing ``\\r``, which a password comparison fails on invisibly."""
        path = tmp_path / ".env"
        path.write_bytes(b"A=1\r\nB=2\r\n")

        assert {entry.name: entry.value for entry in read_dotenv(path).entries} == {
            "A": "1",
            "B": "2",
        }


class TestPermissionWarning:
    def test_a_group_readable_file_warns(self, tmp_path: Path) -> None:
        """A warning, not a refusal: a ``.env`` may hold nothing secret, and a
        password is rotatable where a leaked room key is not."""
        path = write_env(tmp_path, "PW=hunter2")
        path.chmod(0o640)

        parsed = read_dotenv(path)

        assert len(parsed.warnings) == 1
        assert "chmod 600" in parsed.warnings[0]

    def test_a_private_file_is_silent(self, tmp_path: Path) -> None:
        path = write_env(tmp_path, "PW=hunter2")
        path.chmod(0o600)

        assert read_dotenv(path).warnings == ()

    def test_the_warning_survives_into_the_result(self, tmp_path: Path) -> None:
        """It is the result the CLI prints, so a warning that stopped at the
        parsed file would never reach the operator."""
        path = write_env(tmp_path, "PW=hunter2")
        path.chmod(0o644)

        assert load_dotenv(path, environ={}).warnings

    @pytest.mark.parametrize("mode", [0o600, 0o400, 0o700])
    def test_owner_only_modes_do_not_warn(self, tmp_path: Path, mode: int) -> None:
        path = write_env(tmp_path, "PW=hunter2")
        path.chmod(mode)

        assert read_dotenv(path).warnings == ()

    def test_the_warning_reports_the_mode(self, tmp_path: Path) -> None:
        """So the operator can see it is 0644 rather than being told only that
        something is wrong with permissions they cannot see from here."""
        path = write_env(tmp_path, "PW=hunter2")
        path.chmod(0o644)

        assert "0644" in read_dotenv(path).warnings[0]
        assert stat.S_IMODE(path.stat().st_mode) == 0o644


class TestSummary:
    def test_no_file_says_so(self) -> None:
        assert DotenvResult().describe() == "env file: none"

    def test_one_variable_is_singular(self, tmp_path: Path) -> None:
        result = load_dotenv(write_env(tmp_path, "PW=hunter2"), environ={})

        assert result.detail == "1 variable"

    def test_several_variables_are_counted(self, tmp_path: Path) -> None:
        result = load_dotenv(write_env(tmp_path, "A=1\nB=2\n"), environ={})

        assert result.detail == "2 variables"

    def test_shadowing_is_reported(self, tmp_path: Path) -> None:
        """It is the explanation for a value that is plainly in the file and
        plainly not the one in effect."""
        result = load_dotenv(write_env(tmp_path, "A=1\nB=2\n"), environ={"B": "shell"})

        assert result.detail == "1 variable, 1 already set in the environment"

    def test_describe_names_the_path(self, tmp_path: Path) -> None:
        path = write_env(tmp_path, "PW=hunter2")

        assert str(path) in load_dotenv(path, environ={}).describe()


class TestApplyDotenvDirectly:
    def test_it_touches_only_the_mapping_it_is_given(self, tmp_path: Path) -> None:
        """The seam that keeps the whole test file out of ``os.environ``: if
        the default ever stopped being overridable, these tests would start
        leaking variables into every test that runs after them."""
        environ: dict[str, str] = {}

        apply_dotenv(read_dotenv(write_env(tmp_path, "MESHELLE_TEST_ONLY=1")), environ=environ)

        assert environ == {"MESHELLE_TEST_ONLY": "1"}
        assert "MESHELLE_TEST_ONLY" not in os.environ
