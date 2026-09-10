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

"""The TOML line scanner.

A wrong line number is worse than none, because it sends the reader to a line
that is fine. So these tests lean on the cases where a naive line-by-line scan
would guess wrong: keys that appear inside multi-line strings, values that span
lines, comments, and repeated array-of-tables headers.
"""

from __future__ import annotations

import pytest

from meshelle.config.source import build_source_map


class TestSections:
    def test_records_a_section_header(self) -> None:
        source_map = build_source_map("# comment\n[companion]\nport = 'x'\n")

        assert source_map.locate(("companion",)) == 2
        assert source_map.locate(("companion", "port")) == 3

    def test_records_dotted_sections(self) -> None:
        source_map = build_source_map("[room.lobby]\nname = 'Lobby'\n")

        assert source_map.locate(("room", "lobby")) == 1
        assert source_map.locate(("room", "lobby", "name")) == 2

    def test_records_top_level_keys(self) -> None:
        source_map = build_source_map("bare = 1\n\n[section]\nnested = 2\n")

        assert source_map.locate(("bare",)) == 1
        assert source_map.locate(("section", "nested")) == 4

    def test_handles_quoted_section_segments(self) -> None:
        source_map = build_source_map('[room."my room"]\nname = "x"\n')

        assert source_map.locate(("room", "my room")) == 1
        assert source_map.locate(("room", "my room", "name")) == 2

    def test_handles_quoted_keys(self) -> None:
        source_map = build_source_map('[section]\n"odd key" = 1\n')
        assert source_map.locate(("section", "odd key")) == 2

    def test_tolerates_indentation_and_trailing_comments(self) -> None:
        source_map = build_source_map("  [companion]  # the node\n  port = 'x'  # device\n")

        assert source_map.locate(("companion",)) == 1
        assert source_map.locate(("companion", "port")) == 2


class TestArraysOfTables:
    def test_indexes_repeated_headers(self) -> None:
        text = (
            "[room.ops]\n"
            "name = 'Ops'\n"
            "\n"
            "[[room.ops.member]]\n"
            "pubkey = 'a'\n"
            "\n"
            "[[room.ops.member]]\n"
            "pubkey = 'b'\n"
        )
        source_map = build_source_map(text)

        assert source_map.locate(("room", "ops", "member", 0)) == 4
        assert source_map.locate(("room", "ops", "member", 0, "pubkey")) == 5
        assert source_map.locate(("room", "ops", "member", 1)) == 7
        assert source_map.locate(("room", "ops", "member", 1, "pubkey")) == 8

    def test_counters_reset_when_a_new_parent_table_opens(self) -> None:
        """Two rooms each have their own member[0]."""
        text = (
            "[room.a]\n[[room.a.member]]\npubkey = 'x'\n[room.b]\n[[room.b.member]]\npubkey = 'y'\n"
        )
        source_map = build_source_map(text)

        assert source_map.locate(("room", "a", "member", 0, "pubkey")) == 3
        assert source_map.locate(("room", "b", "member", 0, "pubkey")) == 6


class TestMultilineStrings:
    def test_ignores_keys_inside_a_triple_quoted_string(self) -> None:
        """The case a naive scanner gets wrong: text that looks like a key."""
        text = '[room.lobby]\nwelcome = """\nnonsense = \'not a key\'\n"""\nname = \'Lobby\'\n'
        source_map = build_source_map(text)

        assert source_map.locate(("room", "lobby", "welcome")) == 2
        assert source_map.lines.get(("room", "lobby", "nonsense")) is None
        assert source_map.locate(("room", "lobby", "name")) == 5, "scanning resumes after the close"

    def test_handles_single_quoted_multiline(self) -> None:
        text = "[s]\nv = '''\nk = 1\n'''\nafter = 2\n"
        source_map = build_source_map(text)

        assert source_map.lines.get(("s", "k")) is None
        assert source_map.locate(("s", "after")) == 5

    def test_ignores_a_section_header_inside_a_string(self) -> None:
        text = '[real]\nv = """\n[fake]\n"""\nafter = 1\n'
        source_map = build_source_map(text)

        assert source_map.lines.get(("fake",)) is None
        assert source_map.locate(("real", "after")) == 5

    def test_a_single_line_triple_quoted_value_does_not_open_a_block(self) -> None:
        text = '[s]\nv = """inline"""\nafter = 1\n'
        source_map = build_source_map(text)

        assert source_map.locate(("s", "after")) == 3


class TestMultilineValues:
    def test_ignores_keys_inside_a_multiline_array(self) -> None:
        """Inline tables in an array would otherwise look like section keys."""
        text = "[s]\nitems = [\n  { pubkey = 'a' },\n  { pubkey = 'b' },\n]\nafter = 1\n"
        source_map = build_source_map(text)

        assert source_map.locate(("s", "items")) == 2
        assert source_map.lines.get(("s", "pubkey")) is None
        assert source_map.locate(("s", "after")) == 6

    def test_brackets_inside_strings_do_not_affect_depth(self) -> None:
        text = "[s]\nwelcome = 'a [bracket] here'\nafter = 1\n"
        source_map = build_source_map(text)

        assert source_map.locate(("s", "after")) == 3

    def test_a_hash_inside_a_string_is_not_a_comment(self) -> None:
        text = "[s]\nwelcome = 'tag #1'\nafter = 1\n"
        source_map = build_source_map(text)

        assert source_map.locate(("s", "after")) == 3


class TestLocate:
    def test_falls_back_to_the_nearest_ancestor(self) -> None:
        """An inline table has one line, so anything inside it reports that line."""
        source_map = build_source_map("[room.lobby]\npasswords = { admin = 'pw' }\n")

        assert source_map.locate(("room", "lobby", "passwords", "admin")) == 2

    def test_returns_none_for_an_unknown_path(self) -> None:
        source_map = build_source_map("[companion]\nport = 'x'\n")

        assert source_map.locate(("nowhere", "at", "all")) is None

    def test_returns_none_for_an_empty_path(self) -> None:
        assert build_source_map("[s]\n").locate(()) is None

    def test_first_occurrence_wins(self) -> None:
        """A duplicate key is a TOML error; point at where it was first set."""
        source_map = build_source_map("[s]\nv = 1\nv = 2\n")

        assert source_map.locate(("s", "v")) == 2


class TestDegenerateInput:
    @pytest.mark.parametrize(
        "text",
        ["", "\n\n\n", "# only comments\n", "[unclosed\n", "]]weird[[\n", "= 1\n"],
    )
    def test_never_raises(self, text: str) -> None:
        """Malformed TOML is tomllib's job to report; the scanner must not be the
        thing that crashes first."""
        assert build_source_map(text) is not None
