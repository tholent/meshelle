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

"""UTF-8 truncation and splitting."""

from __future__ import annotations

import pytest

from meshelle.proto.text import utf8_split, utf8_truncate


class TestUtf8Truncate:
    def test_passes_through_short_ascii(self) -> None:
        assert utf8_truncate("hello", 10) == b"hello"

    def test_truncates_ascii_at_the_limit(self) -> None:
        assert utf8_truncate("hello world", 5) == b"hello"

    def test_never_splits_a_multibyte_character(self) -> None:
        """'é' is 2 bytes; a 3-byte budget must yield 'aé', not 'aé' + half."""
        assert utf8_truncate("aéé", 3) == "aé".encode()

    @pytest.mark.parametrize("limit", range(1, 13))
    def test_output_always_decodes(self, limit: int) -> None:
        """Whatever the budget, the result must be valid UTF-8."""
        text = "aé☃𝄞bc"
        out = utf8_truncate(text, limit)

        assert len(out) <= limit
        out.decode("utf-8")  # must not raise
        assert text.encode("utf-8").startswith(out)

    @pytest.mark.parametrize("char", ["é", "☃", "𝄞"])
    def test_returns_empty_when_even_one_character_will_not_fit(self, char: str) -> None:
        """Never a lone lead byte -- that is the mojibake this function prevents."""
        assert utf8_truncate(char, 1) == b""

    @pytest.mark.parametrize("limit", [0, -1])
    def test_non_positive_limit_yields_nothing(self, limit: int) -> None:
        assert utf8_truncate("anything", limit) == b""

    def test_four_byte_character_is_kept_whole_or_dropped(self) -> None:
        """A musical symbol is 4 bytes: it fits at 4, vanishes below."""
        assert utf8_truncate("𝄞", 4) == "𝄞".encode()
        for limit in (1, 2, 3):
            assert utf8_truncate("𝄞", limit) == b""


class TestUtf8Split:
    def test_short_text_is_a_single_chunk(self) -> None:
        assert utf8_split("hello", 100) == [b"hello"]

    def test_empty_text_yields_no_chunks(self) -> None:
        assert utf8_split("", 10) == []

    def test_every_chunk_respects_the_limit_and_decodes(self) -> None:
        text = "Welcome to the room. Please play nicely with others, and mind the café sign. ☃"
        chunks = utf8_split(text, 20)

        assert chunks
        for chunk in chunks:
            assert len(chunk) <= 20
            chunk.decode("utf-8")

    def test_rejoins_to_the_original_words(self) -> None:
        """Splitting then rejoining must not lose or duplicate any word."""
        text = "one two three four five six seven eight nine ten"
        chunks = utf8_split(text, 12)

        rejoined = " ".join(c.decode("utf-8") for c in chunks)
        assert rejoined.split() == text.split()

    def test_prefers_to_break_on_whitespace(self) -> None:
        chunks = utf8_split("alpha beta gamma", 11)
        assert chunks[0] == b"alpha beta", "should not slice mid-word when a space is near"

    def test_falls_back_to_a_hard_break_for_an_overlong_word(self) -> None:
        """A single word longer than the chunk must still be emitted."""
        chunks = utf8_split("supercalifragilistic", 8)

        assert chunks[0] == b"supercal"
        assert b"".join(chunks) == b"supercalifragilistic"

    def test_does_not_split_multibyte_characters(self) -> None:
        chunks = utf8_split("é" * 20, 7)
        for chunk in chunks:
            chunk.decode("utf-8")
            assert len(chunk) % 2 == 0, "each é is 2 bytes, so chunks must be even"

    def test_rejects_a_limit_too_small_for_the_text(self) -> None:
        with pytest.raises(ValueError, match="too small"):
            utf8_split("𝄞𝄞", 2)

    @pytest.mark.parametrize("limit", [0, -5])
    def test_rejects_non_positive_limit(self, limit: int) -> None:
        with pytest.raises(ValueError, match="must be positive"):
            utf8_split("text", limit)
