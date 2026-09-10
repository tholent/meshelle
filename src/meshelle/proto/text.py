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

"""UTF-8 aware truncation and splitting.

MeshCore fields are byte-limited, not character-limited: an advert's appdata is
32 bytes and a post is 151. Cutting UTF-8 at an arbitrary byte offset leaves a
partial code point, which renders as a replacement character in every client.

Firmware solves this with ``mesh::validUtf8PrefixLength``
(src/helpers/UTF8Helpers.h); these are the equivalents, plus the splitter needed
to break a long welcome message into postable chunks.
"""

from __future__ import annotations

MAX_UTF8_SEQUENCE = 4


def utf8_truncate(text: str, max_bytes: int) -> bytes:
    """Encode ``text``, truncated to at most ``max_bytes`` whole code points."""
    if max_bytes <= 0:
        return b""

    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return encoded

    # Back off at most 3 bytes to land on a code point boundary. A UTF-8
    # continuation byte matches 0b10xxxxxx, so walk back while we are on one.
    cut = max_bytes
    while cut > 0 and (encoded[cut] & 0xC0) == 0x80:
        cut -= 1
    return encoded[:cut]


def utf8_split(text: str, max_bytes: int) -> list[bytes]:
    """Split ``text`` into chunks of at most ``max_bytes``, never mid-character.

    Prefers to break at a space so chunks read as sentences rather than being
    sliced mid-word, but falls back to a hard boundary when a single word is
    longer than a chunk.
    """
    if max_bytes <= 0:
        raise ValueError(f"max_bytes must be positive, got {max_bytes}")
    if not text:
        return []

    chunks: list[bytes] = []
    remaining = text
    while remaining:
        candidate = utf8_truncate(remaining, max_bytes)
        if not candidate:
            # A single code point exceeds max_bytes; nothing can be emitted.
            raise ValueError(
                f"max_bytes={max_bytes} is too small for the next character in {remaining[:8]!r}"
            )

        consumed = candidate.decode("utf-8")
        if len(consumed) < len(remaining):
            # Try to break on whitespace, but only if that keeps the chunk
            # reasonably full -- otherwise a long word would waste most of it.
            split_at = consumed.rfind(" ")
            if split_at > 0 and split_at >= len(consumed) // 2:
                consumed = consumed[:split_at]

        chunks.append(consumed.encode("utf-8"))
        remaining = remaining[len(consumed) :].lstrip(" ")

    return chunks
