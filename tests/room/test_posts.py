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

"""Post text on the way in and on the way back out."""

from __future__ import annotations

from meshelle.proto.constants import (
    MAX_POST_TEXT_LEN,
    MAX_RAW_TX_PACKET,
    SIGNED_AUTHOR_PREFIX_LEN,
    TXT_FLAGS_TYPE_SHIFT,
    PayloadType,
    RouteType,
    TxtType,
)
from meshelle.proto.packet import Datagram, Packet, TextMessage
from meshelle.room import posts

AUTHOR = bytes([0xAB, 0x00, 0xCD, 0x00]) + bytes(28)
"""Deliberately contains zero bytes: a real public key often does."""


def test_a_push_carries_the_timestamp_flags_author_prefix_then_text() -> None:
    """Protocol semantics: ``[post_ts:4][SIGNED_PLAIN<<2|attempt][author:4][text]``
    (MyMesh.cpp:68). The author prefix is how an app labels who posted."""
    payload = posts.build_push(1_700_000_000, AUTHOR, "hello", attempt=2)

    assert len(payload) == posts.PUSH_OVERHEAD + len("hello")
    assert payload[4] == (TxtType.SIGNED_PLAIN << TXT_FLAGS_TYPE_SHIFT) | 2
    assert payload[5:9] == AUTHOR[:SIGNED_AUTHOR_PREFIX_LEN]
    assert payload[9:] == b"hello"


def test_a_push_with_a_zero_byte_in_the_author_prefix_still_decodes() -> None:
    """Protocol semantics: the client trims a SIGNED_PLAIN message from
    ``&data[9]`` (BaseChatMesh.cpp:273), after the key prefix. Trimming from
    offset 5 instead would cut this message to nothing and compute an ACK the
    room never expects, so the post could never be synced.
    """
    payload = posts.build_push(1_700_000_000, AUTHOR, "still here", attempt=0)

    message = TextMessage.decode(payload + b"\x00" * 6)  # cipher padding

    assert message.author_prefix == AUTHOR[:4]
    assert message.body == b"still here"
    assert message.encode() == payload


def test_the_attempt_bits_change_the_packet_hash_between_retries() -> None:
    """Protocol semantics (MyMesh.cpp:74): a re-push of the same post must hash
    differently, or every repeater between here and the client suppresses it as
    a duplicate of the attempt that already failed."""
    first = posts.build_push(1_700_000_000, AUTHOR, "retry me", attempt=0)
    second = posts.build_push(1_700_000_000, AUTHOR, "retry me", attempt=1)

    assert first != second


def test_a_random_attempt_is_chosen_when_none_is_given() -> None:
    seen = {posts.build_push(1, AUTHOR, "x")[4] for _ in range(50)}

    assert len(seen) > 1


def test_a_full_length_post_still_fits_the_nodes_frame_buffer() -> None:
    """The binding limit is the companion's 176-byte frame, not the protocol's
    184-byte payload: a packet firmware would happily build can still be one
    meshelle cannot hand to the node."""
    text = "x" * MAX_POST_TEXT_LEN
    payload = posts.build_push(1_700_000_000, AUTHOR, text)
    datagram = Datagram.seal(0x11, 0x22, bytes(32), payload)
    packet = Packet(
        route_type=RouteType.DIRECT,
        payload_type=PayloadType.TXT_MSG,
        payload=datagram.encode(),
        path=b"\x01" * 8,
    )

    # 174 exactly: the 151-byte post limit is what makes an eight-hop route
    # fit at all, which is why it is not simply MAX_TEXT_LEN.
    assert len(packet.encode()) == MAX_RAW_TX_PACKET


def test_inbound_text_that_is_not_valid_utf8_is_kept_not_rejected() -> None:
    """A corrupted byte in someone's message is not a reason to refuse the post,
    nor to let a decode error escape into the receive loop."""
    text = posts.decode_post_text(b"caf\xff")

    assert text.startswith("caf")


def test_an_over_long_post_is_cut_on_a_character_boundary() -> None:
    """MeshCore fields are byte-limited, not character-limited. Cutting UTF-8
    mid-sequence renders as a replacement glyph in every client."""
    text = posts.decode_post_text("é".encode() * MAX_POST_TEXT_LEN)

    assert len(text.encode("utf-8")) <= MAX_POST_TEXT_LEN
    assert "�" not in text


def test_a_welcome_is_split_into_separately_pushable_chunks() -> None:
    """Each chunk is its own message with its own ACK, so a client that drops
    off halfway keeps what it already received."""
    chunks = posts.split_welcome("word " * 100)

    assert len(chunks) > 1
    assert all(len(chunk.encode("utf-8")) <= posts.push_text_budget(64) for chunk in chunks)
    assert "".join(chunks).replace(" ", "") == ("word " * 100).replace(" ", "")


def test_a_welcome_chunk_fits_even_the_longest_return_path() -> None:
    """Sized for the worst case, so a chunk is never re-truncated at send time
    for a client that happens to be far away -- which would lose text silently."""
    chunks = posts.split_welcome("a" * 500)

    for chunk in chunks:
        payload = posts.build_push(1, AUTHOR, chunk, path_bytes=64)
        assert payload[9:].decode("utf-8") == chunk


def test_an_empty_welcome_produces_nothing_to_push() -> None:
    assert posts.split_welcome("") == []
    assert posts.split_welcome("   \n ") == []
