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

"""Post text: taking it in off the air, and putting it back out again.

A post makes two trips across the wire in different shapes, and the asymmetry is
the reason this module exists:

* **Inbound** it is a ``TXT_TYPE_PLAIN`` message from one client -- bytes, of
  whatever length survived that client's own limits, padded out to a cipher
  block and not necessarily valid UTF-8 by the time the radio is done with it.
* **Outbound** it is a ``TXT_TYPE_SIGNED_PLAIN`` message to every *other*
  client, and it has grown a 4-byte author prefix, so nine of the available
  bytes are spent before any text goes in (``pushPostToClient``, MyMesh.cpp:68).

Both directions are byte-limited, never character-limited, so every truncation
here goes through :mod:`meshelle.proto.text` and lands on a code-point boundary.
A post cut mid-character renders as a replacement glyph in every client.
"""

from __future__ import annotations

import secrets
import struct

from meshelle.proto.constants import (
    MAX_POST_TEXT_LEN,
    SIGNED_AUTHOR_PREFIX_LEN,
    TXT_ATTEMPT_MASK,
    TXT_FLAGS_TYPE_SHIFT,
    TxtType,
)
from meshelle.proto.packet import TextMessage, max_plaintext_len
from meshelle.proto.text import utf8_split, utf8_truncate

PUSH_OVERHEAD = TextMessage.PREFIX_LEN + SIGNED_AUTHOR_PREFIX_LEN
"""9 bytes: a 4-byte timestamp, the flags byte, and the author's key prefix."""


def decode_post_text(raw: bytes) -> str:
    """Turn the bytes of an inbound post into storable text.

    ``errors="replace"`` rather than a rejection: the text came off a radio
    link, and a corrupted byte in someone's message is not a reason to refuse
    the whole post -- nor to let a decode error escape into the receive loop.
    """
    return utf8_truncate(raw.decode("utf-8", errors="replace"), MAX_POST_TEXT_LEN).decode("utf-8")


def push_text_budget(path_bytes: int = 0) -> int:
    """How many bytes of post text fit in one push over a given return path."""
    return min(MAX_POST_TEXT_LEN, max(0, max_plaintext_len(path_bytes) - PUSH_OVERHEAD))


def build_push(
    post_ts: int,
    author_public_key: bytes,
    text: str,
    *,
    attempt: int | None = None,
    path_bytes: int = 0,
) -> bytes:
    """The plaintext of a pushed post.

    ``[post_ts:4][SIGNED_PLAIN<<2 | attempt][author_pubkey[:4]][text]``

    ``attempt`` is two random bits, not a retry counter, and firmware says why
    (MyMesh.cpp:74): a re-push of the same post must produce a *different*
    packet hash, or every repeater between here and the client will suppress it
    as a duplicate of the attempt that already failed. The client's expected ACK
    changes with it, which is why the ACK is recomputed per push and not stored
    with the post.

    ``post_ts`` is deliberately in the past. The client accepts it because this
    is a room sync, not a live message.
    """
    if attempt is None:
        attempt = secrets.randbelow(TXT_ATTEMPT_MASK + 1)
    flags = (TxtType.SIGNED_PLAIN << TXT_FLAGS_TYPE_SHIFT) | (attempt & TXT_ATTEMPT_MASK)
    body = utf8_truncate(text, push_text_budget(path_bytes))
    return struct.pack("<IB", post_ts, flags) + author_public_key[:SIGNED_AUTHOR_PREFIX_LEN] + body


def split_welcome(text: str) -> list[str]:
    """Break a welcome message into individually pushable chunks.

    Each chunk travels as its own message with its own ACK, so a long welcome
    is not all-or-nothing: a client that drops off halfway keeps what it got.
    Sized for the worst-case route, so a chunk never has to be re-truncated at
    send time for a client that happens to be eight hops away.
    """
    if not text.strip():
        return []
    return [chunk.decode("utf-8") for chunk in utf8_split(text, push_text_budget(64))]
