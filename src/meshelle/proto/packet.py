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

"""MeshCore packet and payload codecs.

Wire layout (docs/packet_format.md, src/Packet.cpp)::

    [header][transport_codes(4, optional)][path_length][path][payload]

``path_length`` is not a byte count. Bits 0-5 hold the hop count and bits 6-7
hold ``hash_size - 1``, so the path occupies ``hop_count * hash_size`` bytes
(``Packet::getPathByteLen``). A hash size of 4 is reserved and invalid.

Above the frame sit the payload types meshelle needs. Two share a shape:

* **Datagram** (REQ, RESPONSE, TXT_MSG, PATH) —
  ``[dest_hash:1][src_hash:1][mac:2][ciphertext]``
* **AnonRequest** (ANON_REQ) —
  ``[dest_hash:1][sender_pubkey:32][mac:2][ciphertext]``

Decrypted plaintext is always zero-padded to a cipher block, so every plaintext
codec here recovers its real length from structure -- a C string terminator for
text and passwords, or a fixed layout. Firmware does the same thing by writing a
NUL at the padded length and calling ``strlen``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Self

from meshelle.proto import crypto
from meshelle.proto.constants import (
    CIPHER_MAC_SIZE,
    MAX_PACKET_PAYLOAD,
    MAX_PATH_SIZE,
    PATH_HASH_SIZE_MASK,
    PATH_HASH_SIZE_SHIFT,
    PATH_HOP_COUNT_MASK,
    PH_ROUTE_MASK,
    PH_TYPE_MASK,
    PH_TYPE_SHIFT,
    PH_VER_MASK,
    PH_VER_SHIFT,
    PUB_KEY_SIZE,
    SIGNED_AUTHOR_PREFIX_LEN,
    TRANSPORT_CODES_SIZE,
    TXT_ATTEMPT_MASK,
    TXT_FLAGS_TYPE_SHIFT,
    PayloadType,
    PayloadVersion,
    RouteType,
    TxtType,
)

NODE_HASH_SIZE = 1
"""A node hash is the first byte of its public key (docs/payloads.md)."""

MAX_PATH_HASH_SIZE = 3
"""Hash size 4 is reserved; ``Packet::isValidPathLen`` rejects it."""


class PacketError(Exception):
    """A packet or payload could not be decoded."""


def _c_string(data: bytes, offset: int = 0) -> bytes:
    """Bytes from ``offset`` up to the first NUL, or the end.

    Decrypted payloads carry cipher padding, so this is how the real length of a
    text or password field is recovered.
    """
    body = data[offset:]
    terminator = body.find(b"\x00")
    return body if terminator < 0 else body[:terminator]


# ---------------------------------------------------------------------------
# The outer frame
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Packet:
    """One MeshCore radio packet."""

    route_type: RouteType
    payload_type: PayloadType
    payload: bytes
    path: bytes = b""
    path_hash_size: int = 1
    transport_codes: tuple[int, int] = (0, 0)
    payload_version: PayloadVersion = PayloadVersion.V1

    def __post_init__(self) -> None:
        if not 1 <= self.path_hash_size <= MAX_PATH_HASH_SIZE:
            raise PacketError(
                f"path hash size must be 1..{MAX_PATH_HASH_SIZE}, got {self.path_hash_size}"
            )
        if len(self.path) % self.path_hash_size:
            raise PacketError(
                f"path of {len(self.path)} bytes is not a multiple of "
                f"the {self.path_hash_size}-byte hash size"
            )
        if len(self.path) > MAX_PATH_SIZE:
            raise PacketError(f"path exceeds {MAX_PATH_SIZE} bytes: {len(self.path)}")
        if self.hop_count > PATH_HOP_COUNT_MASK:
            raise PacketError(f"hop count exceeds {PATH_HOP_COUNT_MASK}: {self.hop_count}")
        if len(self.payload) > MAX_PACKET_PAYLOAD:
            raise PacketError(f"payload exceeds {MAX_PACKET_PAYLOAD} bytes: {len(self.payload)}")
        if not self.payload:
            # Firmware's readFrom rejects this via `if (i >= len) return false`.
            raise PacketError("payload must not be empty")

    @property
    def hop_count(self) -> int:
        return len(self.path) // self.path_hash_size

    @property
    def header(self) -> int:
        return (
            (self.payload_version << PH_VER_SHIFT)
            | (self.payload_type << PH_TYPE_SHIFT)
            | self.route_type
        )

    @property
    def path_length_byte(self) -> int:
        return ((self.path_hash_size - 1) << PATH_HASH_SIZE_SHIFT) | self.hop_count

    @property
    def packet_hash(self) -> bytes:
        """The 8-byte duplicate-detection hash, excluding the path."""
        return crypto.packet_hash(self.payload_type, self.payload)

    def encode(self) -> bytes:
        parts = [bytes([self.header])]
        if self.route_type.has_transport_codes:
            parts.append(struct.pack("<HH", *self.transport_codes))
        parts.append(bytes([self.path_length_byte]))
        parts.append(self.path)
        parts.append(self.payload)
        return b"".join(parts)

    @classmethod
    def decode(cls, raw: bytes) -> Self:
        """Parse a raw packet, mirroring ``Packet::readFrom`` plus bounds checks.

        Firmware trusts its caller for lengths; we are fed bytes straight off the
        air, so every field is checked against the buffer.
        """
        if len(raw) < 2:
            raise PacketError(f"packet too short: {len(raw)} bytes")

        header = raw[0]
        route_type = RouteType(header & PH_ROUTE_MASK)
        payload_type_raw = (header >> PH_TYPE_SHIFT) & PH_TYPE_MASK
        try:
            payload_type = PayloadType(payload_type_raw)
        except ValueError as exc:
            raise PacketError(f"reserved payload type 0x{payload_type_raw:02X}") from exc
        payload_version = PayloadVersion((header >> PH_VER_SHIFT) & PH_VER_MASK)

        offset = 1
        transport_codes = (0, 0)
        if route_type.has_transport_codes:
            if len(raw) < offset + TRANSPORT_CODES_SIZE:
                raise PacketError("truncated transport codes")
            codes = struct.unpack_from("<HH", raw, offset)
            transport_codes = (codes[0], codes[1])
            offset += TRANSPORT_CODES_SIZE

        if len(raw) <= offset:
            raise PacketError("missing path length byte")
        path_length_byte = raw[offset]
        offset += 1

        path_hash_size = ((path_length_byte >> PATH_HASH_SIZE_SHIFT) & PATH_HASH_SIZE_MASK) + 1
        if path_hash_size > MAX_PATH_HASH_SIZE:
            raise PacketError("path hash size 4 is reserved")
        hop_count = path_length_byte & PATH_HOP_COUNT_MASK
        path_bytes = hop_count * path_hash_size
        if path_bytes > MAX_PATH_SIZE:
            raise PacketError(f"path of {path_bytes} bytes exceeds {MAX_PATH_SIZE}")
        if len(raw) < offset + path_bytes:
            raise PacketError(f"truncated path: need {path_bytes} bytes, have {len(raw) - offset}")
        path = raw[offset : offset + path_bytes]
        offset += path_bytes

        payload = raw[offset:]
        if not payload:
            raise PacketError("packet has no payload")
        if len(payload) > MAX_PACKET_PAYLOAD:
            raise PacketError(f"payload exceeds {MAX_PACKET_PAYLOAD} bytes: {len(payload)}")

        return cls(
            route_type=route_type,
            payload_type=payload_type,
            payload=payload,
            path=path,
            path_hash_size=path_hash_size,
            transport_codes=transport_codes,
            payload_version=payload_version,
        )


# ---------------------------------------------------------------------------
# Encrypted payload envelopes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Datagram:
    """``[dest_hash][src_hash][mac][ciphertext]`` -- REQ, RESPONSE, TXT_MSG, PATH."""

    dest_hash: int
    src_hash: int
    sealed: bytes
    """``mac || ciphertext``, as passed to :func:`crypto.mac_then_decrypt`."""

    HEADER_LEN = NODE_HASH_SIZE * 2

    def encode(self) -> bytes:
        return bytes([self.dest_hash, self.src_hash]) + self.sealed

    @classmethod
    def decode(cls, payload: bytes) -> Self:
        if len(payload) <= cls.HEADER_LEN + CIPHER_MAC_SIZE:
            raise PacketError(f"datagram payload too short: {len(payload)} bytes")
        return cls(
            dest_hash=payload[0],
            src_hash=payload[1],
            sealed=payload[cls.HEADER_LEN :],
        )

    @classmethod
    def seal(cls, dest_hash: int, src_hash: int, secret: bytes, plaintext: bytes) -> Self:
        return cls(
            dest_hash=dest_hash,
            src_hash=src_hash,
            sealed=crypto.encrypt_then_mac(secret, plaintext),
        )

    def open(self, secret: bytes) -> bytes:
        """Decrypt. Raises :class:`crypto.DecryptionError` if not ours."""
        return crypto.mac_then_decrypt(secret, self.sealed)


@dataclass(frozen=True, slots=True)
class AnonRequest:
    """``[dest_hash][sender_pubkey:32][mac][ciphertext]`` -- ANON_REQ.

    The sender includes its full public key because the recipient has no prior
    contact record to look it up from. This is how a room learns who is logging
    in, and why meshelle needs no contact book at all.
    """

    dest_hash: int
    sender_public_key: bytes
    sealed: bytes

    HEADER_LEN = NODE_HASH_SIZE + PUB_KEY_SIZE

    def __post_init__(self) -> None:
        if len(self.sender_public_key) != PUB_KEY_SIZE:
            raise PacketError(f"sender public key must be {PUB_KEY_SIZE} bytes")

    def encode(self) -> bytes:
        return bytes([self.dest_hash]) + self.sender_public_key + self.sealed

    @classmethod
    def decode(cls, payload: bytes) -> Self:
        if len(payload) <= cls.HEADER_LEN + CIPHER_MAC_SIZE:
            raise PacketError(f"anon request payload too short: {len(payload)} bytes")
        return cls(
            dest_hash=payload[0],
            sender_public_key=payload[NODE_HASH_SIZE : NODE_HASH_SIZE + PUB_KEY_SIZE],
            sealed=payload[cls.HEADER_LEN :],
        )

    def open(self, secret: bytes) -> bytes:
        return crypto.mac_then_decrypt(secret, self.sealed)


# ---------------------------------------------------------------------------
# Plaintext payload bodies
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TextMessage:
    """``[timestamp:4][txt_type<<2 | attempt][text]``.

    For :attr:`TxtType.SIGNED_PLAIN` the text is prefixed with 4 bytes of the
    author's public key; :attr:`author_prefix` and :attr:`body` split that out.
    """

    timestamp: int
    txt_type: TxtType
    attempt: int
    text: bytes

    PREFIX_LEN = 5

    def encode(self) -> bytes:
        flags = (self.txt_type << TXT_FLAGS_TYPE_SHIFT) | (self.attempt & TXT_ATTEMPT_MASK)
        return struct.pack("<IB", self.timestamp, flags) + self.text

    @classmethod
    def decode(cls, plaintext: bytes) -> Self:
        if len(plaintext) < cls.PREFIX_LEN:
            raise PacketError(f"text message too short: {len(plaintext)} bytes")
        timestamp, flags = struct.unpack_from("<IB", plaintext, 0)
        txt_type_raw = flags >> TXT_FLAGS_TYPE_SHIFT
        try:
            txt_type = TxtType(txt_type_raw)
        except ValueError as exc:
            raise PacketError(f"unsupported text type 0x{txt_type_raw:02X}") from exc
        return cls(
            timestamp=timestamp,
            txt_type=txt_type,
            attempt=flags & TXT_ATTEMPT_MASK,
            text=_c_string(plaintext, cls.PREFIX_LEN),
        )

    @property
    def author_prefix(self) -> bytes:
        """First 4 bytes of the author's public key, for SIGNED_PLAIN only."""
        if self.txt_type is not TxtType.SIGNED_PLAIN:
            return b""
        return self.text[:SIGNED_AUTHOR_PREFIX_LEN]

    @property
    def body(self) -> bytes:
        """The message text with any author prefix removed."""
        if self.txt_type is not TxtType.SIGNED_PLAIN:
            return self.text
        return self.text[SIGNED_AUTHOR_PREFIX_LEN:]

    def ack_hash(self, recipient_public_key: bytes) -> bytes:
        """The ACK a recipient returns for this message.

        Firmware hashes ``timestamp || flags || strlen-trimmed text`` against the
        *client's* public key (MyMesh.cpp:461), so the trimmed text is what
        counts -- not the padded plaintext it arrived in.
        """
        return crypto.ack_hash(self.encode(), recipient_public_key)


@dataclass(frozen=True, slots=True)
class LoginRequest:
    """ANON_REQ plaintext for a room: ``[timestamp:4][sync_since:4][password]``.

    ``sync_since`` is the client telling us the timestamp of the newest post it
    already holds, so we only push what it is missing.
    """

    timestamp: int
    sync_since: int
    password: bytes

    PREFIX_LEN = 8

    def encode(self) -> bytes:
        return struct.pack("<II", self.timestamp, self.sync_since) + self.password

    @classmethod
    def decode(cls, plaintext: bytes) -> Self:
        if len(plaintext) < cls.PREFIX_LEN:
            raise PacketError(f"login request too short: {len(plaintext)} bytes")
        timestamp, sync_since = struct.unpack_from("<II", plaintext, 0)
        return cls(
            timestamp=timestamp,
            sync_since=sync_since,
            password=_c_string(plaintext, cls.PREFIX_LEN),
        )


@dataclass(frozen=True, slots=True)
class ServerRequest:
    """REQ plaintext: ``[timestamp:4][req_type:1][data]``."""

    timestamp: int
    req_type: int
    data: bytes

    PREFIX_LEN = 5

    def encode(self) -> bytes:
        return struct.pack("<IB", self.timestamp, self.req_type) + self.data

    @classmethod
    def decode(cls, plaintext: bytes) -> Self:
        if len(plaintext) < cls.PREFIX_LEN:
            raise PacketError(f"request too short: {len(plaintext)} bytes")
        timestamp, req_type = struct.unpack_from("<IB", plaintext, 0)
        return cls(timestamp=timestamp, req_type=req_type, data=plaintext[cls.PREFIX_LEN :])


@dataclass(frozen=True, slots=True)
class PathReturn:
    """PATH plaintext: ``[path_length][path][extra_type][extra]``.

    The inner ``path_length`` uses the **same** packed encoding as the outer
    packet's -- hop count in bits 0-5, hash size minus one in bits 6-7
    (``Mesh::createPathReturn``). docs/payloads.md describes it as "length of
    next field", which reads as a plain byte count and is not.
    """

    path: bytes
    path_hash_size: int = 1
    extra_type: int = 0xFF
    extra: bytes = b""

    def __post_init__(self) -> None:
        if not 1 <= self.path_hash_size <= MAX_PATH_HASH_SIZE:
            raise PacketError(f"path hash size must be 1..{MAX_PATH_HASH_SIZE}")
        if len(self.path) % self.path_hash_size:
            raise PacketError("path is not a multiple of the hash size")

    @property
    def hop_count(self) -> int:
        return len(self.path) // self.path_hash_size

    def encode(self) -> bytes:
        packed = ((self.path_hash_size - 1) << PATH_HASH_SIZE_SHIFT) | self.hop_count
        return bytes([packed]) + self.path + bytes([self.extra_type]) + self.extra

    @classmethod
    def decode(cls, plaintext: bytes) -> Self:
        if not plaintext:
            raise PacketError("path return is empty")
        packed = plaintext[0]
        path_hash_size = ((packed >> PATH_HASH_SIZE_SHIFT) & PATH_HASH_SIZE_MASK) + 1
        if path_hash_size > MAX_PATH_HASH_SIZE:
            raise PacketError("path hash size 4 is reserved")
        path_bytes = (packed & PATH_HOP_COUNT_MASK) * path_hash_size
        if len(plaintext) < 1 + path_bytes:
            raise PacketError("truncated path in path return")

        path = plaintext[1 : 1 + path_bytes]
        rest = plaintext[1 + path_bytes :]
        extra_type = rest[0] if rest else 0xFF
        return cls(
            path=path,
            path_hash_size=path_hash_size,
            extra_type=extra_type,
            extra=rest[1:],
        )


@dataclass(frozen=True, slots=True)
class Ack:
    """ACK payload: a bare 4-byte hash, unencrypted and unaddressed.

    Because it carries no destination, an ACK must be matched against every
    outstanding transmission we are waiting on.
    """

    checksum: bytes
    trailer: bytes = field(default=b"")
    """Extra bytes some servers append -- a room adds its unsynced count."""

    LEN = 4

    def __post_init__(self) -> None:
        if len(self.checksum) != self.LEN:
            raise PacketError(f"ack checksum must be {self.LEN} bytes")

    def encode(self) -> bytes:
        return self.checksum + self.trailer

    @classmethod
    def decode(cls, payload: bytes) -> Self:
        if len(payload) < cls.LEN:
            raise PacketError(f"ack payload too short: {len(payload)} bytes")
        return cls(checksum=payload[: cls.LEN], trailer=payload[cls.LEN :])
