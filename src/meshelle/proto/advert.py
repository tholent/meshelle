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

"""Node advertisements.

An advert is how a room announces itself so clients can add it as a contact.
Payload layout (docs/payloads.md, ``Mesh::createAdvert``)::

    [public_key:32][timestamp:4][signature:64][appdata]

The signature covers ``public_key || timestamp || appdata`` -- not the packet
header or path -- so it survives being re-flooded by repeaters.

``appdata`` is at most 32 bytes (``MAX_ADVERT_DATA_SIZE``) and is self-describing
via its leading flags byte::

    [flags:1][lat:int32][lon:int32][feat1:uint16][feat2:uint16][name...]

The low nibble of ``flags`` is the node type; the high bits say which optional
fields are present. The name takes whatever space is left, which is why a room
with a location gets 23 bytes of name and one without gets 31.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Self

from meshelle.proto.constants import (
    ADV_FEAT1_MASK,
    ADV_FEAT2_MASK,
    ADV_LATLON_MASK,
    ADV_NAME_MASK,
    MAX_ADVERT_DATA_SIZE,
    PUB_KEY_SIZE,
    SIGNATURE_SIZE,
    AdvertType,
)
from meshelle.proto.identity import LocalIdentity, verify_signature
from meshelle.proto.packet import PacketError
from meshelle.proto.text import utf8_truncate

ADVERT_TYPE_MASK = 0x0F
LATLON_SCALE = 1_000_000
"""Latitude and longitude travel as degrees * 1e6 in a signed 32-bit integer."""


@dataclass(frozen=True, slots=True)
class AdvertData:
    """The decoded ``appdata`` block of an advert."""

    node_type: AdvertType
    name: str = ""
    latitude: float | None = None
    longitude: float | None = None
    feat1: int = 0
    feat2: int = 0

    @property
    def has_location(self) -> bool:
        return self.latitude is not None and self.longitude is not None

    def encode(self) -> bytes:
        """Encode to at most ``MAX_ADVERT_DATA_SIZE`` bytes.

        The name is truncated on a UTF-8 boundary to fit whatever space the
        optional fields leave, matching ``AdvertDataBuilder::encodeTo``.
        """
        flags = int(self.node_type) & ADVERT_TYPE_MASK
        body = b""

        if self.has_location:
            assert self.latitude is not None and self.longitude is not None  # noqa: S101
            flags |= ADV_LATLON_MASK
            body += struct.pack(
                "<ii",
                int(self.latitude * LATLON_SCALE),
                int(self.longitude * LATLON_SCALE),
            )
        # Firmware only emits these when non-zero, and so do we: a zero feature
        # word with its flag set would be indistinguishable from absent anyway.
        if self.feat1:
            flags |= ADV_FEAT1_MASK
            body += struct.pack("<H", self.feat1)
        if self.feat2:
            flags |= ADV_FEAT2_MASK
            body += struct.pack("<H", self.feat2)

        if self.name:
            room_for_name = MAX_ADVERT_DATA_SIZE - 1 - len(body)
            encoded_name = utf8_truncate(self.name, room_for_name)
            if encoded_name:
                flags |= ADV_NAME_MASK
                body += encoded_name

        return bytes([flags]) + body

    @classmethod
    def decode(cls, appdata: bytes) -> Self:
        if not appdata:
            raise PacketError("advert appdata is empty")

        flags = appdata[0]
        offset = 1
        latitude: float | None = None
        longitude: float | None = None
        feat1 = feat2 = 0

        if flags & ADV_LATLON_MASK:
            if len(appdata) < offset + 8:
                raise PacketError("advert claims a location but is truncated")
            raw_lat, raw_lon = struct.unpack_from("<ii", appdata, offset)
            latitude, longitude = raw_lat / LATLON_SCALE, raw_lon / LATLON_SCALE
            offset += 8

        if flags & ADV_FEAT1_MASK:
            if len(appdata) < offset + 2:
                raise PacketError("advert claims feat1 but is truncated")
            feat1 = struct.unpack_from("<H", appdata, offset)[0]
            offset += 2

        if flags & ADV_FEAT2_MASK:
            if len(appdata) < offset + 2:
                raise PacketError("advert claims feat2 but is truncated")
            feat2 = struct.unpack_from("<H", appdata, offset)[0]
            offset += 2

        name = ""
        if flags & ADV_NAME_MASK and len(appdata) > offset:
            # Names come off the air from other people's nodes, so a malformed
            # one must not take the server down.
            name = appdata[offset:].decode("utf-8", errors="replace")

        node_type_raw = flags & ADVERT_TYPE_MASK
        try:
            node_type = AdvertType(node_type_raw)
        except ValueError:
            # Types 5..15 are reserved for future use; treat unknown as NONE
            # rather than rejecting, so a newer node's advert still parses.
            node_type = AdvertType.NONE

        return cls(
            node_type=node_type,
            name=name,
            latitude=latitude,
            longitude=longitude,
            feat1=feat1,
            feat2=feat2,
        )


@dataclass(frozen=True, slots=True)
class Advert:
    """A complete, signed advert payload."""

    public_key: bytes
    timestamp: int
    signature: bytes
    appdata: bytes

    HEADER_LEN = PUB_KEY_SIZE + 4 + SIGNATURE_SIZE

    def __post_init__(self) -> None:
        if len(self.public_key) != PUB_KEY_SIZE:
            raise PacketError(f"advert public key must be {PUB_KEY_SIZE} bytes")
        if len(self.signature) != SIGNATURE_SIZE:
            raise PacketError(f"advert signature must be {SIGNATURE_SIZE} bytes")
        if len(self.appdata) > MAX_ADVERT_DATA_SIZE:
            raise PacketError(
                f"advert appdata exceeds {MAX_ADVERT_DATA_SIZE} bytes: {len(self.appdata)}"
            )

    @property
    def signed_message(self) -> bytes:
        """Exactly what the signature covers."""
        return self.public_key + struct.pack("<I", self.timestamp) + self.appdata

    @property
    def is_valid(self) -> bool:
        return verify_signature(self.public_key, self.signed_message, self.signature)

    @property
    def data(self) -> AdvertData:
        return AdvertData.decode(self.appdata)

    def encode(self) -> bytes:
        return self.public_key + struct.pack("<I", self.timestamp) + self.signature + self.appdata

    @classmethod
    def decode(cls, payload: bytes) -> Self:
        if len(payload) < cls.HEADER_LEN:
            raise PacketError(
                f"advert payload too short: {len(payload)} bytes, need {cls.HEADER_LEN}"
            )
        return cls(
            public_key=payload[:PUB_KEY_SIZE],
            timestamp=struct.unpack_from("<I", payload, PUB_KEY_SIZE)[0],
            signature=payload[PUB_KEY_SIZE + 4 : cls.HEADER_LEN],
            appdata=payload[cls.HEADER_LEN :],
        )

    @classmethod
    def create(cls, identity: LocalIdentity, timestamp: int, data: AdvertData) -> Self:
        """Build and sign an advert for ``identity``."""
        appdata = data.encode()
        message = identity.public_key + struct.pack("<I", timestamp) + appdata
        return cls(
            public_key=identity.public_key,
            timestamp=timestamp,
            signature=identity.sign(message),
            appdata=appdata,
        )
