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

"""MeshCore wire protocol constants.

Every value here is transcribed from the MeshCore firmware, which is the single
authority for the wire format. Each group cites its source file so the values
can be re-verified against a future firmware release:

* ``src/MeshCore.h``                       — size limits
* ``src/Packet.h``                         — header layout, route and payload types
* ``src/helpers/ClientACL.h``              — permission bits
* ``src/helpers/AdvertDataHelpers.h``      — advert types and appdata flags
* ``src/helpers/BaseChatMesh.h``           — text length limit
* ``examples/simple_room_server/MyMesh.cpp`` — room server requests and timings
* ``examples/companion_radio/MyMesh.cpp``  — companion serial protocol

Integers are little-endian on the wire throughout.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Final

# ---------------------------------------------------------------------------
# Size limits (src/MeshCore.h)
# ---------------------------------------------------------------------------

PUB_KEY_SIZE: Final = 32
PRV_KEY_SIZE: Final = 64
"""MeshCore private keys are the *expanded* 64-byte (a, RH) pair, not a seed."""
SEED_SIZE: Final = 32
SIGNATURE_SIZE: Final = 64
CIPHER_MAC_SIZE: Final = 2
CIPHER_KEY_SIZE: Final = 16
CIPHER_BLOCK_SIZE: Final = 16
MAX_HASH_SIZE: Final = 8
MAX_PACKET_PAYLOAD: Final = 184
MAX_PATH_SIZE: Final = 64
MAX_TRANS_UNIT: Final = 255
MAX_ADVERT_DATA_SIZE: Final = 32

MAX_TEXT_LEN: Final = 160
"""``10 * CIPHER_BLOCK_SIZE`` (src/helpers/BaseChatMesh.h)."""

MAX_POST_TEXT_LEN: Final = MAX_TEXT_LEN - 9
"""151. A pushed post spends 9 bytes on the timestamp, flags and author prefix."""

# ---------------------------------------------------------------------------
# Packet header (src/Packet.h)
#
#   header byte: 0bVVPPPPRR  — V=version, P=payload type, R=route type
# ---------------------------------------------------------------------------

PH_ROUTE_MASK: Final = 0x03
PH_TYPE_SHIFT: Final = 2
PH_TYPE_MASK: Final = 0x0F
PH_VER_SHIFT: Final = 6
PH_VER_MASK: Final = 0x03

TRANSPORT_CODES_SIZE: Final = 4
"""Two uint16 codes, present only for the TRANSPORT_* route types."""

PATH_HOP_COUNT_MASK: Final = 0x3F
"""``path_length`` bits 0-5: number of path hashes (0-63)."""
PATH_HASH_SIZE_SHIFT: Final = 6
"""``path_length`` bits 6-7: hash size minus one, so 0b00 means 1-byte hashes."""
PATH_HASH_SIZE_MASK: Final = 0x03

OUT_PATH_UNKNOWN: Final = 0xFF
"""Sentinel for "we have no known return path to this client" (ClientACL.h)."""


class RouteType(IntEnum):
    """Packet header bits 0-1."""

    TRANSPORT_FLOOD = 0x00
    FLOOD = 0x01
    DIRECT = 0x02
    TRANSPORT_DIRECT = 0x03

    @property
    def is_flood(self) -> bool:
        return self in (RouteType.FLOOD, RouteType.TRANSPORT_FLOOD)

    @property
    def is_direct(self) -> bool:
        return self in (RouteType.DIRECT, RouteType.TRANSPORT_DIRECT)

    @property
    def has_transport_codes(self) -> bool:
        return self in (RouteType.TRANSPORT_FLOOD, RouteType.TRANSPORT_DIRECT)


class PayloadType(IntEnum):
    """Packet header bits 2-5."""

    REQ = 0x00
    RESPONSE = 0x01
    TXT_MSG = 0x02
    ACK = 0x03
    ADVERT = 0x04
    GRP_TXT = 0x05
    GRP_DATA = 0x06
    ANON_REQ = 0x07
    PATH = 0x08
    TRACE = 0x09
    MULTIPART = 0x0A
    CONTROL = 0x0B
    RAW_CUSTOM = 0x0F


class PayloadVersion(IntEnum):
    """Packet header bits 6-7. Only V1 exists; the rest are reserved."""

    V1 = 0x00
    V2 = 0x01
    V3 = 0x02
    V4 = 0x03


# ---------------------------------------------------------------------------
# Text messages (docs/payloads.md)
#
#   flags byte: upper 6 bits are the txt type, lower 2 bits the attempt number
# ---------------------------------------------------------------------------

TXT_FLAGS_TYPE_SHIFT: Final = 2
TXT_ATTEMPT_MASK: Final = 0x03


class TxtType(IntEnum):
    PLAIN = 0x00
    CLI_DATA = 0x01
    SIGNED_PLAIN = 0x02


SIGNED_AUTHOR_PREFIX_LEN: Final = 4
"""A SIGNED_PLAIN message prefixes the text with 4 bytes of the author's pubkey."""

# ---------------------------------------------------------------------------
# Access control (src/helpers/ClientACL.h)
# ---------------------------------------------------------------------------

PERM_ACL_ROLE_MASK: Final = 0x03


class Permission(IntEnum):
    """The 2-bit role stored in ``ClientInfo.permissions``.

    Sent verbatim as byte 7 of the login response. meshcore-pi hardcodes this to
    zero, which is why every room it hosts appears read-only to current apps.
    """

    GUEST = 0
    READ_ONLY = 1
    READ_WRITE = 2
    ADMIN = 3


# ---------------------------------------------------------------------------
# Adverts (src/helpers/AdvertDataHelpers.h)
# ---------------------------------------------------------------------------


class AdvertType(IntEnum):
    """Low nibble of the advert appdata flags byte."""

    NONE = 0
    CHAT = 1
    REPEATER = 2
    ROOM = 3
    SENSOR = 4


ADV_LATLON_MASK: Final = 0x10
ADV_FEAT1_MASK: Final = 0x20
ADV_FEAT2_MASK: Final = 0x40
ADV_NAME_MASK: Final = 0x80

# ---------------------------------------------------------------------------
# Room server requests and responses (examples/simple_room_server/MyMesh.cpp)
# ---------------------------------------------------------------------------


class ReqType(IntEnum):
    GET_STATUS = 0x01
    KEEP_ALIVE = 0x02
    GET_TELEMETRY_DATA = 0x03
    GET_ACCESS_LIST = 0x05


RESP_SERVER_LOGIN_OK: Final = 0
"""The only ANON_REQ response. A failed login gets no reply at all."""

FIRMWARE_VER_LEVEL: Final = 1
"""Byte 12 of the login response; lets clients gate on server capabilities."""

LOGIN_RESPONSE_LEN: Final = 13

# ---------------------------------------------------------------------------
# Room server timings, in milliseconds unless named otherwise
# (examples/simple_room_server/MyMesh.cpp:3-13)
# ---------------------------------------------------------------------------

REPLY_DELAY_MILLIS: Final = 1500
PUSH_NOTIFY_DELAY_MILLIS: Final = 2000
SYNC_PUSH_INTERVAL_MILLIS: Final = 1200
PUSH_ACK_TIMEOUT_FLOOD_MILLIS: Final = 12000
PUSH_TIMEOUT_BASE_MILLIS: Final = 4000
PUSH_ACK_TIMEOUT_FACTOR_MILLIS: Final = 2000
SERVER_RESPONSE_DELAY_MILLIS: Final = 300
TXT_ACK_DELAY_MILLIS: Final = 200

POST_SYNC_DELAY_SECS: Final = 6
"""A post is held this long before being pushed, so the author's ACK lands first."""

MAX_PUSH_FAILURES: Final = 3
"""After this many unacknowledged pushes a client is left alone until it talks."""

# ---------------------------------------------------------------------------
# Companion serial protocol (examples/companion_radio/MyMesh.cpp)
# ---------------------------------------------------------------------------

MAX_FRAME_SIZE: Final = 176
"""src/helpers/BaseSerialInterface.h. Caps BOTH directions: a received packet
larger than ``MAX_FRAME_SIZE - 3`` is never mirrored to us, and an outbound
CMD_SEND_RAW_PACKET frame must fit too (``MAX_FRAME_SIZE - 2`` of packet)."""

MAX_RAW_RX_PACKET: Final = MAX_FRAME_SIZE - 3
MAX_RAW_TX_PACKET: Final = MAX_FRAME_SIZE - 2


class Cmd(IntEnum):
    """Commands we send to the companion. Only the ones meshelle needs."""

    APP_START = 1
    GET_DEVICE_TIME = 5
    SET_DEVICE_TIME = 6
    DEVICE_QUERY = 22
    SEND_RAW_PACKET = 65


class RespCode(IntEnum):
    """Companion replies we care about."""

    OK = 0
    ERR = 1
    SELF_INFO = 5
    CURR_TIME = 9
    DEVICE_INFO = 13
    DISABLED = 15


class PushCode(IntEnum):
    """Unsolicited frames the companion sends at any time."""

    ADVERT = 0x80
    PATH_UPDATED = 0x81
    SEND_CONFIRMED = 0x82
    MSG_WAITING = 0x83
    RAW_DATA = 0x84
    LOGIN_SUCCESS = 0x85
    LOGIN_FAIL = 0x86
    STATUS_RESPONSE = 0x87
    LOG_RX_DATA = 0x88
    TRACE_DATA = 0x89
    NEW_ADVERT = 0x8A
    TELEMETRY_RESPONSE = 0x8B
    BINARY_RESPONSE = 0x8C
    PATH_DISCOVERY_RESPONSE = 0x8D
    CONTROL_DATA = 0x8E
    CONTACT_DELETED = 0x8F
    CONTACTS_FULL = 0x90


class ErrCode(IntEnum):
    """Second byte of a RespCode.ERR frame."""

    UNSUPPORTED_CMD = 1
    NOT_FOUND = 2
    TABLE_FULL = 3
    BAD_STATE = 4
    FILE_IO_ERROR = 5
    ILLEGAL_ARG = 6


FRAME_START_TX: Final = b"<"
"""Serial framing: outbound frames are ``b'<' + uint16 length + payload``."""
FRAME_START_RX: Final = b">"
"""Serial framing: inbound frames are ``b'>' + uint16 length + payload``."""

COMPANION_API_VERSION: Final = 3
"""Version we request in CMD_DEVICE_QUERY."""

DEFAULT_BAUD_RATE: Final = 115200
