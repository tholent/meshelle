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

"""The client half of MeshCore, in the shape a real app implements it.

Without this there is no way to test a room server: every assertion worth making
is about what a *client* observes -- that a login reply grants write access,
that a post is acknowledged exactly once, that a pushed post arrives decryptable
and its ACK advances the sync cursor.

So this builds real packets with real X25519/AES/HMAC, and opens the replies the
same way an app does. Nothing here is stubbed: if the room server encrypts
wrongly, addresses wrongly, or computes an ACK over the wrong bytes, these
methods fail to decode it rather than politely agreeing.

Two details are transcribed from the firmware's client half rather than invented,
because getting them wrong would make the tests agree with a broken server:

* the ACK for a pushed post is hashed over ``9 + strlen(&data[9])`` bytes --
  from *after* the author's key prefix (``BaseChatMesh.cpp:273``);
* an ACK to a flooded message travels back inside a PATH return, not as a bare
  ACK packet (``BaseChatMesh.cpp:277``).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from meshelle.proto import crypto
from meshelle.proto.constants import (
    FIRMWARE_VER_LEVEL,
    LOGIN_RESPONSE_LEN,
    RESP_SERVER_LOGIN_OK,
    PayloadType,
    Permission,
    ReqType,
    RouteType,
    TxtType,
)
from meshelle.proto.identity import LocalIdentity
from meshelle.proto.packet import (
    Ack,
    AnonRequest,
    Datagram,
    LoginRequest,
    Packet,
    PathReturn,
    ServerRequest,
    TextMessage,
)


@dataclass(frozen=True, slots=True)
class LoginOk:
    """A decoded 13-byte login response.

    :attr:`permissions` is byte 7 and is the whole point of the project: an app
    shows a compose box when it is ``READ_WRITE`` or better, and a read-only
    view when it is ``GUEST``. meshcore-pi always sends ``GUEST``.
    """

    timestamp: int
    legacy_admin: int
    permissions: Permission
    firmware_ver_level: int
    random_blob: bytes

    @property
    def may_post(self) -> bool:
        """What the app decides from this reply."""
        return self.permissions in (Permission.READ_WRITE, Permission.ADMIN)


@dataclass(frozen=True, slots=True)
class PushedPost:
    """A ``TXT_TYPE_SIGNED_PLAIN`` message: one post being synced to us."""

    timestamp: int
    author_prefix: bytes
    text: str
    ack: bytes
    """What we must send back to acknowledge it."""


@dataclass(frozen=True, slots=True)
class CliReply:
    timestamp: int
    text: str


@dataclass(frozen=True, slots=True)
class AckFrame:
    checksum: bytes
    trailer: bytes

    @property
    def unsynced_count(self) -> int | None:
        """The byte a room appends to a keep-alive ACK, if it appended one."""
        return self.trailer[0] if self.trailer else None


@dataclass(frozen=True, slots=True)
class PathReceived:
    """A PATH return: the route to the room, plus whatever it bundled."""

    path: bytes
    path_hash_size: int
    extra_type: int
    response: LoginOk | bytes | None
    ack: bytes | None


class FakeClient:
    """One MeshCore client talking to one room."""

    def __init__(
        self,
        room_public_key: bytes,
        identity: LocalIdentity | None = None,
        *,
        path_to_room: bytes = b"",
    ) -> None:
        self.identity = identity or LocalIdentity.generate()
        self.room_public_key = room_public_key
        self.secret = self.identity.shared_secret(room_public_key)
        self.path_to_room = path_to_room
        """The path a flooded packet from us would have accumulated. Tests set
        this to model repeaters between the client and the room."""
        self.out_path = b""
        """The route to the room, once a PATH return has taught it to us."""
        self._awaiting = ""
        """What the last request we sent was.

        A RESPONSE payload carries no type tag -- only the reflected request
        timestamp -- so the *only* way to know whether 13 bytes are a login
        response or the start of a status struct is to remember what was asked.
        A real app disambiguates the same way, by the request it has outstanding.
        """

    # -- addressing ----------------------------------------------------------

    @property
    def public_key(self) -> bytes:
        return self.identity.public_key

    @property
    def node_hash(self) -> int:
        return self.identity.node_hash

    @property
    def room_hash(self) -> int:
        return self.room_public_key[0]

    @property
    def knows_path(self) -> bool:
        return bool(self.out_path)

    # -- building packets ----------------------------------------------------

    def login(
        self,
        *,
        timestamp: int,
        password: str = "",
        sync_since: int = 0,
        flood: bool = True,
    ) -> Packet:
        """An ``ANON_REQ`` login.

        Flooded by default because that is what a client with no path does, and
        it is the route that makes the room answer with a PATH return.
        """
        plaintext = LoginRequest(
            timestamp=timestamp,
            sync_since=sync_since,
            # A C string on the wire: firmware reads it with strcmp.
            password=password.encode("utf-8") + b"\x00",
        ).encode()
        request = AnonRequest(
            dest_hash=self.room_hash,
            sender_public_key=self.public_key,
            sealed=crypto.encrypt_then_mac(self.secret, plaintext),
        )
        self._awaiting = "login"
        return self._wrap(PayloadType.ANON_REQ, request.encode(), flood=flood)

    def post(self, text: str, *, timestamp: int, attempt: int = 0, flood: bool = False) -> Packet:
        """A ``TXT_TYPE_PLAIN`` message: a new post."""
        return self._text(TxtType.PLAIN, text.encode("utf-8"), timestamp, attempt, flood)

    def cli(self, command: str, *, timestamp: int, attempt: int = 0, flood: bool = False) -> Packet:
        """A ``TXT_TYPE_CLI_DATA`` message: an admin console line."""
        return self._text(TxtType.CLI_DATA, command.encode("utf-8"), timestamp, attempt, flood)

    def keep_alive(self, *, timestamp: int, force_since: int | None = None) -> Packet:
        """A keep-alive. Always direct -- the room refuses to answer a flooded one."""
        data = b"" if force_since is None else struct.pack("<I", force_since)
        return self.request(ReqType.KEEP_ALIVE, data=data, timestamp=timestamp, flood=False)

    def request(
        self,
        req_type: ReqType | int,
        *,
        timestamp: int,
        data: bytes = b"",
        flood: bool = False,
    ) -> Packet:
        plaintext = ServerRequest(timestamp=timestamp, req_type=int(req_type), data=data).encode()
        self._awaiting = "request"
        return self._datagram(PayloadType.REQ, plaintext, flood=flood)

    def path_return(self, *, extra_type: int = 0xFF, extra: bytes = b"") -> Packet:
        """Tell the room the route back to us.

        The path we send is the one a flooded packet from us accumulated, which
        is what the room stores and replays to reach us directly. No reversal
        happens anywhere in MeshCore: the same byte order works in both
        directions (``Packet::writePath``).
        """
        plaintext = PathReturn(path=self.path_to_room, extra_type=extra_type, extra=extra).encode()
        return self._datagram(PayloadType.PATH, plaintext, flood=False)

    def ack(self, checksum: bytes) -> Packet:
        """A bare ACK packet, as sent for a directly-routed message."""
        return self._wrap(PayloadType.ACK, Ack(checksum=checksum).encode(), flood=False)

    def acknowledge(self, push: PushedPost, *, flood: bool = False) -> Packet:
        """Acknowledge a pushed post, by the route firmware would use.

        A flooded push is acknowledged inside a PATH return so the room learns
        the way back at the same time; a direct one gets a bare ACK.
        """
        if flood:
            return self.path_return(extra_type=int(PayloadType.ACK), extra=push.ack)
        return self.ack(push.ack)

    # -- opening what comes back ---------------------------------------------

    def receive(
        self, packet: Packet
    ) -> LoginOk | PushedPost | CliReply | AckFrame | PathReceived | None:
        """Interpret a packet the room sent. ``None`` if it is not for us."""
        if packet.payload_type is PayloadType.ACK:
            frame = Ack.decode(packet.payload)
            return AckFrame(checksum=frame.checksum, trailer=frame.trailer)

        datagram = Datagram.decode(packet.payload)
        if datagram.dest_hash != self.node_hash or datagram.src_hash != self.room_hash:
            return None
        try:
            plaintext = datagram.open(self.secret)
        except crypto.DecryptionError:
            return None

        if packet.payload_type is PayloadType.RESPONSE:
            return self._read_response(plaintext)
        if packet.payload_type is PayloadType.TXT_MSG:
            return self._read_text(plaintext)
        if packet.payload_type is PayloadType.PATH:
            return self._read_path(plaintext)
        return None

    def _read_response(self, plaintext: bytes) -> LoginOk | None:
        if self._awaiting != "login":
            return None
        if len(plaintext) < LOGIN_RESPONSE_LEN or plaintext[4] != RESP_SERVER_LOGIN_OK:
            return None
        return LoginOk(
            timestamp=struct.unpack_from("<I", plaintext, 0)[0],
            legacy_admin=plaintext[6],
            permissions=Permission(plaintext[7]),
            firmware_ver_level=plaintext[12],
            random_blob=plaintext[8:12],
        )

    def _read_text(self, plaintext: bytes) -> PushedPost | CliReply | None:
        message = TextMessage.decode(plaintext)
        if message.txt_type is TxtType.SIGNED_PLAIN:
            # The ACK covers exactly the bytes the room built, which is the
            # 9-byte header plus the text up to its terminator -- not the
            # cipher-padded plaintext this arrived in.
            exact = message.encode()
            return PushedPost(
                timestamp=message.timestamp,
                author_prefix=message.author_prefix,
                text=message.body.decode("utf-8", errors="replace"),
                ack=crypto.ack_hash(exact, self.public_key),
            )
        if message.txt_type is TxtType.CLI_DATA:
            return CliReply(
                timestamp=message.timestamp,
                text=message.text.decode("utf-8", errors="replace"),
            )
        return None

    def _read_path(self, plaintext: bytes) -> PathReceived:
        returned = PathReturn.decode(plaintext)
        self.out_path = returned.path

        response: LoginOk | bytes | None = None
        ack: bytes | None = None
        extra_type = returned.extra_type & 0x0F
        if extra_type == PayloadType.RESPONSE and returned.extra:
            response = self._read_response(returned.extra) or returned.extra
        elif extra_type == PayloadType.ACK and len(returned.extra) >= Ack.LEN:
            ack = returned.extra[: Ack.LEN]

        return PathReceived(
            path=returned.path,
            path_hash_size=returned.path_hash_size,
            extra_type=extra_type,
            response=response,
            ack=ack,
        )

    # -- expectations tests assert against ------------------------------------

    def expected_post_ack(self, text: str, *, timestamp: int, attempt: int = 0) -> bytes:
        """The ACK the room owes us for a post, computed the way firmware does."""
        message = TextMessage(
            timestamp=timestamp,
            txt_type=TxtType.PLAIN,
            attempt=attempt,
            text=text.encode("utf-8"),
        )
        return message.ack_hash(self.public_key)

    def expected_keep_alive_ack(self, *, timestamp: int, force_since: int = 0) -> bytes:
        """The ACK for a keep-alive: hashed over exactly nine bytes.

        Nine whether or not we sent the last four (MyMesh.cpp:565): cipher
        padding means they are always present in the room's plaintext, as zeros.
        """
        body = struct.pack("<IBI", timestamp, int(ReqType.KEEP_ALIVE), force_since)
        return crypto.ack_hash(body, self.public_key)

    # -- packet plumbing -----------------------------------------------------

    def _text(
        self, txt_type: TxtType, body: bytes, timestamp: int, attempt: int, flood: bool
    ) -> Packet:
        plaintext = TextMessage(
            timestamp=timestamp, txt_type=txt_type, attempt=attempt, text=body
        ).encode()
        return self._datagram(PayloadType.TXT_MSG, plaintext, flood=flood)

    def _datagram(self, payload_type: PayloadType, plaintext: bytes, *, flood: bool) -> Packet:
        datagram = Datagram.seal(self.room_hash, self.node_hash, self.secret, plaintext)
        return self._wrap(payload_type, datagram.encode(), flood=flood)

    def _wrap(self, payload_type: PayloadType, payload: bytes, *, flood: bool) -> Packet:
        if flood:
            # A packet we flood arrives at the room carrying the hashes of every
            # repeater that forwarded it. Tests set path_to_room to model that.
            return Packet(
                route_type=RouteType.FLOOD,
                payload_type=payload_type,
                payload=payload,
                path=self.path_to_room,
            )
        return Packet(
            route_type=RouteType.DIRECT,
            payload_type=payload_type,
            payload=payload,
            path=self.out_path,
        )


def assert_login_grants(reply: object, permission: Permission) -> LoginOk:
    """Assert a login reply carries a permission byte, with a useful message.

    Byte 7 is invisible in logs and in packet dumps that only show lengths, so a
    plain equality failure here would say almost nothing about what went wrong.
    """
    if not isinstance(reply, LoginOk):
        raise AssertionError(f"expected a login response, got {reply!r}")
    if reply.permissions is not permission:
        raise AssertionError(
            f"login granted {reply.permissions.name} (byte 7 = {int(reply.permissions)}), "
            f"expected {permission.name} ({int(permission)}). "
            f"A zero here is the meshcore-pi bug: the room appears read-only in every app."
        )
    if reply.firmware_ver_level != FIRMWARE_VER_LEVEL:
        raise AssertionError(f"unexpected firmware level {reply.firmware_ver_level}")
    return reply
