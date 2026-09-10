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

"""Packet frame and payload codec tests.

The path-length encoding and the PATH payload's *inner* path length are the two
places this format invites off-by-one bugs, so both get explicit coverage across
all three legal hash sizes.
"""

from __future__ import annotations

import secrets

import pytest

from meshelle.proto.constants import (
    MAX_PACKET_PAYLOAD,
    MAX_PATH_SIZE,
    PayloadType,
    PayloadVersion,
    RouteType,
    TxtType,
)
from meshelle.proto.crypto import DecryptionError, ack_hash, encrypt_then_mac
from meshelle.proto.packet import (
    Ack,
    AnonRequest,
    Datagram,
    LoginRequest,
    Packet,
    PacketError,
    PathReturn,
    ServerRequest,
    TextMessage,
)


class TestPacketFrame:
    def test_header_packs_version_type_and_route(self) -> None:
        packet = Packet(
            route_type=RouteType.DIRECT,
            payload_type=PayloadType.TXT_MSG,
            payload=b"x",
        )
        # version 0 << 6 | type 2 << 2 | route 2  ==  0b00_0010_10
        assert packet.header == 0b00001010

    @pytest.mark.parametrize("route_type", list(RouteType))
    @pytest.mark.parametrize("hash_size", [1, 2, 3])
    def test_round_trips(self, route_type: RouteType, hash_size: int) -> None:
        path = secrets.token_bytes(4 * hash_size)
        original = Packet(
            route_type=route_type,
            payload_type=PayloadType.REQ,
            payload=secrets.token_bytes(40),
            path=path,
            path_hash_size=hash_size,
            transport_codes=(0x1234, 0xABCD),
        )

        decoded = Packet.decode(original.encode())

        assert decoded.route_type is route_type
        assert decoded.path == path
        assert decoded.path_hash_size == hash_size
        assert decoded.hop_count == 4
        assert decoded.payload == original.payload
        if route_type.has_transport_codes:
            assert decoded.transport_codes == (0x1234, 0xABCD)
        else:
            assert decoded.transport_codes == (0, 0), "codes absent unless the route has them"

    @pytest.mark.parametrize(
        ("hash_size", "hops", "expected"),
        [(1, 0, 0x00), (1, 5, 0x05), (2, 5, 0x45), (3, 10, 0x8A)],
    )
    def test_path_length_byte_matches_documented_examples(
        self, hash_size: int, hops: int, expected: int
    ) -> None:
        """The worked examples from docs/packet_format.md."""
        packet = Packet(
            route_type=RouteType.FLOOD,
            payload_type=PayloadType.ADVERT,
            payload=b"p",
            path=bytes(hops * hash_size),
            path_hash_size=hash_size,
        )
        assert packet.path_length_byte == expected

    def test_transport_codes_are_omitted_for_plain_routes(self) -> None:
        plain = Packet(
            route_type=RouteType.FLOOD,
            payload_type=PayloadType.ADVERT,
            payload=b"p",
            transport_codes=(0xFFFF, 0xFFFF),
        )
        scoped = Packet(
            route_type=RouteType.TRANSPORT_FLOOD,
            payload_type=PayloadType.ADVERT,
            payload=b"p",
            transport_codes=(0xFFFF, 0xFFFF),
        )
        assert len(scoped.encode()) == len(plain.encode()) + 4

    def test_packet_hash_ignores_the_path(self) -> None:
        """Same packet by two routes must dedupe to one."""
        common = {
            "route_type": RouteType.FLOOD,
            "payload_type": PayloadType.TXT_MSG,
            "payload": b"same payload",
        }
        near = Packet(**common, path=b"\x01")  # type: ignore[arg-type]
        far = Packet(**common, path=b"\x01\x02\x03")  # type: ignore[arg-type]

        assert near.packet_hash == far.packet_hash

    def test_packet_hash_is_route_agnostic_but_payload_sensitive(self) -> None:
        flood = Packet(route_type=RouteType.FLOOD, payload_type=PayloadType.ACK, payload=b"abcd")
        direct = Packet(route_type=RouteType.DIRECT, payload_type=PayloadType.ACK, payload=b"abcd")
        other = Packet(route_type=RouteType.FLOOD, payload_type=PayloadType.ACK, payload=b"abce")

        assert flood.packet_hash == direct.packet_hash
        assert flood.packet_hash != other.packet_hash

    @pytest.mark.parametrize(
        ("raw", "match"),
        [
            (b"", "too short"),
            (b"\x01", "too short"),
            # TRANSPORT_FLOOD (route 0) but no room for 4 code bytes
            (b"\x00\x01\x02", "truncated transport codes"),
            # FLOOD, path says 5 one-byte hops but only 2 follow
            (b"\x01\x05ab", "truncated path"),
            # FLOOD, 0 hops, no payload at all
            (b"\x01\x00", "no payload"),
            # path hash size 4 (bits 6-7 = 0b11) is reserved
            (b"\x01\xc1aaaapayload", "reserved"),
        ],
    )
    def test_rejects_malformed_packets(self, raw: bytes, match: str) -> None:
        with pytest.raises(PacketError, match=match):
            Packet.decode(raw)

    def test_rejects_reserved_payload_type(self) -> None:
        # type 0x0C is reserved: 0b00_1100_01
        with pytest.raises(PacketError, match="reserved payload type"):
            Packet.decode(bytes([0b00110001, 0x00]) + b"payload")

    def test_rejects_oversize_payload_on_construction(self) -> None:
        with pytest.raises(PacketError, match="payload exceeds"):
            Packet(
                route_type=RouteType.FLOOD,
                payload_type=PayloadType.TXT_MSG,
                payload=bytes(MAX_PACKET_PAYLOAD + 1),
            )

    def test_rejects_oversize_path(self) -> None:
        with pytest.raises(PacketError, match="path exceeds"):
            Packet(
                route_type=RouteType.DIRECT,
                payload_type=PayloadType.TXT_MSG,
                payload=b"x",
                path=bytes(MAX_PATH_SIZE + 1),
            )

    def test_rejects_path_not_aligned_to_hash_size(self) -> None:
        with pytest.raises(PacketError, match="not a multiple"):
            Packet(
                route_type=RouteType.DIRECT,
                payload_type=PayloadType.TXT_MSG,
                payload=b"x",
                path=b"\x01\x02\x03",
                path_hash_size=2,
            )

    def test_rejects_empty_payload(self) -> None:
        with pytest.raises(PacketError, match="must not be empty"):
            Packet(route_type=RouteType.FLOOD, payload_type=PayloadType.ACK, payload=b"")

    def test_preserves_payload_version(self) -> None:
        raw = Packet(
            route_type=RouteType.FLOOD,
            payload_type=PayloadType.TXT_MSG,
            payload=b"x",
            payload_version=PayloadVersion.V2,
        ).encode()
        assert Packet.decode(raw).payload_version is PayloadVersion.V2


class TestDatagram:
    def test_seals_and_opens(self) -> None:
        secret = secrets.token_bytes(32)
        datagram = Datagram.seal(0xAB, 0xCD, secret, b"\x01\x02\x03\x04hello")

        assert datagram.dest_hash == 0xAB
        assert datagram.src_hash == 0xCD
        assert datagram.open(secret)[:9] == b"\x01\x02\x03\x04hello"

    def test_round_trips_through_the_wire_form(self) -> None:
        secret = secrets.token_bytes(32)
        original = Datagram.seal(0x11, 0x22, secret, b"payload here")

        decoded = Datagram.decode(original.encode())

        assert decoded == original
        assert decoded.open(secret)[:12] == b"payload here"

    def test_wrong_secret_is_a_decryption_error_not_a_packet_error(self) -> None:
        """With 1-byte hashes, several keys can be candidates; this is routine."""
        datagram = Datagram.seal(0x11, 0x22, secrets.token_bytes(32), b"not for you")
        with pytest.raises(DecryptionError):
            datagram.open(secrets.token_bytes(32))

    @pytest.mark.parametrize("length", [0, 1, 2, 3, 4])
    def test_rejects_payload_too_short_to_hold_a_mac(self, length: int) -> None:
        with pytest.raises(PacketError, match="too short"):
            Datagram.decode(bytes(length))


class TestAnonRequest:
    def test_round_trips_and_carries_the_sender_key(self) -> None:
        sender_key = secrets.token_bytes(32)
        secret = secrets.token_bytes(32)
        original = AnonRequest(
            dest_hash=0x42,
            sender_public_key=sender_key,
            sealed=encrypt_then_mac(secret, LoginRequest(1000, 900, b"hunter2").encode()),
        )

        decoded = AnonRequest.decode(original.encode())

        assert decoded.dest_hash == 0x42
        assert decoded.sender_public_key == sender_key
        login = LoginRequest.decode(decoded.open(secret))
        assert (login.timestamp, login.sync_since, login.password) == (1000, 900, b"hunter2")

    def test_rejects_wrong_sender_key_length(self) -> None:
        with pytest.raises(PacketError, match="32 bytes"):
            AnonRequest(dest_hash=1, sender_public_key=bytes(31), sealed=bytes(20))

    def test_rejects_short_payload(self) -> None:
        with pytest.raises(PacketError, match="too short"):
            AnonRequest.decode(bytes(34))


class TestTextMessage:
    @pytest.mark.parametrize("txt_type", list(TxtType))
    @pytest.mark.parametrize("attempt", [0, 1, 2, 3])
    def test_round_trips(self, txt_type: TxtType, attempt: int) -> None:
        original = TextMessage(
            timestamp=0xDEADBEEF, txt_type=txt_type, attempt=attempt, text=b"hi there"
        )
        decoded = TextMessage.decode(original.encode())

        assert decoded == original

    def test_trims_cipher_padding_at_the_nul(self) -> None:
        """Decrypted plaintext is block-padded; the text ends at the first NUL."""
        padded = TextMessage(
            timestamp=1, txt_type=TxtType.PLAIN, attempt=0, text=b"short"
        ).encode() + bytes(6)

        assert TextMessage.decode(padded).text == b"short"

    def test_splits_the_author_prefix_of_a_signed_message(self) -> None:
        author = b"\xde\xad\xbe\xef"
        message = TextMessage(
            timestamp=5,
            txt_type=TxtType.SIGNED_PLAIN,
            attempt=0,
            text=author + b"the post body",
        )

        assert message.author_prefix == author
        assert message.body == b"the post body"

    def test_plain_message_has_no_author_prefix(self) -> None:
        message = TextMessage(timestamp=5, txt_type=TxtType.PLAIN, attempt=0, text=b"body")

        assert message.author_prefix == b""
        assert message.body == b"body"

    def test_ack_hash_covers_timestamp_flags_and_trimmed_text(self) -> None:
        """Firmware hashes the strlen-trimmed form, not the padded plaintext."""
        recipient = secrets.token_bytes(32)
        message = TextMessage(timestamp=7, txt_type=TxtType.PLAIN, attempt=0, text=b"post")

        assert message.ack_hash(recipient) == ack_hash(message.encode(), recipient)

    def test_attempt_number_changes_the_ack(self) -> None:
        """Retries must hash differently so their ACKs are distinguishable."""
        recipient = secrets.token_bytes(32)
        first = TextMessage(timestamp=7, txt_type=TxtType.PLAIN, attempt=0, text=b"post")
        retry = TextMessage(timestamp=7, txt_type=TxtType.PLAIN, attempt=1, text=b"post")

        assert first.ack_hash(recipient) != retry.ack_hash(recipient)

    def test_rejects_unsupported_text_type(self) -> None:
        # txt_type 0x3F << 2 is not a known TxtType
        with pytest.raises(PacketError, match="unsupported text type"):
            TextMessage.decode(b"\x00\x00\x00\x00\xfc" + b"body")

    def test_rejects_short_plaintext(self) -> None:
        with pytest.raises(PacketError, match="too short"):
            TextMessage.decode(b"\x00\x00\x00")


class TestLoginRequest:
    def test_round_trips(self) -> None:
        original = LoginRequest(timestamp=1700000000, sync_since=1699990000, password=b"pw")
        assert LoginRequest.decode(original.encode()) == original

    def test_blank_password_decodes_as_empty(self) -> None:
        """A blank password means 'check the ACL by pubkey only'."""
        decoded = LoginRequest.decode(LoginRequest(1, 2, b"").encode())
        assert decoded.password == b""

    def test_trims_padding_from_the_password(self) -> None:
        padded = LoginRequest(1, 2, b"secret").encode() + bytes(8)
        assert LoginRequest.decode(padded).password == b"secret"

    def test_rejects_short_plaintext(self) -> None:
        with pytest.raises(PacketError, match="too short"):
            LoginRequest.decode(bytes(7))


class TestServerRequest:
    def test_round_trips(self) -> None:
        original = ServerRequest(timestamp=42, req_type=0x02, data=b"\x01\x02\x03\x04")
        assert ServerRequest.decode(original.encode()) == original

    def test_keeps_trailing_zeros_in_data(self) -> None:
        """Keep-alive's optional 'since' may legitimately be four zero bytes."""
        decoded = ServerRequest.decode(ServerRequest(1, 0x02, bytes(4)).encode())
        assert decoded.data == bytes(4)

    def test_rejects_short_plaintext(self) -> None:
        with pytest.raises(PacketError, match="too short"):
            ServerRequest.decode(bytes(4))


class TestPathReturn:
    @pytest.mark.parametrize("hash_size", [1, 2, 3])
    def test_round_trips(self, hash_size: int) -> None:
        original = PathReturn(
            path=secrets.token_bytes(3 * hash_size),
            path_hash_size=hash_size,
            extra_type=0x01,
            extra=b"response bytes",
        )
        decoded = PathReturn.decode(original.encode())

        assert decoded == original
        assert decoded.hop_count == 3

    def test_inner_path_length_uses_the_packed_encoding(self) -> None:
        """Not a raw byte count: 3 hops of 2-byte hashes encodes as 0x43."""
        encoded = PathReturn(path=bytes(6), path_hash_size=2).encode()
        assert encoded[0] == 0x43

    def test_zero_hop_path_still_carries_extra(self) -> None:
        decoded = PathReturn.decode(PathReturn(path=b"", extra_type=0x01, extra=b"x").encode())
        assert decoded.path == b""
        assert decoded.extra == b"x"

    def test_rejects_reserved_hash_size(self) -> None:
        with pytest.raises(PacketError, match="reserved"):
            PathReturn.decode(b"\xc1\x00")

    def test_rejects_truncated_path(self) -> None:
        with pytest.raises(PacketError, match="truncated"):
            PathReturn.decode(b"\x05ab")

    def test_rejects_empty(self) -> None:
        with pytest.raises(PacketError, match="empty"):
            PathReturn.decode(b"")


class TestAck:
    def test_round_trips(self) -> None:
        original = Ack(checksum=b"\x01\x02\x03\x04")
        assert Ack.decode(original.encode()).checksum == original.checksum

    def test_keeps_the_trailing_unsynced_count(self) -> None:
        """A room appends its unsynced count to keep-alive ACKs."""
        decoded = Ack.decode(b"\x01\x02\x03\x04\x07")

        assert decoded.checksum == b"\x01\x02\x03\x04"
        assert decoded.trailer == b"\x07"

    def test_rejects_short_payload(self) -> None:
        with pytest.raises(PacketError, match="too short"):
            Ack.decode(b"\x01\x02\x03")

    def test_rejects_wrong_checksum_length(self) -> None:
        with pytest.raises(PacketError, match="must be 4 bytes"):
            Ack(checksum=b"\x01\x02")
