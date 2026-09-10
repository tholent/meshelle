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

"""Advert encoding, signing, and appdata field packing."""

from __future__ import annotations

import struct

import pytest

from meshelle.proto.advert import LATLON_SCALE, Advert, AdvertData
from meshelle.proto.constants import (
    ADV_LATLON_MASK,
    ADV_NAME_MASK,
    MAX_ADVERT_DATA_SIZE,
    SIGNATURE_SIZE,
    AdvertType,
)
from meshelle.proto.identity import LocalIdentity
from meshelle.proto.packet import PacketError


class TestAdvertData:
    def test_round_trips_a_plain_room(self) -> None:
        original = AdvertData(node_type=AdvertType.ROOM, name="Lobby")
        assert AdvertData.decode(original.encode()) == original

    def test_round_trips_with_a_location(self) -> None:
        original = AdvertData(
            node_type=AdvertType.ROOM, name="Lobby", latitude=51.5074, longitude=-0.1278
        )
        decoded = AdvertData.decode(original.encode())

        assert decoded.node_type is AdvertType.ROOM
        assert decoded.name == "Lobby"
        assert decoded.latitude == pytest.approx(51.5074, abs=1e-6)
        assert decoded.longitude == pytest.approx(-0.1278, abs=1e-6)

    def test_flags_byte_encodes_type_in_the_low_nibble(self) -> None:
        encoded = AdvertData(node_type=AdvertType.ROOM).encode()
        assert encoded[0] & 0x0F == AdvertType.ROOM

    def test_sets_the_name_and_latlon_flags(self) -> None:
        encoded = AdvertData(
            node_type=AdvertType.ROOM, name="x", latitude=1.0, longitude=2.0
        ).encode()
        assert encoded[0] & ADV_NAME_MASK
        assert encoded[0] & ADV_LATLON_MASK

    def test_omits_flags_for_absent_fields(self) -> None:
        encoded = AdvertData(node_type=AdvertType.ROOM).encode()

        assert not encoded[0] & ADV_NAME_MASK
        assert not encoded[0] & ADV_LATLON_MASK
        assert len(encoded) == 1

    def test_latlon_are_scaled_integers(self) -> None:
        encoded = AdvertData(
            node_type=AdvertType.ROOM, latitude=51.5074, longitude=-0.1278
        ).encode()
        raw_lat, raw_lon = struct.unpack_from("<ii", encoded, 1)

        assert raw_lat == int(51.5074 * LATLON_SCALE)
        assert raw_lon == int(-0.1278 * LATLON_SCALE)

    def test_negative_coordinates_survive(self) -> None:
        """Signed int32: the southern and western hemispheres must work."""
        original = AdvertData(node_type=AdvertType.ROOM, latitude=-33.8688, longitude=-70.6693)
        decoded = AdvertData.decode(original.encode())

        assert decoded.latitude == pytest.approx(-33.8688, abs=1e-6)
        assert decoded.longitude == pytest.approx(-70.6693, abs=1e-6)

    def test_features_are_only_emitted_when_non_zero(self) -> None:
        """Firmware skips zero features, so a zero round-trips as absent."""
        with_feat = AdvertData(node_type=AdvertType.ROOM, feat1=0x1234)
        decoded = AdvertData.decode(with_feat.encode())
        assert decoded.feat1 == 0x1234

        without = AdvertData(node_type=AdvertType.ROOM, feat1=0)
        assert len(without.encode()) == 1

    def test_appdata_never_exceeds_the_limit(self) -> None:
        long_name = "A room with a very long name indeed, far past the limit"
        encoded = AdvertData(node_type=AdvertType.ROOM, name=long_name).encode()

        assert len(encoded) <= MAX_ADVERT_DATA_SIZE

    def test_a_location_leaves_less_room_for_the_name(self) -> None:
        """flags(1) + latlon(8) leaves 23 name bytes; without it, 31."""
        name = "N" * 40
        with_loc = AdvertData(
            node_type=AdvertType.ROOM, name=name, latitude=1.0, longitude=2.0
        ).encode()
        without_loc = AdvertData(node_type=AdvertType.ROOM, name=name).encode()

        assert len(with_loc) == MAX_ADVERT_DATA_SIZE
        assert len(without_loc) == MAX_ADVERT_DATA_SIZE
        assert AdvertData.decode(with_loc).name == "N" * 23
        assert AdvertData.decode(without_loc).name == "N" * 31

    def test_truncates_a_long_name_on_a_character_boundary(self) -> None:
        decoded = AdvertData.decode(AdvertData(node_type=AdvertType.ROOM, name="é" * 40).encode())

        assert decoded.name == "é" * 15, "31 bytes holds 15 two-byte characters"
        assert "�" not in decoded.name

    def test_unknown_node_type_decodes_as_none_rather_than_failing(self) -> None:
        """Types 5..15 are reserved; a newer node's advert must still parse."""
        assert AdvertData.decode(bytes([0x07])).node_type is AdvertType.NONE

    def test_replaces_invalid_utf8_in_a_received_name(self) -> None:
        """Names arrive from other people's nodes and must not crash us."""
        appdata = bytes([AdvertType.CHAT | ADV_NAME_MASK]) + b"bad\xff\xfename"
        assert "�" in AdvertData.decode(appdata).name

    @pytest.mark.parametrize(
        ("appdata", "match"),
        [
            (b"", "empty"),
            (bytes([AdvertType.ROOM | ADV_LATLON_MASK]) + b"\x01\x02", "truncated"),
            (bytes([AdvertType.ROOM | 0x20]) + b"\x01", "feat1"),
            (bytes([AdvertType.ROOM | 0x40]) + b"\x01", "feat2"),
        ],
    )
    def test_rejects_truncated_appdata(self, appdata: bytes, match: str) -> None:
        with pytest.raises(PacketError, match=match):
            AdvertData.decode(appdata)


class TestAdvert:
    def test_create_produces_a_valid_signature(self) -> None:
        identity = LocalIdentity.generate()
        advert = Advert.create(
            identity, 1700000000, AdvertData(node_type=AdvertType.ROOM, name="Lobby")
        )

        assert advert.is_valid
        assert advert.public_key == identity.public_key
        assert advert.data.name == "Lobby"

    def test_round_trips_through_the_wire_form(self) -> None:
        identity = LocalIdentity.generate()
        original = Advert.create(
            identity,
            1700000000,
            AdvertData(node_type=AdvertType.ROOM, name="Lobby", latitude=1.5, longitude=2.5),
        )

        decoded = Advert.decode(original.encode())

        assert decoded == original
        assert decoded.is_valid

    def test_signature_covers_key_timestamp_and_appdata_only(self) -> None:
        """Not the header or path, so repeaters can re-flood it unchanged."""
        identity = LocalIdentity.generate()
        advert = Advert.create(identity, 42, AdvertData(node_type=AdvertType.ROOM, name="R"))

        expected = identity.public_key + struct.pack("<I", 42) + advert.appdata
        assert advert.signed_message == expected

    def test_tampering_with_the_name_invalidates_it(self) -> None:
        identity = LocalIdentity.generate()
        advert = Advert.create(identity, 42, AdvertData(node_type=AdvertType.ROOM, name="Lobby"))

        forged = Advert(
            public_key=advert.public_key,
            timestamp=advert.timestamp,
            signature=advert.signature,
            appdata=AdvertData(node_type=AdvertType.ROOM, name="Evil").encode(),
        )
        assert not forged.is_valid

    def test_tampering_with_the_timestamp_invalidates_it(self) -> None:
        identity = LocalIdentity.generate()
        advert = Advert.create(identity, 42, AdvertData(node_type=AdvertType.ROOM, name="Lobby"))

        forged = Advert(
            public_key=advert.public_key,
            timestamp=43,
            signature=advert.signature,
            appdata=advert.appdata,
        )
        assert not forged.is_valid

    def test_another_key_cannot_claim_the_advert(self) -> None:
        signer, impostor = LocalIdentity.generate(), LocalIdentity.generate()
        advert = Advert.create(signer, 42, AdvertData(node_type=AdvertType.ROOM))

        forged = Advert(
            public_key=impostor.public_key,
            timestamp=advert.timestamp,
            signature=advert.signature,
            appdata=advert.appdata,
        )
        assert not forged.is_valid

    def test_both_signing_paths_produce_the_same_advert(self) -> None:
        """A migrated (expanded-only) room key adverts identically."""
        seed = bytes(range(32))
        seed_backed = LocalIdentity.from_seed(seed)
        expanded_only = LocalIdentity.from_expanded(seed_backed.private_key)
        data = AdvertData(node_type=AdvertType.ROOM, name="Lobby")

        assert Advert.create(seed_backed, 99, data).encode() == (
            Advert.create(expanded_only, 99, data).encode()
        )

    def test_rejects_a_truncated_payload(self) -> None:
        with pytest.raises(PacketError, match="too short"):
            Advert.decode(bytes(Advert.HEADER_LEN - 1))

    def test_decodes_an_advert_with_no_appdata(self) -> None:
        """appdata is optional on the wire, even if a room always sends some."""
        payload = bytes(32) + struct.pack("<I", 1) + bytes(SIGNATURE_SIZE)
        advert = Advert.decode(payload)

        assert advert.appdata == b""
        assert not advert.is_valid, "an all-zero signature must not verify"

    @pytest.mark.parametrize(
        ("field", "value", "match"),
        [
            ("public_key", bytes(31), "public key must be"),
            ("signature", bytes(63), "signature must be"),
            ("appdata", bytes(MAX_ADVERT_DATA_SIZE + 1), "appdata exceeds"),
        ],
    )
    def test_rejects_malformed_construction(self, field: str, value: bytes, match: str) -> None:
        kwargs: dict[str, object] = {
            "public_key": bytes(32),
            "timestamp": 1,
            "signature": bytes(SIGNATURE_SIZE),
            "appdata": b"",
        }
        kwargs[field] = value
        with pytest.raises(PacketError, match=match):
            Advert(**kwargs)  # type: ignore[arg-type]
