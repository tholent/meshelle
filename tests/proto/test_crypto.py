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

"""Validate the MeshCore crypto primitives.

The load-bearing claim is that OpenSSL's X25519 computes the same thing as the
firmware's ``ed25519_key_exchange``. ``_firmware_key_exchange`` below is an
independent transcription of lib/ed25519/key_exchange.c used purely as a test
oracle: two implementations of the same spec agreeing is real evidence, whereas
asserting our code against itself would be none.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

import pytest

from meshelle.proto.constants import CIPHER_BLOCK_SIZE, CIPHER_MAC_SIZE
from meshelle.proto.crypto import (
    P25519,
    DecryptionError,
    ack_hash,
    encrypt_then_mac,
    mac_then_decrypt,
    packet_hash,
    shared_secret,
)
from meshelle.proto.ed25519_expanded import derive_public_key, expanded_from_seed

FIRMWARE_TEST_PRV = bytes.fromhex(
    "7065e18fd9fabb70c1ed90dca19907de698c88b709ea146eafd93d9b830c7b60"
    "c4681193c79bbc39945ba8064104bb618f8fd7a84a0af6f57033d6e8ddcd6471"
)
FIRMWARE_TEST_PUB = bytes.fromhex(
    "1ec77175b0918ed206f9ae04ec136d6d5d4315bb26305427f645b492e9350c10"
)


def _firmware_key_exchange(public_key: bytes, private_key: bytes) -> bytes:
    """Transcription of ``ed25519_key_exchange`` (lib/ed25519/key_exchange.c).

    Test oracle only. Deliberately follows the C line for line, including the
    Montgomery ladder, rather than reusing anything from the module under test.
    """
    e = bytearray(private_key[:32])
    e[0] &= 248
    e[31] &= 63
    e[31] |= 64
    scalar = int.from_bytes(e, "little")

    # unpack the public key and convert edwards to montgomery
    y = int.from_bytes(public_key, "little") & ~(1 << 255)
    tmp0 = (y + 1) % P25519
    tmp1 = pow((1 - y) % P25519, P25519 - 2, P25519)
    x1 = tmp0 * tmp1 % P25519

    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for pos in range(254, -1, -1):
        b = (scalar >> pos) & 1
        swap ^= b
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = b

        tmp0 = (x3 - z3) % P25519
        tmp1 = (x2 - z2) % P25519
        x2 = (x2 + z2) % P25519
        z2 = (x3 + z3) % P25519
        z3 = tmp0 * x2 % P25519
        z2 = z2 * tmp1 % P25519
        tmp0 = tmp1 * tmp1 % P25519
        tmp1 = x2 * x2 % P25519
        x3 = (z3 + z2) % P25519
        z2 = (z3 - z2) % P25519
        x2 = tmp1 * tmp0 % P25519
        tmp1 = (tmp1 - tmp0) % P25519
        z2 = z2 * z2 % P25519
        z3 = tmp1 * 121666 % P25519
        x3 = x3 * x3 % P25519
        tmp0 = (tmp0 + z3) % P25519
        z3 = x1 * z2 % P25519
        z2 = tmp1 * tmp0 % P25519

    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2

    x2 = x2 * pow(z2, P25519 - 2, P25519) % P25519
    return x2.to_bytes(32, "little")


class TestSharedSecret:
    def test_matches_the_firmware_ladder_for_the_firmware_test_vector(self) -> None:
        ours = shared_secret(FIRMWARE_TEST_PRV, FIRMWARE_TEST_PUB)
        assert ours == _firmware_key_exchange(FIRMWARE_TEST_PUB, FIRMWARE_TEST_PRV)

    @pytest.mark.parametrize("iteration", range(10))
    def test_matches_the_firmware_ladder_for_random_keys(self, iteration: int) -> None:
        prv = expanded_from_seed(secrets.token_bytes(32))
        peer_pub = derive_public_key(expanded_from_seed(secrets.token_bytes(32)))
        assert shared_secret(prv, peer_pub) == _firmware_key_exchange(peer_pub, prv)

    def test_is_symmetric(self) -> None:
        """The property the firmware itself checks in validatePrivateKey."""
        a_prv = expanded_from_seed(secrets.token_bytes(32))
        b_prv = expanded_from_seed(secrets.token_bytes(32))
        a_pub, b_pub = derive_public_key(a_prv), derive_public_key(b_prv)

        assert shared_secret(a_prv, b_pub) == shared_secret(b_prv, a_pub)

    def test_accepts_a_bare_32_byte_scalar(self) -> None:
        """Only the first 32 bytes of the expanded key take part."""
        assert shared_secret(FIRMWARE_TEST_PRV[:32], FIRMWARE_TEST_PUB) == shared_secret(
            FIRMWARE_TEST_PRV, FIRMWARE_TEST_PUB
        )

    def test_rejects_degenerate_peer_key(self) -> None:
        """y == 1 maps to u == 0, which has no usable shared secret."""
        degenerate = (1).to_bytes(32, "little")
        with pytest.raises(DecryptionError, match="degenerate"):
            shared_secret(FIRMWARE_TEST_PRV, degenerate)

    def test_rejects_bad_lengths(self) -> None:
        with pytest.raises(ValueError, match="32 or 64 bytes"):
            shared_secret(b"\x00" * 33, FIRMWARE_TEST_PUB)
        with pytest.raises(ValueError, match="public key must be 32 bytes"):
            shared_secret(FIRMWARE_TEST_PRV, b"\x00" * 31)


class TestEncryptThenMac:
    @pytest.mark.parametrize("length", [1, 15, 16, 17, 31, 32, 160])
    def test_round_trips(self, length: int) -> None:
        secret = secrets.token_bytes(32)
        plaintext = secrets.token_bytes(length)

        recovered = mac_then_decrypt(secret, encrypt_then_mac(secret, plaintext))

        # Output is block-padded, so compare the meaningful prefix.
        assert recovered[:length] == plaintext
        assert len(recovered) % CIPHER_BLOCK_SIZE == 0

    @pytest.mark.parametrize(
        ("plaintext_len", "expected_ciphertext_len"),
        [(0, 0), (1, 16), (16, 16), (17, 32), (160, 160)],
    )
    def test_pads_to_block_boundary(self, plaintext_len: int, expected_ciphertext_len: int) -> None:
        secret = secrets.token_bytes(32)
        out = encrypt_then_mac(secret, bytes(plaintext_len))
        assert len(out) == CIPHER_MAC_SIZE + expected_ciphertext_len

    def test_empty_plaintext_is_not_decryptable_on_either_side(self) -> None:
        """An empty payload encrypts to a bare MAC, which nothing can decrypt.

        ``Utils::encrypt`` emits zero bytes for zero input, and
        ``Utils::MACThenDecrypt`` then rejects the result via its
        ``src_len <= CIPHER_MAC_SIZE`` guard. Firmware behaves identically, and no
        real MeshCore payload is empty -- all of them start with a 4-byte
        timestamp -- so this is a documented dead end, not a round-trip gap.
        """
        secret = secrets.token_bytes(32)
        payload = encrypt_then_mac(secret, b"")

        assert len(payload) == CIPHER_MAC_SIZE
        with pytest.raises(DecryptionError, match="too short"):
            mac_then_decrypt(secret, payload)

    def test_mac_is_truncated_hmac_sha256_over_ciphertext(self) -> None:
        """Pin the exact construction: key is the FULL secret, not the AES half."""
        secret = secrets.token_bytes(32)
        out = encrypt_then_mac(secret, b"hello room")
        mac, ciphertext = out[:CIPHER_MAC_SIZE], out[CIPHER_MAC_SIZE:]

        assert mac == hmac.digest(secret, ciphertext, hashlib.sha256)[:CIPHER_MAC_SIZE]

    def test_is_ecb_so_identical_blocks_encrypt_identically(self) -> None:
        """Not a recommendation -- a record of the wire format we must match."""
        secret = secrets.token_bytes(32)
        out = encrypt_then_mac(secret, b"A" * 32)
        ciphertext = out[CIPHER_MAC_SIZE:]
        assert ciphertext[:16] == ciphertext[16:32]

    def test_wrong_key_fails_the_mac(self) -> None:
        good, bad = secrets.token_bytes(32), secrets.token_bytes(32)
        payload = encrypt_then_mac(good, b"for someone else")

        with pytest.raises(DecryptionError, match="MAC mismatch"):
            mac_then_decrypt(bad, payload)

    def test_tampered_ciphertext_fails_the_mac(self) -> None:
        secret = secrets.token_bytes(32)
        payload = bytearray(encrypt_then_mac(secret, b"sixteen bytes!!!"))
        payload[-1] ^= 0x01

        with pytest.raises(DecryptionError, match="MAC mismatch"):
            mac_then_decrypt(secret, bytes(payload))

    @pytest.mark.parametrize("length", [0, 1, 2])
    def test_rejects_payload_too_short_for_a_mac(self, length: int) -> None:
        with pytest.raises(DecryptionError, match="too short"):
            mac_then_decrypt(secrets.token_bytes(32), bytes(length))

    def test_rejects_non_block_multiple_ciphertext(self) -> None:
        with pytest.raises(DecryptionError, match="block multiple"):
            mac_then_decrypt(secrets.token_bytes(32), bytes(CIPHER_MAC_SIZE + 5))


class TestHashes:
    def test_ack_hash_order_is_data_then_pubkey(self) -> None:
        """Utils::sha256(dest, len, frag1, len1, frag2, len2) hashes in order.

        Swapping the fragments yields a different ACK, which the client would
        reject -- so the order is worth pinning explicitly.
        """
        data, pubkey = b"\x01\x02\x03\x04message", FIRMWARE_TEST_PUB

        assert ack_hash(data, pubkey) == hashlib.sha256(data + pubkey).digest()[:4]
        assert ack_hash(data, pubkey) != hashlib.sha256(pubkey + data).digest()[:4]

    def test_ack_hash_is_four_bytes(self) -> None:
        assert len(ack_hash(b"x", FIRMWARE_TEST_PUB)) == 4

    def test_packet_hash_covers_type_and_payload(self) -> None:
        assert packet_hash(0x02, b"payload") == hashlib.sha256(b"\x02payload").digest()[:8]

    def test_packet_hash_distinguishes_payload_type(self) -> None:
        """Same bytes under a different payload type is a different packet."""
        assert packet_hash(0x02, b"same") != packet_hash(0x03, b"same")

    def test_packet_hash_is_eight_bytes(self) -> None:
        assert len(packet_hash(0x04, b"advert")) == 8
