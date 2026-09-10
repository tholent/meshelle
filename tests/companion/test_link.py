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

"""Companion link behaviour, including each failure mode it exists to survive."""

from __future__ import annotations

import asyncio
import struct
from collections.abc import Callable

import pytest

from meshelle.companion.link import (
    ADVERT_SEND_TTL,
    CompanionError,
    CompanionLink,
    RawPacketUnsupportedError,
    parse_device_info,
    parse_self_info,
)
from meshelle.proto.constants import (
    MAX_RAW_TX_PACKET,
    Cmd,
    ErrCode,
    PushCode,
    RespCode,
)
from tests.fakes.companion import FakeCompanion, FakeCompanionConfig, NodeFactory

SAMPLE_PACKET = bytes([0x01, 0x00]) + b"payload bytes"


def fast_link(
    factory: Callable[[], FakeCompanion],
    *,
    heartbeat_interval: float = 3600.0,
    heartbeat_timeout: float = 0.2,
    reconnect_min_delay: float = 0.01,
    reconnect_max_delay: float = 0.05,
) -> CompanionLink:
    """A link with production code paths but a compressed clock.

    Real backoff and heartbeat timeouts would make these tests take half a
    minute, and nothing under test depends on the absolute values.
    """
    return CompanionLink(
        factory,
        heartbeat_interval=heartbeat_interval,
        heartbeat_timeout=heartbeat_timeout,
        reconnect_min_delay=reconnect_min_delay,
        reconnect_max_delay=reconnect_max_delay,
    )


async def running_link(
    config: FakeCompanionConfig | None = None,
    *,
    heartbeat_interval: float = 3600.0,
) -> tuple[CompanionLink, FakeCompanion, asyncio.Task[None]]:
    """Start a link against one fake node and wait for it to be ready."""
    node = FakeCompanion(config)
    link = fast_link(lambda: node, heartbeat_interval=heartbeat_interval)
    task = asyncio.create_task(link.run())
    async with asyncio.timeout(2):
        await link.wait_ready()
    return link, node, task


async def shutdown(link: CompanionLink, task: asyncio.Task[None]) -> None:
    await link.stop()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


class TestHandshakeParsers:
    def test_device_info_round_trips_through_the_fake(self) -> None:
        node = FakeCompanion(
            FakeCompanionConfig(
                firmware_version="v1.18.0",
                build_date="01 Jan 2027",
                manufacturer="Acme Radios",
                path_hash_mode=2,
            )
        )
        version_code, version, build_date, manufacturer, path_hash_mode = parse_device_info(
            node._device_info()
        )

        assert version == "v1.18.0"
        assert build_date == "01 Jan 2027"
        assert manufacturer == "Acme Radios"
        assert path_hash_mode == 2
        assert version_code == 10

    def test_device_info_tolerates_older_shorter_frames(self) -> None:
        """v9 firmware omits path_hash_mode; v8 omits the version string too."""
        short = bytearray(60)
        short[0] = RespCode.DEVICE_INFO
        short[1] = 8
        short[8:20] = b"01 Jan 2026\x00"
        short[20:60] = b"Older Board".ljust(40, b"\x00")

        _, version, _, manufacturer, path_hash_mode = parse_device_info(bytes(short))

        assert version == ""
        assert manufacturer == "Older Board"
        assert path_hash_mode == 0

    def test_device_info_rejects_a_truncated_frame(self) -> None:
        with pytest.raises(CompanionError, match="too short"):
            parse_device_info(bytes(20))

    def test_self_info_extracts_radio_settings(self) -> None:
        node = FakeCompanion(
            FakeCompanionConfig(
                node_name="Hilltop",
                frequency_khz=915000,
                bandwidth_hz=250000,
                spreading_factor=11,
                coding_rate=8,
            )
        )
        (
            public_key,
            name,
            tx_power,
            max_tx,
            freq,
            bandwidth,
            sf,
            cr,
        ) = parse_self_info(node._self_info())

        assert name == "Hilltop"
        assert len(public_key) == 32
        assert (freq, bandwidth, sf, cr) == (915000, 250000, 11, 8)
        assert (tx_power, max_tx) == (20, 22)

    def test_self_info_rejects_a_truncated_frame(self) -> None:
        with pytest.raises(CompanionError, match="too short"):
            parse_self_info(bytes(30))


class TestHandshake:
    async def test_completes_and_reports_the_node(self) -> None:
        link, _node, task = await running_link(FakeCompanionConfig(node_name="Hilltop"))
        try:
            info = await link.wait_ready()

            assert info.node_name == "Hilltop"
            assert info.frequency_khz == 869618
            assert link.is_connected
            assert "Hilltop" in info.summary()
        finally:
            await shutdown(link, task)

    async def test_sends_device_query_then_app_start(self) -> None:
        link, node, task = await running_link()
        try:
            assert node.commands[:2] == [Cmd.DEVICE_QUERY, Cmd.APP_START]
        finally:
            await shutdown(link, task)

    async def test_a_silent_node_does_not_hang_the_link(self) -> None:
        """meshcore-pi's bare readexactly(1) blocks here forever instead.

        The link must give up, report it, and get back to its reconnect loop.
        """
        node = FakeCompanion(FakeCompanionConfig(answer_device_query=False))
        link = fast_link(lambda: node)
        task = asyncio.create_task(link.run())
        try:
            with pytest.raises(TimeoutError):
                async with asyncio.timeout(0.5):
                    await link.wait_ready()
            assert not link.is_connected
        finally:
            await shutdown(link, task)

    async def test_a_garbled_device_info_is_reported_not_crashed_on(self) -> None:
        node = FakeCompanion(
            FakeCompanionConfig(device_info_override=bytes([RespCode.DEVICE_INFO, 1, 2]))
        )
        link = fast_link(lambda: node)
        task = asyncio.create_task(link.run())
        try:
            with pytest.raises(TimeoutError):
                async with asyncio.timeout(0.5):
                    await link.wait_ready()
        finally:
            await shutdown(link, task)

    async def test_skips_unsolicited_pushes_during_the_handshake(self) -> None:
        """The node may already be hearing adverts while we are still shaking hands."""
        node = FakeCompanion()
        node.push(bytes([PushCode.ADVERT]) + bytes(32))
        link = fast_link(lambda: node)
        task = asyncio.create_task(link.run())
        try:
            async with asyncio.timeout(2):
                info = await link.wait_ready()
            assert info.node_name == "Test Node"
        finally:
            await shutdown(link, task)


class TestTransmit:
    async def test_sends_a_queued_packet_with_the_priority_byte(self) -> None:
        link, node, task = await running_link()
        try:
            await link.send_packet(SAMPLE_PACKET, priority=2)
            async with asyncio.timeout(2):
                await node.wait_for_transmit()

            assert node.transmitted_packets == [SAMPLE_PACKET]
            assert node.transmitted[0].priority == 2
        finally:
            await shutdown(link, task)

    async def test_a_packet_queued_before_ready_is_still_sent(self) -> None:
        """The startup-advert race: meshcore-pi logs and drops it.

        Queue a packet before the handshake finishes and it must reach the air
        once the link is up, not vanish.
        """
        node = FakeCompanion()
        link = fast_link(lambda: node)
        await link.send_packet(SAMPLE_PACKET, description="startup advert")

        task = asyncio.create_task(link.run())
        try:
            async with asyncio.timeout(2):
                await link.wait_ready()
                await node.wait_for_transmit()

            assert node.transmitted_packets == [SAMPLE_PACKET]
        finally:
            await shutdown(link, task)

    async def test_preserves_queue_order(self) -> None:
        link, node, task = await running_link()
        try:
            for index in range(5):
                await link.send_packet(bytes([0x01, 0x00, index]))
            async with asyncio.timeout(2):
                await node.wait_for_transmit(5)

            assert [p[2] for p in node.transmitted_packets] == [0, 1, 2, 3, 4]
        finally:
            await shutdown(link, task)

    async def test_drops_a_packet_that_waited_past_its_ttl(self) -> None:
        """A post push that is minutes stale is worse than useless."""
        node = FakeCompanion()
        link = fast_link(lambda: node)
        await link.send_packet(SAMPLE_PACKET, ttl=-1.0, description="stale push")

        task = asyncio.create_task(link.run())
        try:
            async with asyncio.timeout(2):
                await link.wait_ready()
            await asyncio.sleep(0.05)

            assert node.transmitted_packets == []
        finally:
            await shutdown(link, task)

    async def test_an_advert_gets_a_long_ttl(self) -> None:
        """Adverts stay useful long after an acknowledged push would not."""
        link, node, task = await running_link()
        try:
            await link.send_packet(SAMPLE_PACKET, ttl=ADVERT_SEND_TTL)
            async with asyncio.timeout(2):
                await node.wait_for_transmit()
            assert node.transmitted_packets == [SAMPLE_PACKET]
        finally:
            await shutdown(link, task)

    async def test_rejects_a_packet_too_large_for_the_node_buffer(self) -> None:
        link, _node, task = await running_link()
        try:
            with pytest.raises(CompanionError, match="exceeds the"):
                await link.send_packet(bytes(MAX_RAW_TX_PACKET + 1))
        finally:
            await shutdown(link, task)

    async def test_rejects_an_out_of_range_priority(self) -> None:
        link, _node, task = await running_link()
        try:
            with pytest.raises(CompanionError, match="priority"):
                await link.send_packet(SAMPLE_PACKET, priority=256)
        finally:
            await shutdown(link, task)

    async def test_firmware_without_raw_packet_support_fails_loudly(self) -> None:
        """And does not retry: reconnecting cannot add a missing command."""
        node = FakeCompanion(FakeCompanionConfig(supports_raw_packet=False))
        link = fast_link(lambda: node)
        task = asyncio.create_task(link.run())

        async with asyncio.timeout(2):
            await link.wait_ready()
        await link.send_packet(SAMPLE_PACKET)

        with pytest.raises(RawPacketUnsupportedError, match="CMD_SEND_RAW_PACKET"):
            async with asyncio.timeout(2):
                await task


class TestReceive:
    async def test_yields_packets_with_radio_metadata(self) -> None:
        link, node, task = await running_link()
        try:
            node.deliver_packet(SAMPLE_PACKET, snr=7.25, rssi=-92)

            packets = link.packets()
            async with asyncio.timeout(2):
                received = await anext(packets)

            assert received.raw == SAMPLE_PACKET
            assert received.snr == 7.25
            assert received.rssi == -92
        finally:
            await shutdown(link, task)

    async def test_a_one_byte_ok_frame_is_not_treated_as_malformed(self) -> None:
        """meshcore-pi warns 'frame too short' on every successful transmit."""
        link, node, task = await running_link()
        try:
            node.push(bytes([RespCode.OK]))
            await link.send_packet(SAMPLE_PACKET)
            async with asyncio.timeout(2):
                await node.wait_for_transmit()

            # Still healthy, still transmitting.
            assert node.transmitted_packets == [SAMPLE_PACKET]
            assert link.is_connected
        finally:
            await shutdown(link, task)

    async def test_ignores_push_codes_it_does_not_need(self) -> None:
        """The node adds our own rooms as contacts and announces it; so what."""
        link, node, task = await running_link()
        try:
            node.push(bytes([PushCode.NEW_ADVERT]) + bytes(40))
            node.push(bytes([PushCode.CONTACTS_FULL]))
            node.push(bytes([PushCode.MSG_WAITING]))
            node.deliver_packet(SAMPLE_PACKET)

            async with asyncio.timeout(2):
                received = await anext(link.packets())
            assert received.raw == SAMPLE_PACKET
        finally:
            await shutdown(link, task)

    async def test_ignores_an_rx_log_frame_with_no_packet(self) -> None:
        link, node, task = await running_link()
        try:
            node.push(bytes([PushCode.LOG_RX_DATA, 0x28, 0xA4]))
            node.deliver_packet(SAMPLE_PACKET)

            async with asyncio.timeout(2):
                received = await anext(link.packets())
            assert received.raw == SAMPLE_PACKET
        finally:
            await shutdown(link, task)

    async def test_negative_snr_and_rssi_decode_as_signed(self) -> None:
        link, node, task = await running_link()
        try:
            node.push(bytes([PushCode.LOG_RX_DATA]) + struct.pack("<bb", -40, -120) + SAMPLE_PACKET)

            async with asyncio.timeout(2):
                received = await anext(link.packets())

            assert received.snr == -10.0
            assert received.rssi == -120
        finally:
            await shutdown(link, task)


class TestReconnect:
    async def test_reconnects_after_the_link_drops(self) -> None:
        factory = NodeFactory()
        link = fast_link(factory)
        task = asyncio.create_task(link.run())
        try:
            async with asyncio.timeout(2):
                first = await factory.wait_for_node(1)
                await link.wait_ready()

            first.drop_connection()

            async with asyncio.timeout(5):
                await factory.wait_for_node(2)
                await link.wait_ready()

            assert link.is_connected
        finally:
            await shutdown(link, task)

    async def test_a_packet_queued_while_down_is_sent_after_reconnect(self) -> None:
        """Nothing is lost merely because the port happened to be reconnecting."""
        factory = NodeFactory()
        link = fast_link(factory)
        task = asyncio.create_task(link.run())
        try:
            async with asyncio.timeout(2):
                first = await factory.wait_for_node(1)
                await link.wait_ready()

            first.drop_connection()
            await link.send_packet(SAMPLE_PACKET, ttl=ADVERT_SEND_TTL)

            async with asyncio.timeout(5):
                second = await factory.wait_for_node(2)
                await second.wait_for_transmit()

            assert second.transmitted_packets == [SAMPLE_PACKET]
            assert first.transmitted_packets == []
        finally:
            await shutdown(link, task)

    async def test_a_node_that_stops_answering_the_heartbeat_is_dropped(self) -> None:
        """Silence alone is not a fault -- an idle mesh sends nothing.

        So liveness is an explicit clock request, and failing it forces a
        reconnect.
        """
        factory = NodeFactory(FakeCompanionConfig(answer_heartbeat=False))
        link = fast_link(factory, heartbeat_interval=0.02)
        task = asyncio.create_task(link.run())
        try:
            async with asyncio.timeout(2):
                first = await factory.wait_for_node(1)
                await link.wait_ready()

            # The heartbeat fires, goes unanswered, and the session is torn down.
            async with asyncio.timeout(5):
                await factory.wait_for_node(2)

            assert Cmd.GET_DEVICE_TIME in first.commands
        finally:
            await shutdown(link, task)

    async def test_heartbeat_keeps_a_healthy_link_up(self) -> None:
        link, node, task = await running_link(heartbeat_interval=0.05)
        try:
            await asyncio.sleep(0.3)

            assert link.is_connected
            assert node.commands.count(Cmd.GET_DEVICE_TIME) >= 2
        finally:
            await shutdown(link, task)


class TestProbe:
    async def test_reports_support_without_transmitting(self) -> None:
        """The probe must prove the command exists without using the radio."""
        node = FakeCompanion()
        await node.connect()
        link = fast_link(lambda: node)

        assert await link.probe_raw_packet_support(node) is True
        assert node.transmitted_packets == [], "the probe must never reach the air"

    async def test_reports_missing_support(self) -> None:
        node = FakeCompanion(FakeCompanionConfig(supports_raw_packet=False))
        await node.connect()
        link = fast_link(lambda: node)

        assert await link.probe_raw_packet_support(node) is False

    async def test_skips_unrelated_errors_while_probing(self) -> None:
        node = FakeCompanion()
        await node.connect()
        node.push(bytes([RespCode.ERR, ErrCode.TABLE_FULL]))
        link = fast_link(lambda: node)

        assert await link.probe_raw_packet_support(node) is True
