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

"""The room server state machine.

Spec: ``examples/simple_room_server/MyMesh.cpp``. This is a faithful port of
that state machine onto a host with a database, with the differences called out
at each site where one exists.

What a room does, in one paragraph: clients log in with an ``ANON_REQ`` carrying
a password and the timestamp of the newest post they already hold; the room
answers with a 13-byte login response whose seventh byte is the client's
permission level; clients then post ``TXT_TYPE_PLAIN`` messages, which the room
stores and acknowledges; and a slow round-robin loop pushes each stored post to
every client that has not yet acknowledged it, one outstanding push at a time.

Four things about this file are worth knowing before changing it:

**Byte 7 of the login response is the reason this project exists.** It is the
client's permission level, and meshcore-pi hardcodes it to zero, which makes
every room it hosts read-only in current apps. It is invisible in logs -- the
only way to check it is that a compose box appears in the app -- so it is
asserted directly in the tests.

**A rejected login gets no reply at all.** Not an error packet. A wrong password
is indistinguishable from a room that is out of range, which denies an attacker
a password oracle.

**Replies are delayed, never immediate.** A client that has just transmitted is
still turning its radio around. The delays are scheduled rather than awaited, so
the receive loop keeps running.

**The room owns the mesh endpoint.** The companion node is a modem; every packet
here is built, encrypted and signed by meshelle with the room's own key.
"""

from __future__ import annotations

import hmac
import logging
import secrets
import struct
from collections import deque
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from meshelle.companion.link import ADVERT_SEND_TTL, ReceivedPacket
from meshelle.config.model import Role, RoomSettings
from meshelle.mesh.clock import Clock
from meshelle.mesh.dispatcher import PacketSink
from meshelle.mesh.scheduler import Scheduler, Timings
from meshelle.proto import crypto
from meshelle.proto.advert import Advert, AdvertData
from meshelle.proto.constants import (
    FIRMWARE_VER_LEVEL,
    LOGIN_RESPONSE_LEN,
    OUT_PATH_UNKNOWN,
    PATH_HASH_SIZE_MASK,
    PATH_HASH_SIZE_SHIFT,
    PATH_HOP_COUNT_MASK,
    RESP_SERVER_LOGIN_OK,
    AdvertType,
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
    PacketError,
    PathReturn,
    ServerRequest,
    TextMessage,
    max_plaintext_len,
)
from meshelle.proto.text import utf8_truncate
from meshelle.room import acl, posts
from meshelle.room.admin_cli import CliContext, handle_command, split_prefix
from meshelle.room.stats import (
    COUNTER_POST_PUSH,
    COUNTER_POSTED,
    RadioStats,
    ServerStats,
)
from meshelle.store import repo
from meshelle.store.db import Store

logger = logging.getLogger(__name__)

ACL_ENTRY_LEN = 7
"""``REQ_TYPE_GET_ACCESS_LIST`` entries: 6 pubkey bytes plus a permissions byte."""

ACL_PUBKEY_PREFIX_LEN = 6

RESPONSE_TIMESTAMP_LEN = 4
"""Every RESPONSE payload starts with a reflected 4-byte request timestamp."""


@dataclass(slots=True)
class ClientSession:
    """One client's live state.

    The durable half of this lives in the ``clients`` table; this is the part
    that is either derivable (the shared secret) or meaningless across a restart
    (a pending ACK). Keeping the shared secret in memory only is deliberate:
    it is recomputable from our private key and the client's public key, so
    persisting it would add secret-at-rest exposure for nothing.
    """

    public_key: bytes
    shared_secret: bytes
    role: Role
    source: acl.RoleSource
    sync_since: int = 0
    last_timestamp: int = 0
    """The client's own clock, used only as a replay floor. Never compared
    against our post timestamps -- the two clocks are unrelated."""
    out_path: bytes = b""
    out_path_len: int = OUT_PATH_UNKNOWN
    """The *packed* path-length byte, as stored on the wire and in the database."""
    last_activity: int = 0
    pending_ack: bytes | None = None
    push_post_ts: int = 0
    push_is_welcome: bool = False
    ack_timeout: float = 0.0
    push_failures: int = 0
    welcome: deque[str] = field(default_factory=deque)

    @property
    def has_out_path(self) -> bool:
        return self.out_path_len != OUT_PATH_UNKNOWN

    @property
    def hop_count(self) -> int:
        return self.out_path_len & PATH_HOP_COUNT_MASK

    @property
    def path_hash_size(self) -> int:
        return ((self.out_path_len >> PATH_HASH_SIZE_SHIFT) & PATH_HASH_SIZE_MASK) + 1

    def forget_path(self) -> None:
        """Drop the return path, so replies flood until a new one is learned."""
        self.out_path = b""
        self.out_path_len = OUT_PATH_UNKNOWN


class RoomServer:
    """One hosted room: one identity, one ACL, one push loop."""

    def __init__(
        self,
        *,
        slug: str,
        settings: RoomSettings,
        identity: LocalIdentity,
        room_id: int,
        store: Store,
        sink: PacketSink,
        scheduler: Scheduler,
        clock: Clock,
        radio: RadioStats,
        version: str,
        timings: Timings | None = None,
    ) -> None:
        self._slug = slug
        self._settings = settings
        self._identity = identity
        self._room_id = room_id
        self._store = store
        self._sink = sink
        self._scheduler = scheduler
        self._clock = clock
        self._radio = radio
        self._version = version
        self._timings = timings if timings is not None else Timings()

        self._sessions: dict[bytes, ClientSession] = {}
        self._round_robin = 0
        self._next_push = 0.0

    # -- identity ------------------------------------------------------------

    @property
    def slug(self) -> str:
        return self._slug

    @property
    def node_hash(self) -> int:
        return self._identity.node_hash

    @property
    def settings(self) -> RoomSettings:
        return self._settings

    @property
    def sessions(self) -> dict[bytes, ClientSession]:
        """Live client state, for tests and for the future ``doctor`` command."""
        return self._sessions

    # -- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        """Rehydrate known clients so a restart resumes syncing mid-stream.

        Without this, a restart would leave every client's owed posts unsent
        until it happened to log in again -- and a client with a working out_path
        may not log in for hours.
        """
        clients = await self._store.run(lambda s: repo.list_clients(s, self._room_id))
        for client in clients:
            try:
                secret = self._identity.shared_secret(client.public_key)
            except crypto.DecryptionError:
                # A stored key that cannot produce a shared secret is corrupt.
                # Skipping it loses one client, not the room.
                logger.warning(
                    "room %s: skipping client %s with an unusable public key",
                    self._slug,
                    client.public_key[:4].hex(),
                )
                continue

            role = acl.resolve_without_password(self._settings, client.public_key)
            self._sessions[client.public_key] = ClientSession(
                public_key=client.public_key,
                shared_secret=secret,
                role=role,
                source=acl.RoleSource.MEMBER
                if self._settings.role_for_member(client.public_key)
                else acl.RoleSource.ALLOW_UNKNOWN,
                sync_since=client.sync_since,
                last_timestamp=client.last_timestamp,
                out_path=client.out_path,
                out_path_len=client.out_path_len,
                last_activity=client.last_activity,
            )
        logger.info("room %s: resumed %d known client(s)", self._slug, len(self._sessions))

    def apply_settings(self, settings: RoomSettings) -> None:
        """Adopt reloaded configuration without disturbing sync state.

        Declared members are re-resolved immediately, so adding or demoting one
        takes effect on the next packet. A role earned by password is left alone
        until that client logs in again: the password it used is not recorded,
        so there is nothing here to re-check it against.
        """
        self._settings = settings
        for session in self._sessions.values():
            member_role = settings.role_for_member(session.public_key)
            if member_role is not None:
                session.role = member_role
                session.source = acl.RoleSource.MEMBER
            elif session.source is acl.RoleSource.MEMBER:
                # Was a member, is no longer: fall back to what the config now
                # grants a stranger, rather than keeping a revoked role.
                session.role = acl.resolve_without_password(settings, session.public_key)
                session.source = acl.RoleSource.ALLOW_UNKNOWN

    # -- inbound -------------------------------------------------------------

    async def handle(self, packet: Packet, received: ReceivedPacket) -> bool:  # noqa: ARG002
        """Try to claim a packet. ``True`` means it was ours and was handled."""
        try:
            if packet.payload_type is PayloadType.ACK:
                return await self._on_ack(Ack.decode(packet.payload).checksum)
            if packet.payload_type is PayloadType.ANON_REQ:
                return await self._on_anon_request(packet)
            if packet.payload_type in (
                PayloadType.REQ,
                PayloadType.TXT_MSG,
                PayloadType.PATH,
                PayloadType.RESPONSE,
            ):
                return await self._on_datagram(packet)
        except PacketError as exc:
            # The MAC already proved the packet was ours, so a malformed body is
            # a real protocol mismatch worth seeing -- but not worth crashing.
            logger.warning("room %s: malformed %s: %s", self._slug, packet.payload_type.name, exc)
            return True
        return False

    async def _on_anon_request(self, packet: Packet) -> bool:
        anon = AnonRequest.decode(packet.payload)
        if anon.dest_hash != self.node_hash:
            return False

        try:
            secret = self._identity.shared_secret(anon.sender_public_key)
            plaintext = anon.open(secret)
        except crypto.DecryptionError:
            # Not for us: with a one-byte destination hash this is the ordinary
            # outcome for another node's login, not a fault.
            return False

        login = LoginRequest.decode(plaintext)
        await self._login(packet, anon.sender_public_key, secret, login)
        return True

    async def _login(
        self,
        packet: Packet,
        public_key: bytes,
        secret: bytes,
        login: LoginRequest,
    ) -> None:
        grant = acl.resolve(self._settings, public_key, login.password)
        if grant is None:
            logger.info(
                "room %s: refused login from %s (no member entry, no password match)",
                self._slug,
                public_key[:4].hex(),
            )
            return

        existing = self._sessions.get(public_key)
        if existing is not None and login.timestamp <= existing.last_timestamp:
            # Firmware's test is `<=` (MyMesh.cpp:355): a login must carry a
            # strictly newer timestamp than anything already seen from that key,
            # so a captured ANON_REQ cannot be replayed to re-enter the room.
            logger.warning(
                "room %s: replayed login from %s (timestamp %d <= %d)",
                self._slug,
                public_key[:4].hex(),
                login.timestamp,
                existing.last_timestamp,
            )
            return

        now = self._clock.now()
        arrived_by_flood = packet.route_type.is_flood
        client = await self._store.run(
            lambda session: repo.record_login(
                session,
                self._room_id,
                public_key,
                role=grant.role.permission,
                sender_timestamp=login.timestamp,
                sync_since=login.sync_since,
                now=now,
                reset_out_path=arrived_by_flood,
            )
        )

        session = existing or ClientSession(
            public_key=public_key,
            shared_secret=secret,
            role=grant.role,
            source=grant.source,
        )
        session.role = grant.role
        session.source = grant.source
        session.shared_secret = secret
        session.sync_since = client.sync_since
        session.last_timestamp = login.timestamp
        session.last_activity = now
        session.pending_ack = None
        session.push_failures = 0
        if arrived_by_flood:
            # The route we had is no longer known to be good: this login came
            # the long way round, so replies must flood until a PATH comes back.
            session.forget_path()
        self._sessions[public_key] = session

        if login.sync_since == 0 and self._settings.welcome:
            # "First sync" is the client's own claim to hold no posts, so a
            # client that clears its history is welcomed again on purpose.
            session.welcome = deque(posts.split_welcome(self._settings.welcome))

        logger.info("room %s: login %s", self._slug, grant.describe(public_key))
        self._pause_pushes()
        self._send_response(session, packet, self._login_response(grant.role))

    def _login_response(self, role: Role) -> bytes:
        """The 13 bytes that decide whether an app shows a compose box.

        ``[now:4][RESP_SERVER_LOGIN_OK][0][legacy_admin][permissions][rand:4][ver]``

        Byte 7 is ``permissions`` (MyMesh.cpp:381). meshcore-pi writes a zero
        there, which every current app reads as "guest", which is why rooms it
        hosts cannot be posted to. Byte 5 is a legacy keep-alive interval that
        firmware now always zeroes, and byte 6 is the legacy admin flag apps
        used before byte 7 existed -- both are still sent, because an older app
        reads them and a newer one ignores them.
        """
        permission = role.permission
        # Firmware tests `client->permissions == 0` (MyMesh.cpp:380); for us the
        # whole byte *is* the role, so that is exactly GUEST.
        legacy_admin = (
            1 if permission is Permission.ADMIN else (2 if permission is Permission.GUEST else 0)
        )
        response = (
            struct.pack("<I", self._clock.unique_now())
            + bytes([RESP_SERVER_LOGIN_OK, 0, legacy_admin, int(permission)])
            # Four random bytes so two logins in the same second still produce
            # different packet hashes; without them the second reply would be
            # suppressed as a duplicate by every repeater it crossed.
            + secrets.token_bytes(4)
            + bytes([FIRMWARE_VER_LEVEL])
        )
        if len(response) != LOGIN_RESPONSE_LEN:  # pragma: no cover - structural
            raise PacketError(f"login response must be {LOGIN_RESPONSE_LEN} bytes")
        return response

    async def _on_datagram(self, packet: Packet) -> bool:
        datagram = Datagram.decode(packet.payload)
        if datagram.dest_hash != self.node_hash:
            return False

        for session in self._candidate_sessions(datagram.src_hash):
            try:
                plaintext = datagram.open(session.shared_secret)
            except crypto.DecryptionError:
                # Another client of ours whose key happens to start with the
                # same byte. Try the next one.
                continue

            if packet.payload_type is PayloadType.TXT_MSG:
                await self._on_text(session, plaintext)
            elif packet.payload_type is PayloadType.REQ:
                await self._on_request(session, packet, plaintext)
            elif packet.payload_type is PayloadType.PATH:
                await self._on_path_return(session, plaintext)
            else:
                # A RESPONSE addressed to a room: nothing asks a client for one,
                # so this is a confused peer rather than something to answer.
                logger.debug("room %s: ignoring a RESPONSE from a client", self._slug)
            return True
        return False

    def _candidate_sessions(self, src_hash: int) -> list[ClientSession]:
        """Every known client whose key starts with ``src_hash``.

        More than one is entirely possible -- 256 buckets, and the birthday
        bound bites at about 20 clients -- so the MAC does the disambiguating.
        """
        return [s for key, s in self._sessions.items() if key[0] == src_hash]

    # -- text messages: posts and the admin CLI ------------------------------

    async def _on_text(self, session: ClientSession, plaintext: bytes) -> None:
        message = TextMessage.decode(plaintext)
        if message.txt_type not in (TxtType.PLAIN, TxtType.CLI_DATA):
            logger.debug("room %s: ignoring %s text", self._slug, message.txt_type.name)
            return

        if message.timestamp < session.last_timestamp:
            logger.warning(
                "room %s: replayed message from %s (timestamp %d < %d)",
                self._slug,
                session.public_key[:4].hex(),
                message.timestamp,
                session.last_timestamp,
            )
            return

        # Equal timestamps mean a retry: the client did not hear our ACK. It
        # must be acknowledged again, but must not be posted again -- that is
        # the difference between a lost ACK and a duplicated message.
        is_retry = message.timestamp == session.last_timestamp
        session.last_timestamp = message.timestamp
        session.last_activity = self._clock.now()
        session.push_failures = 0  # it is talking to us, so resume pushing

        expected_ack = message.ack_hash(session.public_key)

        if message.txt_type is TxtType.CLI_DATA:
            reply_text = await self._run_cli(session, message, is_retry)
            send_ack = False
        else:
            reply_text = ""
            send_ack = await self._accept_post(session, message, is_retry)

        delay = 0.0
        if send_ack:
            self._send_ack(session, expected_ack, delay=self._timings.txt_ack_delay)
            # The CLI reply waits for the ACK to clear the air first. No message
            # type currently both acknowledges and replies -- firmware's shape is
            # kept so one that did would be paced correctly rather than putting
            # two packets on the air at once.
            delay = self._timings.txt_ack_delay + self._timings.reply_delay

        if reply_text:
            self._send_cli_reply(
                session, message, reply_text, delay=delay + self._timings.server_response_delay
            )

    async def _accept_post(
        self, session: ClientSession, message: TextMessage, is_retry: bool
    ) -> bool:
        """Store a post. Returns whether to acknowledge it.

        Guests and read-only clients get **no ACK and no reply**, so their app
        shows the message as undelivered rather than silently swallowing it.

        This is stricter than firmware, which refuses only ``PERM_ACL_GUEST``
        and so lets a client it labelled "read only" post anyway
        (MyMesh.cpp:480). meshelle honours the name it gave the role; the wire
        byte is still 1, so apps still label it correctly.
        """
        if not session.role.may_post:
            logger.info(
                "room %s: refused post from %s (role %s)",
                self._slug,
                session.public_key[:4].hex(),
                session.role.value,
            )
            return False

        if is_retry:
            logger.debug("room %s: re-acknowledging a retried post", self._slug)
            return True

        text = posts.decode_post_text(message.body)
        if not text:
            return True

        await self._store_post(session.public_key, text)
        logger.info("room %s: post from %s", self._slug, session.public_key[:4].hex())
        return True

    async def _store_post(self, author_public_key: bytes, text: str) -> int:
        """Record a post and apply retention, in one transaction."""
        now = self._clock.now()
        retention = self._settings.post_retention
        max_posts = self._settings.max_posts

        def work(db: Session) -> int:
            post_ts = repo.next_post_ts(db, self._room_id, now)
            post = repo.add_post(db, self._room_id, author_public_key, text, post_ts)
            repo.increment_counter(db, self._room_id, COUNTER_POSTED)
            repo.prune_posts(
                db,
                self._room_id,
                older_than=None if retention is None else now - retention,
                keep_newest=max_posts,
            )
            return post.post_ts

        post_ts = await self._store.run(work)
        # Hold off pushing so the author's own ACK is not competing with a push
        # for the same airtime.
        self._pause_pushes()
        return post_ts

    async def _run_cli(self, session: ClientSession, message: TextMessage, is_retry: bool) -> str:
        """Handle a console line. Non-admins get nothing at all.

        No ACK either way, matching firmware: the console is request/response,
        and the reply *is* the acknowledgement.
        """
        if session.role is not Role.ADMIN:
            logger.info(
                "room %s: ignoring CLI from non-admin %s",
                self._slug,
                session.public_key[:4].hex(),
            )
            return ""
        if is_retry:
            # Re-running a command would repeat its side effect -- `room.post`
            # twice, an extra advert. The app already showed the first reply.
            return ""

        prefix, command = split_prefix(message.body.decode("utf-8", errors="replace"))
        reply = await handle_command(command, self._cli_context())
        logger.info("room %s: cli %r -> %r", self._slug, command, reply)
        return f"{prefix}{reply}" if reply else ""

    def _cli_context(self) -> CliContext:
        return CliContext(
            room_slug=self._slug,
            version=self._version,
            now=self._clock.now(),
            acl_entries=[(m.pubkey, m.role.value) for m in self._settings.members],
            send_advert=self.send_advert,
            clear_stats=self.clear_stats,
            post_message=self.post_system_message,
        )

    # -- requests ------------------------------------------------------------

    async def _on_request(self, session: ClientSession, packet: Packet, plaintext: bytes) -> None:
        request = ServerRequest.decode(plaintext)
        if request.timestamp < session.last_timestamp:
            logger.warning(
                "room %s: replayed request from %s",
                self._slug,
                session.public_key[:4].hex(),
            )
            return

        session.last_timestamp = request.timestamp
        session.last_activity = self._clock.now()
        session.push_failures = 0

        if request.req_type == ReqType.KEEP_ALIVE and packet.route_type.is_direct:
            await self._on_keep_alive(session, plaintext, request)
            return

        body = await self._request_reply(session, request)
        if not body:
            logger.debug("room %s: no reply for request type %d", self._slug, request.req_type)
            return

        # Every RESPONSE reflects the request's timestamp back as a correlation
        # tag, so a client with two outstanding requests can tell them apart.
        self._send_response(session, packet, struct.pack("<I", request.timestamp) + body)

    async def _on_keep_alive(
        self, session: ClientSession, plaintext: bytes, request: ServerRequest
    ) -> None:
        """Answer a keep-alive with an ACK carrying the unsynced count.

        **Direct route only** (MyMesh.cpp:568). A keep-alive exists to prove the
        stored return path still works; answering a flooded one would confirm a
        path that was not used, and would put a flood on the air every interval
        for every client.

        The extra byte on the end of the ACK is how an app shows "3 messages
        waiting" without waiting for them to arrive.
        """
        # The client may append the newest post timestamp it holds. Cipher
        # padding means those four bytes always exist; they are simply zero when
        # the client did not send them, which firmware notes in situ.
        force_since = 0
        if len(request.data) >= 4:
            force_since = struct.unpack_from("<I", request.data, 0)[0]

        if force_since > 0 and force_since != session.sync_since:
            session.sync_since = force_since
            public_key = session.public_key
            await self._store.run(
                lambda db: repo.force_sync_since(db, self._room_id, public_key, force_since)
            )

        session.pending_ack = None

        if not session.has_out_path:
            logger.debug(
                "room %s: keep-alive from %s with no return path; nothing to answer over",
                self._slug,
                session.public_key[:4].hex(),
            )
            return

        # The hash covers exactly nine bytes -- timestamp, request type, and the
        # four "since" bytes whether or not the client meant to send them.
        checksum = crypto.ack_hash(plaintext[:9], session.public_key)
        unsynced = await self._store.run(
            lambda db: repo.count_unsynced_posts(
                db, self._room_id, session.public_key, session.sync_since
            )
        )
        ack = Ack(checksum=checksum, trailer=bytes([min(unsynced, 0xFF)]))
        packet = Packet(
            route_type=RouteType.DIRECT,
            payload_type=PayloadType.ACK,
            payload=ack.encode(),
            path=session.out_path,
            path_hash_size=session.path_hash_size,
        )
        self._schedule(packet, self._timings.server_response_delay, "keep-alive ack")

    async def _request_reply(self, session: ClientSession, request: ServerRequest) -> bytes:
        """The body of a RESPONSE, without the reflected timestamp."""
        if request.req_type == ReqType.GET_STATUS:
            return await self._status_reply()

        if request.req_type == ReqType.GET_ACCESS_LIST:
            if session.role is not Role.ADMIN:
                return b""
            # Two reserved bytes for future query parameters; a non-zero value
            # means a query we do not understand, so we must not answer it with
            # the unfiltered list (MyMesh.cpp:203).
            reserved = request.data[:2].ljust(2, b"\x00")
            if reserved != b"\x00\x00":
                return b""
            return self._access_list_reply()

        return b""

    async def _status_reply(self) -> bytes:
        counters = await self._store.run(lambda db: repo.get_counters(db, self._room_id))
        stats = ServerStats.build(
            self._radio,
            monotonic_now=self._clock.monotonic(),
            posted=counters.get(COUNTER_POSTED, 0),
            post_pushes=counters.get(COUNTER_POST_PUSH, 0),
        )
        return stats.encode()

    def _access_list_reply(self) -> bytes:
        """Declared members: a 6-byte key prefix and a permissions byte each.

        Firmware sends only its admins, because admins are the only entries its
        ACL persists (``saveFilter``, MyMesh.cpp:988). meshelle's ACL is the
        config file, which holds every role, so the whole declared list is sent
        -- it is what the requesting admin asked for, and it is what they would
        see by reading the file.
        """
        budget = max_plaintext_len() - RESPONSE_TIMESTAMP_LEN
        capacity = budget // ACL_ENTRY_LEN

        entries = bytearray()
        for member in self._settings.members[:capacity]:
            entries += member.pubkey[:ACL_PUBKEY_PREFIX_LEN]
            entries.append(int(member.role.permission))
        if len(self._settings.members) > capacity:
            logger.info(
                "room %s: access list truncated to %d of %d members (one packet)",
                self._slug,
                capacity,
                len(self._settings.members),
            )
        return bytes(entries)

    # -- path returns and acks ----------------------------------------------

    async def _on_path_return(self, session: ClientSession, plaintext: bytes) -> None:
        """Learn the route back to a client, and take any ACK bundled with it.

        No reciprocal path is sent. Firmware is explicit about this
        (``NOTE: no reciprocal path send!!``): the client already knows the way
        here, or it could not have sent this.
        """
        path_return = PathReturn.decode(plaintext)
        packed_len = (
            (path_return.path_hash_size - 1) << PATH_HASH_SIZE_SHIFT
        ) | path_return.hop_count

        session.out_path = path_return.path
        session.out_path_len = packed_len
        session.last_activity = self._clock.now()
        await self._store.run(
            lambda db: repo.set_out_path(
                db, self._room_id, session.public_key, path_return.path, packed_len
            )
        )
        logger.info(
            "room %s: learned a %d-hop path to %s",
            self._slug,
            path_return.hop_count,
            session.public_key[:4].hex(),
        )

        # Firmware masks the extra type to its low nibble (Mesh.cpp:170); the
        # upper four bits are reserved and must not defeat the comparison.
        if (path_return.extra_type & 0x0F) == PayloadType.ACK and len(path_return.extra) >= Ack.LEN:
            await self._on_ack(path_return.extra[: Ack.LEN])

    async def _on_ack(self, checksum: bytes) -> bool:
        """Match a bare ACK against every client we are waiting on.

        An ACK carries no addressing at all, so this is the only way to know who
        sent it -- which also means it is offered to every room on the node.
        """
        for session in self._sessions.values():
            if session.pending_ack is None:
                continue
            if not hmac.compare_digest(session.pending_ack, checksum):
                continue

            session.pending_ack = None
            session.push_failures = 0
            if session.push_is_welcome:
                if session.welcome:
                    session.welcome.popleft()
            else:
                session.sync_since = session.push_post_ts
                # Through a method, not a lambda in the loop: a closure over the
                # loop variable is how a later iteration silently rewrites an
                # earlier client's row.
                await self._advance_sync(session.public_key, session.push_post_ts)
            logger.debug(
                "room %s: %s acknowledged a push",
                self._slug,
                session.public_key[:4].hex(),
            )
            return True
        return False

    async def _advance_sync(self, public_key: bytes, post_ts: int) -> None:
        await self._store.run(lambda db: repo.advance_sync(db, self._room_id, public_key, post_ts))

    # -- outbound ------------------------------------------------------------

    def _send_response(self, session: ClientSession, request: Packet, payload: bytes) -> None:
        """Reply to a request, choosing the route the way firmware does.

        A request that arrived by flood is answered with a ``PAYLOAD_TYPE_PATH``
        packet that carries the response *inside* it. That is not an
        optimisation: it is how the client learns the route to this room. Sending
        a plain RESPONSE back would answer the question and leave the client
        still flooding every future message.
        """
        if request.route_type.is_flood:
            bundled = PathReturn(
                path=request.path,
                path_hash_size=request.path_hash_size,
                extra_type=int(PayloadType.RESPONSE),
                extra=payload,
            )
            datagram = Datagram.seal(
                session.public_key[0], self.node_hash, session.shared_secret, bundled.encode()
            )
            packet = Packet(
                route_type=RouteType.FLOOD,
                payload_type=PayloadType.PATH,
                payload=datagram.encode(),
                path_hash_size=request.path_hash_size,
            )
            self._schedule(packet, self._timings.server_response_delay, "path return + response")
            return

        datagram = Datagram.seal(
            session.public_key[0], self.node_hash, session.shared_secret, payload
        )
        packet = self._addressed(session, PayloadType.RESPONSE, datagram.encode())
        self._schedule(packet, self._timings.server_response_delay, "response")

    def _send_ack(self, session: ClientSession, checksum: bytes, *, delay: float) -> None:
        packet = self._addressed(session, PayloadType.ACK, Ack(checksum=checksum).encode())
        self._schedule(packet, delay, "message ack")

    def _send_cli_reply(
        self, session: ClientSession, request: TextMessage, text: str, *, delay: float
    ) -> None:
        now = self._clock.unique_now()
        if now == request.timestamp:
            # Firmware's workaround (MyMesh.cpp:518): an app's console shows the
            # request and the reply side by side, and identical timestamps make
            # the two indistinguishable in that view.
            now += 1

        budget = max_plaintext_len(len(session.out_path)) - TextMessage.PREFIX_LEN
        body = utf8_truncate(text, budget)
        plaintext = TextMessage(
            timestamp=now, txt_type=TxtType.CLI_DATA, attempt=0, text=body
        ).encode()
        datagram = Datagram.seal(
            session.public_key[0], self.node_hash, session.shared_secret, plaintext
        )
        packet = self._addressed(session, PayloadType.TXT_MSG, datagram.encode())
        self._schedule(packet, delay, "cli reply")

    def _addressed(
        self, session: ClientSession, payload_type: PayloadType, payload: bytes
    ) -> Packet:
        """Wrap a payload for one client, direct if we know the way there.

        Falling back to a flood is not a failure mode: it is how the first reply
        after a restart reaches a client whose PATH we have not re-learned.
        """
        if session.has_out_path:
            return Packet(
                route_type=RouteType.DIRECT,
                payload_type=payload_type,
                payload=payload,
                path=session.out_path,
                path_hash_size=session.path_hash_size,
            )
        return Packet(route_type=RouteType.FLOOD, payload_type=payload_type, payload=payload)

    def _schedule(self, packet: Packet, delay: float, description: str) -> None:
        """Queue a send for later, without holding up the receive loop."""

        async def transmit() -> None:
            await self._sink.send(packet, description=f"{self._slug} {description}")

        self._scheduler.call_later(delay, transmit, description=f"{self._slug} {description}")

    # -- adverts -------------------------------------------------------------

    async def send_advert(self, flood: bool) -> None:
        """Announce this room.

        A flood advert crosses the whole mesh and is how a new client discovers
        the room at all. A zero-hop advert reaches only nodes in direct earshot
        and exists to refresh neighbours cheaply -- it is a DIRECT packet with an
        empty path, which is exactly what "zero hop" means on this protocol
        (``Mesh::sendZeroHop``).
        """
        data = AdvertData(
            node_type=AdvertType.ROOM,
            name=self._settings.name,
            latitude=self._settings.latitude,
            longitude=self._settings.longitude,
        )
        advert = Advert.create(self._identity, self._clock.unique_now(), data)
        packet = Packet(
            route_type=RouteType.FLOOD if flood else RouteType.DIRECT,
            payload_type=PayloadType.ADVERT,
            payload=advert.encode(),
        )
        # Firmware de-prioritises flooded adverts (priority 3 in Mesh::sendFlood)
        # so they never delay a reply someone is waiting on.
        await self._sink.send(
            packet,
            priority=3 if flood else 0,
            ttl=ADVERT_SEND_TTL,
            description=f"{self._slug} {'flood' if flood else 'zero-hop'} advert",
        )

    async def run_advert_loop(self) -> None:
        """Advertise on startup, then on the two configured intervals.

        The startup advert is what makes a restarted room reachable again
        without waiting out a six-hour interval -- meshcore-pi sends its first
        advert before its link is up, so it is lost.
        """
        await self.send_advert(flood=True)

        flood_interval = self._settings.advert_flood_interval
        local_interval = self._settings.advert_local_interval
        if not flood_interval and not local_interval:
            return

        now = self._clock.monotonic()
        next_flood = now + flood_interval if flood_interval else None
        next_local = now + local_interval if local_interval else None

        while True:
            deadlines = [d for d in (next_flood, next_local) if d is not None]
            await self._clock.sleep(max(0.0, min(deadlines) - self._clock.monotonic()))
            now = self._clock.monotonic()

            # Flood wins a tie, and re-arms the local timer too, so the two do
            # not stack up and put two adverts on the air back to back.
            if next_flood is not None and now >= next_flood:
                await self.send_advert(flood=True)
                next_flood = now + flood_interval if flood_interval else None
                next_local = now + local_interval if local_interval else None
            elif next_local is not None and now >= next_local:
                await self.send_advert(flood=False)
                next_local = now + local_interval if local_interval else None

    # -- the push loop -------------------------------------------------------

    def _pause_pushes(self) -> None:
        """Hold pushes off for a moment after a reply or a new post."""
        self._next_push = self._clock.monotonic() + self._timings.push_notify_delay

    async def run_push_loop(self) -> None:
        """Push owed posts to one client at a time, forever.

        Strictly one outstanding push per client. Two in flight would race:
        both ACKs match on a 4-byte hash, and ``sync_since`` would advance past
        a post whose push was never acknowledged.
        """
        while True:
            wait = self._next_push - self._clock.monotonic()
            if wait > 0:
                await self._clock.sleep(wait)
                continue

            pushed = await self.push_once()
            interval = (
                self._timings.sync_push_interval if pushed else self._timings.idle_push_interval
            )
            self._next_push = self._clock.monotonic() + interval

    async def push_once(self) -> bool:
        """One round-robin step. Returns whether anything went out."""
        self._expire_pending_acks()
        if not self._sessions:
            return False

        ordered = list(self._sessions.values())
        self._round_robin %= len(ordered)
        session = ordered[self._round_robin]
        self._round_robin = (self._round_robin + 1) % len(ordered)

        if session.pending_ack is not None:
            return False
        if session.last_activity == 0:
            return False
        if session.push_failures >= self._timings.max_push_failures:
            # Left alone until it talks to us again, which resets the counter.
            # Otherwise a client that has gone out of range costs the whole room
            # airtime for as long as it stays away.
            return False

        if session.welcome:
            await self._push_welcome(session)
            return True

        not_newer_than = self._clock.now() - self._timings.post_sync_delay
        post = await self._store.run(
            lambda db: repo.next_unsynced_post(
                db,
                self._room_id,
                session.public_key,
                session.sync_since,
                not_newer_than=not_newer_than,
            )
        )
        if post is None:
            return False

        await self._push(
            session,
            posts.build_push(
                post.post_ts,
                post.author_public_key,
                post.text,
                path_bytes=len(session.out_path),
            ),
            post_ts=post.post_ts,
            is_welcome=False,
            description="post push",
        )
        await self._store.run(
            lambda db: repo.increment_counter(db, self._room_id, COUNTER_POST_PUSH)
        )
        return True

    async def _push_welcome(self, session: ClientSession) -> None:
        """Send the next welcome chunk, authored by the room itself.

        Welcome chunks are not posts: they are per-client, so they are not in
        the post table and acknowledging one does not move ``sync_since``.
        """
        await self._push(
            session,
            posts.build_push(
                self._clock.unique_now(),
                self._identity.public_key,
                session.welcome[0],
                path_bytes=len(session.out_path),
            ),
            post_ts=0,
            is_welcome=True,
            description="welcome push",
        )

    async def _push(
        self,
        session: ClientSession,
        plaintext: bytes,
        *,
        post_ts: int,
        is_welcome: bool,
        description: str,
    ) -> None:
        session.pending_ack = crypto.ack_hash(plaintext, session.public_key)
        session.push_post_ts = post_ts
        session.push_is_welcome = is_welcome

        datagram = Datagram.seal(
            session.public_key[0], self.node_hash, session.shared_secret, plaintext
        )
        packet = self._addressed(session, PayloadType.TXT_MSG, datagram.encode())
        is_flood = packet.route_type.is_flood
        session.ack_timeout = self._clock.monotonic() + self._timings.push_ack_timeout(
            is_flood=is_flood, hop_count=session.hop_count
        )
        await self._sink.send(packet, description=f"{self._slug} {description}")

    def _expire_pending_acks(self) -> None:
        now = self._clock.monotonic()
        for session in self._sessions.values():
            if session.pending_ack is None or now < session.ack_timeout:
                continue
            session.pending_ack = None
            session.push_failures += 1
            logger.info(
                "room %s: push to %s went unacknowledged (%d/%d)",
                self._slug,
                session.public_key[:4].hex(),
                session.push_failures,
                self._timings.max_push_failures,
            )

    # -- actions the CLI triggers -------------------------------------------

    async def clear_stats(self) -> None:
        await self._store.run(lambda db: repo.reset_counters(db, self._room_id))
        self._radio.reset()

    async def post_system_message(self, text: str) -> None:
        """Post as the room itself, for ``room.post``."""
        await self._store_post(self._identity.public_key, posts.decode_post_text(text.encode()))
        logger.info("room %s: system post", self._slug)
