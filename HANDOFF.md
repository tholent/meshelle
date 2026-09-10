# meshelle — agent handoff

Read this first. It carries the context that is **expensive to re-derive** and the
decisions that should **not be relitigated**. Everything else is in the code, which
is heavily commented on purpose — the *why* lives next to the *what*.

Last updated: Phase 6 complete (2026-09-10).

---

## 1. What this is

A single-purpose **MeshCore room server** that runs on a computer (target: a Pi)
with a MeshCore companion node attached over USB. It is *not* a repeater, not a
companion emulator, not a chat client.

The architecture turn that makes it work: **the companion node is a bare radio
modem, not a peer.** Companion firmware has no ACL, no post store, no sync logic,
so it cannot *be* a room server. meshelle therefore owns the whole mesh endpoint —
its own Ed25519 identity per room, its own packet construction and encryption — and
uses the node only to get bytes on and off the air:

- **TX:** `CMD_SEND_RAW_PACKET = 65`, frame `[65][priority][raw packet]`
- **RX:** `PUSH_CODE_LOG_RX_DATA = 0x88`, frame `[0x88][snr*4 int8][rssi int8][raw packet]`,
  emitted unconditionally by `Dispatcher::checkRecv()` — no logging mode to enable

Why it exists: firmware room servers cap at 20 clients / 32 posts in RAM, and
`meshcore-pi` (the only other Python option) has a hardcoded `0` ACL byte in its
login reply that makes **every room it hosts read-only to current apps**, plus a
startup advert race, a missing device-query timeout, and config keys whose
documented spelling the code does not read.

---

## 2. Current state

| | |
|---|---|
| Branch | `main` (was `master`; renamed, no remote) |
| Commits | 37, conventional commits |
| Tests | **802 passing**, ~16s |
| Coverage | **94%** overall |
| Gate | ruff + ruff format + mypy strict all clean |

**Phases 1–6 are done and committed.** Phases 7–8 remain.

```
✅ 1  toolchain + Apache-2.0 licensing
✅ 2  proto/      crypto, identity, packet + advert codecs      (1765 lines, 93-100%)
✅ 3  transport/  framing, serial/TCP/BLE, companion link        (1195 lines, 55-100%)
✅ 4  store/      SQLAlchemy models, Alembic, repositories       (1071 lines, 91-100%)
✅ 5  config/     strict schema, loader, line-number diagnostics (1104 lines, 96-98%)
✅ 6  mesh/ + room/   the room server itself           (1650 lines, 95-100%)
⬜ 7  app.py + cli.py  wiring, signals, subcommands      ← NEXT
⬜ 8  docs         README, config.example.toml, PROTOCOL-NOTES.md
```

`cli.py` still does `--version` and nothing else, and there is no `app.py`: that
is Phase 7 work, not an oversight. Nothing constructs a `Dispatcher` or a
`RoomServer` yet — Phase 6 built and tested the parts, Phase 7 wires them up.

---

## 3. How to work on this

```bash
uv sync --all-extras
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run pytest -q
```

All four must pass before a commit. Then:

```bash
python3 scripts/add_license_headers.py   # after adding any .py file
```

**Commit convention** (the user asked for this explicitly):
- Conventional commits, on `main`, no feature branches
- **Commit at the end of each phase, in as many commits as the phase needs** —
  typically one per module plus one for its tests
- Commit bodies explain *why*, and name the failure mode a choice prevents
- Footer on every commit:
  ```
  Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01RsHdBcvRH7wnH9gQoXmtsz
  ```
- ⚠️ **Stage explicitly — never `git add -A` before a commit.** Doing that once
  swallowed an entire phase into one commit and needed a soft reset to redo.

**Testing standard:** no coverage-padding tests. Every test should name a real
behaviour or a real failure mode. Where a test encodes protocol semantics, say so
in the docstring. Prefer Event-driven waits over `asyncio.sleep` polling.

---

## 4. Reference checkouts — keep these

```
~/src/meshcore-refs/MeshCore      # THE authority for every wire-format detail
~/src/meshcore-refs/meshcore-pi   # reference only; never a dependency
```

Re-clone if missing:

```bash
mkdir -p ~/src/meshcore-refs && cd ~/src/meshcore-refs
git clone --depth 1 https://github.com/meshcore-dev/MeshCore.git
git clone --depth 1 https://github.com/brianwiddas/meshcore-pi.git
```

**Do not guess wire constants.** Every value in `proto/constants.py` cites its
source file. The highest-value files in the firmware repo:

| Path | What it settles |
|---|---|
| `docs/packet_format.md` | header bits, path-length encoding |
| `docs/payloads.md` | payload layouts (see trap #5 below) |
| `docs/companion_protocol.md` | companion framing, push codes |
| `examples/simple_room_server/MyMesh.cpp` | **the room state machine** — Phase 6's spec |
| `examples/companion_radio/MyMesh.cpp` | command/response/push/error codes |
| `src/Utils.cpp` | `encryptThenMAC`, `MACThenDecrypt`, `sha256` fragment order |
| `src/Packet.cpp` | `calculatePacketHash`, `readFrom`, `isValidPathLen` |
| `src/helpers/ClientACL.h` | `PERM_ACL_*` values |

---

## 5. Decisions already made — do not relitigate

**User's explicit choices** (asked and answered; changing these needs the user):

| Decision | Choice |
|---|---|
| Storage | SQLite via **SQLAlchemy + Alembic** |
| ACL model | **Config-only, fully declarative.** `setperm` over the air is refused |
| Transports | Serial + TCP now, BLE behind the `[ble]` extra |
| Identity | Generate seeds; also import MeshCore 64-byte expanded keys |
| DB threading | **Sync SQLAlchemy on a dedicated single-worker thread** |
| Migrations | **Auto-upgrade on startup** |
| Licence | Apache-2.0, per-file headers, enforced by a test |
| Git | Conventional commits on `main`, per-phase |

**Engineering calls made during implementation** (documented in commit bodies):

- **`cryptography` only** — no pycryptodome, no vendored pure-Python curve math.
  meshcore-pi's Montgomery ladder is replaced by OpenSSL X25519, proven equivalent
  by a test that transcribes the firmware's ladder as an independent oracle.
- **`pydantic-settings` dropped** — the loader merges layers itself because
  explicit precedence is clearer and better-diagnosed. `extra="forbid"` is plain
  pydantic. Nothing imported it, so shipping it would be dead weight.
- **`companion` is a required config section** — no sensible default for *which
  node*, and a `default_factory` that fails its own validation masks every other
  error.
- **Frame-oriented transport abstraction** — because BLE is frame-oriented
  (one GATT notification == one frame, no length prefix) while serial/TCP are
  stream-oriented with a 3-byte header. Frames are the level all three agree on.
- **No timeouts on stream reads** — a cancelled read mid-frame desynchronises the
  stream. A reader task parses into a bounded queue; callers time out on the queue.
- **`Role.may_post` is stricter than firmware.** Firmware only refuses
  `PERM_ACL_GUEST`, so it lets a "read only" client post
  (`simple_room_server/MyMesh.cpp:480`). meshelle honours the name; the wire byte
  is still `1` so apps label it correctly.
- **A member's declared role wins over any password.** Firmware consults its ACL
  only when the password field is blank (`MyMesh.cpp:337`), so a demoted member
  who still knows the admin password stays an admin. meshelle checks the member
  list first, which is what makes a demotion in the config actually demote.
- **Flooded replies go out un-scoped**, not with the request's transport codes
  mirrored. See trap #10 — mirroring them is worse than sending none.
- **Waiting is part of the `Clock` interface.** Both room loops and the scheduler
  wait via `clock.sleep`, never `asyncio.sleep` directly. A loop that reads an
  injected clock but sleeps on the real one measures one timeline and waits on
  another; it also makes every interval test cost its own interval. Tests now run
  the room against its **real** protocol delays for free.
- **Clients are rehydrated from the database at startup, but a password-earned
  role is not.** The password is never recorded, so a restart cannot re-verify it
  — restoring the role anyway would mean removing a password from the config
  achieved nothing until every client happened to log in again. Rehydrated
  strangers get `Role.GUEST` and must log in again before they can post; their
  owed posts still get pushed, which is what the restart case needs.

---

## 6. Traps — these have already bitten once

1. **`asyncio.TaskGroup` wraps child exceptions in an `ExceptionGroup`.** A plain
   `except CompanionError` does not match through it. `CompanionLink.run` uses
   `except*` and re-raises the *leaf* via `_first_leaf`, so callers get an
   actionable error rather than a group to unwrap. Any new supervisor needs the
   same treatment.

2. **`filterwarnings = ["error"]` is on, deliberately.** It has already caught a
   leaked `StreamWriter`, an orphaned `sqlite3.Connection`, and an Alembic
   `path_separator` deprecation. When it fires, **fix the cause**, do not loosen
   the filter. Note it often blames whichever *unrelated* test ran next.

3. **`MAX_FRAME_SIZE = 176` caps both directions.** A received packet larger than
   173 bytes is never mirrored to us at all; an outbound frame must stay under 174.
   Room traffic fits; long-path flood packets from others may be invisible.

4. **WAL and `synchronous=NORMAL` are a pair.** In WAL mode NORMAL skips the commit
   fsync safely; in rollback-journal mode it risks corruption. Dropping WAL without
   restoring `FULL` turns a durability trade-off into a data-loss bug. Said in situ
   in `store/db.py`.

5. **`docs/payloads.md` is wrong about one thing.** The PATH payload's *inner*
   `path_len` uses the same packed encoding as the outer packet's (hop count in
   bits 0-5, hash size − 1 in bits 6-7), not the plain byte count the docs imply.
   `Mesh::createPathReturn` is the authority. Pinned by a test.

6. **A pragma failing orphans the raw connection.** SQLAlchemy has not adopted it
   yet, so nothing closes it. `_apply_pragmas` closes it before re-raising.

7. **`CMD_SEND_RAW_PACKET` is undocumented** in `docs/companion_protocol.md`
   despite existing in firmware. Treat as supported-but-unversioned.
   `CompanionLink.probe_raw_packet_support` checks for it **without transmitting**:
   a malformed 2-byte packet gets `ILLEGAL_ARG` if the command exists and
   `UNSUPPORTED_CMD` if not.

8. **The companion hears its own rooms.** Flooded room adverts reach the node,
   which auto-adds each room as a contact and pushes `NEW_ADVERT` /
   `CONTACTS_FULL` at us. Ignored by design; operator docs should suggest
   `manual_add_contacts`.

9. **Mirroring transport codes on a flooded reply gets it dropped.** A transport
   code is an HMAC over *that packet's own payload*, keyed by a region key
   (`TransportKeyStore.cpp:4`). Our reply has a different payload, so a mirrored
   code matches no region, and a repeater's `allowPacketForward` drops any flood
   whose region resolved to NULL (`simple_repeater/MyMesh.cpp:440`). An un-scoped
   `ROUTE_TYPE_FLOOD` reply resolves to the wildcard region instead and is
   forwarded. meshelle has no region key configured, so `chooseReplyScope` would
   return `REPLY_SCOPE_NONE` for it in every case — which is what it does.
   *If* scoped replies are ever wanted, the config needs a region transport key;
   there is no way to fake one. (An earlier draft of this document said to mirror
   the codes. It was wrong.)

10. **A `SIGNED_PLAIN` message is trimmed from offset 9, not 5.** The 4-byte
   author key prefix sits between the flags byte and the text, and a public key
   often contains a zero byte. Firmware's client scans from `&data[9]`
   (`BaseChatMesh.cpp:273`). Scanning from 5 truncates such a message to nothing
   *and* computes an ACK the room never expects, so that author's posts can never
   be synced to anyone. Fixed in `TextMessage.decode`; pinned by a test.

11. **Retention policies are OR, not AND.** `post_retention` and `max_posts` are
   independent reasons to delete. ANDing them (as `prune_posts` originally did)
   makes `max_posts` a dead letter whenever a retention age is also set — which
   it is by default — so a busy room grows past its declared cap. The sync floor
   is still ANDed: a post no client has been sent is never deleted, so a strict
   `max_posts` legitimately does nothing while someone is behind.

12. **Never share a key between two rooms, or with the companion node.** Two state
   machines answering one destination hash produce conflicting replies, duplicate
   ACKs, and mutually-overwriting sync cursors. Config validates this. (The
   companion's key *is* extractable via `CMD_EXPORT_PRIVATE_KEY`, enabled in the
   base `platformio.ini` — that is not a reason to use it.)

---

## 7. What the finished layers give Phase 7

`proto/` — pure functions and frozen dataclasses, no I/O:

- `identity`: `LocalIdentity`, `load_or_create_identity`, `verify_signature`
- `packet`: `Packet`, `Datagram`, `AnonRequest`, `TextMessage`, `LoginRequest`,
  `ServerRequest`, `PathReturn`, `Ack`, `max_plaintext_len`
- `advert`: `Advert`, `AdvertData`
- `crypto`: `DecryptionError`, `ack_hash`, `packet_hash`
- `text`: `utf8_split`, `utf8_truncate`

```python
# companion/ — already handles reconnect, queueing, heartbeat
link = CompanionLink(lambda: SerialTransport(port))
asyncio.create_task(link.run())
info = await link.wait_ready()  # bound it with asyncio.timeout

# store/ — repo functions are sync, dispatched to the DB thread
post = await store.run(lambda s: repo.add_post(s, room_id, author, text, ts))

# config/
settings = load_settings(path, overrides=cli_overrides)
room.role_for_member(pubkey)  # -> Role | None
```

Repository semantics already enforced, so nothing above should re-implement them:
`sync_since` only moves forward *on an ACK* (`force_sync_since` is the deliberate
exception, for a keep-alive); the replay guard only rises; a post is never
returned to its own author; retention cannot delete an unsynced post;
`next_post_ts` survives an NTP step backwards.

---

## 8. Phase 6 — the room server (done)

```
mesh/clock.py        wall + monotonic + sleep, all injectable      100%
mesh/dedupe.py       packet_hash seen-table, TTL and capacity      100%
mesh/scheduler.py    delayed sends; `Timings` holds every delay     99%
mesh/dispatcher.py   demux by dest hash; the only place we TX       97%
room/acl.py          member -> password -> allow_unknown           100%
room/posts.py        post text in and out, welcome splitting       100%
room/stats.py        the 52-byte ServerStats struct + RadioStats   100%
room/admin_cli.py    the over-the-air console, and its refusals    100%
room/server.py       login, post, push/ack, keep-alive, requests    95%
tests/fakes/client.py  the client half of MeshCore, for real
tests/fakes/room.py    ManualClock, CapturingSink, `drain`
```

**What was built, and the parts that are easy to get wrong:**

- **Byte 7 of the login response is the permission level.** This is the whole
  reason the project exists, and it is invisible in logs. It is asserted through
  `tests.fakes.client.assert_login_grants`, whose failure message says what a
  zero there means.
- **A refused login gets no reply at all** — silence, not an error. A wrong
  password is then indistinguishable from being out of range.
- **Flood in → `PAYLOAD_TYPE_PATH` with the response bundled inside; direct in →
  plain `RESPONSE`.** The PATH form is how the client learns the route here; a
  plain reply would answer the question and leave it flooding forever. Flooded
  replies are un-scoped (trap #9).
- **The dispatcher is the only place that transmits**, so every outbound packet
  is marked in the seen-table first. That is what stops us processing our own
  packets when a repeater echoes them back through the node.
- **Hash collisions are handled, not assumed away**, in both directions: two
  rooms sharing a destination byte, and two clients sharing a source byte. The
  MAC disambiguates; both have explicit tests.
- **One outstanding push per client, round-robin.** Two in flight would race on
  a 4-byte ACK hash and advance `sync_since` past a post never acknowledged.
- **Welcome chunks are pushed like posts but are not posts** — per-client, not in
  the post table, and acknowledging one does not move `sync_since`.
- **The admin CLI refuses `setperm`/`set`/`password`/`clock sync`/`time`/`erase`/
  `reboot` by name**, each saying where the setting actually lives. Silently
  ignoring `setperm` would let an operator believe someone is an admin who is not.

**Deliberately not done:** `REQ_TYPE_GET_TELEMETRY_DATA` (there are no sensors on
a host running this), and `ADVERT` handling (a room learns a client's key from
the login itself, so it keeps no contact book).

## 9. Phases 7–8

**7 — app + CLI:** nothing constructs the Phase 6 objects yet. The wiring is:
one `Store`, one `CompanionLink`, one `SeenTable`/`RadioStats`, one `Scheduler`,
one `UniqueClock`, and one `RoomServer` per configured room, all handed to a
single `Dispatcher`, with `dispatcher.run(link.packets())` plus each room's
`run_push_loop()` and `run_advert_loop()` under one `TaskGroup` (see trap #1).
`RoomServer.start()` must run before the loops; `RoomServer.apply_settings()` is
the SIGHUP path. `asyncio.TaskGroup` supervision, `upgrade_to_head` at startup,
SIGHUP reload (re-resolve roles; keep sync cursors), SIGTERM graceful shutdown,
stderr logging. Subcommands: `run`, `check-config`, `keygen`, `doctor`, `db`.
`doctor` should use `probe_raw_packet_support` and report the node's identity.

**8 — docs:** README (credit meshcore-pi as prior art), `config.example.toml`,
`docs/PROTOCOL-NOTES.md` recording byte layouts with firmware line references, and
a record of dependency licences.

---

## 10. Verification on real hardware

Unit tests cannot prove the thing works on the air. The end-to-end sequence:

```bash
uv run meshelle keygen --room lobby
uv run meshelle check-config --config room.toml
uv run meshelle doctor --config room.toml     # probes CMD 65, reports the node
uv run meshelle run --config room.toml --log-level debug
```

1. The room advert appears in the MeshCore app; add it as a contact.
2. Log in as admin — **the app must offer a compose box, not a read-only view.**
   This is the ACL byte, and it cannot be checked any other way.
3. Post from client A; client B receives it within ~10s.
4. Kill mid-sync, restart: B receives the missed post exactly once.
5. `SIGHUP` after adding a member: the new pubkey logs in with its declared role.

---

## 11. Outstanding / optional

- Four upstream bug reports worth filing against `meshcore-pi`: the config key
  mismatch, the startup advert race, the missing device-query timeout, and the
  ACL byte.
- `transport/ble.py` is at 55% — the happy path needs hardware and belongs to
  `doctor`, not unit tests. Do not fake it with mocks for a coverage number.
- Scoped (`TRANSPORT_FLOOD`) replies would need a region transport key in the
  config. Un-scoped works on any mesh whose repeaters allow wildcard flooding,
  which is the default; a mesh running `flood.max.unscoped=0` would need this.
- `REQ_TYPE_GET_TELEMETRY_DATA` returns nothing. If a host ever grows sensors
  worth reporting, that is where they go.
- The approved plan file (`~/.claude/plans/eventual-questing-whistle.md`) is
  gone; this document is the plan now.
- If you want this file auto-loaded each run, reference it from a `CLAUDE.md`.
