# meshelle — agent handoff

Read this first. It carries the context that is **expensive to re-derive** and the
decisions that should **not be relitigated**. Everything else is in the code, which
is heavily commented on purpose — the *why* lives next to the *what*.

Last updated: Phase 8 complete — all phases done (2026-09-10).

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
| Commits | 44, conventional commits |
| Tests | **898 passing**, ~15s |
| Coverage | **96%** overall |
| Gate | ruff + ruff format + mypy strict all clean |

**All eight phases are done and committed.** What remains is §11: verification
on real hardware, which no unit test can stand in for.

```
✅ 1  toolchain + Apache-2.0 licensing
✅ 2  proto/      crypto, identity, packet + advert codecs      (1765 lines, 93-100%)
✅ 3  transport/  framing, serial/TCP/BLE, companion link        (1195 lines, 55-100%)
✅ 4  store/      SQLAlchemy models, Alembic, repositories       (1071 lines, 91-100%)
✅ 5  config/     strict schema, loader, line-number diagnostics (1104 lines, 96-98%)
✅ 6  mesh/ + room/   the room server itself           (1650 lines, 95-100%)
✅ 7  app.py + cli.py + logs.py + paths.py  the wiring   (560 lines, 97-100%)
✅ 8  docs         README, example config, protocol notes, systemd unit
```

Everything runs and everything is documented. `meshelle run` hosts the
configured rooms; `check-config`, `keygen`, `doctor` and `db` are implemented;
the README, `config.example.toml`, `docs/PROTOCOL-NOTES.md`,
`docs/DEPENDENCIES.md` and `packaging/meshelle.service` all ship.

**Next: §11.** Nothing here has touched a radio.

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
- **Relative paths in the config are relative to the config *file*.** Not to the
  working directory: a systemd unit runs with `WorkingDirectory=/`, so the same
  file would give the service `/data` and the operator `./data` — two databases,
  one config. One rule in `paths.py`, used by the database, the key files and
  the log file alike.
- **Logging always goes to stderr; a file sink is additional.** meshcore-pi's
  `basicConfig(filename=...)` redirects everything, so raising the log level
  looks like it does nothing and a service start looks silent.
- **A SIGHUP reload is all-or-nothing, and only re-resolves what can change.**
  An invalid file is refused whole, keeping the running configuration — losing
  a room's ACL to a typo in an unrelated section is the worst outcome of a
  routine edit. Companion settings, `data_dir`, added rooms and changed room
  identities are *named* as needing a restart rather than silently ignored; a
  removed room keeps running, because dropping it mid-sync would abandon what
  it still owes its clients.
- **Diagnostics create nothing.** `check-config` and `doctor` never generate a
  key file and never migrate; a command asked what is missing must not make it
  stop being missing. Only `run` creates state, and it logs a generated room
  identity at WARNING.
- **`Dispatcher.add_room` exists because the wiring is circular.** A room
  transmits through the dispatcher and the dispatcher routes to the room; one
  of them has to be attachable after construction.
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

## 7. What each layer gives its callers

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

## 9. Phase 7 — app + CLI (done)

```
paths.py     one rule for resolving a relative config path            100%
logs.py      stderr always, optional file, text or JSON, idempotent    97%
app.py       identities, wiring, TaskGroup supervision, signals        99%
cli.py       run / check-config / keygen / doctor / db                 97%
```

The shape, and why it is that shape:

- **One of everything the node owns, one `RoomServer` per room.** One `Store`,
  one `CompanionLink`, one `SeenTable`, one `RadioStats`, one `Scheduler`, one
  `UniqueClock` — all shared — behind a single `Dispatcher`. A per-room
  seen-table would let one room reprocess a packet another room's reply had
  already put on the air.
- **`RoomServer.start()` runs before the loops.** A push loop that started first
  would see no sessions and idle while owed posts sat unsent.
- **`link.packets()` is held, not passed inline**, so shutdown can `aclose()` it.
  A garbage-collected async generator is reported as "async generator ignored
  GeneratorExit" and, under `filterwarnings = ["error"]`, fails unrelated code.
- **`_identify_node` refuses to share the companion's key** (trap #12). The
  config cannot catch this: the node's key is only known once it has answered.
- **`plan_rooms` catches identity collisions the config validator cannot** — a
  default `<slug>.key` colliding with another room's explicit `key_file`, or a
  seed and its expanded form given to two rooms as different-looking strings.
- **Shutdown cancels the children explicitly.** `TaskGroup` ignores a child it
  sees as cancelled, so the body cancels each task after `link.stop()`; the
  failure path uses `except*` and `first_leaf` (trap #1).
- `CompanionLink._handshake` and `_first_leaf` are now public (`handshake`,
  `first_leaf`) — `doctor` drives one connection itself rather than starting the
  reconnect supervisor, which would report a timeout instead of the real error.

CLI surface:

```bash
meshelle run          -c room.toml [--log-level debug] [--log-format json]
meshelle check-config -c room.toml     # valid? and what does it actually say
meshelle keygen       -c room.toml [--room lobby] [--force]
meshelle doctor       -c room.toml     # probes CMD 65 without transmitting
meshelle db           current | upgrade | downgrade REV
```

Config is found at `--config`, then `$MESHELLE_CONFIG`, then `./meshelle.toml`,
then `/etc/meshelle/meshelle.toml`. Exit codes: 0 fine, 1 meshelle cannot
proceed (message on stderr, never a traceback), 2 bad invocation.

Signals: `SIGTERM`/`SIGINT` stop; `SIGHUP` reloads. Both are exercised for real
in `tests/test_app.py::TestSignals` — raised at the process — because a test
that called `request_stop()` directly would pass with no handler installed at
all, and the first `systemctl reload` would be what found out.

## 10. Phase 8 — docs (done)

```
README.md                     what it is, why, quickstart, the CLI, the console
config.example.toml           commented in full; the file operators copy
docs/PROTOCOL-NOTES.md        every byte layout, with its firmware citation
docs/DEPENDENCIES.md          licence record; all permissive, no copyleft
packaging/meshelle.service    systemd unit, ExecReload=SIGHUP, hardened
tests/test_docs.py            the drift guard
```

**Documentation drift is silent, so three claims are tested rather than
trusted** (`tests/test_docs.py`):

- `config.example.toml` validates as shipped, and carries a *working* instance
  of each feature it documents — a commented-out example is not exercised by
  anything. It uses `env:` for its passwords on purpose, so it ships no working
  password and an operator who forgets the variable gets an error naming it.
- Every subcommand the README's table promises still exists, and every relative
  link in it resolves.
- Every direct dependency in `pyproject.toml` appears in `docs/DEPENDENCIES.md`.
  A dependency added without recording its licence is precisely the omission
  that record exists to prevent — the same reasoning as the licence-header test.

`PROTOCOL-NOTES.md` is the place to look before touching `proto/`. It carries
the two places MeshCore's published docs are wrong (traps #5 and #10) and the
one thing they omit (trap #7), each with the firmware source that settles it.

Claims in the README were checked against the firmware rather than memory:
`MAX_CLIENTS 20` is `ClientACL.h:37`, `MAX_UNSYNCED_POSTS 32` is
`simple_room_server/MyMesh.h:69`. Both are `#ifndef` defaults, and the README
says so.

## 11. Verification on real hardware

Unit tests cannot prove the thing works on the air. The end-to-end sequence:

```bash
uv run meshelle keygen       --config room.toml --room lobby
uv run meshelle check-config --config room.toml
uv run meshelle doctor       --config room.toml   # probes CMD 65, reports the node
uv run meshelle run          --config room.toml --log-level debug
```

1. The room advert appears in the MeshCore app; add it as a contact.
2. Log in as admin — **the app must offer a compose box, not a read-only view.**
   This is the ACL byte, and it cannot be checked any other way.
3. Post from client A; client B receives it within ~10s.
4. Kill mid-sync, restart: B receives the missed post exactly once.
5. `SIGHUP` after adding a member: the new pubkey logs in with its declared role.

---

## 12. Outstanding / optional

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
- `meshelle run` cannot add or remove a *room* on SIGHUP, only re-resolve the
  ones already running. Doing it live would mean creating a `RoomServer` and
  attaching it to a `Dispatcher` mid-flight, and tearing one down without
  abandoning what it owes its clients. A restart is cheap; this is not.
- If you want this file auto-loaded each run, reference it from a `CLAUDE.md`.
