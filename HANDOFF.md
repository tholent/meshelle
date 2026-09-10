# meshelle — agent handoff

Read this first. It carries the context that is **expensive to re-derive** and the
decisions that should **not be relitigated**. Everything else is in the code, which
is heavily commented on purpose — the *why* lives next to the *what*.

Last updated: Phase 5 complete (2026-09-10).

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
| Commits | 24, conventional commits |
| Tests | **607 passing**, ~6s |
| Coverage | **93%** overall |
| Gate | ruff + ruff format + mypy strict all clean |

**Phases 1–5 are done and committed.** Phases 6–8 remain.

```
✅ 1  toolchain + Apache-2.0 licensing
✅ 2  proto/      crypto, identity, packet + advert codecs      (1765 lines, 93-100%)
✅ 3  transport/  framing, serial/TCP/BLE, companion link        (1195 lines, 55-100%)
✅ 4  store/      SQLAlchemy models, Alembic, repositories       (1071 lines, 91-100%)
✅ 5  config/     strict schema, loader, line-number diagnostics (1104 lines, 96-98%)
⬜ 6  mesh/ + room/   the room server itself            ← NEXT, and the biggest
⬜ 7  app.py + cli.py  wiring, signals, subcommands
⬜ 8  docs         README, config.example.toml, PROTOCOL-NOTES.md
```

`src/meshelle/mesh/` and `src/meshelle/room/` contain only licensed `__init__.py`
stubs. `cli.py` does `--version` and nothing else. Those are Phase 6/7 work, not
oversights.

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

9. **Never share a key between two rooms, or with the companion node.** Two state
   machines answering one destination hash produce conflicting replies, duplicate
   ACKs, and mutually-overwriting sync cursors. Config validates this. (The
   companion's key *is* extractable via `CMD_EXPORT_PRIVATE_KEY`, enabled in the
   base `platformio.ini` — that is not a reason to use it.)

---

## 7. What the finished layers give Phase 6

`proto/` — pure functions and frozen dataclasses, no I/O:

- `identity`: `LocalIdentity`, `load_or_create_identity`, `verify_signature`
- `packet`: `Packet`, `Datagram`, `AnonRequest`, `TextMessage`, `LoginRequest`,
  `ServerRequest`, `PathReturn`, `Ack`
- `advert`: `Advert`, `AdvertData`
- `crypto`: `DecryptionError`, `ack_hash`, `packet_hash`
- `text`: `utf8_split`, `utf8_truncate`

```python
# companion/ — already handles reconnect, queueing, heartbeat
link = CompanionLink(lambda: SerialTransport(port))
asyncio.create_task(link.run())
info = await link.wait_ready()  # bound it with asyncio.timeout
await link.send_packet(raw, priority=0, ttl=..., description="lobby advert")
async for received in link.packets():  # ReceivedPacket(raw, snr, rssi)
    ...

# store/ — repo functions are sync, dispatched to the DB thread
post = await store.run(lambda s: repo.add_post(s, room_id, author, text, ts))
owed = await store.run(
    lambda s: repo.next_unsynced_post(
        s, room_id, client_key, since, not_newer_than=now - POST_SYNC_DELAY_SECS
    )
)

# config/
settings = load_settings(path, overrides=cli_overrides)
room.role_for_member(pubkey)  # -> Role | None
room.passwords.as_pairs()  # -> [(Role, SecretStr)], strongest first
room.allow_unknown.role  # -> Role | None  (None == reject silently)
```

Repository semantics already enforced, so Phase 6 must not re-implement them:
`sync_since` only moves forward; the replay guard only rises; a post is never
returned to its own author; retention cannot delete an unsynced post;
`next_post_ts` survives an NTP step backwards.

---

## 8. Phase 6 — the room server (next)

Spec: `examples/simple_room_server/MyMesh.cpp`. Build:

```
mesh/dispatcher.py   demux inbound packets across rooms by dest hash
mesh/dedupe.py       packet_hash seen-table with TTL (also drops our own echoes)
mesh/scheduler.py    delayed sends (SERVER_RESPONSE_DELAY etc.)
mesh/clock.py        wall clock + unique timestamps
room/acl.py          member -> password -> allow_unknown resolution
room/server.py       login, post, push/ack loop, keep-alive, requests
room/posts.py        post ingestion + welcome message splitting
room/stats.py        the 52-byte ServerStats struct
room/admin_cli.py    over-the-air CLI (TXT_TYPE_CLI_DATA, admins only)
tests/fakes/client.py  THE CLIENT HALF of MeshCore — build this first
```

**Build `tests/fakes/client.py` first.** It is what makes every room assertion
possible: it must construct `ANON_REQ` logins, post, ACK, send keep-alives, and
decrypt pushes. Without it the room server cannot be tested end to end.

### The single most important detail

The login reply is **13 bytes**, and byte 7 carries the real permission value:

```
[ts:4][RESP_SERVER_LOGIN_OK=0][0][legacy_admin][permissions][rand:4][FIRMWARE_VER_LEVEL=1]
```

- `permissions` = `Permission.GUEST|READ_ONLY|READ_WRITE|ADMIN` (0–3).
  **meshcore-pi hardcodes this to 0, which is the bug that makes every room
  read-only.** Getting it right is the project's reason to exist.
- `legacy_admin` = `1` if admin, else `2` if permissions == 0, else `0`
- This is **invisible in logs** — it must be verified in a real app by checking
  that a compose box appears.

### Other Phase 6 requirements

- Flood-routed login → reply as `PAYLOAD_TYPE_PATH` with the response bundled;
  direct → plain `RESPONSE`. Mirror the request's route type and transport codes
  (unscoped floods get dropped by repeaters running `flood.max.unscoped=0`).
- Posts: role ≥ `read_write` → store + ACK. Guests and read-only get **neither**.
  A retry (same timestamp) re-ACKs without double-posting; older is a replay.
- Push: per-room round-robin, one outstanding push per client,
  `TXT_TYPE_SIGNED_PLAIN` with the author's 4-byte pubkey prefix, post held
  `POST_SYNC_DELAY_SECS=6`, `SYNC_PUSH_INTERVAL=1200ms`, ACK timeout
  4s+2s/hop direct or 12s flood, 3 failures → client goes quiet.
- `REQ_TYPE_KEEP_ALIVE` (direct only) → ACK with an appended unsynced-count byte.
- `REQ_TYPE_GET_STATUS` → 52-byte struct `<HHhhIIIIIIIIHhHHHH` + reflected timestamp.
- `REQ_TYPE_GET_ACCESS_LIST` (admin) → 6-byte pubkey prefix + permissions each.
- Admin CLI: `ver`, `clock`, `advert`, `advert.zerohop`, `clear stats`, `get acl`,
  `room.post <msg>`; explicit refusals for `setperm`/`set`/`password` explaining
  that config owns the ACL. Reflect the `XX|` prefix.
- Welcome message on first sync (`sync_since == 0`), split with `utf8_split`.
- **Hash collisions across rooms must be handled, not assumed away** — the dest
  hash is one byte. MAC verification disambiguates. This needs an explicit test.
- ADVERT packets can be ignored entirely: a room learns a client's public key from
  the login itself, so there is no contact book.

---

## 9. Phases 7–8

**7 — app + CLI:** `asyncio.TaskGroup` supervision, `upgrade_to_head` at startup,
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
- The approved plan is at `~/.claude/plans/eventual-questing-whistle.md`.
- If you want this file auto-loaded each run, reference it from a `CLAUDE.md`.
