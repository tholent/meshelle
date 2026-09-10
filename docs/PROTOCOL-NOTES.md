# MeshCore protocol notes

What meshelle had to work out to speak MeshCore, written down so the next
person does not have to work it out again.

**The firmware is the authority, not this file and not MeshCore's own docs.**
Every layout below cites the source that settles it. Re-verify against a
checkout before trusting anything here:

```bash
git clone --depth 1 https://github.com/meshcore-dev/MeshCore.git
```

Constants live in `src/meshelle/proto/constants.py`, which cites a source file
per group. Nothing in meshelle guesses a wire value.

Integers are **little-endian** throughout.

---

## 1. The companion node is a modem

The architecture turn the whole project rests on: a stock MeshCore companion
node has no ACL, no post store and no sync logic, so it cannot *be* a room
server. But it will hand you raw packets in both directions, and that is
enough — meshelle owns the mesh endpoint, generates each room's Ed25519
identity, and builds, encrypts and signs every packet itself.

| Direction | Mechanism |
|---|---|
| TX | `CMD_SEND_RAW_PACKET = 65`, frame `[65][priority][raw packet]` |
| RX | `PUSH_CODE_LOG_RX_DATA = 0x88`, frame `[0x88][snr×4 int8][rssi int8][raw packet]` |

Two things about this are worth knowing before relying on it:

- **`CMD_SEND_RAW_PACKET` is undocumented.** It exists in firmware but not in
  `docs/companion_protocol.md`. Treat it as supported-but-unversioned.
  `meshelle doctor` probes for it *without transmitting*: a deliberately
  malformed 2-byte packet gets `ERR_CODE_ILLEGAL_ARG` if the command exists and
  `ERR_CODE_UNSUPPORTED_CMD` if it does not.
- **`LOG_RX_DATA` is unconditional.** `Dispatcher::checkRecv()` emits it for
  every packet heard, with no logging mode to enable first.

### Serial/TCP framing

```
outbound   '<' | uint16 length | payload
inbound    '>' | uint16 length | payload
```

BLE has no length prefix at all — one GATT notification is one frame. That is
why meshelle's transport abstraction is **frame-oriented**: frames are the only
level at which serial, TCP and BLE agree.

### `MAX_FRAME_SIZE = 176` caps both directions

`src/helpers/BaseSerialInterface.h`. A received packet larger than 173 bytes is
never mirrored to us at all, and an outbound frame must stay under 174. Room
traffic fits comfortably; long-path flood packets from other nodes may simply
be invisible to a host-side implementation.

---

## 2. Packet framing

`docs/packet_format.md`, `src/Packet.cpp`

```
[header:1][transport_codes:4?][path_length:1][path:N][payload]
```

The header byte is `0bVVPPPPRR`:

| Bits | Field | Values |
|---|---|---|
| 0-1 | route type | 0 `TRANSPORT_FLOOD`, 1 `FLOOD`, 2 `DIRECT`, 3 `TRANSPORT_DIRECT` |
| 2-5 | payload type | see below |
| 6-7 | version | only `0` (V1) exists |

`transport_codes` (two `uint16`) are present **only** for the two
`TRANSPORT_*` route types.

### `path_length` is not a byte count

This is the first thing that bites. It is packed:

| Bits | Meaning |
|---|---|
| 0-5 | hop count, 0-63 |
| 6-7 | hash size **minus one**, so `0b00` means 1-byte hashes |

The path therefore occupies `hop_count × hash_size` bytes
(`Packet::getPathByteLen`). A hash size of 4 is reserved and
`Packet::isValidPathLen` rejects it.

### Payload types

`src/Packet.h`. meshelle implements the starred ones.

| Value | Name | |
|---|---|---|
| 0x00 | `REQ` | ★ server requests |
| 0x01 | `RESPONSE` | ★ |
| 0x02 | `TXT_MSG` | ★ posts and CLI |
| 0x03 | `ACK` | ★ |
| 0x04 | `ADVERT` | ★ transmit only |
| 0x05 | `GRP_TXT` | |
| 0x06 | `GRP_DATA` | |
| 0x07 | `ANON_REQ` | ★ login |
| 0x08 | `PATH` | ★ |
| 0x09 | `TRACE` | |
| 0x0A | `MULTIPART` | |
| 0x0B | `CONTROL` | |
| 0x0F | `RAW_CUSTOM` | |

### Addressing is one byte

A datagram names its destination by `public_key[0]`, so 256 destinations share
a namespace with every node on the mesh. A packet addressed to `0x7A` may be
for your room, for a stranger's node, or for two of your own rooms at once. The
only proof is a matching 2-byte MAC, and **a mismatch is the normal case, not
an error** — firmware's `searchPeersByHash` returns up to four candidates and
tries each. meshelle does the same and logs a decryption failure at debug.

### Duplicate detection

`Packet::calculatePacketHash` — `sha256(payload_type || payload)[:8]`.

It deliberately excludes the path, so the same packet arriving by two routes
hashes identically. That is also what lets a sender recognise its *own* packet
echoed back by a repeater, which matters here: meshelle marks every outbound
packet in its seen-table **before** transmitting, because the echo can arrive
while the serial write is still in flight.

---

## 3. Payload layouts

`docs/payloads.md`, with the corrections noted.

Two shapes cover most of it:

```
Datagram      (REQ, RESPONSE, TXT_MSG, PATH)
              [dest_hash:1][src_hash:1][mac:2][ciphertext]

AnonRequest   (ANON_REQ)
              [dest_hash:1][sender_pubkey:32][mac:2][ciphertext]
```

Decrypted plaintext is always zero-padded to a cipher block, so every plaintext
codec recovers its true length from structure — a C string terminator, or a
fixed layout. Firmware does the same: it writes a NUL at the padded length and
calls `strlen`.

### Text message plaintext

```
[timestamp:4][flags:1][text...]
```

`flags` is `txt_type << 2 | attempt`, where `attempt` is a 2-bit retry counter.
Text types: `0` `PLAIN`, `1` `CLI_DATA`, `2` `SIGNED_PLAIN`.

> **`SIGNED_PLAIN` is trimmed from offset 9, not 5.** Four bytes of the
> author's public key sit between the flags byte and the text. A public key
> often contains a zero byte, so scanning for the C string terminator from
> offset 5 truncates such a message to nothing *and* computes an ACK the room
> never expects — after which that author's posts can never be synced to
> anyone. Firmware's client scans from `&data[9]` (`BaseChatMesh.cpp:273`).

### Login request plaintext (`ANON_REQ`)

```
[timestamp:4][sync_since:4][password C-string]
```

`sync_since` is the timestamp of the newest post the client already holds.
Zero means "I have nothing", which is what triggers a welcome message.

### Server request plaintext (`REQ`)

```
[timestamp:4][req_type:1][data...]
```

| Value | Request |
|---|---|
| 0x01 | `GET_STATUS` |
| 0x02 | `KEEP_ALIVE` |
| 0x03 | `GET_TELEMETRY_DATA` |
| 0x05 | `GET_ACCESS_LIST` |

### Response plaintext

Every `RESPONSE` begins with the reflected 4-byte request timestamp. **There is
no type tag** — the only way to tell a 13-byte login response from the start of
a status struct is to remember what was asked. A real app disambiguates the
same way, by the request it has outstanding.

### PATH plaintext

```
[path_length:1][path:N][extra_type:1][extra...]
```

> **The inner `path_length` uses the same packed encoding as the outer packet's**
> — hop count in bits 0-5, hash size minus one in bits 6-7. `docs/payloads.md`
> calls it "length of next field", which reads as a plain byte count and is not.
> `Mesh::createPathReturn` is the authority. meshelle pins this with a test.

`extra` carries a bundled reply: `extra_type` is a payload type, so a flooded
login is answered with a PATH containing the `RESPONSE`. That is how the client
learns the route at the same moment it learns its permission — a plain reply
would answer the question and leave it flooding forever.

### ACK

```
[checksum:4][trailer...]
```

The checksum is `sha256(data || peer_pubkey)[:4]` (`Utils::sha256`, two
fragments, hashed in order — the concatenation order matters and meshelle
asserts it). The trailer is optional; a keep-alive ACK uses it to carry the
number of posts still owed.

### Advert

```
[public_key:32][timestamp:4][signature:64][appdata:≤32]
```

The signature covers `public_key || timestamp || appdata` — **not** the packet
header or path — so it survives being re-flooded by repeaters.

`appdata` is self-describing via a leading flags byte:

```
[flags:1][lat:int32][lon:int32][feat1:uint16][feat2:uint16][name...]
```

The low nibble of `flags` is the node type (`0` none, `1` chat, `2` repeater,
`3` **room**, `4` sensor); the high bits say which optional fields follow
(`0x10` lat/lon, `0x20` feat1, `0x40` feat2, `0x80` name). Latitude and
longitude are degrees × 1e6 in a signed 32-bit integer. The name takes whatever
space is left, which is why a room with a location gets 23 bytes of name and
one without gets 31.

---

## 4. Cryptography

`src/Utils.cpp`, `src/Identity.cpp`

| Purpose | Primitive |
|---|---|
| Key agreement | X25519 |
| Cipher | AES-128-ECB, final partial block zero-padded |
| Authentication | HMAC-SHA256 truncated to **2 bytes** |

ECB and a 2-byte tag are weak. They are also the wire format: a room server
that "improves" them cannot talk to any MeshCore app.

Details that matter:

- The cipher key is the **first 16 bytes** of the shared secret
  (`CIPHER_KEY_SIZE = 16`); the MAC is keyed with the **full 32**.
- `ed25519_key_exchange` (`lib/ed25519/key_exchange.c`) clamps the low 32 bytes
  of the expanded private key exactly as RFC 7748 requires, and maps the peer's
  Ed25519 public key onto the Montgomery curve with `u = (y + 1)/(1 - y) mod p`.
  That is standard X25519, so OpenSSL computes it — there is no need for the
  pure-Python Montgomery ladder meshcore-pi carries. meshelle proves the
  equivalence with a test that transcribes the firmware ladder as an
  independent oracle.
- **MeshCore private keys are the expanded 64-byte `(a, RH)` pair**, not a
  32-byte seed. meshelle generates seeds (which enables the OpenSSL signing
  path) but imports either, and records both in its key file so a corrupted one
  is detected on load.

---

## 5. The room server state machine

Spec: `examples/simple_room_server/MyMesh.cpp`.

### Login

A client sends an `ANON_REQ` carrying a password and its `sync_since`. The room
answers with 13 bytes:

```
[now:4][RESP_SERVER_LOGIN_OK:1][0:1][legacy_admin:1][permissions:1][rand:4][ver:1]
   0-3         4                  5        6              7          8-11   12
```

> **Byte 7 is the client's permission level, and it is the reason this project
> exists.** `MyMesh.cpp:381`. Values are `0` guest, `1` read-only, `2`
> read-write, `3` admin (`src/helpers/ClientACL.h`). An app shows a compose box
> only when it reads 2 or better. meshcore-pi hardcodes a zero here, which is
> why every room it hosts is read-only in current apps — and the byte is
> invisible in logs, so nothing reports it.

Byte 5 is a legacy keep-alive interval firmware now always zeroes. Byte 6 is
the legacy admin flag apps read before byte 7 existed: `1` for admin, `2` when
the permissions byte is zero (which is how an older app tells "guest" from
"unknown"), otherwise `0`. Both are still sent — an older app reads them and a
newer one ignores them.

Bytes 8-11 are random. Without them two logins in the same second would produce
identical packet hashes, and the second reply would be suppressed as a
duplicate by every repeater it crossed.

> **A refused login gets no reply at all.** Not an error packet — silence. A
> wrong password is then indistinguishable from a room that is out of range,
> which denies an attacker a password oracle.

### Replies are delayed, never immediate

A client that has just transmitted is still turning its radio around. From
`MyMesh.cpp:3-13`:

| Constant | Value | What it delays |
|---|---|---|
| `SERVER_RESPONSE_DELAY` | 300 ms | a `REQ`/`ANON_REQ` reply |
| `TXT_ACK_DELAY` | 200 ms | the ACK for a received post |
| `REPLY_DELAY` | 1500 ms | a CLI reply, *on top of* the ACK delay |
| `PUSH_NOTIFY_DELAY` | 2000 ms | pushes, after a login reply or a new post |
| `SYNC_PUSH_INTERVAL` | 1200 ms | between push attempts |
| `PUSH_ACK_TIMEOUT_FLOOD` | 12000 ms | a flooded push must cross the mesh twice |
| `PUSH_TIMEOUT_BASE` + `FACTOR × (hops+1)` | 4000 + 2000 ms | a direct push |
| `POST_SYNC_DELAY` | 6 s | a post is held before it may be pushed |
| `MAX_PUSH_FAILURES` | 3 | before a client is left alone |

### Push, one at a time

Posts go out round-robin, **strictly one outstanding push per client**. Two in
flight would race: both ACKs match on a 4-byte hash, and the sync cursor would
advance past a post whose push was never acknowledged.

### Flooded replies go out un-scoped

A transport code is an HMAC over *that packet's own payload*, keyed by a region
key (`TransportKeyStore.cpp:4`). Mirroring a request's codes onto a reply with
a different payload produces a code that matches no region, and a repeater's
`allowPacketForward` drops any flood whose region resolved to NULL
(`simple_repeater/MyMesh.cpp:440`). An un-scoped `ROUTE_TYPE_FLOOD` reply
resolves to the wildcard region instead and is forwarded.

So: **send no transport codes, not the wrong ones.** Scoped replies would need
a region transport key in the config, and there is no way to fake one. A mesh
running `flood.max.unscoped=0` would need that; the default does not.

### `ServerStats` — 52 bytes

Answer to `REQ_TYPE_GET_STATUS`. Struct format `<HHhhIIIIIIIIHhHHHH`:

| Offset | Type | Field |
|---|---|---|
| 0 | uint16 | `batt_milli_volts` |
| 2 | uint16 | `curr_tx_queue_len` |
| 4 | int16 | `noise_floor` |
| 6 | int16 | `last_rssi` |
| 8 | uint32 | `n_packets_recv` |
| 12 | uint32 | `n_packets_sent` |
| 16 | uint32 | `total_air_time_secs` |
| 20 | uint32 | `total_up_time_secs` |
| 24 | uint32 | `n_sent_flood` |
| 28 | uint32 | `n_sent_direct` |
| 32 | uint32 | `n_recv_flood` |
| 36 | uint32 | `n_recv_direct` |
| 40 | uint16 | `err_events` |
| 42 | int16 | `last_snr` (×4) |
| 44 | uint16 | `n_direct_dups` |
| 46 | uint16 | `n_flood_dups` |
| 48 | uint16 | `n_posted` |
| 50 | uint16 | `n_post_push` |

meshelle reports zero for `batt_milli_volts` and `total_air_time_secs`: a host
runs on mains, and only the node's radio driver can measure air time. Counters
**saturate** rather than wrap — a long-running room will exceed 65535 posts,
and a stats reply that failed to encode would take out the reply path.

### `REQ_TYPE_GET_ACCESS_LIST`

Seven bytes per entry: six bytes of public key prefix, then a permissions byte.

---

## 6. Where the published docs are wrong

Two corrections, both already pinned by tests in meshelle:

1. **`docs/payloads.md` on the PATH payload's inner `path_len`.** It uses the
   packed encoding, not a plain byte count. `Mesh::createPathReturn` wins.
2. **A `SIGNED_PLAIN` message body starts at offset 9, not 5.** See §3.

And one omission:

3. **`CMD_SEND_RAW_PACKET = 65` is absent from `docs/companion_protocol.md`**
   despite existing in firmware.

---

## 7. Things meshelle deliberately does not implement

- **`REQ_TYPE_GET_TELEMETRY_DATA`** — a host running a room server has no
  sensors. It returns nothing.
- **Inbound `ADVERT` handling** — a room learns a client's public key from the
  login itself, so it keeps no contact book and an advert tells it nothing.
  (Your own room adverts come back to you here: the companion node auto-adds
  each room as a contact and pushes `NEW_ADVERT`/`CONTACTS_FULL` at you.
  Harmless, and `manual_add_contacts` on the node stops it.)
- **`TRACE`, `MULTIPART`, `GRP_TXT`, `GRP_DATA`, `CONTROL`, `RAW_CUSTOM`** —
  not part of being a room.
- **Scoped (`TRANSPORT_FLOOD`) replies** — see §5.
