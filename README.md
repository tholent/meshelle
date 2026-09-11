# meshelle

A dedicated [MeshCore](https://meshcore.co.uk/) **room server**, hosted on a
computer with a companion node as its radio.

Rooms are MeshCore's shared message boards: clients log in, post, and sync the
posts they missed. meshelle hosts them on a Raspberry Pi or any Linux box,
using a stock MeshCore companion node over USB, TCP or BLE purely as a modem.

```
   MeshCore app                 companion node              meshelle
  ┌─────────────┐    LoRa      ┌──────────────┐   USB     ┌──────────────────┐
  │  client A   │◄────────────►│  bare radio  │◄─────────►│ rooms, ACL, posts│
  │  client B   │              │    modem     │           │ SQLite, sync     │
  └─────────────┘              └──────────────┘           └──────────────────┘
```

## Why

A companion node cannot *be* a room server — its firmware has no ACL, no post
store and no sync logic. So meshelle owns the whole mesh endpoint: its own
Ed25519 identity per room, its own packet construction, encryption and signing.
The node only puts bytes on and off the air.

That buys three things over a firmware room server, which by default holds 20
clients (`ClientACL.h:37`) and 32 posts (`simple_room_server/MyMesh.h:69`) in
RAM — build-time constants, but bounded by the device either way:

- **thousands of posts and clients**, in SQLite, surviving a restart mid-sync;
- **a declarative ACL** in a config file, re-readable with `SIGHUP`;
- **room identities you can back up**, rather than ones locked in a device.

meshelle also grants a real permission level on login. That sounds like table
stakes, and it is the single reason this project exists — see
[Permissions actually work](#permissions-actually-work).

## Status

Alpha. Everything documented here is implemented and covered by a test
suite that runs the real server against a simulated companion node — but
**none of it has been verified against real hardware yet**. Expect to find
bugs, and please file them.

## Requirements

- Python 3.13+
- A MeshCore companion node whose firmware has `CMD_SEND_RAW_PACKET` (65).
  `meshelle doctor` checks for this without transmitting anything.

## Install

Not on PyPI yet. From a checkout:

```bash
git clone https://github.com/cwlls/meshelle && cd meshelle
uv sync --all-extras          # drop --all-extras to skip BLE support
```

Commands below are shown as `meshelle …`; from a checkout, prefix them with
`uv run`.

## Quick start

```bash
cp config.example.toml meshelle.toml
$EDITOR meshelle.toml            # at minimum: companion.port, and the rooms
                                 # you actually want
export LOBBY_ADMIN_PW=…          # the example uses env: for its passwords
                                 # (or put it in a .env -- see Secrets below)

meshelle check-config -c meshelle.toml         # valid? and what does it say
meshelle keygen       -c meshelle.toml         # give each room an identity
meshelle doctor       -c meshelle.toml         # can this node do the job?
meshelle run          -c meshelle.toml
```

Then, in a MeshCore app: the room's advert appears within a few seconds of
startup, add it as a contact, and log in.

Config is found at `--config`, then `$MESHELLE_CONFIG`, then `./meshelle.toml`,
then `/etc/meshelle/meshelle.toml`.

## Commands

| | |
|---|---|
| `meshelle run` | host the configured rooms until stopped |
| `meshelle check-config` | validate the config and print what it means |
| `meshelle keygen` | generate a room's key file (`--room`, `--force`) |
| `meshelle doctor` | probe the node, the database and the room identities |
| `meshelle db current` | report the schema revision on disk |
| `meshelle db upgrade` | migrate (`run` does this automatically) |
| `meshelle db downgrade REV` | roll back |

Every command takes `-c/--config`, `--env-file`, `--log-level` and `--log-format`.
Exit codes: `0` fine, `1` meshelle cannot proceed, `2` bad invocation.

**Diagnostics create nothing.** `check-config` and `doctor` never generate a
key file and never migrate the database — a command run to find out whether
something is missing must not make it stop being missing.

## Configuration

See [`config.example.toml`](config.example.toml), which is commented in full.
The shape:

```toml
[companion]
transport = "serial"
port = "/dev/ttyUSB0"

[node]
data_dir = "data"

[defaults]                       # inherited by every room
post_retention = "30d"
max_posts = 5000
client_retention = "90d"

[room.lobby]
name = "The Lobby"
allow_unknown = "read_only"
welcome = "Welcome to the lobby."

[room.lobby.passwords]
admin = "env:LOBBY_ADMIN_PW"     # or "file:/run/secrets/..." or a literal

[[room.lobby.member]]
pubkey = "1ec77175b0918ed2…"
role = "admin"
```

Three things about it are deliberate:

**Unknown keys are errors.** meshcore-pi documents `admin.keys` while its code
reads `admin.pubkeys`, so the documented spelling is accepted, ignored, and the
room silently has no admins. Here an unknown key fails startup, names the file
and line, and suggests the nearest valid key.

**The ACL is fully declarative.** Roles are resolved on every login, in order:
an explicit member entry, then a password, then the room's `allow_unknown`
policy. `setperm` over the air is *refused by name*, so the config file is
always the source of truth — and a member's declared role wins over any
password, which is what makes a demotion in the file actually demote someone
who still knows the admin password.

**Relative paths are relative to the config file**, not the working directory.
A systemd unit runs with `WorkingDirectory=/`, and one config file resolving to
two different databases is not a useful surprise.

### Secrets and the env file

Passwords do not belong in the config file. `env:NAME` reads one from the
environment and `file:/path` from a file, and neither ever appears in a
`check-config` dump.

Under systemd, `EnvironmentFile=` is the natural place to put those variables.
Everywhere else there is `--env-file`:

```bash
printf 'LOBBY_ADMIN_PW=hunter2\n' > .env
chmod 600 .env
meshelle run -c meshelle.toml
```

It is found at `--env-file`, then `$MESHELLE_ENV_FILE`, then `.env` **beside the
config file** — never the working directory, for the same reason relative paths
are not: a service runs with `WorkingDirectory=/`, and a password that works
only when you test by hand is a bad afternoon.

A file named with `--env-file` or `$MESHELLE_ENV_FILE` must exist; a default
`.env` need not. `check-config` and `doctor` both say which file was read and
how many variables came out of it, and warn if it is group- or world-readable.

The format is the familiar one, with three deliberate differences:

- **The real environment wins.** `MESHELLE_LOG__LEVEL=debug meshelle run` is not
  undone by a stale `.env` next to the config.
- **No interpolation.** `$` and `${}` are literal, because passwords contain `$`
  far more often than a `.env` wants substitution.
- **Nothing is skipped silently.** A malformed line, or the same name twice, is
  an error citing the line number. A password that never got set is the same
  outage either way; only one of them tells you.

`export NAME=value`, `#` comments, and single-, double- and multi-line quoted
values all work as expected. Single quotes are literal, as in a shell.

### Roles

| Role | Wire value | Can post | Notes |
|---|---|---|---|
| `guest` | 0 | no | |
| `read_only` | 1 | no | stricter than firmware, which lets this role post |
| `read_write` | 2 | yes | |
| `admin` | 3 | yes | can use the over-the-air console |

## Running as a service

A unit file is in [`packaging/meshelle.service`](packaging/meshelle.service).

```bash
sudo install -m644 packaging/meshelle.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now meshelle
```

`systemctl reload meshelle` sends `SIGHUP`: the config is re-read and every
ACL re-resolved **without dropping a single client's sync position**. A config
that fails to validate is refused whole and the running one is kept, so a typo
in one section cannot cost a room its ACL. The env file is re-read first, and
the variables the last read supplied are dropped before it — so a rotated
password takes effect and a *deleted* line actually revokes, rather than
staying live for as long as the process runs. Adding or removing a *room* still
needs a restart, and is logged as such rather than silently ignored.

## The over-the-air console

An admin can send commands to a room from a MeshCore app:

| Command | |
|---|---|
| `ver` | the running version |
| `clock` | the host's UTC time |
| `advert` / `advert.zerohop` | re-announce now |
| `get acl` | the declared members and their roles |
| `clear stats` | reset the radio counters (node-wide) |
| `room.post <text>` | post as the room itself |

A non-admin who sends a command gets **no reply at all**, matching firmware.
If a console looks dead, check the role the login actually granted.

`setperm`, `set`, `password`, `clock sync`, `time`, `erase` and `reboot` are
**refused by name**, each saying where the setting actually lives. Silently
ignoring `setperm` would let an operator believe someone is an admin who is not.

## Permissions actually work

Byte 7 of the login response is the client's permission level. An app shows a
compose box only when it reads `read_write` or better.

[meshcore-pi](https://github.com/brianwiddas/meshcore-pi) hardcodes a zero
there, so **every room it hosts is read-only in current apps** — and the byte is
invisible in logs, so nothing reports it. meshelle sends the real value, and
asserts it directly in its tests with a failure message that says what a zero
there means.

The only way to confirm it on real hardware is to log in as an admin and check
that the app offers you a compose box.

## Design notes

- **One process, one node, every room.** One database, one link, one seen-table
  and one scheduler, shared; one room server per configured room behind a single
  dispatcher; everything under one `asyncio.TaskGroup`, so a failure anywhere
  stops the process cleanly instead of leaving a server that answers logins but
  never pushes a post.
- **Never share a key between two rooms**, or with the companion node. Two state
  machines answering one destination hash produce conflicting replies, duplicate
  ACKs and mutually-overwriting sync cursors. meshelle refuses to start if it
  detects either case — including the node's own key, which it can only check
  once the node has answered.
- **Retention policies are independent.** `post_retention` and `max_posts` are
  separate reasons to delete, combined with OR. Neither ever deletes a post a
  known client has not yet been sent.
- **Clients are forgotten when idle.** Nothing else removes a client row, so a
  room with `allow_unknown` set would otherwise gain one per stranger and keep
  it forever, reloading all of them at every start. `client_retention` (90 days
  by default) bounds that. It costs a forgotten client nothing on return: its
  own login carries the timestamp of the newest post it holds, so it resumes
  where it left off. What it does lose is its replay floor, which is why the
  default is generous rather than brisk.
- **A restart resumes mid-sync.** Clients are rehydrated from the database at
  startup, so owed posts keep flowing without waiting for each client to log in
  again. A role earned by *password* is not restored — the password is never
  recorded, so it cannot be re-verified, and restoring it anyway would mean
  removing a password from the config achieved nothing.

More, including every byte layout and the places MeshCore's own docs are wrong:
[`docs/PROTOCOL-NOTES.md`](docs/PROTOCOL-NOTES.md).

## Development

```bash
uv sync --all-extras
uv run ruff check . && uv run ruff format --check .
uv run mypy                  # strict, covers src, tests and scripts
uv run pytest -q
```

All four must pass. New `.py` files need a licence header:
`python3 scripts/add_license_headers.py` (it reads git-tracked files, so
`git add` first).

## Prior art

[**meshcore-pi**](https://github.com/brianwiddas/meshcore-pi) by Brian Widdas
got there first, and meshelle owes it the architectural insight that makes any
of this possible: that a stock companion node can be driven as a bare radio
modem. It is also where the expanded-Ed25519-key format is documented. meshelle
shares no code with it, and reaches different conclusions in several places —
the permission byte, the config schema, the startup advert ordering, and the
device-query timeout among them.

[**MeshCore**](https://github.com/meshcore-dev/MeshCore) by Scott Powell is the
protocol and the authority for every wire detail here.

Both are MIT-licensed. See [`NOTICE`](NOTICE).

## Licence

Apache-2.0. Every source file carries an SPDX header, enforced by a test.
Dependency licences are recorded in
[`docs/DEPENDENCIES.md`](docs/DEPENDENCIES.md).
