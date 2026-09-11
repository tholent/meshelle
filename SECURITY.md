# Security policy

## Reporting a vulnerability

Report privately, not in a public issue: open a
[security advisory](https://github.com/cwlls/meshelle/security/advisories/new)
on the repository.

Please include what an attacker needs to be able to do — be on the mesh, hold a
room password, have filesystem access — since that is usually what decides
severity here.

meshelle is alpha software with no release cadence to promise against. A
confirmed report gets an acknowledgement and a fix on `main`.

## What is in scope

- Anything that grants a role the config did not declare, or that lets a client
  post to a room it may only read.
- Anything that leaks a room's private key, or a configured password, into a
  log, an over-the-air reply, or a file readable by another user.
- Anything reachable over the radio that stops a running room from serving the
  clients it already has.
- The over-the-air admin CLI accepting a command `room/admin_cli.py` refuses.

## What is not

**The wire cryptography is weak, and that is not a meshelle bug.** MeshCore's
packet format uses AES-128-ECB over the first 16 bytes of the shared secret and
authenticates with an HMAC-SHA256 truncated to **2 bytes**. Both are properties
of the protocol, documented in `proto/crypto.py`. A room server that "fixed"
them could not talk to any MeshCore app. Reports that ECB is a weak mode, or
that a 2-byte tag is forgeable in ~2^15 attempts, are correct and already known.

Related, and also out of scope:

- **Traffic analysis.** Packets are addressed by a one-byte destination hash and
  paths are visible to every repeater. The protocol is not private about who is
  talking to whom.
- **A client that shares its password.** Passwords are a role, not an identity.
  Use `[[room.*.members]]` entries, which match on the full public key, where
  that matters.
- **Denial of service by occupying the channel.** Anyone with a radio can do
  this to any LoRa mesh; it is not specific to meshelle.
- **`proto/ed25519_expanded.py` not being constant time.** It signs only our own
  long-term key, with no attacker-chosen scalar and no remote timing signal, and
  says so at the function. A demonstration that it leaks under those constraints
  would be very much in scope.

## Operator notes

- Room key files must be mode `0600`; meshelle refuses to load one that is
  group- or world-accessible, and creates new ones with `O_EXCL` so they are
  never briefly readable.
- Keep passwords out of the config file with `env:NAME` or `file:/path`, and
  put them in a `.env` (mode `0600`) or systemd's `EnvironmentFile=`.
- `allow_unknown` defaults to `reject`. Setting it to anything else lets any
  node in radio range into the room; that is the intended meaning, not a bug.
- Never share an Ed25519 key between two rooms or with the companion node.
  meshelle refuses to start if it detects either.
