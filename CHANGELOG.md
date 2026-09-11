# Changelog

Notable changes to meshelle. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `client_retention` (default 90 days): clients idle longer than this are
  forgotten. Nothing else removed a client row, so a room with `allow_unknown`
  set gained one per stranger and reloaded all of them at every start. A
  forgotten client resumes where it left off on its next login — its own login
  carries the timestamp of the newest post it holds.
- CI running the four gates (ruff check, ruff format, mypy, pytest) on every
  push and pull request, plus an advisory `pip-audit` of the locked tree.
- `CONTRIBUTING.md`, `SECURITY.md`, and this file.

## [0.1.0] — unreleased

First working version. Alpha: complete and covered by tests, but not yet
verified against real hardware.

- Hosts multiple MeshCore rooms from one companion node used as a bare modem,
  over serial, TCP or BLE.
- **Grants a real permission level on login.** The reason the project exists:
  `meshcore-pi` hardcodes byte 7 of the login response to zero, which every
  current app reads as "guest", making every room it hosts read-only.
- Declarative per-room ACL in a config file — member entries matched on the full
  public key, plus role-granting passwords — re-read on `SIGHUP`. `setperm` over
  the air is refused by name, not silently ignored.
- Posts, clients and sync cursors in SQLite, migrated automatically with
  Alembic; a restart resumes syncing mid-stream.
- Per-room Ed25519 identities in backed-up key files, importable from MeshCore's
  expanded private key format.
- `run`, `check-config`, `keygen`, `doctor` and `db` commands; a hardened
  systemd unit; `.env` support for password indirection.

[Unreleased]: https://github.com/cwlls/meshelle/compare/main...HEAD
