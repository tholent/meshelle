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

"""Command line entry point.

Five subcommands, each answering one operator question:

``run``           host the configured rooms until told to stop
``check-config``  is this file valid, and what does it actually say?
``keygen``        give a room an identity, before it goes on the air
``doctor``        can this node do what meshelle needs of it?
``db``            what schema is on disk, and bring it forward

Diagnostics are strictly read-only. ``check-config`` and ``doctor`` never
generate a key file and never migrate the database: a command run to find out
whether something is missing must not make it stop being missing. Only ``run``
creates state, and it says so in the log when it does.

Everything the operator is told goes to **stdout**; logging goes to stderr. That
keeps ``meshelle check-config | ...`` usable and keeps a failure visible even
when stdout is being captured.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from meshelle import __version__
from meshelle.app import (
    AppError,
    Application,
    make_transport_factory,
    room_key_path,
)
from meshelle.companion.link import CompanionError, CompanionLink
from meshelle.config.dotenv import DotenvError, DotenvResult, load_dotenv
from meshelle.config.loader import ConfigError, load_settings
from meshelle.config.model import LogFormat, LogLevel, RoomSettings, Settings
from meshelle.logs import LoggingError, configure_logging
from meshelle.paths import anchor, config_base
from meshelle.proto.identity import IdentityError, LocalIdentity, load_identity, save_identity
from meshelle.store.migrate import (
    MigrationError,
    current_revision,
    downgrade,
    head_revision,
    upgrade_to_head,
)
from meshelle.transport.base import Transport, TransportError

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2
"""argparse's own exit code for a bad invocation; reused for a missing subcommand."""

CONFIG_ENV_VAR = "MESHELLE_CONFIG"
ENV_FILE_ENV_VAR = "MESHELLE_ENV_FILE"

DEFAULT_CONFIG_PATHS = (
    Path("meshelle.toml"),
    Path("/etc/meshelle/meshelle.toml"),
)
"""Searched in order when ``--config`` is absent. Deliberately short: a config
found somewhere the operator did not expect is worse than being asked for one."""

DEFAULT_ENV_FILE_NAME = ".env"
"""Looked for beside the config file only -- never in the working directory.

Same reason ``paths.anchor`` measures from the config file: a service runs with
``WorkingDirectory=/``, so a ``.env`` picked up from the CWD would apply when
the operator tested by hand and vanish once it was installed properly, which
presents as a password that works only in the terminal."""

DOCTOR_TIMEOUT = 30.0
"""Long enough for a node that is busy, short enough that a wrong port fails
while the operator is still watching."""


class UsageError(Exception):
    """The command cannot run as invoked. Distinct from a bad config file."""


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _common_options() -> argparse.ArgumentParser:
    """Options every subcommand shares, as a parent parser.

    A parent rather than top-level flags, so ``meshelle run --config x.toml``
    works -- which is the order people actually type.
    """
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "-c",
        "--config",
        type=Path,
        metavar="PATH",
        help=f"config file (default: ${CONFIG_ENV_VAR}, ./meshelle.toml, /etc/meshelle/)",
    )
    parent.add_argument(
        "--env-file",
        type=Path,
        metavar="PATH",
        help=f"env file to load (default: ${ENV_FILE_ENV_VAR}, or .env beside the config)",
    )
    parent.add_argument(
        "--log-level",
        choices=[level.value for level in LogLevel],
        help="override log.level",
    )
    parent.add_argument(
        "--log-format",
        choices=[fmt.value for fmt in LogFormat],
        help="override log.format",
    )
    return parent


def build_parser() -> argparse.ArgumentParser:
    common = _common_options()
    parser = argparse.ArgumentParser(
        prog="meshelle",
        description="Host MeshCore room servers using a companion node as the radio.",
    )
    parser.add_argument("--version", action="version", version=f"meshelle {__version__}")
    subcommands = parser.add_subparsers(dest="command", metavar="COMMAND")

    subcommands.add_parser(
        "run",
        parents=[common],
        help="host the configured rooms",
        description="Host every configured room until SIGTERM. SIGHUP reloads the ACL.",
    )

    subcommands.add_parser(
        "check-config",
        parents=[common],
        help="validate the configuration and print what it means",
        description="Validate the config file and summarise it. Creates nothing.",
    )

    keygen = subcommands.add_parser(
        "keygen",
        parents=[common],
        help="generate a room identity",
        description="Generate the key file for a room that does not have one yet.",
    )
    keygen.add_argument(
        "--room",
        metavar="SLUG",
        help="which room (default: every room that is missing a key file)",
    )
    keygen.add_argument(
        "--force",
        action="store_true",
        help="replace an existing key -- every client loses its contact for the room",
    )

    subcommands.add_parser(
        "doctor",
        parents=[common],
        help="check the node, the database and the room identities",
        description="Probe the companion node and report anything that would stop a run.",
    )

    database = subcommands.add_parser(
        "db",
        parents=[common],
        help="inspect or migrate the database",
    )
    db_actions = database.add_subparsers(dest="db_command", metavar="ACTION")
    db_actions.add_parser("current", parents=[common], help="report the schema revision")
    db_actions.add_parser("upgrade", parents=[common], help="migrate to the newest revision")
    rollback = db_actions.add_parser("downgrade", parents=[common], help="roll back to a revision")
    rollback.add_argument("revision", help="the revision to roll back to, or 'base'")

    return parser


def find_config(explicit: Path | None, environ: dict[str, str] | None = None) -> Path:
    """Locate the config file, or say exactly where it was looked for.

    An explicit path that does not exist is an error rather than a fall-through
    to the defaults: silently hosting a different room than the one named on the
    command line is the failure this prevents.
    """
    source = os.environ if environ is None else environ

    if explicit is not None:
        if not explicit.exists():
            raise UsageError(f"config file not found: {explicit}")
        return explicit

    from_env = source.get(CONFIG_ENV_VAR)
    if from_env:
        path = Path(from_env)
        if not path.exists():
            raise UsageError(f"{CONFIG_ENV_VAR} points at a missing file: {path}")
        return path

    for candidate in DEFAULT_CONFIG_PATHS:
        if candidate.exists():
            return candidate

    searched = ", ".join(str(path) for path in DEFAULT_CONFIG_PATHS)
    raise UsageError(f"no config file given and none found. Tried: {searched}. Use --config PATH.")


def find_env_file(
    explicit: Path | None,
    config_path: Path | None = None,
    environ: dict[str, str] | None = None,
) -> Path | None:
    """Locate the env file, or ``None`` when there is nothing to load.

    An asked-for file that is missing is an error, the same way ``--config`` is:
    a run that was meant to get its passwords from a file and silently got none
    starts a room with no admin, which is discovered by someone else.

    Note the ordering this implies: the config file is found *first*, so
    ``MESHELLE_CONFIG`` set inside a ``.env`` cannot choose the config -- there
    would be nowhere to look for the ``.env`` until the config was already known.
    """
    source = os.environ if environ is None else environ

    if explicit is not None:
        if not explicit.exists():
            raise UsageError(f"env file not found: {explicit}")
        return explicit

    from_env = source.get(ENV_FILE_ENV_VAR)
    if from_env:
        path = Path(from_env)
        if not path.exists():
            raise UsageError(f"{ENV_FILE_ENV_VAR} points at a missing file: {path}")
        return path

    beside_config = config_base(config_path) / DEFAULT_ENV_FILE_NAME
    return beside_config if beside_config.is_file() else None


def cli_overrides(args: argparse.Namespace) -> dict[str, Any]:
    """Flags that override config values, in the shape the loader merges."""
    log: dict[str, Any] = {}
    if args.log_level is not None:
        log["level"] = args.log_level
    if args.log_format is not None:
        log["format"] = args.log_format
    return {"log": log} if log else {}


# ---------------------------------------------------------------------------
# Shared loading
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Loaded:
    """Everything the subcommands need out of the loading step.

    A record rather than a tuple because the env file has to travel with the
    settings: ``run`` logs it, the diagnostics print it, and a reload has to
    re-read it.
    """

    path: Path
    settings: Settings
    overrides: dict[str, Any]
    env_file: DotenvResult


def _load(args: argparse.Namespace) -> Loaded:
    path = find_config(args.config)
    # The env file goes into the environment before the config is validated, so
    # both MESHELLE_* overrides and env: password indirection can come from it.
    env_path = find_env_file(args.env_file, path)
    env_file = load_dotenv(env_path) if env_path is not None else DotenvResult()
    overrides = cli_overrides(args)
    settings = load_settings(path, overrides=overrides, env_sources=env_file.sources)
    return Loaded(path=path, settings=settings, overrides=overrides, env_file=env_file)


def _describe_room(slug: str, room: RoomSettings, key_path: Path | None) -> list[str]:
    lines = [f"  room {slug} -- {room.name!r}"]

    if key_path is None:
        lines.append("    identity: inline private_key")
    elif key_path.exists():
        try:
            identity = load_identity(key_path)
        except IdentityError as exc:
            lines.append(f"    identity: UNUSABLE -- {exc}")
        else:
            lines.append(f"    identity: {identity.public_key.hex()} ({key_path})")
    else:
        lines.append(f"    identity: missing, generated on first run ({key_path})")

    roles = sorted({member.role.value for member in room.members})
    lines.append(f"    members: {len(room.members)}" + (f" ({', '.join(roles)})" if roles else ""))
    passwords = [role.value for role, _ in room.passwords.as_pairs()]
    lines.append(f"    passwords: {', '.join(passwords) if passwords else 'none'}")
    lines.append(f"    unknown clients: {room.allow_unknown.value}")

    retention = "forever" if room.post_retention is None else f"{room.post_retention}s"
    cap = "unlimited" if room.max_posts is None else str(room.max_posts)
    clients = "forever" if room.client_retention is None else f"{room.client_retention}s"
    lines.append(f"    retention: {retention}, at most {cap} posts; clients {clients}")

    flood = "off" if not room.advert_flood_interval else f"{room.advert_flood_interval}s"
    local = "off" if not room.advert_local_interval else f"{room.advert_local_interval}s"
    lines.append(f"    adverts: flood {flood}, zero-hop {local}")
    if room.welcome:
        lines.append(f"    welcome: {len(room.welcome)} characters")
    return lines


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def command_check_config(args: argparse.Namespace) -> int:
    loaded = _load(args)
    path, settings = loaded.path, loaded.settings
    base = config_base(path)
    data_dir = anchor(settings.node.data_dir, base)

    lines = [
        f"{path}: valid",
        # Named even when there is none: "which .env did it read?" is the first
        # question asked about a password that is set in a file and not in
        # effect, and silence there reads as "it must have loaded it".
        f"  {loaded.env_file.describe()}",
        f"  companion: {settings.companion.transport.value} "
        f"{settings.companion.port or settings.companion.host or settings.companion.address}",
        f"  data directory: {data_dir}",
        f"  database: {anchor(settings.node.database_path, base)}",
        f"  logging: {settings.log.level.value}/{settings.log.format.value}"
        + (f" + {anchor(settings.log.file, base)}" if settings.log.file else ""),
    ]
    # The mode warning belongs here as well as in doctor: writing the .env is
    # what check-config is normally run straight after, and that is the moment
    # the permissions can still be fixed before a password has been in a
    # world-readable file on a running box.
    lines.extend(f"  warning: {warning}" for warning in loaded.env_file.warnings)
    for slug, room in settings.rooms.items():
        lines.extend(_describe_room(slug, room, room_key_path(slug, room, data_dir)))

    print("\n".join(lines))
    return EXIT_OK


def command_keygen(args: argparse.Namespace) -> int:
    loaded = _load(args)
    path, settings = loaded.path, loaded.settings
    data_dir = anchor(settings.node.data_dir, config_base(path))

    if args.room is not None:
        if args.room not in settings.rooms:
            known = ", ".join(sorted(settings.rooms)) or "none"
            raise UsageError(f"no room {args.room!r} in {path}. Configured rooms: {known}")
        wanted = [args.room]
    else:
        wanted = list(settings.rooms)

    generated = 0
    for slug in wanted:
        room = settings.rooms[slug]
        key_path = room_key_path(slug, room, data_dir)
        if key_path is None:
            print(f"room {slug}: configured with an inline private_key, nothing to generate")
            continue
        if key_path.exists() and not args.force:
            if args.room is not None:
                # Asked for by name, so this is a refusal, not a skip: replacing
                # the key would strand every client that already has the room in
                # its contacts, and --force says the operator means it.
                raise UsageError(
                    f"room {slug} already has a key file: {key_path}. "
                    f"Use --force to replace it -- every client would have to re-add the room."
                )
            print(f"room {slug}: already has a key ({key_path})")
            continue

        identity = LocalIdentity.generate()
        save_identity(key_path, identity, overwrite=args.force)
        generated += 1
        print(f"room {slug}: {identity.public_key.hex()}")
        print(f"  written to {key_path} (mode 0600 -- back it up, it cannot be recovered)")

    if generated == 0 and args.room is None:
        print("nothing to do; every room already has an identity")
    return EXIT_OK


def command_db(args: argparse.Namespace) -> int:
    loaded = _load(args)
    path, settings = loaded.path, loaded.settings
    db_path = anchor(settings.node.database_path, config_base(path))
    action = args.db_command or "current"

    if action == "current":
        current = current_revision(db_path)
        head = head_revision()
        exists = "present" if db_path.exists() else "absent"
        print(f"database: {db_path} ({exists})")
        print(f"  revision: {current or 'not migrated'}")
        print(f"  shipped:  {head or 'none'}")
        if current != head:
            print("  status:   behind -- 'meshelle run' migrates automatically")
        else:
            print("  status:   up to date")
        return EXIT_OK

    if action == "upgrade":
        print(upgrade_to_head(db_path).describe())
        return EXIT_OK

    print(downgrade(db_path, args.revision).describe())
    return EXIT_OK


async def _doctor(
    settings: Settings,
    path: Path,
    *,
    env_file: DotenvResult | None = None,
    transport_factory: Callable[[], Transport] | None = None,
) -> int:
    """Report anything that would stop a run, and return 1 if there is any.

    ``transport_factory`` is injectable so the node checks can be exercised
    against a simulated companion; production passes nothing and gets the one
    the config describes.
    """
    base = config_base(path)
    data_dir = anchor(settings.node.data_dir, base)
    db_path = anchor(settings.node.database_path, base)
    problems: list[str] = []

    print(f"config:   {path}: valid")
    if env_file is not None and env_file.path is not None:
        print(f"env:      {env_file.path}: {env_file.detail}")
        for warning in env_file.warnings:
            # Advisory, not a problem: a loose mode does not stop a run, and
            # exiting 1 over it would train operators to ignore doctor.
            print(f"env:      warning -- {warning}")

    current, head = current_revision(db_path), head_revision()
    if not db_path.exists():
        print(f"database: {db_path}: absent, created on first run")
    elif current != head:
        print(f"database: {db_path}: at {current or 'base'}, ships {head} -- run migrates it")
    else:
        print(f"database: {db_path}: up to date ({head})")

    room_keys: dict[bytes, str] = {}
    for slug, room in settings.rooms.items():
        key_path = room_key_path(slug, room, data_dir)
        if key_path is None:
            identity: LocalIdentity | None = LocalIdentity.from_hex(str(room.private_key))
        elif not key_path.exists():
            print(f"room {slug}: no key file yet ({key_path}); run 'meshelle keygen'")
            identity = None
        else:
            try:
                identity = load_identity(key_path)
            except IdentityError as exc:
                problems.append(f"room {slug}: {exc}")
                print(f"room {slug}: UNUSABLE key file -- {exc}")
                identity = None
        if identity is not None:
            print(f"room {slug}: {identity.public_key.hex()} (hash 0x{identity.node_hash:02X})")
            room_keys[identity.public_key] = slug

    factory = (
        transport_factory
        if transport_factory is not None
        else make_transport_factory(settings.companion)
    )
    link = CompanionLink(factory)
    transport = factory()
    print(f"node:     connecting to {transport.description} ...")
    try:
        async with asyncio.timeout(DOCTOR_TIMEOUT):
            async with transport:
                # The link is driven directly here rather than through run():
                # a diagnostic that quietly retried a wrong port would report a
                # timeout instead of the actual connection error.
                info = await link.handshake(transport)
                print(f"node:     {info.summary()}")

                if info.public_key in room_keys:
                    problems.append(
                        f"room {room_keys[info.public_key]!r} uses the node's own key; "
                        f"the node would answer for the room's destination hash"
                    )
                    print(
                        f"node:     CONFLICT -- shares its key with room "
                        f"{room_keys[info.public_key]!r}"
                    )

                supported = await link.probe_raw_packet_support(transport)
                if supported:
                    print("node:     CMD_SEND_RAW_PACKET (65) supported -- nothing transmitted")
                else:
                    problems.append(
                        "the node's firmware has no CMD_SEND_RAW_PACKET (65), so meshelle "
                        "cannot put packets on the air. Flash firmware that includes it."
                    )
                    print("node:     CMD_SEND_RAW_PACKET (65) MISSING")
    except TimeoutError:
        problems.append(f"the node did not answer within {DOCTOR_TIMEOUT:.0f}s")
        print(f"node:     no answer within {DOCTOR_TIMEOUT:.0f}s")
    except (CompanionError, TransportError) as exc:
        problems.append(str(exc))
        print(f"node:     FAILED -- {exc}")

    if problems:
        print()
        print(f"{len(problems)} problem(s):")
        for problem in problems:
            print(f"  - {problem}")
        return EXIT_FAILURE

    print()
    print("all checks passed")
    return EXIT_OK


def command_doctor(args: argparse.Namespace) -> int:
    loaded = _load(args)
    return asyncio.run(_doctor(loaded.settings, loaded.path, env_file=loaded.env_file))


def command_run(args: argparse.Namespace) -> int:
    loaded = _load(args)
    configure_logging(loaded.settings.log, base=config_base(loaded.path))
    if loaded.env_file.path is not None:
        # Logged after configure_logging, not printed during loading: which
        # variables a run took from a file is exactly what a later incident
        # wants from the journal.
        logger.info("loaded %s", loaded.env_file.describe().removeprefix("env file: "))
        for warning in loaded.env_file.warnings:
            logger.warning("%s", warning)
    app = Application(
        loaded.settings,
        config_path=loaded.path,
        overrides=loaded.overrides,
        env_file=loaded.env_file,
    )
    return asyncio.run(app.run())


COMMANDS = {
    "run": command_run,
    "check-config": command_check_config,
    "keygen": command_keygen,
    "doctor": command_doctor,
    "db": command_db,
}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return EXIT_USAGE

    try:
        return COMMANDS[args.command](args)
    except (
        AppError,
        ConfigError,
        DotenvError,
        IdentityError,
        LoggingError,
        MigrationError,
        UsageError,
    ) as exc:
        # One handler for every "meshelle cannot proceed" case, because they all
        # want the same treatment: the operator's message on stderr, no
        # traceback, exit 1. A traceback here would bury the actual explanation.
        print(f"meshelle: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    except KeyboardInterrupt:  # pragma: no cover - depends on a real terminal
        return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())
