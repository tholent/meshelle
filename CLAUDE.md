# meshelle

A MeshCore room server. The companion node is a **bare radio modem**, not a peer —
meshelle owns the mesh endpoint and every room identity.

**Read `HANDOFF.md` first.** It has current phase state, settled decisions, the
known traps, and the Phase 6 spec. Do not re-derive what is already in there.

# Bash commands

- `uv sync --all-extras` — install deps
- `uv run pytest -q` — full suite (~6s)
- `uv run pytest tests/proto -q` — one directory; prefer this while iterating
- `uv run mypy` — strict, covers src + tests + scripts
- `uv run ruff check . && uv run ruff format .`
- `python3 scripts/add_license_headers.py` — run after adding any `.py` file
- `uv run meshelle --version`

# Workflow

- All four gates must pass before a commit: ruff check, ruff format, mypy, pytest.
- Run `add_license_headers.py` after creating files, or the compliance test fails.
- New `.py` files must be `git add`-ed before that script sees them (it reads
  tracked files only).

# Code style

- Python 3.13. `from __future__ import annotations` in every module.
- mypy strict. No `Any` at module boundaries. Use PEP 695 generics (`def f[T]`).
- Frozen dataclasses for wire types; `slots=True`.
- Comments explain **why**, not what. Put the rationale next to the code.
- Name the failure mode a choice prevents, in the comment or docstring.
- Line length 100.

# Testing

- No coverage-padding tests. Every test names a real behaviour or failure mode.
- Docstrings on tests that encode protocol semantics, saying which.
- Use `asyncio.Event` waits, never `asyncio.sleep` polling.
- `filterwarnings = ["error"]` is deliberate. When it fires, **fix the cause** —
  never loosen the filter. It often blames an unrelated later test.
- Compress clocks in tests via injected timings, not real backoff waits.

# Git

- Conventional commits on `main`. No feature branches.
- Commit at the end of each phase, in as many commits as it needs — usually one
  per module plus one for its tests.
- Commit bodies explain why, and name the failure mode prevented.
- **IMPORTANT: stage explicitly. Never `git add -A` before committing** — it has
  already swallowed a whole phase into one commit.
- Commit and push only when asked.

# Protocol work

- **IMPORTANT: never guess a wire constant.** The authority is
  `~/src/meshcore-refs/MeshCore`; `proto/constants.py` cites a source file per
  group. `examples/simple_room_server/MyMesh.cpp` is the room server's spec.
- `~/src/meshcore-refs/meshcore-pi` is reference only, never a dependency.
- `docs/payloads.md` is wrong about the PATH payload's inner `path_len` — it uses
  the outer packed encoding. `Mesh::createPathReturn` wins.
- `asyncio.TaskGroup` wraps child exceptions in an `ExceptionGroup`; match with
  `except*` and re-raise the leaf.
- Frames cap at 176 bytes in both directions (`MAX_FRAME_SIZE`).
- Never share an Ed25519 key between two rooms, or with the companion node.

# Do not relitigate

Settled with the user: SQLite via SQLAlchemy + Alembic; config-only declarative
ACL (`setperm` over the air is refused); sync SQLAlchemy on a dedicated DB thread;
auto-migrate on startup; Apache-2.0 with enforced per-file headers. Rationale in
`HANDOFF.md` §5.
