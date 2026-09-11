# Contributing to meshelle

## The four gates

All four must pass before a commit. CI runs exactly these, in this order, so a
green checkout and a green pull request mean the same thing:

```bash
uv sync --all-extras
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest -q
```

After adding any `.py` file:

```bash
git add path/to/new_file.py          # the script reads tracked files only
python3 scripts/add_license_headers.py
```

`tests/test_license_headers.py` fails otherwise. Adding a *dependency* needs a
line in `docs/DEPENDENCIES.md` for the same reason — `tests/test_docs.py`
checks that the licence record is complete.

## Code style

- Python 3.13, `from __future__ import annotations` in every module.
- mypy strict. No `Any` at module boundaries. PEP 695 generics (`def f[T]`).
- Frozen dataclasses with `slots=True` for wire types.
- Line length 100.
- **Comments explain why, not what**, and name the failure mode a choice
  prevents. This is the house style and it is not optional: most of this code
  is a port of someone else's state machine, and the reason a line looks the
  way it does is rarely recoverable from the line.

## Tests

- No coverage-padding tests. Every test names a real behaviour or failure mode.
- Where a test encodes protocol semantics, say which in the docstring.
- Use `asyncio.Event` waits, never `asyncio.sleep` polling.
- Compress clocks through injected timings, not real backoff waits.
- `filterwarnings = ["error"]` is deliberate. When it fires, fix the cause —
  never loosen the filter. It often blames an unrelated later test.

## Protocol work

**Never guess a wire constant.** The authority is the MeshCore firmware source:

```bash
mkdir -p ~/src/meshcore-refs && cd ~/src/meshcore-refs
git clone --depth 1 https://github.com/meshcore-dev/MeshCore.git
```

`examples/simple_room_server/MyMesh.cpp` is the room server's specification.
`proto/constants.py` cites a source file per group, and
`docs/PROTOCOL-NOTES.md` records every layout meshelle relies on with its
firmware citation — update it when a constant changes.

Note that `docs/payloads.md` upstream is wrong about the PATH payload's inner
`path_len`; `Mesh::createPathReturn` wins.

## Commits

Conventional commits on `main`; no feature branches. Commit bodies explain why
and name the failure mode prevented. Stage explicitly — never `git add -A`.

## Reporting a bug

Please include your `meshelle --version`, the companion node's firmware version
(`meshelle doctor` prints it), and the relevant log lines at `--log-level debug`.
Redact your config's passwords before pasting it.

For anything with a security dimension, see [SECURITY.md](SECURITY.md) instead.
