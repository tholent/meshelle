# Dependency licences

meshelle is Apache-2.0 and **vendors no third-party source**. Everything below
is a runtime dependency resolved from PyPI, recorded here so a redistributor
can see what ships alongside it without resolving the tree themselves.

Every licence here is permissive. There is no copyleft anywhere in the tree, so
distributing meshelle imposes no obligations beyond retaining the notices in
`LICENSE` and `NOTICE`.

Versions are the ones this table was verified against; the constraints in
`pyproject.toml` are what actually binds. Re-check after a dependency bump:

```bash
python - <<'PY'
from importlib.metadata import metadata
for name in ("alembic", "cryptography", "pydantic", "pyserial-asyncio-fast",
             "sqlalchemy", "bleak"):
    m = metadata(name)
    print(name, m["Version"], m.get("License-Expression") or m.get("License"))
PY
```

## Direct

| Package | Verified | Licence | Why |
|---|---|---|---|
| `alembic` | 1.19.2 | MIT | schema migrations, run automatically at startup |
| `cryptography` | 50.0.1 | Apache-2.0 OR BSD-3-Clause | X25519, Ed25519, AES; OpenSSL under it |
| `pydantic` | 2.13.5 | MIT | the strict config schema |
| `pyserial-asyncio-fast` | 0.16 | BSD-3-Clause | the serial transport |
| `sqlalchemy` | 2.0.52 | MIT | posts, clients and sync cursors |

## Optional — the `ble` extra

| Package | Verified | Licence | Why |
|---|---|---|---|
| `bleak` | 3.0.2 | MIT | the BLE transport |

Not installed unless the extra is requested, so a serial-only deployment never
pulls it in. `meshelle.transport.ble` imports it inside `connect()` rather than
at module scope, so a config that merely *mentions* BLE still parses without it.

## Transitive

| Package | Verified | Licence | Pulled in by |
|---|---|---|---|
| `annotated-types` | 0.8.0 | MIT | pydantic |
| `cffi` | 2.1.1 | MIT-0 | cryptography |
| `dbus-fast` | 5.0.22 | MIT | bleak (Linux) |
| `greenlet` | 3.5.5 | MIT AND PSF-2.0 | sqlalchemy |
| `mako` | 1.4.1 | MIT | alembic |
| `markupsafe` | 3.0.3 | BSD-3-Clause | mako |
| `pycparser` | 3.0 | BSD-3-Clause | cffi |
| `pydantic-core` | 2.46.5 | MIT | pydantic |
| `pyserial` | 3.5 | BSD-3-Clause | pyserial-asyncio-fast |
| `typing-extensions` | 4.16.0 | PSF-2.0 | pydantic, sqlalchemy |
| `typing-inspection` | 0.4.4 | MIT | pydantic |

## Development only

`mypy`, `pytest`, `pytest-asyncio`, `pytest-cov`, `ruff` and their transitive
dependencies are in the `dev` group. They are not installed by
`pip install meshelle` and are not distributed with it.

## Reference material, not a dependency

`NOTICE` records the two MIT-licensed projects meshelle was written *against* —
MeshCore and meshcore-pi. No code from either is included, vendored or linked.
