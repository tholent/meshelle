"""Prepend the Apache-2.0 header to any Python source file missing one.

Run from the repository root::

    uv run python scripts/add_license_headers.py          # fix in place
    uv run python scripts/add_license_headers.py --check  # report only

``tests/test_license_headers.py`` asserts the same condition; this script is the
companion that fixes it. Keep the two in agreement via ``SPDX_MARKER``.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

SPDX_MARKER = "SPDX-License-Identifier: Apache-2.0"
HEADER_SCAN_LINES = 20
HEADER_PATH = Path(__file__).parent / "license_header.txt"


def tracked_python_files(root: Path) -> list[Path]:
    """Every git-tracked ``.py`` file, so untracked scratch files are ignored."""
    out = subprocess.run(  # noqa: S603
        ["git", "-C", str(root), "ls-files", "-z", "*.py"],  # noqa: S607
        capture_output=True,
        check=True,
        text=True,
    )
    return [root / name for name in out.stdout.split("\0") if name]


def has_header(path: Path) -> bool:
    with path.open(encoding="utf-8") as fh:
        for _, line in zip(range(HEADER_SCAN_LINES), fh, strict=False):
            if SPDX_MARKER in line:
                return True
    return False


def add_header(path: Path, header: str) -> None:
    """Insert the header, keeping any shebang on the first line."""
    body = path.read_text(encoding="utf-8")
    if body.startswith("#!"):
        shebang, _, rest = body.partition("\n")
        path.write_text(f"{shebang}\n{header}{rest}", encoding="utf-8")
    else:
        path.write_text(f"{header}{body}", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="report files missing a header without modifying them",
    )
    args = parser.parse_args()

    root = Path(__file__).parent.parent
    header = HEADER_PATH.read_text(encoding="utf-8") + "\n"

    missing = [p for p in tracked_python_files(root) if not has_header(p)]
    for path in missing:
        rel = path.relative_to(root)
        if args.check:
            print(f"missing license header: {rel}", file=sys.stderr)
        else:
            add_header(path, header)
            print(f"added license header: {rel}")

    if missing and args.check:
        print(
            f"\n{len(missing)} file(s) missing a header. Fix with:\n"
            f"    uv run python scripts/add_license_headers.py",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
