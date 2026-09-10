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

Phase 1 provides only ``--version``. The ``run``, ``check-config``, ``keygen``,
``doctor`` and ``db`` subcommands arrive with the app wiring.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from meshelle import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="meshelle",
        description="Host MeshCore room servers using a companion node as the radio.",
    )
    parser.add_argument("--version", action="version", version=f"meshelle {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(argv)
    # No subcommands yet; argparse has already handled --version/--help.
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
