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

"""Every tracked Python file must carry the Apache-2.0 SPDX identifier.

This is a real compliance check, not a coverage filler: Apache-2.0 §4 requires
notices to survive redistribution, and a header that is applied by hand is a
header that eventually is not. Fix failures with::

    uv run python scripts/add_license_headers.py
"""

from __future__ import annotations

from pathlib import Path

import pytest
from add_license_headers import SPDX_MARKER, has_header, tracked_python_files

REPO_ROOT = Path(__file__).parent.parent


def test_license_file_is_the_canonical_apache_text() -> None:
    """Guard against a hand-edited or truncated LICENSE."""
    text = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "Apache License" in text
    assert "Version 2.0, January 2004" in text
    # The canonical text from apache.org is exactly this long; a mangled copy
    # (reflowed, partially pasted, CRLF-converted) will not be.
    assert len(text) == 11358, f"LICENSE is {len(text)} bytes, expected the canonical 11358"


def test_notice_file_exists_and_names_the_project() -> None:
    text = (REPO_ROOT / "NOTICE").read_text(encoding="utf-8")
    assert "meshelle" in text
    assert "Apache License" in text


@pytest.mark.parametrize(
    "path",
    tracked_python_files(REPO_ROOT),
    ids=lambda p: str(p.relative_to(REPO_ROOT)),
)
def test_python_file_has_license_header(path: Path) -> None:
    assert has_header(path), (
        f"{path.relative_to(REPO_ROOT)} is missing '{SPDX_MARKER}'. "
        f"Run: uv run python scripts/add_license_headers.py"
    )
