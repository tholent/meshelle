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

"""Relative paths in the config are measured from the config file.

The failure this rule prevents: a systemd unit runs with ``WorkingDirectory=/``
unless told otherwise, so ``data_dir = "data"`` resolved against the process's
CWD gives the service ``/data`` and the operator testing the same file by hand
``./data`` -- two databases from one config, and a room that appears to have
lost every post the moment it is installed properly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from meshelle.paths import anchor, config_base


def test_base_is_the_config_files_directory(tmp_path: Path) -> None:
    assert config_base(tmp_path / "room.toml") == tmp_path.resolve()


def test_base_falls_back_to_the_working_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Configuration can come from the environment alone, with no file at all."""
    monkeypatch.chdir(tmp_path)
    assert config_base(None) == Path.cwd()


def test_relative_paths_hang_off_the_base(tmp_path: Path) -> None:
    assert anchor(Path("data/meshelle.db"), tmp_path) == tmp_path / "data" / "meshelle.db"


def test_absolute_paths_are_left_alone(tmp_path: Path) -> None:
    absolute = tmp_path / "elsewhere" / "meshelle.db"
    assert anchor(absolute, Path("/nowhere")) == absolute


def test_tilde_expands_to_the_home_directory(tmp_path: Path) -> None:
    """Otherwise ``~/meshelle`` becomes a literal directory named '~'."""
    resolved = anchor(Path("~/meshelle/data"), tmp_path)
    assert resolved == Path.home() / "meshelle" / "data"
    assert "~" not in str(resolved)
