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

"""How a relative path in the config file is resolved.

One rule, in one place, because three different things read paths out of the
config -- the database directory, the room key files, and the log file -- and
they must agree.

**Relative paths are relative to the config file, not the process's working
directory.** A systemd unit runs with ``WorkingDirectory=/`` unless told
otherwise, so a ``data_dir = "data"`` interpreted against the CWD would put the
database at ``/data`` for the service and at ``./data`` for the operator
testing the same file by hand -- two databases, one config, and a room that
appears to have lost every post the moment it is installed properly.
"""

from __future__ import annotations

from pathlib import Path


def config_base(config_path: Path | None) -> Path:
    """The directory relative paths are measured from.

    Falls back to the working directory when the configuration came from the
    environment alone and there is no file to be relative to.
    """
    if config_path is None:
        return Path.cwd()
    return config_path.expanduser().resolve().parent


def anchor(path: Path, base: Path) -> Path:
    """Resolve ``path`` against ``base`` unless it is already absolute.

    ``~`` is expanded first, so ``~/meshelle`` is the operator's home rather
    than a literal directory named ``~`` next to the config file.
    """
    expanded = path.expanduser()
    if expanded.is_absolute():
        return expanded
    return base / expanded
