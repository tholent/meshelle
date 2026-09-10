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

"""The shipped documentation has to stay true, and drift is silent.

Three kinds of documentation here are load-bearing rather than decorative, and
each has a failure mode worth a test:

* ``config.example.toml`` is what every operator copies. If it stops validating,
  the first thing a new user does is hit an error in a file they did not write.
* the README promises specific commands. A renamed subcommand leaves the
  promise standing and nothing to notice it.
* ``docs/DEPENDENCIES.md`` is a licence-compliance record. A dependency added
  without a line there is exactly the omission that record exists to prevent --
  the same reason ``test_license_headers.py`` exists.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

from meshelle.cli import main
from meshelle.config.loader import ConfigError, load_settings

REPO_ROOT = Path(__file__).parent.parent
README = REPO_ROOT / "README.md"
EXAMPLE_CONFIG = REPO_ROOT / "config.example.toml"
DEPENDENCIES = REPO_ROOT / "docs" / "DEPENDENCIES.md"

EXAMPLE_SECRETS = {
    "LOBBY_ADMIN_PW": "example",
    "LOBBY_WRITE_PW": "example",
    "OPS_ADMIN_PW": "example",
}
"""The variables the example config's own comments tell you to set."""

MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


class TestExampleConfig:
    def test_it_validates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """It is what every operator copies; it has to load as shipped."""
        for name, value in EXAMPLE_SECRETS.items():
            monkeypatch.setenv(name, value)

        settings = load_settings(EXAMPLE_CONFIG)

        assert set(settings.rooms) == {"lobby", "ops"}

    def test_it_demonstrates_the_features_it_documents(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A commented-out example is not exercised by the test above.

        These four are the ones an operator is most likely to copy wrongly, so
        the file has to carry a working instance of each rather than only prose.
        """
        for name, value in EXAMPLE_SECRETS.items():
            monkeypatch.setenv(name, value)

        settings = load_settings(EXAMPLE_CONFIG)
        lobby, ops = settings.rooms["lobby"], settings.rooms["ops"]

        assert lobby.members, "no member entry to copy"
        assert lobby.passwords.admin is not None, "no password indirection to copy"
        assert lobby.welcome, "no welcome message to copy"
        # [defaults] inherited by ops, then overridden: both halves demonstrated.
        assert ops.post_retention is None
        assert lobby.post_retention == 30 * 86400

    def test_an_unset_secret_fails_loudly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The example uses env: on purpose, so it ships no working password.

        An operator who copies it and forgets the variable must get an error
        naming the variable, not a room that quietly has no admin password.
        """
        for name in EXAMPLE_SECRETS:
            monkeypatch.delenv(name, raising=False)

        with pytest.raises(ConfigError, match="LOBBY_ADMIN_PW"):
            load_settings(EXAMPLE_CONFIG)


class TestReadme:
    @pytest.mark.parametrize("command", ["run", "check-config", "keygen", "doctor", "db"])
    def test_every_documented_command_exists(self, command: str) -> None:
        """A renamed subcommand leaves the README's promise standing."""
        assert command in README.read_text(encoding="utf-8")
        with pytest.raises(SystemExit) as caught:
            main([command, "--help"])
        assert caught.value.code == 0

    def test_every_relative_link_resolves(self) -> None:
        """A broken link to a file we ship is a defect we can just check for."""
        broken = [
            target
            for target in MARKDOWN_LINK.findall(README.read_text(encoding="utf-8"))
            if not target.startswith(("http://", "https://", "#"))
            and not (REPO_ROOT / target).exists()
        ]
        assert broken == []


class TestDependencyRecord:
    def test_every_direct_dependency_is_recorded(self) -> None:
        """Adding a dependency without recording its licence is the omission
        this record exists to prevent."""
        pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        project = pyproject["project"]

        declared = list(project["dependencies"])
        for extra in project.get("optional-dependencies", {}).values():
            declared.extend(extra)

        recorded = DEPENDENCIES.read_text(encoding="utf-8")
        missing = [
            spec
            for spec in declared
            if re.split(r"[<>=!~\[]", spec, maxsplit=1)[0].strip() not in recorded
        ]
        assert missing == [], f"not in docs/DEPENDENCIES.md: {missing}"
