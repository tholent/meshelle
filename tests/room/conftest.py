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

"""Fixtures shared by the room tests."""

from __future__ import annotations

import pytest

from meshelle.proto.identity import LocalIdentity


@pytest.fixture
def room_identity() -> LocalIdentity:
    return LocalIdentity.generate()


@pytest.fixture
def client_identity() -> LocalIdentity:
    return LocalIdentity.generate()
