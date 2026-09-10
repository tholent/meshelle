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

"""initial schema

Creates rooms, posts, clients, counters and meta.

Note the batch_alter_table around the posts index: ``render_as_batch=True`` is on
for SQLite, which cannot ALTER TABLE in place. It is harmless for a CREATE INDEX
and essential for any future column change.

Revision ID: a24f8ebb248f
Revises: None
Create Date: 2026-09-10
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a24f8ebb248f"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "meta",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )
    op.create_table(
        "rooms",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("public_key", sa.LargeBinary(length=32), nullable=False),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("public_key"),
        sa.UniqueConstraint("slug"),
    )
    op.create_table(
        "clients",
        sa.Column("room_id", sa.Integer(), nullable=False),
        sa.Column("public_key", sa.LargeBinary(length=32), nullable=False),
        sa.Column("last_role", sa.Integer(), nullable=False),
        sa.Column("last_timestamp", sa.Integer(), nullable=False),
        sa.Column("sync_since", sa.Integer(), nullable=False),
        sa.Column("out_path", sa.LargeBinary(length=64), nullable=False),
        sa.Column("out_path_len", sa.Integer(), nullable=False),
        sa.Column("first_seen", sa.Integer(), nullable=False),
        sa.Column("last_activity", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["room_id"], ["rooms.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("room_id", "public_key"),
    )
    op.create_table(
        "counters",
        sa.Column("room_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=32), nullable=False),
        sa.Column("value", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["room_id"], ["rooms.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("room_id", "name"),
    )
    op.create_table(
        "posts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("room_id", sa.Integer(), nullable=False),
        sa.Column("author_public_key", sa.LargeBinary(length=32), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("post_ts", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["room_id"], ["rooms.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("room_id", "post_ts", name="uq_posts_room_ts"),
    )
    with op.batch_alter_table("posts", schema=None) as batch_op:
        batch_op.create_index("ix_posts_room_ts", ["room_id", "post_ts"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("posts", schema=None) as batch_op:
        batch_op.drop_index("ix_posts_room_ts")

    op.drop_table("posts")
    op.drop_table("counters")
    op.drop_table("clients")
    op.drop_table("rooms")
    op.drop_table("meta")
