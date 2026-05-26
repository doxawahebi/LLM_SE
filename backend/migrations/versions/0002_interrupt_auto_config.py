"""Add interrupt_points and auto_config tables.

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-24
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "interrupt_points",
        sa.Column("interrupt_id", sa.String(), primary_key=True),
        sa.Column("run_id", sa.String(), sa.ForeignKey("runs.run_id"), nullable=False),
        sa.Column("spec_id", sa.String(), sa.ForeignKey("specs.spec_id"), nullable=True),
        sa.Column("function_name", sa.String(), nullable=False),
        sa.Column("phase", sa.Integer(), nullable=False),
        sa.Column("turn", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(), server_default="waiting", nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("resumed_at", sa.DateTime(), nullable=True),
        sa.Column("modified_files", postgresql.JSONB(), server_default="[]"),
        sa.Column("option_overrides", postgresql.JSONB(), server_default="{}"),
    )
    op.create_index("ix_interrupt_points_run_status", "interrupt_points", ["run_id", "status"])

    op.create_table(
        "auto_config",
        sa.Column("run_id", sa.String(), sa.ForeignKey("runs.run_id"), primary_key=True),
        sa.Column("config", postgresql.JSONB(), server_default="{}"),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("auto_config")
    op.drop_table("interrupt_points")
