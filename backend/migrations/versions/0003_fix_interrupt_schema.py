"""Fix interrupt_points schema: remove phase, add scope/resolved_at/resolved_by/input_files.

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-25
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Remove phase column (derivable from function_name prefix)
    op.drop_column("interrupt_points", "phase")

    # Rename modified_files → semantically replaced by input_files + resume_files
    op.drop_column("interrupt_points", "modified_files")

    # Add scope column: "run" | "spec"
    op.add_column(
        "interrupt_points",
        sa.Column("scope", sa.String(), nullable=False, server_default="spec"),
    )

    # Add resolved_at / resolved_by for audit trail
    op.add_column(
        "interrupt_points",
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "interrupt_points",
        sa.Column("resolved_by", sa.String(), nullable=True),
    )

    # input_files: files shown to the user at interrupt creation time
    op.add_column(
        "interrupt_points",
        sa.Column("input_files", postgresql.JSONB(), server_default="[]"),
    )

    # Backend-internal columns for resume tracking
    op.add_column(
        "interrupt_points",
        sa.Column("resume_files", postgresql.JSONB(), server_default="[]"),
    )
    op.add_column(
        "interrupt_points",
        sa.Column("resume_overrides", postgresql.JSONB(), server_default="{}"),
    )
    op.add_column(
        "interrupt_points",
        sa.Column("uploaded_artifact_refs", postgresql.JSONB(), server_default="[]"),
    )

    # Drop old auto_config keys (they used dotted format) — reset to empty
    op.execute("UPDATE auto_config SET config = '{}'::jsonb")


def downgrade() -> None:
    op.drop_column("interrupt_points", "uploaded_artifact_refs")
    op.drop_column("interrupt_points", "resume_overrides")
    op.drop_column("interrupt_points", "resume_files")
    op.drop_column("interrupt_points", "input_files")
    op.drop_column("interrupt_points", "resolved_by")
    op.drop_column("interrupt_points", "resolved_at")
    op.drop_column("interrupt_points", "scope")

    op.add_column(
        "interrupt_points",
        sa.Column("modified_files", postgresql.JSONB(), server_default="[]"),
    )
    op.add_column(
        "interrupt_points",
        sa.Column("phase", sa.Integer(), nullable=False, server_default="2"),
    )
