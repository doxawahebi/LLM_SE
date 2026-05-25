"""Initial schema.

Revision ID: 0001
Revises:
Create Date: 2026-05-24
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("user_id", sa.String(), primary_key=True),
        sa.Column("username", sa.String(), unique=True, nullable=False),
        sa.Column("hashed_password", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False, server_default="viewer"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_table(
        "runs",
        sa.Column("run_id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("project_zip_ref", sa.String(), nullable=True),
        sa.Column("build_command", sa.String(), nullable=True),
        sa.Column("codeql_build_mode", sa.String(), server_default="autodetect"),
        sa.Column("config", postgresql.JSONB(), server_default="{}"),
        sa.Column("counters", postgresql.JSONB(), server_default="{}"),
        sa.Column("phase1_summary", postgresql.JSONB(), nullable=True),
        sa.Column("status", sa.String(), server_default="created"),
        sa.Column("error", sa.String(), nullable=True),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_runs_status", "runs", ["status"])

    op.create_table(
        "specs",
        sa.Column("spec_id", sa.String(), primary_key=True),
        sa.Column("run_id", sa.String(), sa.ForeignKey("runs.run_id"), nullable=False),
        sa.Column("rule_id", sa.String(), nullable=True),
        sa.Column("file", sa.String(), nullable=True),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("message", sa.String(), nullable=True),
        sa.Column("snippet", sa.String(), nullable=True),
        sa.Column("entrypoint", sa.String(), nullable=True),
        sa.Column("assertion_template", sa.String(), nullable=True),
        sa.Column("trace", postgresql.JSONB(), nullable=True),
        sa.Column("suspect_calls", postgresql.JSONB(), nullable=True),
        sa.Column("pointer_vars", postgresql.JSONB(), nullable=True),
        sa.Column("length_vars", postgresql.JSONB(), nullable=True),
        sa.Column("bounds_hints", postgresql.JSONB(), nullable=True),
        sa.Column("build_context", postgresql.JSONB(), nullable=True),
        sa.Column("phase1_status", sa.String(), server_default="emitted"),
        sa.Column("phase2_status", sa.String(), server_default="queued"),
        sa.Column("phase3_status", sa.String(), server_default="not_eligible"),
        sa.Column("current_turn", sa.Integer(), server_default="0"),
        sa.Column("turn_count_total", sa.Integer(), server_default="0"),
        sa.Column("refine_count", sa.Integer(), server_default="0"),
        sa.Column("phase2_outcome", sa.String(), nullable=True),
        sa.Column("phase2_error", sa.String(), nullable=True),
        sa.Column("phase3_verdict", sa.String(), nullable=True),
        sa.Column("phase3_error", sa.String(), nullable=True),
        sa.Column("worker_id", sa.String(), nullable=True),
        sa.Column("locked_until", sa.DateTime(), nullable=True),
        sa.Column("intervention_pending", sa.Boolean(), server_default="false"),
        sa.Column("artifacts_root", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("last_event_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_specs_run_phase2", "specs", ["run_id", "phase2_status"])
    op.create_index("ix_specs_run_phase3", "specs", ["run_id", "phase3_status"])
    op.create_index("ix_specs_lease", "specs", ["worker_id", "locked_until"])
    op.create_index("ix_specs_phase2_status", "specs", ["phase2_status"])
    op.create_index("ix_specs_phase3_status", "specs", ["phase3_status"])

    op.create_table(
        "interventions",
        sa.Column("intervention_id", sa.String(), primary_key=True),
        sa.Column("spec_id", sa.String(), sa.ForeignKey("specs.spec_id"), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("submitted_by", sa.String(), nullable=True),
        sa.Column("applied", sa.Boolean(), server_default="false"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_table(
        "turns",
        sa.Column("turn_id", sa.String(), primary_key=True),
        sa.Column("spec_id", sa.String(), sa.ForeignKey("specs.spec_id"), nullable=False),
        sa.Column("turn_number", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("summary", sa.String(), nullable=True),
        sa.Column("payload_ref", sa.String(), nullable=True),
        sa.Column("tokens_consumed", sa.Integer(), nullable=True),
        sa.Column("klee_seconds", sa.Integer(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("started_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("ended_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_turns_spec_number", "turns", ["spec_id", "turn_number"])

    op.create_table(
        "verdicts",
        sa.Column("verdict_id", sa.String(), primary_key=True),
        sa.Column("spec_id", sa.String(), sa.ForeignKey("specs.spec_id"), nullable=False),
        sa.Column("verdict", sa.String(), nullable=False),
        sa.Column("cwe", sa.String(), nullable=True),
        sa.Column("asan_type", sa.String(), nullable=True),
        sa.Column("file", sa.String(), nullable=True),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("func", sa.String(), nullable=True),
        sa.Column("inputs", postgresql.JSONB(), nullable=True),
        sa.Column("asan_report_ref", sa.String(), nullable=True),
        sa.Column("replay_driver_ref", sa.String(), nullable=True),
        sa.Column("verified_bug_json", postgresql.JSONB(), nullable=True),
        sa.Column("dedup_key", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index("ix_verdicts_dedup_key", "verdicts", ["dedup_key"])

    op.create_table(
        "audit_events",
        sa.Column("event_id", sa.String(), primary_key=True),
        sa.Column("actor", sa.String(), nullable=True),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=True),
        sa.Column("diff", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_table(
        "log_lines",
        sa.Column("log_id", sa.String(), primary_key=True),
        sa.Column("run_id", sa.String(), nullable=True),
        sa.Column("spec_id", sa.String(), nullable=True),
        sa.Column("worker_id", sa.String(), nullable=True),
        sa.Column("level", sa.String(), nullable=False),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("message", sa.String(), nullable=False),
        sa.Column("fields", postgresql.JSONB(), nullable=True),
        sa.Column("trace_id", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index("ix_log_lines_run_created", "log_lines", ["run_id", "created_at"])

    op.create_table(
        "export_jobs",
        sa.Column("job_id", sa.String(), primary_key=True),
        sa.Column("run_id", sa.String(), nullable=True),
        sa.Column("spec_ids", postgresql.JSONB(), nullable=True),
        sa.Column("export_type", sa.String(), nullable=False),
        sa.Column("status", sa.String(), server_default="pending"),
        sa.Column("artifact_ref", sa.String(), nullable=True),
        sa.Column("error", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "idempotency_keys",
        sa.Column("key_id", sa.String(), primary_key=True),
        sa.Column("response_body", sa.String(), nullable=False),
        sa.Column("status_code", sa.Integer(), server_default="200"),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_table(
        "settings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("data", postgresql.JSONB(), server_default="{}"),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("settings")
    op.drop_table("idempotency_keys")
    op.drop_table("export_jobs")
    op.drop_table("log_lines")
    op.drop_table("audit_events")
    op.drop_table("verdicts")
    op.drop_table("turns")
    op.drop_table("interventions")
    op.drop_table("specs")
    op.drop_table("runs")
    op.drop_table("users")
