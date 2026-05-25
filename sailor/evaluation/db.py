"""EvaluationDB — SQLite persistence layer for Sailor evaluation results.

Each phase result is written to the DB immediately after completion.
This prevents redundant LLM calls when a run is interrupted and resumed.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Optional

from sailor.models.schemas import (
    CVEEvaluationResult,
    CVERecord,
    EvaluationVerdict,
    FailureReason,
    Phase1Result,
    Phase2Result,
    Phase3Result,
    PhaseStatus,
)

logger = logging.getLogger("sailor.evaluation.db")

_CREATE_EVALUATIONS = """
CREATE TABLE IF NOT EXISTS evaluations (
    eval_id               TEXT PRIMARY KEY,
    cve_id                TEXT NOT NULL,
    run_number            INTEGER NOT NULL,
    phase1_status         TEXT NOT NULL,
    phase2_status         TEXT NOT NULL,
    phase3_status         TEXT NOT NULL,
    phase1_result         TEXT,
    phase2_result         TEXT,
    phase3_result         TEXT,
    phase1_detected       INTEGER,
    phase2_triggered      INTEGER,
    phase3_confirmed      INTEGER,
    verdict               TEXT,
    failure_reason        TEXT,
    failure_detail        TEXT,
    phase1_duration_sec   REAL,
    phase2_duration_sec   REAL,
    phase3_duration_sec   REAL,
    phase2_turns_used     INTEGER,
    total_duration_sec    REAL,
    llm_calls             INTEGER,
    estimated_tokens_used INTEGER,
    estimated_cost_usd    REAL,
    timestamp_start       TEXT,
    timestamp_end         TEXT
)
"""

_CREATE_CVE_RECORDS = """
CREATE TABLE IF NOT EXISTS cve_records (
    cve_id      TEXT PRIMARY KEY,
    record_json TEXT NOT NULL
)
"""


class EvaluationDB:
    """SQLite-based persistence layer for evaluation results.

    All write operations use immediate transactions so that each phase
    checkpoint survives process interruptions.

    Args:
        db_path: Path to the SQLite file (created on first access).
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self.init_schema()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def init_schema(self) -> None:
        """Create tables if they do not exist."""
        with self._conn:
            self._conn.execute(_CREATE_EVALUATIONS)
            self._conn.execute(_CREATE_CVE_RECORDS)
        logger.debug("DB schema initialised at %s", self._db_path)

    # ------------------------------------------------------------------
    # CVE records
    # ------------------------------------------------------------------

    def upsert_cve_record(self, record: CVERecord) -> None:
        """Insert or replace a CVERecord."""
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO cve_records (cve_id, record_json) VALUES (?, ?)",
                (record.cve_id, record.model_dump_json()),
            )

    def get_cve_record(self, cve_id: str) -> Optional[CVERecord]:
        """Retrieve a CVERecord by cve_id."""
        row = self._conn.execute(
            "SELECT record_json FROM cve_records WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        if row is None:
            return None
        return CVERecord.model_validate_json(row["record_json"])

    # ------------------------------------------------------------------
    # Evaluations — create
    # ------------------------------------------------------------------

    def create_evaluation(self, result: CVEEvaluationResult) -> None:
        """Insert a new evaluation row."""
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO evaluations (
                    eval_id, cve_id, run_number,
                    phase1_status, phase2_status, phase3_status,
                    phase1_result, phase2_result, phase3_result,
                    phase1_detected, phase2_triggered, phase3_confirmed,
                    verdict, failure_reason, failure_detail,
                    phase1_duration_sec, phase2_duration_sec, phase3_duration_sec,
                    phase2_turns_used, total_duration_sec,
                    llm_calls, estimated_tokens_used, estimated_cost_usd,
                    timestamp_start, timestamp_end
                ) VALUES (
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?,
                    ?, ?, ?,
                    ?, ?
                )
                """,
                (
                    result.eval_id,
                    result.cve_id,
                    result.run_number,
                    result.phase1_status.value,
                    result.phase2_status.value,
                    result.phase3_status.value,
                    None,
                    None,
                    None,
                    int(result.phase1_detected),
                    int(result.phase2_triggered),
                    int(result.phase3_confirmed),
                    result.verdict.value if result.verdict else None,
                    result.failure_reason.value if result.failure_reason else None,
                    result.failure_detail,
                    result.phase1_duration_sec,
                    result.phase2_duration_sec,
                    result.phase3_duration_sec,
                    result.phase2_turns_used,
                    result.total_duration_sec,
                    result.llm_calls,
                    result.estimated_tokens_used,
                    result.estimated_cost_usd,
                    result.timestamp_start,
                    result.timestamp_end,
                ),
            )
        logger.debug("Created evaluation row eval_id=%s", result.eval_id)

    # ------------------------------------------------------------------
    # Evaluations — update (checkpoints)
    # ------------------------------------------------------------------

    def update_phase_status(
        self,
        eval_id: str,
        phase: int,
        status: PhaseStatus,
        result_json: Optional[str] = None,
    ) -> None:
        """Update phase status and result atomically.

        Args:
            eval_id: Evaluation identifier.
            phase: Phase number (1, 2, or 3).
            status: New phase status.
            result_json: Serialised phase result (JSON string) or None.
        """
        col_status = f"phase{phase}_status"
        col_result = f"phase{phase}_result"
        with self._conn:
            self._conn.execute(
                f"UPDATE evaluations SET {col_status} = ?, {col_result} = ? WHERE eval_id = ?",
                (status.value, result_json, eval_id),
            )
        logger.debug(
            "Checkpoint: eval_id=%s phase%d=%s", eval_id, phase, status.value
        )

    def update_verdict(
        self,
        eval_id: str,
        verdict: EvaluationVerdict,
        failure_reason: Optional[FailureReason],
        failure_detail: str,
    ) -> None:
        """Set final verdict after Phase 3."""
        with self._conn:
            self._conn.execute(
                """UPDATE evaluations
                   SET verdict = ?, failure_reason = ?, failure_detail = ?
                   WHERE eval_id = ?""",
                (
                    verdict.value,
                    failure_reason.value if failure_reason else None,
                    failure_detail,
                    eval_id,
                ),
            )

    def update_metrics(
        self,
        eval_id: str,
        phase1_duration: float,
        phase2_duration: float,
        phase3_duration: float,
        phase2_turns: int,
        llm_calls: int,
        estimated_tokens: int,
        estimated_cost: float,
    ) -> None:
        """Update performance and cost metrics."""
        total = phase1_duration + phase2_duration + phase3_duration
        with self._conn:
            self._conn.execute(
                """UPDATE evaluations
                   SET phase1_duration_sec = ?,
                       phase2_duration_sec = ?,
                       phase3_duration_sec = ?,
                       phase2_turns_used   = ?,
                       total_duration_sec  = ?,
                       llm_calls           = ?,
                       estimated_tokens_used = ?,
                       estimated_cost_usd  = ?
                   WHERE eval_id = ?""",
                (
                    phase1_duration,
                    phase2_duration,
                    phase3_duration,
                    phase2_turns,
                    total,
                    llm_calls,
                    estimated_tokens,
                    estimated_cost,
                    eval_id,
                ),
            )

    def update_ground_truth_flags(
        self,
        eval_id: str,
        phase1_detected: bool,
        phase2_triggered: bool,
        phase3_confirmed: bool,
    ) -> None:
        """Update ground-truth matching flags."""
        with self._conn:
            self._conn.execute(
                """UPDATE evaluations
                   SET phase1_detected = ?, phase2_triggered = ?, phase3_confirmed = ?
                   WHERE eval_id = ?""",
                (
                    int(phase1_detected),
                    int(phase2_triggered),
                    int(phase3_confirmed),
                    eval_id,
                ),
            )

    def update_timestamps(
        self, eval_id: str, timestamp_start: str, timestamp_end: str
    ) -> None:
        """Update start/end timestamps."""
        with self._conn:
            self._conn.execute(
                "UPDATE evaluations SET timestamp_start = ?, timestamp_end = ? WHERE eval_id = ?",
                (timestamp_start, timestamp_end, eval_id),
            )

    # ------------------------------------------------------------------
    # Evaluations — read
    # ------------------------------------------------------------------

    def get_evaluation(self, eval_id: str) -> Optional[CVEEvaluationResult]:
        """Retrieve a full evaluation result by eval_id."""
        row = self._conn.execute(
            "SELECT * FROM evaluations WHERE eval_id = ?", (eval_id,)
        ).fetchone()
        return self._row_to_result(row) if row else None

    def get_latest_evaluation(self, cve_id: str) -> Optional[CVEEvaluationResult]:
        """Get the most recent evaluation for a cve_id by run_number."""
        row = self._conn.execute(
            "SELECT * FROM evaluations WHERE cve_id = ? ORDER BY run_number DESC LIMIT 1",
            (cve_id,),
        ).fetchone()
        return self._row_to_result(row) if row else None

    def get_resumable_phase(self, cve_id: str) -> Optional[tuple[str, int]]:
        """Check if a previous run exists that can be resumed.

        Returns:
            ``(eval_id, next_phase)`` where next_phase is 2 or 3, or None
            if no resumable run exists.
        """
        row = self._conn.execute(
            "SELECT * FROM evaluations WHERE cve_id = ? ORDER BY run_number DESC LIMIT 1",
            (cve_id,),
        ).fetchone()
        if row is None:
            return None
        p1 = row["phase1_status"]
        p2 = row["phase2_status"]
        p3 = row["phase3_status"]
        eval_id = row["eval_id"]

        # Phase 1 complete, Phase 2 not yet started → resume at Phase 2
        if p1 == PhaseStatus.COMPLETED.value and p2 == PhaseStatus.PENDING.value:
            return (eval_id, 2)
        # Phase 2 complete, Phase 3 not yet started → resume at Phase 3
        if p2 == PhaseStatus.COMPLETED.value and p3 == PhaseStatus.PENDING.value:
            return (eval_id, 3)
        return None

    def list_evaluations(
        self, cve_id: Optional[str] = None
    ) -> list[CVEEvaluationResult]:
        """List all evaluations, optionally filtered by cve_id."""
        if cve_id:
            rows = self._conn.execute(
                "SELECT * FROM evaluations WHERE cve_id = ? ORDER BY run_number",
                (cve_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM evaluations ORDER BY cve_id, run_number"
            ).fetchall()
        return [self._row_to_result(r) for r in rows]

    def get_summary_stats(self) -> dict:
        """Aggregate statistics across all evaluations."""
        rows = self._conn.execute("SELECT * FROM evaluations").fetchall()
        results = [self._row_to_result(r) for r in rows]

        cve_ids = set(r.cve_id for r in results)
        tp = sum(1 for r in results if r.verdict == EvaluationVerdict.TRUE_POSITIVE)
        fn = sum(1 for r in results if r.verdict == EvaluationVerdict.FALSE_NEGATIVE)
        fp = sum(1 for r in results if r.verdict == EvaluationVerdict.FALSE_POSITIVE)
        partial = sum(1 for r in results if r.verdict == EvaluationVerdict.PARTIAL)

        turns = [r.phase2_turns_used for r in results if r.phase2_turns_used > 0]
        costs = [r.estimated_cost_usd for r in results]

        failure_counts: dict[str, int] = {}
        for r in results:
            if r.failure_reason:
                key = r.failure_reason.value
                failure_counts[key] = failure_counts.get(key, 0) + 1

        return {
            "total_cves": len(cve_ids),
            "total_runs": len(results),
            "true_positives": tp,
            "false_negatives": fn,
            "false_positives": fp,
            "partials": partial,
            "avg_phase2_turns": sum(turns) / len(turns) if turns else 0.0,
            "avg_cost_usd": sum(costs) / len(costs) if costs else 0.0,
            "total_cost_usd": sum(costs),
            "failure_reason_counts": failure_counts,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _row_to_result(self, row: sqlite3.Row) -> CVEEvaluationResult:
        """Deserialise a DB row into a CVEEvaluationResult."""
        p1_result: Optional[Phase1Result] = None
        if row["phase1_result"]:
            p1_result = Phase1Result.model_validate_json(row["phase1_result"])

        p2_result: Optional[list[Phase2Result]] = None
        if row["phase2_result"]:
            raw = json.loads(row["phase2_result"])
            p2_result = [Phase2Result.model_validate(item) for item in raw]

        p3_result: Optional[Phase3Result] = None
        if row["phase3_result"]:
            p3_result = Phase3Result.model_validate_json(row["phase3_result"])

        return CVEEvaluationResult(
            eval_id=row["eval_id"],
            cve_id=row["cve_id"],
            run_number=row["run_number"],
            phase1_status=PhaseStatus(row["phase1_status"]),
            phase2_status=PhaseStatus(row["phase2_status"]),
            phase3_status=PhaseStatus(row["phase3_status"]),
            phase1_result=p1_result,
            phase2_result=p2_result,
            phase3_result=p3_result,
            phase1_detected=bool(row["phase1_detected"]),
            phase2_triggered=bool(row["phase2_triggered"]),
            phase3_confirmed=bool(row["phase3_confirmed"]),
            verdict=EvaluationVerdict(row["verdict"]) if row["verdict"] else None,
            failure_reason=FailureReason(row["failure_reason"]) if row["failure_reason"] else None,
            failure_detail=row["failure_detail"] or "",
            phase1_duration_sec=row["phase1_duration_sec"] or 0.0,
            phase2_duration_sec=row["phase2_duration_sec"] or 0.0,
            phase3_duration_sec=row["phase3_duration_sec"] or 0.0,
            phase2_turns_used=row["phase2_turns_used"] or 0,
            total_duration_sec=row["total_duration_sec"] or 0.0,
            llm_calls=row["llm_calls"] or 0,
            estimated_tokens_used=row["estimated_tokens_used"] or 0,
            estimated_cost_usd=row["estimated_cost_usd"] or 0.0,
            timestamp_start=row["timestamp_start"] or "",
            timestamp_end=row["timestamp_end"] or "",
        )

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._conn.close()
