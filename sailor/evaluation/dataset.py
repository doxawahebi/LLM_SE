"""CVEDataset — manages the collection of CVE records used for evaluation."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from sailor.models.schemas import CVERecord
from sailor.evaluation.db import EvaluationDB

logger = logging.getLogger("sailor.evaluation.dataset")


class CVEDataset:
    """CVE dataset manager backed by EvaluationDB.

    Supports loading from a JSON file for easy extension.
    Designed to start with 1 CVE and scale to N without structural changes.

    Args:
        db: Initialised :class:`EvaluationDB` instance.
    """

    def __init__(self, db: EvaluationDB) -> None:
        self._db = db

    def load_from_file(self, path: Path) -> int:
        """Load a list of CVERecords from a JSON file and upsert into DB.

        Args:
            path: Path to a JSON file containing a list of CVERecord dicts.

        Returns:
            Number of records loaded.
        """
        raw: list[dict] = json.loads(path.read_text(encoding="utf-8"))
        count = 0
        for item in raw:
            record = CVERecord.model_validate(item)
            self._db.upsert_cve_record(record)
            count += 1
        logger.info("Loaded %d CVE records from %s", count, path)
        return count

    def get(self, cve_id: str) -> Optional[CVERecord]:
        """Retrieve a single CVERecord by cve_id."""
        return self._db.get_cve_record(cve_id)

    def list_all(self) -> list[CVERecord]:
        """Return all CVERecords stored in the DB."""
        rows = self._db._conn.execute(
            "SELECT record_json FROM cve_records ORDER BY cve_id"
        ).fetchall()
        return [CVERecord.model_validate_json(r["record_json"]) for r in rows]

    def add(self, record: CVERecord) -> None:
        """Add or update a single CVERecord programmatically."""
        self._db.upsert_cve_record(record)
        logger.debug("Added CVE record: %s", record.cve_id)

    def load_initial_dataset(self) -> int:
        """Load the built-in INITIAL_DATASET into the DB.

        Returns:
            Number of records loaded.
        """
        count = 0
        for item in INITIAL_DATASET:
            record = CVERecord.model_validate(item)
            self._db.upsert_cve_record(record)
            count += 1
        logger.info("Loaded %d records from INITIAL_DATASET", count)
        return count


# ── Initial 1-CVE dataset (Binutils CVE from the paper) ──────────────────────

INITIAL_DATASET: list[dict] = [
    {
        "cve_id": "CVE-2025-11494",
        "cwe": "CWE-125",
        "description": (
            "Out-of-bounds read in _bfd_x86_elf_late_size_sections "
            "in bfd/elfxx-x86.c. plt_eh_frame->size not validated "
            "against contents allocation size before read."
        ),
        "project": "binutils",
        "project_url": "https://sourceware.org/git/binutils-gdb.git",
        "vulnerable_commit": "binutils-2_45",
        "fixed_commit": "b6ac5a8a5b82f0ae6a4642c8d7149b325f4cc60a",
        "vulnerable_file": "bfd/elfxx-x86.c",
        "vulnerable_line": 0,
        "vulnerable_func": "_bfd_x86_elf_late_size_sections",
        "expected_asan_type": "heap-buffer-overflow",
        "build_system": "autotools",
        "build_commands": [
            "git checkout binutils-2_45",
            "./configure --disable-gdb --disable-sim --disable-gold "
            "--enable-targets=x86_64-linux-gnu",
            "bear -- make -j4 all-bfd",
        ],
        "dependencies": [
            "ca-certificates",
            "build-essential",
            "bear",
            "autoconf",
            "automake",
            "libz-dev",
            "libtool",
            "texinfo",
            "git",
            "clang",
        ],
        "docker_image": "ubuntu:22.04",
        "env_vars": {"CC": "clang", "CXX": "clang++"},
        "extra_cflags": "-O1 -g",
    }
]
