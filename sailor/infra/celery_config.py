"""Celery broker and backend configuration loaded from environment variables."""

import os

broker_url: str = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
result_backend: str = os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/1")

task_serializer: str = "json"
result_serializer: str = "json"
accept_content: list[str] = ["json"]
timezone: str = "UTC"
enable_utc: bool = True

task_routes: dict = {
    "sailor.infra.celery_tasks.run_phase1_task": {"queue": "phase1"},
    "sailor.infra.celery_tasks.run_phase2_task": {"queue": "phase2"},
    "sailor.infra.celery_tasks.run_phase3_task": {"queue": "phase3"},
}

task_acks_late: bool = True
worker_prefetch_multiplier: int = 1
