"""Celery application with queue definitions."""

from celery import Celery

from config import settings

celery_app = Celery("sailor")

celery_app.config_from_object(
    {
        "broker_url": settings.celery_broker_url,
        "result_backend": settings.celery_result_backend,
        "task_serializer": "json",
        "result_serializer": "json",
        "accept_content": ["json"],
        "task_routes": {
            "tasks.phase1.*": {"queue": "phase1"},
            "tasks.phase2.*": {"queue": "phase2"},
            "tasks.phase3.*": {"queue": "phase3"},
            "tasks.exports.*": {"queue": "exports"},
        },
        "task_queues": {
            "phase1": {"exchange": "phase1", "routing_key": "phase1"},
            "phase2": {"exchange": "phase2", "routing_key": "phase2"},
            "phase3": {"exchange": "phase3", "routing_key": "phase3"},
            "exports": {"exchange": "exports", "routing_key": "exports"},
        },
        "worker_concurrency": 4,
        "task_soft_time_limit": 18060,  # 60 turns × 300s + 60s
        "task_time_limit": 18120,
    }
)

celery_app.conf.include = ["tasks.phase1", "tasks.phase2", "tasks.phase3", "tasks.exports"]
