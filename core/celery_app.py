from celery import Celery
import os
from typing import Dict, Any

redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
celery_app = Celery(
    'vuln_tasks',
    broker=redis_url,
    backend=redis_url
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)

@celery_app.task(bind=True, name='core.celery_app.run_vulnerability_analysis')
def run_vulnerability_analysis(
    self,
    sarif_path: str,
    source_dir: str,
    target_binary: str,
    engine: str = 'angr',
    klee_whitebox: bool = True,
    max_retries: int = 3,
):
    from core.workflow import pipeline_app
    from langchain_core.runnables import RunnableConfig
    
    # We will use the Celery task ID as the thread ID for LangGraph
    thread_id = self.request.id
    config: RunnableConfig = {"configurable": {"thread_id": thread_id}}
    
    inputs = {
        "sarif_path": sarif_path,
        "source_dir": source_dir,
        "target_binary": target_binary,
        "engine": engine,
        "klee_whitebox": klee_whitebox,
        "max_retries": max_retries,
        # Multi-finding iteration fields
        "findings": None,
        "current_index": 0,
        "results": [],
        # Per-finding working state
        "metadata": None,
        "harness_code": None,
        "poc_path": None,
        "rca_report": None,
        "retry_count": 0,
        "skip_reason": None,
        "status": "started",
        "error_msg": None,
    }

    # Run the graph until the interrupt (before run_symbex) or completion
    for output in pipeline_app.stream(inputs, config=config, stream_mode="updates"):
        self.update_state(state="PROGRESS", meta={"status": "Running", "langgraph_output": output})

    state = pipeline_app.get_state(config)

    # Paused for HITL (interrupt_before=["run_symbex"])
    if state.next and state.next[0] == "run_symbex":
        meta = state.values.get("metadata") or {}
        return {
            "status": "paused_for_hitl",
            "thread_id": thread_id,
            "harness_code": state.values.get("harness_code"),
            "current_finding": {
                "index": state.values.get("current_index"),
                "function_name": meta.get("function_name"),
                "file_path": meta.get("file_path"),
                "cwe_id": meta.get("cwe_id"),
            },
        }

    return {
        "status": "completed",
        "results": state.values.get("results", []),
        "final_state": state.values,
    }
