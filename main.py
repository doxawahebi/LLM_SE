"""
Antigravity HAST — FastAPI Backend
====================================
Endpoints
---------
POST /upload                      — Upload a .zip of source code; returns workspace_id
POST /build/{workspace_id}        — Run custom build + CodeQL + ASan compilation
GET  /build/{workspace_id}/status — Poll build job status + logs
POST /analyze                     — Launch LangGraph pipeline
GET  /status/{task_id}            — Poll Celery task status
GET  /pipeline/{thread_id}/state  — Inspect LangGraph checkpoint
POST /pipeline/{thread_id}/resume — Inject edited harness + resume
POST /pipeline/{thread_id}/pause  — Set a pause-after-next-node interrupt
GET  /sessions                    — List all known pipeline sessions
DELETE /sessions/{thread_id}      — Remove a session from the registry
"""

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
from core.celery_app import run_vulnerability_analysis
from core.workflow import pipeline_app
from celery.result import AsyncResult
from langchain_core.runnables import RunnableConfig
import os
import shutil
import uuid
import subprocess
import threading
import json
import zipfile

app = FastAPI(title="Antigravity HAST API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Workspace root ──────────────────────────────────────────────────────────
WORKSPACES_DIR = os.path.abspath("workspaces")
os.makedirs(WORKSPACES_DIR, exist_ok=True)

# ── In-memory session registry (persisted to JSON for reload) ───────────────
SESSION_FILE = os.path.join(WORKSPACES_DIR, "sessions.json")

def _load_sessions() -> dict:
    if os.path.exists(SESSION_FILE):
        try:
            with open(SESSION_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def _save_sessions(sessions: dict):
    with open(SESSION_FILE, "w") as f:
        json.dump(sessions, f, indent=2)

sessions: dict = _load_sessions()

def _register_session(thread_id: str, meta: dict):
    sessions[thread_id] = meta
    _save_sessions(sessions)

# ── Build job tracking (in-memory, keyed by workspace_id) ──────────────────
build_jobs: dict = {}  # workspace_id → {"status", "logs", "artifacts"}


# ===========================================================================
# /upload — Accept a .zip of source code
# ===========================================================================

@app.post("/upload")
async def upload_source(file: UploadFile = File(...)):
    workspace_id = str(uuid.uuid4())[:8]
    workspace_path = os.path.join(WORKSPACES_DIR, workspace_id)
    os.makedirs(workspace_path, exist_ok=True)

    zip_dest = os.path.join(workspace_path, "source.zip")
    with open(zip_dest, "wb") as f:
        content = await file.read()
        f.write(content)

    # Extract the zip
    try:
        with zipfile.ZipFile(zip_dest, "r") as z:
            z.extractall(workspace_path)
    except zipfile.BadZipFile as e:
        shutil.rmtree(workspace_path, ignore_errors=True)
        raise HTTPException(status_code=400, detail=f"Invalid zip file: {e}")

    os.remove(zip_dest)
    return {"workspace_id": workspace_id, "workspace_path": workspace_path}


# ===========================================================================
# /build — Run custom build commands inside the workspace
# ===========================================================================

class BuildRequest(BaseModel):
    build_command: str          # e.g. "make" or "cmake .. && make"
    codeql_language: str = "c-cpp"
    asan_extra_flags: str = ""  # extra flags appended to the ASan compile step

def _run_build_job(workspace_id: str, workspace_path: str, build_command: str,
                   codeql_language: str, asan_extra_flags: str):
    job = build_jobs[workspace_id]
    logs: list[str] = []

    def log(msg: str):
        logs.append(msg)
        job["logs"] = "\n".join(logs)

    try:
        # ── Step 1: Run custom build command ────────────────────────────────
        log(f"[build] Running: {build_command}")
        res = subprocess.run(
            build_command, shell=True, cwd=workspace_path,
            capture_output=True, text=True, timeout=300
        )
        log(res.stdout)
        if res.returncode != 0:
            log(f"[build] FAILED:\n{res.stderr}")
            job["status"] = "build_failed"
            job["error"] = res.stderr
            return
        log("[build] Build succeeded.")

        # ── Step 2: Create CodeQL database ──────────────────────────────────
        codeql_db = os.path.join(workspace_path, "codeql_db")
        log(f"[codeql] Creating database...")
        codeql_cmd = (
            f"codeql database create {codeql_db}"
            f" --language={codeql_language}"
            f" --command='{build_command}'"
            f" --overwrite"
        )
        res = subprocess.run(
            codeql_cmd, shell=True, cwd=workspace_path,
            capture_output=True, text=True, timeout=600
        )
        log(res.stdout + res.stderr)
        if res.returncode != 0:
            log("[codeql] CodeQL DB creation failed. Continuing with ASan only.")
            codeql_db = None
        else:
            log("[codeql] Database created.")

            # ── Step 2b: Run CodeQL analysis ────────────────────────────────
            sarif_out = os.path.join(workspace_path, "results.sarif")
            log("[codeql] Running analysis queries...")
            analyze_cmd = (
                f"codeql database analyze {codeql_db}"
                f" --format=sarifv2.1.0 --output={sarif_out}"
                f" codeql/{codeql_language}-queries:codeql-suites/{codeql_language}-security-and-quality.qls"
            )
            res = subprocess.run(
                analyze_cmd, shell=True, cwd=workspace_path,
                capture_output=True, text=True, timeout=1200
            )
            log(res.stdout + res.stderr)
            if res.returncode != 0:
                log("[codeql] Analysis failed.")
                sarif_out = None
            else:
                log(f"[codeql] SARIF written to {sarif_out}")

        # ── Step 3: Compile ASan-instrumented binary ─────────────────────────
        asan_out = os.path.join(workspace_path, "target_asan")
        log("[asan] Compiling ASan binary...")
        asan_cmd = (
            f"gcc -fsanitize=address -g -O0 {asan_extra_flags}"
            f" -o {asan_out}"
            f" $(find {workspace_path} -name '*.c' | head -20 | tr '\\n' ' ')"
        )
        res = subprocess.run(
            asan_cmd, shell=True, cwd=workspace_path,
            capture_output=True, text=True, timeout=120
        )
        log(res.stdout + res.stderr)
        if res.returncode != 0:
            log("[asan] ASan compilation failed.")
            asan_out = None
        else:
            log(f"[asan] Binary: {asan_out}")

        job["status"] = "done"
        job["artifacts"] = {
            "sarif_path": sarif_out if sarif_out and os.path.exists(sarif_out) else None,
            "asan_binary": asan_out if asan_out and os.path.exists(asan_out) else None,
            "codeql_db": codeql_db,
            "workspace_path": workspace_path,
        }

    except subprocess.TimeoutExpired:
        job["status"] = "timeout"
        job["error"] = "Build step timed out."
    except Exception as e:
        job["status"] = "error"
        job["error"] = str(e)


@app.post("/build/{workspace_id}")
async def start_build(workspace_id: str, req: BuildRequest, background_tasks: BackgroundTasks):
    workspace_path = os.path.join(WORKSPACES_DIR, workspace_id)
    if not os.path.isdir(workspace_path):
        raise HTTPException(status_code=404, detail="Workspace not found")

    build_jobs[workspace_id] = {"status": "running", "logs": "", "artifacts": None, "error": None}
    background_tasks.add_task(
        _run_build_job, workspace_id, workspace_path,
        req.build_command, req.codeql_language, req.asan_extra_flags
    )
    return {"workspace_id": workspace_id, "status": "started"}


@app.get("/build/{workspace_id}/status")
async def get_build_status(workspace_id: str):
    if workspace_id not in build_jobs:
        raise HTTPException(status_code=404, detail="Build job not found")
    job = build_jobs[workspace_id]
    return {
        "workspace_id": workspace_id,
        "status": job["status"],
        "logs": job["logs"],
        "artifacts": job["artifacts"],
        "error": job.get("error"),
    }


# ===========================================================================
# /analyze — Launch the LangGraph pipeline
# ===========================================================================

class AnalysisRequest(BaseModel):
    sarif_path: str
    source_dir: str
    target_binary: str
    engine: str = "angr"
    klee_whitebox: bool = True
    max_retries: int = 3
    label: Optional[str] = None  # human-readable name for the session

@app.post("/analyze")
async def analyze_vulnerability(request: AnalysisRequest):
    if not os.path.exists(request.sarif_path):
        raise HTTPException(status_code=404, detail="SARIF file not found")
    if not os.path.exists(request.source_dir):
        raise HTTPException(status_code=404, detail="Source directory not found")

    task = run_vulnerability_analysis.delay(
        request.sarif_path,
        request.source_dir,
        request.target_binary,
        request.engine,
        request.klee_whitebox,
        request.max_retries,
    )

    import datetime
    _register_session(task.id, {
        "task_id": task.id,
        "label": request.label or f"Analysis {task.id[:8]}",
        "engine": request.engine,
        "sarif_path": request.sarif_path,
        "created_at": datetime.datetime.utcnow().isoformat(),
        "status": "running",
    })

    return {"task_id": task.id, "status": "pending"}


# ===========================================================================
# /status — Celery task poll
# ===========================================================================

@app.get("/status/{task_id}")
async def get_status(task_id: str):
    task_result = AsyncResult(task_id)
    result = None
    if task_result.ready():
        result = task_result.result
        # Update registry status
        if task_id in sessions:
            sessions[task_id]["status"] = "completed" if task_result.successful() else "failed"
            _save_sessions(sessions)

    return {
        "task_id": task_id,
        "status": task_result.status,
        "result": result,
        "info": task_result.info if not task_result.ready() else None,
    }


# ===========================================================================
# /pipeline — LangGraph state management
# ===========================================================================

@app.get("/pipeline/{thread_id}/state")
async def get_pipeline_state(thread_id: str):
    config: RunnableConfig = {"configurable": {"thread_id": thread_id}}
    state = pipeline_app.get_state(config)
    if not state:
        raise HTTPException(status_code=404, detail="Thread not found")
    return {"values": state.values, "next": list(state.next)}


class ResumeRequest(BaseModel):
    harness_code: Optional[str] = None

def _resume_in_background(thread_id: str, harness_code: Optional[str]):
    config: RunnableConfig = {"configurable": {"thread_id": thread_id}}
    state = pipeline_app.get_state(config)
    if not state or not state.next:
        return
    if harness_code:
        # Inject edited harness AND clear the prior error so LLM doesn't re-correct
        pipeline_app.update_state(config, {"harness_code": harness_code, "error_msg": None})
    for _ in pipeline_app.stream(None, config=config, stream_mode="updates"):
        pass
    # Update session registry
    if thread_id in sessions:
        sessions[thread_id]["status"] = "running"
        _save_sessions(sessions)

@app.post("/pipeline/{thread_id}/resume")
async def resume_pipeline(thread_id: str, request: ResumeRequest, background_tasks: BackgroundTasks):
    config: RunnableConfig = {"configurable": {"thread_id": thread_id}}
    state = pipeline_app.get_state(config)
    if not state or not state.next:
        raise HTTPException(status_code=400, detail="Pipeline is not paused or thread not found")
    background_tasks.add_task(_resume_in_background, thread_id, request.harness_code)
    if thread_id in sessions:
        sessions[thread_id]["status"] = "paused"
        _save_sessions(sessions)
    return {"status": "resumed", "thread_id": thread_id}


@app.post("/pipeline/{thread_id}/pause")
async def pause_pipeline(thread_id: str):
    """
    Set a dynamic interrupt so the graph pauses after the current node finishes.
    LangGraph persists the full state to Redis; the UI can then call /state.
    """
    config: RunnableConfig = {"configurable": {"thread_id": thread_id}}
    # Update state to signal the pipeline to pause (use a sentinel status)
    try:
        pipeline_app.update_state(config, {"status": "pause_requested"})
        if thread_id in sessions:
            sessions[thread_id]["status"] = "paused"
            _save_sessions(sessions)
        return {"status": "pause_requested", "thread_id": thread_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ===========================================================================
# /sessions — Session registry CRUD
# ===========================================================================

@app.get("/sessions")
async def list_sessions():
    return {"sessions": list(sessions.values())}

@app.delete("/sessions/{thread_id}")
async def delete_session(thread_id: str):
    if thread_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    del sessions[thread_id]
    _save_sessions(sessions)
    return {"status": "deleted"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
