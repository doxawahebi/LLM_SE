from fastapi import FastAPI, HTTPException
from core.models import AnalysisRequest, AnalysisResponse, TaskStatusResponse
from core.celery_app import run_vulnerability_analysis
from celery.result import AsyncResult
import os

app = FastAPI(title="Vulnerability Detection, Verification, and RCA Reporter")

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_vulnerability(request: AnalysisRequest):
    if not os.path.exists(request.sarif_path):
        raise HTTPException(status_code=404, detail="SARIF file not found")
    if not os.path.exists(request.source_dir):
        raise HTTPException(status_code=404, detail="Source directory not found")
        
    task = run_vulnerability_analysis.delay(
        request.sarif_path, 
        request.source_dir, 
        request.target_binary
    )
    return AnalysisResponse(task_id=task.id, status="pending")

@app.get("/status/{task_id}", response_model=TaskStatusResponse)
async def get_status(task_id: str):
    task_result = AsyncResult(task_id)
    result = None
    if task_result.ready():
        result = task_result.result
    return TaskStatusResponse(
        task_id=task_id,
        status=task_result.status,
        result=result
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
