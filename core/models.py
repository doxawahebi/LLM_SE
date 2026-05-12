from pydantic import BaseModel
from typing import Optional, Any

class AnalysisRequest(BaseModel):
    sarif_path: str
    source_dir: str
    target_binary: str

class AnalysisResponse(BaseModel):
    task_id: str
    status: str

class TaskStatusResponse(BaseModel):
    task_id: str
    status: str
    result: Optional[Any] = None
