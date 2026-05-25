"""File validation endpoint — POST /api/validate/file (public, stateless)."""

import base64

from fastapi import APIRouter
from pydantic import BaseModel

from services.validation_service import get_validator_service

router = APIRouter(prefix="/api/validate", tags=["validate"])


class ValidateFileRequest(BaseModel):
    filename: str
    content_base64: str


class ValidateFileResponse(BaseModel):
    valid: bool
    severity: str
    message: str
    detected_format: str


@router.post("/file", response_model=ValidateFileResponse)
async def validate_file(body: ValidateFileRequest) -> ValidateFileResponse:
    try:
        content_bytes = base64.b64decode(body.content_base64)
    except Exception:
        return ValidateFileResponse(
            valid=False,
            severity="error",
            message="content_base64 is not valid base64.",
            detected_format="unknown",
        )
    svc = get_validator_service()
    result = svc.validate(body.filename, content_bytes)
    return ValidateFileResponse(
        valid=result.valid,
        severity=result.severity,
        message=result.message,
        detected_format=result.detected_format,
    )
