"""File validation endpoint — POST /api/validate/file (public, stateless)."""

from fastapi import APIRouter, File, Form, UploadFile

from services.validation_service import get_validator_service
from shared.contracts.sailor_models import FileValidationResult

router = APIRouter(prefix="/api/validate", tags=["validate"])


@router.post("/file", response_model=FileValidationResult)
async def validate_file(
    file: UploadFile = File(...),
    filename: str = Form(...),
) -> FileValidationResult:
    """Validate file structure.

    Body: multipart/form-data
      file     — binary file content
      filename — logical filename including extension (drives validator dispatch)

    Always returns HTTP 200; check `severity` field for validation outcome.
    ApiError is only returned for endpoint-level failures (auth, server error).
    """
    content_bytes = await file.read()
    svc = get_validator_service()
    return svc.validate(filename, content_bytes)
