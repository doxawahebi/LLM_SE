"""Settings schemas."""

from pydantic import BaseModel


class SettingsData(BaseModel):
    max_zip_size_mb: int = 500
    max_specs_per_run: int = 50000
    max_concurrent_runs: int = 4
    max_artifact_age_days: int = 90
    max_log_age_days: int = 30
    phase2_default_parallelism: int = 128
    phase2_default_t_max: int = 60
    phase3_enabled_default: bool = True
    anthropic_api_key_last4: str = ""
    gemini_api_key_last4: str = ""


class SettingsPatch(BaseModel):
    max_zip_size_mb: int | None = None
    max_specs_per_run: int | None = None
    max_concurrent_runs: int | None = None
    max_artifact_age_days: int | None = None
    max_log_age_days: int | None = None
    phase2_default_parallelism: int | None = None
    phase2_default_t_max: int | None = None
    phase3_enabled_default: bool | None = None
    # Write-only: accepted but never returned
    anthropic_api_key: str | None = None
    gemini_api_key: str | None = None
