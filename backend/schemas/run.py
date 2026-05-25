"""Run request/response schemas."""

from datetime import datetime

from pydantic import BaseModel, computed_field


class RunConfig(BaseModel):
    phase1_query_suite: list[str] = []
    phase1_skip_files: list[str] = []
    phase1_skip_functions: list[str] = []
    phase2_t_explore: int = 8
    phase2_t_author: int = 12
    phase2_t_max: int = 60
    phase2_t_klee_seconds: int = 300
    phase2_r_max: int = 15
    phase2_parallelism: int = 128
    phase2_llm_provider: str = "gemini"
    phase2_llm_model: str = "gemini-2.0-flash"
    phase3_enabled: bool = True
    phase3_asan_options: str = ""


class RunCounters(BaseModel):
    specs_total: int = 0
    specs_filtered_out: int = 0
    specs_emitted: int = 0
    specs_phase2_queued: int = 0
    specs_phase2_running: int = 0
    specs_phase2_bug_triggered: int = 0
    specs_phase2_inconclusive: int = 0
    specs_phase2_likely_fp: int = 0
    specs_phase2_errored: int = 0
    specs_phase3_queued: int = 0
    specs_phase3_confirmed: int = 0
    specs_phase3_rejected: int = 0
    unique_confirmed: int = 0
    total_llm_tokens: int = 0
    total_klee_seconds: int = 0


class RunCreate(BaseModel):
    name: str
    build_command: str = ""
    codeql_build_mode: str = "autodetect"
    config: RunConfig = RunConfig()


class RunSummary(BaseModel):
    run_id: str
    name: str
    status: str
    counters: RunCounters
    created_at: datetime
    created_by: str | None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def id(self) -> str:
        return self.run_id

    class Config:
        from_attributes = True


class RunDetail(RunSummary):
    project_zip_ref: str | None
    build_command: str | None
    codeql_build_mode: str
    config: dict
    phase1_summary: dict | None
    error: str | None
    started_at: datetime | None
    completed_at: datetime | None

    class Config:
        from_attributes = True


class RunCreateResponse(BaseModel):
    run_id: str
    status: str


class BuildConfigRequest(BaseModel):
    build_command: str


class CloneRequest(BaseModel):
    config: RunConfig | None = None
