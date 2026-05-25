"""Intervention discriminated union schemas."""

from typing import Annotated, Literal

from pydantic import BaseModel, Field


class EditHarness(BaseModel):
    type: Literal["edit_harness"] = "edit_harness"
    artifact: Literal["driver", "slice", "assertions"]
    contents: str
    base_version: int


class ForceOutcome(BaseModel):
    type: Literal["force_outcome"] = "force_outcome"
    outcome: Literal["skip_to_phase3", "mark_inconclusive", "mark_likely_fp"]
    witness_ktest_ref: str | None = None


class EditSpec(BaseModel):
    type: Literal["edit_spec"] = "edit_spec"
    spec: dict  # full VulnerabilitySpec replacement


InterventionPayload = Annotated[
    EditHarness | ForceOutcome | EditSpec,
    Field(discriminator="type"),
]
