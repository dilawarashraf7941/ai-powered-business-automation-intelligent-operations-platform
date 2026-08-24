"""Strict operational reconciliation inputs and safe responses."""

import re
import unicodedata
from enum import StrEnum
from typing import Annotated

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator
from pydantic_core import PydanticCustomError

from ai_business_automation.models.approvals import ActorId
from ai_business_automation.models.executions import ExecutionId, ExecutionStatus

MAX_RECONCILIATION_REASON_LENGTH = 500
_SAFE_REASON = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .,;:'()_-]*$")
_PROHIBITED_REASON = re.compile(
    r"(?:https?://|ftp://|file://|www\.|\bBearer\s+[A-Za-z0-9._~+/-]{8,}|"
    r"\bsk-[A-Za-z0-9_-]{10,}|private[ _-]?key|```|\$\(|`|"
    r"(?:^|\s)(?:bash|sh|cmd|powershell|pwsh|curl|wget|sudo|rm|python|node)\s+)",
    re.IGNORECASE,
)


class ReconciliationOutcome(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


type ReconciliationReason = Annotated[
    str, Field(min_length=1, max_length=MAX_RECONCILIATION_REASON_LENGTH)
]


class ReconciliationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    outcome: ReconciliationOutcome
    reason: ReconciliationReason

    @field_validator("outcome", mode="before")
    @classmethod
    def parse_outcome(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        try:
            return ReconciliationOutcome(value)
        except ValueError as exc:
            raise PydanticCustomError(
                "unsupported_reconciliation_outcome",
                "unsupported reconciliation outcome",
            ) from exc

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        sanitized = value.strip()
        if (
            not sanitized
            or sanitized != value
            or any(unicodedata.category(character) in {"Cc", "Cf"} for character in value)
            or not _SAFE_REASON.fullmatch(sanitized)
            or _PROHIBITED_REASON.search(sanitized)
        ):
            raise ValueError("reconciliation reason contains prohibited content")
        return sanitized


class ReconciliationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    execution_id: ExecutionId
    status: ExecutionStatus
    result_code: Annotated[str, Field(pattern=r"^RECONCILED$")]
    reconciled_at: AwareDatetime
    reconciler_id: ActorId
