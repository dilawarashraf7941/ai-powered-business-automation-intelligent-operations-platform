"""Controlled single-use execution orchestration for one fixed GHL action."""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from ai_business_automation.models import (
    ContactTagExecutionRequest,
    ExecutionFailureCategory,
    ExecutionRecord,
    ExecutionStatus,
    GHLAddContactTagParameters,
)
from ai_business_automation.providers import (
    GHLFailureCategory,
    GHLOutcomeCertainty,
    GHLProviderError,
)
from ai_business_automation.repositories import ExecutionRepository
from ai_business_automation.services.actions import ContactTagExecutor

_LOGGER = logging.getLogger("ai_business_automation.executions")

_FAILURE_MAP = {
    GHLFailureCategory.AUTHENTICATION: ExecutionFailureCategory.PROVIDER_AUTHENTICATION,
    GHLFailureCategory.RATE_LIMIT: ExecutionFailureCategory.PROVIDER_RATE_LIMIT,
    GHLFailureCategory.BAD_REQUEST: ExecutionFailureCategory.PROVIDER_BAD_REQUEST,
    GHLFailureCategory.UNAVAILABLE: ExecutionFailureCategory.PROVIDER_UNAVAILABLE,
    GHLFailureCategory.TIMEOUT: ExecutionFailureCategory.PROVIDER_TIMEOUT,
    GHLFailureCategory.PROVIDER_ERROR: ExecutionFailureCategory.PROVIDER_ERROR,
    GHLFailureCategory.UNKNOWN: ExecutionFailureCategory.UNKNOWN_OUTCOME,
}


@dataclass(frozen=True, slots=True)
class ExecutionService:
    repository: ExecutionRepository
    executor: ContactTagExecutor
    actor_id: str
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    def execute(self, request: ContactTagExecutionRequest) -> ExecutionRecord:
        parameters = GHLAddContactTagParameters(contact_id=request.contact_id, tag=request.tag)
        claimed, _approval = self.repository.claim(
            request.approval_id, parameters, _utc(self.clock()), self.actor_id
        )
        self._log("execution_claimed", claimed)
        try:
            self.executor.execute(parameters)
        except GHLProviderError as exc:
            status = (
                ExecutionStatus.FAILED
                if exc.certainty is GHLOutcomeCertainty.DEFINITIVE
                else ExecutionStatus.UNKNOWN
            )
            completed = self.repository.complete(
                claimed.execution_id,
                status,
                _utc(self.clock()),
                _FAILURE_MAP[exc.category],
            )
        except Exception:
            completed = self.repository.complete(
                claimed.execution_id,
                ExecutionStatus.UNKNOWN,
                _utc(self.clock()),
                ExecutionFailureCategory.UNKNOWN_OUTCOME,
            )
        else:
            completed = self.repository.complete(
                claimed.execution_id, ExecutionStatus.SUCCEEDED, _utc(self.clock()), None
            )
        self._log(f"execution_{completed.status.value.lower()}", completed)
        return completed

    def get(self, execution_id: str) -> ExecutionRecord:
        return self.repository.get_execution(execution_id)

    def verify_integrity(self, execution_id: str) -> bool:
        return self.repository.verify_integrity(execution_id)

    @staticmethod
    def _log(event_name: str, record: ExecutionRecord) -> None:
        _LOGGER.info(
            event_name,
            extra={
                "execution_id": record.execution_id,
                "approval_id": record.approval_id,
                "event_id": record.event_id,
                "action": record.action.value,
                "status": record.status.value,
                "outcome": "completed",
                "error_category": (
                    record.failure_category.value if record.failure_category is not None else "NONE"
                ),
            },
        )


def _utc(value: datetime) -> datetime:
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError("server execution clock must use UTC")
    return value.astimezone(UTC)
