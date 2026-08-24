"""Controlled single-use execution orchestration for local allowlisted actions."""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from pydantic import ValidationError

from ai_business_automation.models import (
    ActionContext,
    ExecutionFailureCategory,
    ExecutionRecord,
    ExecutionStatus,
)
from ai_business_automation.repositories import ExecutionRepository
from ai_business_automation.services.actions import (
    ActionRegistry,
    DefinitiveActionFailure,
    UnknownActionOutcome,
)

_LOGGER = logging.getLogger("ai_business_automation.executions")


@dataclass(frozen=True, slots=True)
class ExecutionService:
    """Claim once, invoke one fixed local handler, and persist a terminal result."""

    repository: ExecutionRepository
    registry: ActionRegistry
    actor_id: str
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    def execute(self, approval_id: str, actor_id: str | None = None) -> ExecutionRecord:
        now = _utc(self.clock())
        claimed, approval = self.repository.claim(approval_id, now, actor_id or self.actor_id)
        self._log("execution_claimed", claimed, "claimed")
        context = ActionContext(
            execution_id=claimed.execution_id,
            approval_id=claimed.approval_id,
            event_id=claimed.event_id,
            action=claimed.action,
            risk=approval.risk,
            started_at=claimed.started_at,
            action_parameters=approval.action_parameters,
        )
        if context.action not in self.registry.actions:
            completed = self.repository.complete(
                claimed.execution_id,
                ExecutionStatus.FAILED,
                _utc(self.clock()),
                "Action is not allowlisted.",
                failure_category=ExecutionFailureCategory.ACTION_NOT_ALLOWED,
            )
            self._log("execution_failed", completed, "action_not_allowed")
            return completed
        try:
            outcome = self.registry.execute(context)
        except DefinitiveActionFailure as exc:
            completed = self.repository.complete(
                claimed.execution_id,
                ExecutionStatus.FAILED,
                _utc(self.clock()),
                "Internal action definitively failed.",
                failure_category=ExecutionFailureCategory(exc.category),
            )
        except ValidationError:
            completed = self.repository.complete(
                claimed.execution_id,
                ExecutionStatus.FAILED,
                _utc(self.clock()),
                "Internal action validation failed.",
                failure_category=ExecutionFailureCategory.INTERNAL_FAILURE,
            )
        except UnknownActionOutcome as exc:
            completed = self.repository.complete(
                claimed.execution_id,
                ExecutionStatus.UNKNOWN,
                _utc(self.clock()),
                "Internal action outcome is unknown.",
                failure_category=ExecutionFailureCategory(exc.category),
            )
        except Exception:
            completed = self.repository.complete(
                claimed.execution_id,
                ExecutionStatus.UNKNOWN,
                _utc(self.clock()),
                "Internal action outcome is unknown.",
                failure_category=ExecutionFailureCategory.INTERNAL_UNKNOWN,
            )
        else:
            completed = self.repository.complete(
                claimed.execution_id,
                ExecutionStatus.SUCCEEDED,
                _utc(self.clock()),
                outcome.safe_summary,
                outcome,
            )
        self._log(f"execution_{completed.status.value.lower()}", completed, "completed")
        return completed

    def get(self, execution_id: str) -> ExecutionRecord:
        record = self.repository.get_execution(execution_id)
        self._log("execution_read", record, "success")
        return record

    def verify_integrity(self, execution_id: str) -> bool:
        return self.repository.verify_integrity(execution_id)

    @staticmethod
    def _log(event_name: str, record: ExecutionRecord, outcome: str) -> None:
        _LOGGER.info(
            event_name,
            extra={
                "execution_id": record.execution_id,
                "approval_id": record.approval_id,
                "event_id": record.event_id,
                "action": record.action.value,
                "status": record.status.value,
                "result_code": (
                    record.result_code.value if record.result_code is not None else "PENDING"
                ),
                "outcome": outcome,
                "error_category": (
                    record.failure_category.value if record.failure_category is not None else "NONE"
                ),
                "provider": ("GHL" if record.action.value == "GHL_ADD_CONTACT_TAG" else "INTERNAL"),
            },
        )


def _utc(value: datetime) -> datetime:
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError("server execution clock must use UTC")
    return value.astimezone(UTC)
