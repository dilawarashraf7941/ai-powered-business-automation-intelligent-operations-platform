"""Provider-free assessment of terminal UNKNOWN executions."""

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from ai_business_automation.models import (
    ReconciliationRequest,
    ReconciliationResponse,
)
from ai_business_automation.repositories import ExecutionRepository
from ai_business_automation.services.execution_errors import ReconciliationIntegrityError

_LOGGER = logging.getLogger("ai_business_automation.reconciliation")


@dataclass(frozen=True, slots=True)
class ReconciliationService:
    repository: ExecutionRepository
    reconciler_id: str
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    def __post_init__(self) -> None:
        if (
            not 1 <= len(self.reconciler_id) <= 64
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", self.reconciler_id) is None
        ):
            raise ReconciliationIntegrityError

    def reconcile(
        self,
        execution_id: str,
        request: ReconciliationRequest,
        actor_id: str | None = None,
    ) -> ReconciliationResponse:
        now = _utc(self.clock())
        record = self.repository.reconcile(
            execution_id,
            request.outcome,
            request.reason,
            now,
            actor_id or self.reconciler_id,
        )
        _LOGGER.info(
            "execution_reconciliation_recorded",
            extra={
                "execution_id": record.execution_id,
                "approval_id": record.approval_id,
                "status": "UNKNOWN",
                "declared_outcome": request.outcome.value,
                "reconciler_id": record.actor_id,
            },
        )
        return record.public()


def _utc(value: datetime) -> datetime:
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError("server reconciliation clock must use UTC")
    return value.astimezone(UTC)
