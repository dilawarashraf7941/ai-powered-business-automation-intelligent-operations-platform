"""Build the server-owned controlled execution boundary."""

from functools import lru_cache
from pathlib import Path

from ai_business_automation.config import get_settings
from ai_business_automation.repositories import SQLiteExecutionRepository
from ai_business_automation.services.actions import ActionRegistry
from ai_business_automation.services.executions import ExecutionService


@lru_cache
def get_execution_service() -> ExecutionService:
    settings = get_settings()
    repository = SQLiteExecutionRepository(Path(settings.approval_database_path))
    repository.initialize()
    return ExecutionService(
        repository=repository,
        registry=ActionRegistry(),
        actor_id=settings.approver_id,
    )
