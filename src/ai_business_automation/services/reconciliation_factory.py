"""Build the provider-free reconciliation boundary."""

from functools import lru_cache
from pathlib import Path

from ai_business_automation.config import get_settings
from ai_business_automation.repositories import SQLiteExecutionRepository
from ai_business_automation.services.reconciliation import ReconciliationService


@lru_cache
def get_reconciliation_service() -> ReconciliationService:
    settings = get_settings()
    repository = SQLiteExecutionRepository(Path(settings.approval_database_path))
    repository.initialize()
    return ReconciliationService(repository, settings.reconciler_id)
