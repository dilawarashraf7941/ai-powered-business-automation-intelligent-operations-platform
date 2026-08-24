"""Build the server-owned SQLite approval boundary."""

from functools import lru_cache
from pathlib import Path

from ai_business_automation.config import get_settings
from ai_business_automation.repositories import SQLiteApprovalRepository
from ai_business_automation.services.approvals import ApprovalService
from ai_business_automation.services.policy_factory import get_policy_service


@lru_cache
def get_approval_service() -> ApprovalService:
    settings = get_settings()
    repository = SQLiteApprovalRepository(Path(settings.approval_database_path))
    repository.initialize()
    return ApprovalService(
        repository=repository,
        policy_service=get_policy_service(),
        ttl_seconds=settings.approval_ttl_seconds,
        approver_id=settings.approver_id,
    )
