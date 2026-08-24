"""Provider-neutral persistence boundaries."""

from ai_business_automation.repositories.approvals import (
    ApprovalRepository,
    SQLiteApprovalRepository,
)

__all__ = ["ApprovalRepository", "SQLiteApprovalRepository"]
