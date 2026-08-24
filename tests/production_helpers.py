"""Clearly local-only valid production-shaped configuration for hardening tests."""

from typing import Any

from pydantic import SecretStr

from ai_business_automation.config import Environment, Settings
from ai_business_automation.models import AuthRole


def production_values(database_path: str = "tests/production-validation.sqlite3") -> dict[str, Any]:
    return {
        "environment": Environment.PRODUCTION,
        "approval_database_path": database_path,
        "auth_token_1": SecretStr("local-ci-auth-material-" + "A7" * 8),
        "auth_actor_1": "operations-admin",
        "auth_role_1": AuthRole.ADMIN,
        "approver_id": "operations-approver",
        "reconciler_id": "operations-reconciler",
        "ghl_api_key": SecretStr("local-ci-ghl-material-" + "B8" * 8),
        "openai_api_key": SecretStr("local-ci-ai-material-" + "C9" * 8),
    }


def production_settings(database_path: str, **updates: Any) -> Settings:
    values = production_values(database_path)
    values.update(updates)
    return Settings(**values)
