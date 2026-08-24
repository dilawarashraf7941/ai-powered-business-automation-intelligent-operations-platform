"""Deterministic local release checks with no external-provider access."""

import re
import sys
from collections.abc import Iterator
from pathlib import Path

from pydantic import SecretStr, ValidationError

from ai_business_automation.config import Environment, Settings
from ai_business_automation.models import AuthRole

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = {
    ".dockerignore",
    ".gitignore",
    "Dockerfile",
    "README.md",
    "docs/deployment.md",
    "requirements.lock",
}
DATABASE_SUFFIXES = {".db", ".sqlite", ".sqlite3"}
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b(?:sk|ghl)[_-](?:live|prod)[_-][A-Za-z0-9_-]{16,}", re.IGNORECASE),
    re.compile(
        r"(?:password|api[_-]?key|access[_-]?token|credential)\s*[:=]\s*"
        r"['\"][A-Za-z0-9_+/=-]{20,}['\"]",
        re.IGNORECASE,
    ),
    re.compile(r"\bBearer\s+(?!fake-|local-)[A-Za-z0-9._~+/-]{20,}", re.IGNORECASE),
)
DOCKERIGNORE_REQUIRED = {
    ".git",
    ".env",
    ".env.*",
    "*.db",
    "*.sqlite",
    "*.sqlite3",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "__pycache__",
    ".coverage",
    "htmlcov",
    "dist",
    "build",
    "*.pyc",
    "tests",
}


def repository_findings(root: Path) -> list[str]:
    findings = [
        f"missing required release file: {name}"
        for name in REQUIRED_FILES
        if not (root / name).is_file()
    ]
    findings.extend(artifact_findings(root))
    findings.extend(secret_findings(root))
    if (root / "Dockerfile").is_file():
        findings.extend(dockerfile_findings((root / "Dockerfile").read_text(encoding="utf-8")))
    if (root / ".dockerignore").is_file():
        ignored = set((root / ".dockerignore").read_text(encoding="utf-8").splitlines())
        for pattern in sorted(DOCKERIGNORE_REQUIRED - ignored):
            findings.append(f"dockerignore is missing: {pattern}")
    lock = root / "requirements.lock"
    if lock.is_file():
        for line in lock.read_text(encoding="utf-8").splitlines():
            if line and not re.fullmatch(r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.+-]+", line):
                findings.append("runtime dependency is not exactly pinned")
                break
    source = root / "src"
    if source.is_dir():
        combined = "\n".join(path.read_text(encoding="utf-8") for path in source.rglob("*.py"))
        if "CORSMiddleware" in combined:
            findings.append("CORS must remain disabled")
        if "https://services.leadconnectorhq.com" not in combined:
            findings.append("fixed GHL origin is missing")
    workflow = root / ".github" / "workflows" / "main.yml"
    if not workflow.is_file() or "python -m pip_audit ." not in workflow.read_text(
        encoding="utf-8"
    ):
        findings.append("CI dependency audit is missing")
    findings.extend(production_configuration_findings(root))
    return findings


def artifact_findings(root: Path) -> list[str]:
    ignored_database_suffixes = _ignored_database_suffixes(root)
    findings: list[str] = []
    for path in _review_files(root):
        if path.name == ".env" or (path.name.startswith(".env.") and path.name != ".env.example"):
            findings.append(f"environment file present: {path.relative_to(root)}")
        if (
            path.suffix.lower() in DATABASE_SUFFIXES
            and path.suffix.lower() not in ignored_database_suffixes
        ):
            findings.append(f"database artifact present: {path.relative_to(root)}")
    return findings


def secret_findings(root: Path) -> list[str]:
    findings: list[str] = []
    for path in _review_files(root):
        if path.suffix.lower() not in {
            ".py",
            ".md",
            ".toml",
            ".yml",
            ".yaml",
            ".txt",
            ".lock",
        } and path.name not in {"Dockerfile", ".dockerignore"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if any(pattern.search(text) for pattern in SECRET_PATTERNS):
            findings.append(f"obvious secret material present: {path.relative_to(root)}")
    return findings


def dockerfile_findings(text: str) -> list[str]:
    checks = {
        "Docker base must be Python 3.12 slim": "FROM python:3.12.10-slim-bookworm",
        "Docker runtime user must be fixed and non-root": "USER 10001:10001",
        "Docker startup must use exec form": 'CMD ["uvicorn"',
        "Docker healthcheck must call /health": "HEALTHCHECK",
        "Docker healthcheck path is missing": "/health",
        "Docker runtime must use one worker": '"--workers", "1"',
    }
    findings = [message for message, marker in checks.items() if marker not in text]
    lowered = text.lower()
    if "sh -c" in lowered or "bash -c" in lowered:
        findings.append("Docker startup must not use a shell")
    if "copy . " in lowered or "add . " in lowered:
        findings.append("Docker build context copy is overly broad")
    if re.search(r"(?im)^\s*(?:env|arg)\s+.*(?:token|api_key|secret|password)", text):
        findings.append("Dockerfile must not contain secret configuration")
    return findings


def production_configuration_findings(root: Path) -> list[str]:
    try:
        Settings(
            environment=Environment.PRODUCTION,
            approval_database_path="tests/release-verification.sqlite3",
            auth_token_1=SecretStr("release-auth-material-" + "A7" * 8),
            auth_actor_1="release-admin",
            auth_role_1=AuthRole.ADMIN,
            approver_id="release-approver",
            reconciler_id="release-reconciler",
            ghl_api_key=SecretStr("release-ghl-material-" + "B8" * 8),
            openai_api_key=SecretStr("release-ai-material-" + "C9" * 8),
        )
    except ValidationError:
        return ["production configuration validation failed"]
    return []


def _ignored_database_suffixes(root: Path) -> set[str]:
    ignore = root / ".gitignore"
    if not ignore.is_file():
        return set()
    patterns = set(ignore.read_text(encoding="utf-8").splitlines())
    return {suffix for suffix in DATABASE_SUFFIXES if f"*{suffix}" in patterns}


def _review_files(root: Path) -> Iterator[Path]:
    excluded = {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".test-data",
        ".venv",
        "__pycache__",
    }
    for path in root.rglob("*"):
        if path.is_file() and not any(part in excluded for part in path.relative_to(root).parts):
            yield path


def main() -> int:
    findings = repository_findings(ROOT)
    if findings:
        print("\n".join(sorted(set(findings))))
        return 1
    print("Release verification passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
