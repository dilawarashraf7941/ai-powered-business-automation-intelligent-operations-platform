"""Deterministic production release checks without network or persistence access."""

import re
import sys
from collections.abc import Iterator
from pathlib import Path

from pydantic import SecretStr, ValidationError

from ai_business_automation.config import Environment, Settings
from ai_business_automation.models import AuthRole

ROOT = Path(__file__).resolve().parents[1]
GHL_ORIGIN = "https://services.leadconnectorhq.com"
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
    """Return bounded static release findings for a repository root."""

    findings = [
        f"missing required release file: {name}"
        for name in REQUIRED_FILES
        if not (root / name).is_file()
    ]
    findings.extend(artifact_findings(root))
    findings.extend(secret_findings(root))
    dockerfile = root / "Dockerfile"
    if dockerfile.is_file():
        findings.extend(dockerfile_findings(dockerfile.read_text(encoding="utf-8")))
    dockerignore = root / ".dockerignore"
    if dockerignore.is_file():
        ignored = set(dockerignore.read_text(encoding="utf-8").splitlines())
        findings.extend(
            f"dockerignore is missing: {pattern}"
            for pattern in sorted(DOCKERIGNORE_REQUIRED - ignored)
        )
    lock = root / "requirements.lock"
    if lock.is_file():
        for line in lock.read_text(encoding="utf-8").splitlines():
            if line and not re.fullmatch(r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.+-]+", line):
                findings.append("runtime dependency is not exactly pinned")
                break
    findings.extend(source_findings(root / "src"))
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
        relative = path.relative_to(root)
        if path.name == ".env" or (path.name.startswith(".env.") and path.name != ".env.example"):
            findings.append(f"environment file present: {relative}")
        if (
            path.suffix.lower() in DATABASE_SUFFIXES
            and path.suffix.lower() not in ignored_database_suffixes
        ):
            findings.append(f"database artifact present: {relative}")
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
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if any(pattern.search(content) for pattern in SECRET_PATTERNS):
            findings.append(f"obvious secret material present: {path.relative_to(root)}")
    return findings


def dockerfile_findings(content: str) -> list[str]:
    checks = {
        "Docker base must be pinned Python 3.12 slim": "FROM python:3.12.10-slim-bookworm",
        "Docker runtime user must be fixed and non-root": "USER 10001:10001",
        "Docker startup must use exec form": 'CMD ["uvicorn"',
        "Docker healthcheck is missing": "HEALTHCHECK",
        "Docker healthcheck path is missing": "/health",
        "Docker runtime must use one worker": '"--workers", "1"',
        "Docker server header must be disabled": '"--no-server-header"',
    }
    findings = [message for message, marker in checks.items() if marker not in content]
    lowered = content.lower()
    if "sh -c" in lowered or "bash -c" in lowered:
        findings.append("Docker startup must not use a shell")
    if "copy . " in lowered or "add . " in lowered:
        findings.append("Docker build context copy is overly broad")
    if re.search(r"(?im)^\s*(?:env|arg)\s+.*(?:token|api_key|secret|password)", content):
        findings.append("Dockerfile must not contain secret configuration")
    return findings


def source_findings(source: Path) -> list[str]:
    if not source.is_dir():
        return ["application source is missing"]
    files = {
        path.relative_to(source).as_posix(): path.read_text(encoding="utf-8")
        for path in source.rglob("*.py")
    }
    combined = "\n".join(files.values())
    findings: list[str] = []
    if "CORSMiddleware" in combined:
        findings.append("CORS must remain disabled")
    ghl_source = files.get("ai_business_automation/providers/ghl.py", "")
    origins = set(re.findall(r"https://[^\"'\s]+", ghl_source))
    if origins != {GHL_ORIGIN}:
        findings.append("GHL provider origin is not exactly fixed")
    if 'GHL_API_VERSION = "v3"' not in ghl_source:
        findings.append("fixed GHL API version is missing")
    if "client.post(" not in ghl_source or "/contacts/{trusted.contact_id}/tags" not in ghl_source:
        findings.append("fixed GHL mutation is missing")
    execution_models = files.get("ai_business_automation/models/executions.py", "")
    action_block = execution_models.split("class ExecutionAction", 1)[-1].split(
        "class ExecutionStatus", 1
    )[0]
    actions = set(
        re.findall(r"^    ([A-Z][A-Z_]*) = \"([A-Z][A-Z_]*)\"$", action_block, re.MULTILINE)
    )
    if actions != {("ADD_CONTACT_TAG", "ADD_CONTACT_TAG")}:
        findings.append("supported execution action set changed")
    middleware = files.get("ai_business_automation/security/middleware.py", "")
    for marker in ("x-content-type-options", "cache-control", "pragma"):
        if marker not in middleware:
            findings.append(f"required security header is missing: {marker}")
    openai_source = files.get("ai_business_automation/providers/openai.py", "")
    for marker in ("store=False", '"strict": True', "max_output_tokens=request.max_output_tokens"):
        if marker not in openai_source:
            findings.append(f"bounded AI provider control is missing: {marker}")
    if "tools=" in openai_source:
        findings.append("AI tools must remain disabled")
    return findings


def production_configuration_findings(root: Path) -> list[str]:
    del root
    try:
        Settings(
            environment=Environment.PRODUCTION,
            approval_database_path="release-verification.sqlite3",
            auth_token_1=SecretStr("release-auth-material-" + "A7" * 8),
            auth_actor_1="release-admin",
            auth_role_1=AuthRole.ADMIN,
            approver_id="release-approver",
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
        "release-16d0xgfi",
        "release-y65qeavv",
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
