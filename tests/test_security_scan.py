"""Source-level enforcement of Phase 2 capability exclusions."""

import ast
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"


def test_production_source_has_no_dangerous_capabilities() -> None:
    forbidden_imports = {"subprocess", "requests", "httpx", "urllib", "importlib"}
    forbidden_calls = {"eval", "exec", "compile", "__import__", "os.system"}
    findings: list[str] = []
    for path in SOURCE.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                findings.extend(
                    f"{path}: import {alias.name}"
                    for alias in node.names
                    if alias.name.split(".")[0] in forbidden_imports
                )
            elif (
                isinstance(node, ast.ImportFrom)
                and (node.module or "").split(".")[0] in forbidden_imports
            ):
                findings.append(f"{path}: import {node.module}")
            elif isinstance(node, ast.Call):
                name = _call_name(node.func)
                if name in forbidden_calls:
                    findings.append(f"{path}: call {name}")
                assert not any(
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for keyword in node.keywords
                )
    assert findings == []


def _call_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    return ""


def test_no_hard_coded_secrets_or_unsafe_debug() -> None:
    secret_assignment = re.compile(
        r"(?i)(password|secret|api[_-]?key|token)\s*=\s*['\"][A-Za-z0-9+/=_-]{16,}['\"]"
    )
    combined = "\n".join(path.read_text(encoding="utf-8") for path in SOURCE.rglob("*.py"))
    assert secret_assignment.search(combined) is None
    assert "debug=True" not in combined.replace(" ", "")


def test_openai_sdk_is_confined_to_provider_adapter() -> None:
    importers: list[str] = []
    for path in SOURCE.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                if any(alias.name.split(".")[0] == "openai" for alias in node.names):
                    importers.append(path.relative_to(ROOT).as_posix())
            elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "openai":
                importers.append(path.relative_to(ROOT).as_posix())
    assert set(importers) == {"src/ai_business_automation/providers/openai.py"}


def test_no_action_framework_or_business_integration_is_present() -> None:
    combined = "\n".join(path.read_text(encoding="utf-8").lower() for path in SOURCE.rglob("*.py"))
    for prohibited in ("langchain", "langgraph", "crewai", "autogen", "n8n", "ghl"):
        assert prohibited not in combined


def test_environment_file_is_ignored_and_not_tracked() -> None:
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".env" in ignore
    tracked = subprocess.run(
        ["git", "ls-files", ".env"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert tracked.stdout.strip() == ""
