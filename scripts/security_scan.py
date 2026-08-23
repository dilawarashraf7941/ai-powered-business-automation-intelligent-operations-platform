"""Focused static checks for capabilities excluded from Phase 1."""

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
FORBIDDEN_CALLS = {"eval", "exec", "compile", "os.system"}
SECRET_PATTERN = re.compile(
    r"(?i)(api[_-]?key|password|secret|token)\s*=\s*['\"][A-Za-z0-9_\-/+=]{16,}['\"]"
)


def scan_file(path: Path) -> list[str]:
    """Return focused security findings for one Python source file."""

    findings: list[str] = []
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text, filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import | ast.ImportFrom):
            names = [alias.name for alias in node.names]
            if any(name == "subprocess" or name.startswith("requests") for name in names):
                findings.append(f"{path}: prohibited capability import")
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name in FORBIDDEN_CALLS:
                findings.append(f"{path}:{node.lineno}: prohibited call {name}")
            for keyword in node.keywords:
                if (
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                ):
                    findings.append(f"{path}:{node.lineno}: prohibited shell mode")
    if SECRET_PATTERN.search(text):
        findings.append(f"{path}: possible hard-coded secret")
    return findings


def _call_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    return ""


def main() -> int:
    findings = [finding for path in SOURCE.rglob("*.py") for finding in scan_file(path)]
    forbidden_files = [ROOT / ".env"]
    findings.extend(
        f"{path}: local environment file must not be tracked"
        for path in forbidden_files
        if path.exists()
    )
    if findings:
        print("\n".join(findings))
        return 1
    print("Security source scan passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
