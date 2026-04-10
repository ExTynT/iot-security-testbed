import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = PROJECT_ROOT / ".github" / "workflows"
USES_RE = re.compile(r"uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?)@([^\s#]+)")
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def test_all_workflow_actions_are_pinned_to_full_commit_sha():
    violations = []
    for workflow_path in sorted(WORKFLOWS_DIR.glob("*.yml")):
        content = workflow_path.read_text(encoding="utf-8")
        for action, ref in USES_RE.findall(content):
            if not FULL_SHA_RE.fullmatch(ref):
                violations.append(f"{workflow_path.name}: {action}@{ref}")

    assert not violations, "Nepinovane actions:\n" + "\n".join(violations)


def test_codeql_workflow_scans_python_and_actions_with_minimum_permissions():
    codeql_workflow = WORKFLOWS_DIR / "codeql.yml"
    content = codeql_workflow.read_text(encoding="utf-8")

    assert "security-events: write" in content
    assert "contents: read" in content
    assert "language: python" in content or '"python"' in content
    assert "language: actions" in content or '"actions"' in content
    assert "github/codeql-action/init@" in content
    assert "github/codeql-action/analyze@" in content
