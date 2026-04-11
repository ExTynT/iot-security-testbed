import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = PROJECT_ROOT / ".github" / "workflows"
USES_RE = re.compile(r"uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?)@([^\s#]+)")
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
NODE24_READY_ACTION_PINS = {
    "actions/setup-python": {
        "e797f83bcb11b83ae66e0230d6156d7c80228e7c",  # v6.0.0
        "83679a892e2d95755f2dac6acb0bfd1e9ac5d548",  # v6.1.0
        "a309ff8b426b58ec0e2a45f0f869d46889d02405",  # v6.2.0
    },
    "actions/upload-artifact": {
        "b7c566a772e6b6bfb58ed0dc250532a479d7789f",  # v6.0.0
        "bbbca2ddaa5d8feaa63e36b76fdaad77386f024f",  # v7.0.0
    },
}


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


def test_ci_workflow_uses_node24_ready_core_actions():
    workflow = (WORKFLOWS_DIR / "ci.yml").read_text(encoding="utf-8")
    refs = {
        action: ref
        for action, ref in USES_RE.findall(workflow)
        if action in NODE24_READY_ACTION_PINS
    }

    for action, allowed_refs in NODE24_READY_ACTION_PINS.items():
        assert refs[action] in allowed_refs, f"{action} is not pinned to a known Node 24-ready SHA"
