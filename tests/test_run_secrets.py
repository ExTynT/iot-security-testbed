import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def resolve_bash():
    git_bash_candidates = [
        Path(r"C:\Program Files\Git\usr\bin\bash.exe"),
        Path(r"C:\Program Files\Git\bin\bash.exe"),
    ]
    for candidate in git_bash_candidates:
        if candidate.exists():
            return str(candidate)

    return shutil.which("bash")


BASH = resolve_bash()
GIT = shutil.which("git")
LEGACY_DEFAULTS = {
    "device01" + "pass",
    "controller01" + "pass",
    "supersecret" + "psk",
}


@pytest.mark.skipif(BASH is None or GIT is None, reason="bash or git not available")
def test_new_run_generates_only_run_id_env_and_per_run_secret_files(tmp_path):
    repo_root = tmp_path / "repo"
    scripts_dir = repo_root / "scripts"
    scripts_dir.mkdir(parents=True)

    source_script = PROJECT_ROOT / "scripts" / "new_run.sh"
    target_script = scripts_dir / "new_run.sh"
    target_script.write_text(source_script.read_text(encoding="utf-8"), encoding="utf-8")
    target_script.chmod(0o755)

    subprocess.run([GIT, "init"], cwd=repo_root, check=True, capture_output=True, text=True)
    subprocess.run([GIT, "config", "user.name", "Codex"], cwd=repo_root, check=True, capture_output=True, text=True)
    subprocess.run(
        [GIT, "config", "user.email", "codex@example.com"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    (repo_root / "README.md").write_text("fixture repo\n", encoding="utf-8")
    subprocess.run([GIT, "add", "README.md"], cwd=repo_root, check=True, capture_output=True, text=True)
    subprocess.run([GIT, "commit", "-m", "fixture"], cwd=repo_root, check=True, capture_output=True, text=True)
    head_commit = subprocess.run(
        [GIT, "rev-parse", "HEAD"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    result = subprocess.run(
        [BASH, str(target_script)],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "LC_ALL": "C"},
    )

    env_lines = (repo_root / ".env").read_text(encoding="utf-8").strip().splitlines()
    assert len(env_lines) == 1
    assert env_lines[0].startswith("RUN_ID=")
    assert all(secret not in env_lines[0] for secret in LEGACY_DEFAULTS)

    run_id = env_lines[0].split("=", 1)[1]
    assert run_id
    assert f"RUN_ID={run_id}" in result.stdout

    run_meta = json.loads((repo_root / "runs" / run_id / "state" / "run_meta.json").read_text(encoding="utf-8"))
    assert run_meta["run_id"] == run_id
    assert run_meta["git_commit"] == head_commit
    assert run_meta["created_at"].endswith("Z")

    shared_dirs = {"pcap", "logs", "results", "state"}
    if os.name == "posix":
        for directory_name in shared_dirs:
            mode = stat.S_IMODE((repo_root / "runs" / run_id / directory_name).stat().st_mode)
            assert mode == 0o1777
        secrets_mode = stat.S_IMODE((repo_root / "runs" / run_id / "secrets").stat().st_mode)
        assert secrets_mode == 0o700

    secrets_dir = repo_root / "runs" / run_id / "secrets"
    secret_files = {
        "mqtt_device_password.txt",
        "mqtt_controller_password.txt",
        "coap_psk.txt",
    }
    assert {path.name for path in secrets_dir.iterdir() if path.is_file()} == secret_files
    for secret_file in secret_files:
        secret_value = (secrets_dir / secret_file).read_text(encoding="utf-8").strip()
        assert secret_value
        assert secret_value not in LEGACY_DEFAULTS


def test_secure_overlays_use_file_based_secrets_and_read_only_pubkey():
    mqtt_secure = (PROJECT_ROOT / "docker-compose.mqtt-secure.yml").read_text(encoding="utf-8")
    coap_secure = (PROJECT_ROOT / "docker-compose.coap-secure.yml").read_text(encoding="utf-8")
    ota_secure = (PROJECT_ROOT / "docker-compose.ota-secure.yml").read_text(encoding="utf-8")

    assert "/run/secrets/mqtt_device_password" in mqtt_secure
    assert "mqtt_controller_password" in mqtt_secure
    assert "mosquitto_secure_bootstrap.sh" in mqtt_secure
    assert "MQTT_PASS=" not in mqtt_secure
    assert "MQTT_CTRL_PASS=" not in mqtt_secure
    assert "/run/secrets/coap_psk" in coap_secure
    assert "COAP_PSK=" not in coap_secure
    assert '"$$coap_psk"' in coap_secure
    assert "MINISIGN_PUBKEY_FILE=/config/minisign.pub" in ota_secure
    assert "MINISIGN_PUBKEY=" not in ota_secure
