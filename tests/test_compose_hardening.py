import json
import os
import stat
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def read_text(path: str) -> str:
    return (PROJECT_ROOT / path).read_text(encoding="utf-8")


def load_yaml(path: str) -> dict:
    return yaml.safe_load((PROJECT_ROOT / path).read_text(encoding="utf-8"))


def service(compose: dict, service_name: str) -> dict:
    services = compose.get("services", {})
    assert service_name in services, f"service block not found: {service_name}"
    return services[service_name]


def test_base_compose_uses_native_runtime_hardening():
    compose = load_yaml("docker-compose.yml")

    mosquitto = service(compose, "mosquitto")
    assert mosquitto["init"] is True
    assert mosquitto["command"] == ["/usr/sbin/mosquitto", "-c", "/mosquitto/config/mosquitto.conf"]
    assert mosquitto["read_only"] is True
    assert mosquitto["cap_drop"] == ["ALL"]
    assert "healthcheck" in mosquitto

    coap = service(compose, "coap")
    assert coap["init"] is True
    assert coap["read_only"] is True
    assert coap["cap_drop"] == ["ALL"]
    assert "/run" in coap["tmpfs"]
    assert "healthcheck" in coap

    ota = service(compose, "ota")
    assert ota["init"] is True
    assert ota["read_only"] is True
    assert ota["cap_drop"] == ["ALL"]
    assert any(str(item).startswith("/run:uid=101") for item in ota["tmpfs"])
    assert "healthcheck" in ota

    dut = service(compose, "dut")
    assert dut["user"] == "10001:10001"
    assert dut["init"] is True
    assert dut["read_only"] is True
    assert dut["cap_drop"] == ["ALL"]
    assert "healthcheck" in dut
    assert dut["depends_on"]["mosquitto"]["condition"] == "service_healthy"

    attacker = service(compose, "attacker")
    assert attacker["user"] == "10002:10002"
    assert attacker["read_only"] is True
    assert attacker["cap_drop"] == ["ALL"]

    monitor_collector = service(compose, "monitor-collector")
    assert monitor_collector["user"] == "10003:10003"
    assert monitor_collector["read_only"] is True
    assert monitor_collector["cap_drop"] == ["ALL"]
    assert "./runs/${RUN_ID}/state:/state:ro" in monitor_collector["volumes"]

    for sniffer in ("sniffer_mqtt", "sniffer_coap", "sniffer_ota", "sniffer_ota_evil"):
        sniffer_service = service(compose, sniffer)
        assert sniffer_service["cap_drop"] == ["ALL"]
        assert sniffer_service["cap_add"] == ["NET_ADMIN", "NET_RAW"]


def test_secure_overlays_override_healthchecks_with_runtime_specific_probes():
    mqtt_secure = load_yaml("docker-compose.mqtt-secure.yml")
    mosquitto = service(mqtt_secure, "mosquitto")
    assert "healthcheck" in mosquitto
    assert "/run/secrets/mqtt_device_password" in mosquitto["healthcheck"]["test"][1]

    coap_secure = load_yaml("docker-compose.coap-secure.yml")
    coap = service(coap_secure, "coap")
    assert "cap_add" not in coap
    assert "healthcheck" in coap
    assert '"$$coap_psk"' in coap["healthcheck"]["test"][1]
    assert "5683=CLOSED 5684=DTLS+PSK" in coap["command"][2]

    ota_secure = load_yaml("docker-compose.ota-secure.yml")
    ota = service(ota_secure, "ota")
    assert (
        "./runs/${RUN_ID}/state/manifest.json.minisig:/usr/share/nginx/html/manifest.json.minisig:ro"
        in ota["volumes"]
    )


def test_runners_use_health_aware_startup_and_wait_ready_is_minimal():
    run_case = read_text("scripts/run_case.sh")
    run_all = read_text("scripts/_run_all.sh")
    makefile = read_text("Makefile")
    wait_ready = read_text("scripts/wait_ready.sh")

    assert "compose_files.txt" in run_case
    assert "compose_files.txt" in run_all
    assert "compose_files.txt" in makefile
    assert "up -d --wait" in run_case
    assert "up -d --wait" in run_all
    assert "up -d --wait" in makefile
    assert "retry_until" not in wait_ready
    assert "docker compose exec" not in wait_ready


def test_ota_helpers_use_configurable_minisign_binary():
    run_case = read_text("scripts/run_case.sh")
    run_all = read_text("scripts/_run_all.sh")
    makefile = read_text("Makefile")
    readme = read_text("README.md")
    legacy_windows_path = "minisign-" + "win64"

    assert 'MINISIGN_BIN="${MINISIGN_BIN:-minisign}"' in run_case
    assert 'MINISIGN_BIN="${MINISIGN_BIN:-minisign}"' in run_all
    assert 'command -v "$MINISIGN_BIN"' in run_case
    assert 'command -v "$MINISIGN_BIN"' in run_all
    assert "MINISIGN_BIN ?= minisign" in makefile
    assert '"$(MINISIGN_BIN)"' in makefile
    assert legacy_windows_path not in run_case
    assert legacy_windows_path not in run_all
    assert legacy_windows_path not in makefile
    assert "Windows Git Bash:" in readme
    assert "MINISIGN_BIN" in readme
    assert "/c/.../minisign.exe" in readme
    assert "state/manifest.json.minisig" in readme
    assert '-x "runs/${1}/state/manifest.json.minisig"' in run_case
    assert '-x "runs/${1}/state/manifest.json.minisig"' in run_all
    assert "-x runs/$$(grep '^RUN_ID=' .env | cut -d= -f2)/state/manifest.json.minisig" in makefile


def test_normal_runners_cleanup_compose_on_failure():
    run_case = read_text("scripts/run_case.sh")
    run_all = read_text("scripts/_run_all.sh")

    assert "docker-compose(\\.[^[:space:]]+)?\\.yml" in run_case
    assert "docker-compose(\\.[^[:space:]]+)?\\.yml" in run_all
    assert 'trap "docker compose $compose_args down --remove-orphans || true" EXIT' in run_case
    assert "down --remove-orphans || true" in run_case
    assert "trap - EXIT" in run_case
    assert "docker compose $compose_args down --remove-orphans || true" in run_case
    assert "OTA_S" in run_case
    assert 'trap "docker compose $compose_args down --remove-orphans || true" EXIT' in run_all
    assert "down --remove-orphans || true" in run_all
    assert "OTA_S" in run_all
    assert "trap - EXIT" in run_all
    assert "docker compose $compose_args down --remove-orphans || true" in run_all


def test_smoke_ci_runs_collector_and_uploads_state_artifacts():
    makefile = read_text("Makefile")
    smoke_test = read_text("scripts/smoke_test.sh")
    workflow = read_text(".github/workflows/ci.yml")

    assert "scripts/smoke_test.sh" in makefile
    assert "monitor-collector" in makefile
    assert "SMOKE_EXPECT_RESULTS=1 bash scripts/smoke_test.sh" in makefile
    assert "results/summary.json" in smoke_test
    assert "state/run_meta.json" in smoke_test
    assert "meta.run_id" in smoke_test
    assert "SMOKE_EXPECT_RESULTS" in smoke_test
    assert 'runs/${{ steps.smoke_run.outputs.run_id }}/state/**' in workflow


def test_ci_installs_pyyaml_for_yaml_backed_test_layer():
    workflow = load_yaml(".github/workflows/ci.yml")
    steps = workflow["jobs"]["lint-test-smoke"]["steps"]
    install_tooling = next(step for step in steps if step.get("name") == "Install Python tooling")

    assert "pip install" in install_tooling["run"]
    assert "pyyaml" in install_tooling["run"].lower()


def test_readme_documents_current_artifacts_and_aggregate_outputs():
    readme = read_text("README.md")

    assert "secrets/" in readme
    assert "runs/final-dataset.json" in readme
    assert "runs/analysis-aggregate.md" in readme
    assert "runs/analysis-aggregate.json" in readme
    assert "runs/aggregate.json" in readme
    assert "state/run_meta.json" in readme
    assert "results/fig_kpi.png" in readme
    assert "summary.schema.json" in readme


def test_readme_keeps_security_citation_and_dev_test_quality_signals():
    readme = read_text("README.md")

    assert "python -m pip install --upgrade pip pytest ruff jsonschema pyyaml" in readme
    assert "## Bezpečnosť a nahlasovanie zraniteľností" in readme
    assert "## Citácia a väzba na prácu" in readme
    assert "## Licencia" in readme
    assert "SECURITY.md" in readme
    assert "CITATION.cff" in readme
    assert ".github/workflows/codeql.yml" in readme
    assert "LICENSE" in readme


def test_repo_exposes_machine_readable_citation_metadata():
    citation = yaml.safe_load(read_text("CITATION.cff"))

    assert citation["cff-version"] == "1.2.0"
    assert citation["title"] == "IoT Security Testbed"
    assert citation["type"] == "software"
    assert citation["repository-code"] == "https://github.com/ExTynT/iot-security-testbed"
    assert citation["license"] == "MIT"
    assert citation["authors"][0]["family-names"] == "Klopček"


def test_reference_dataset_manifest_is_present_and_audit_ready():
    manifest = json.loads(read_text("runs/final-dataset.json"))
    expected_run_ids = [
        "20260322-161426",
        "20260322-161440",
        "20260322-161453",
        "20260322-161510",
        "20260322-161634",
        "20260322-161643",
    ]
    expected_scenarios = [
        "mqtt-baseline",
        "mqtt-secure",
        "coap-baseline",
        "coap-secure",
        "ota-baseline",
        "ota-secure",
    ]

    assert manifest["dataset_id"] == "thesis-final-20260322"
    assert manifest["run_ids"] == expected_run_ids
    assert [entry["scenario"] for entry in manifest["runs"]] == expected_scenarios
    assert "runs/analysis-aggregate.json" in manifest["analysis_outputs"]
    assert "runs/aggregate.json" in manifest["analysis_outputs"]

    for entry, run_id in zip(manifest["runs"], expected_run_ids):
        assert entry["run_id"] == run_id
        assert entry["summary_path"] == f"runs/{run_id}/results/summary.json"


def test_aggregate_json_artifacts_are_present_and_consistent():
    aggregate = json.loads(read_text("runs/aggregate.json"))
    analysis_aggregate = json.loads(read_text("runs/analysis-aggregate.json"))

    assert aggregate == analysis_aggregate
    assert aggregate["totals"]["warning_count"] == sum(
        scenario["warning_count"] for scenario in aggregate["scenarios"].values()
    )
    assert aggregate["totals"]["runs"] == sum(
        scenario["runs"] for scenario in aggregate["scenarios"].values()
    )
    assert aggregate["scenarios"]["coap-secure"]["warning_count"] >= 0


def test_security_policy_exists_for_public_repo():
    security = read_text("SECURITY.md")
    security_lower = security.lower()

    assert "supported versions" in security_lower
    assert "main" in security_lower
    assert "how to report" in security_lower
    assert "response expectation" in security_lower
    assert "academic laboratory testbed" in security_lower
    assert "not a production system" in security_lower


def test_mosquitto_bootstrap_scripts_are_executable_on_posix():
    if os.name != "posix":
        return

    for rel_path in ("scripts/mosquitto_entrypoint.sh", "scripts/mosquitto_secure_bootstrap.sh"):
        mode = (PROJECT_ROOT / rel_path).stat().st_mode
        assert mode & stat.S_IXUSR, f"{rel_path} must be executable on POSIX runners"
