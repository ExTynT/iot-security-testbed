import importlib.util
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_ROOT = PROJECT_ROOT / "tests" / "fixtures"
COLLECTOR_PATH = PROJECT_ROOT / "images" / "monitor-collector" / "collector.py"
SUMMARY_SCHEMA_PATH = PROJECT_ROOT / "schemas" / "summary.schema.json"


def load_collector_module():
    spec = importlib.util.spec_from_file_location("monitor_collector", COLLECTOR_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


collector = load_collector_module()
FIXTURE_CASES = [
    (
        "mqtt-baseline",
        {
            "P1_mqtt_unauth_denied",
            "P1_mqtt_unauth_success",
        },
    ),
    (
        "mqtt-secure",
        {
            "P1_mqtt_unauth_denied",
            "P1_mqtt_unauth_success",
        },
    ),
    (
        "coap-baseline",
        {
            "P2_coap_plain_gets",
            "P2_coap_plain_blocked",
            "P2_coap_dtls_failures",
            "P2_coap_dtls_ok",
        },
    ),
    (
        "coap-secure",
        {
            "P2_coap_plain_gets",
            "P2_coap_plain_blocked",
            "P2_coap_dtls_failures",
            "P2_coap_dtls_ok",
        },
    ),
    (
        "ota-baseline",
        {
            "P3_ota_evil_applied",
            "P3_ota_evil_blocked",
            "P3_ota_signed_ok",
        },
    ),
    (
        "ota-secure",
        {
            "P3_ota_evil_applied",
            "P3_ota_evil_blocked",
            "P3_ota_signed_ok",
        },
    ),
]
FIXTURE_NAMES = [name for name, _ in FIXTURE_CASES]


def load_summary_schema():
    return json.loads(SUMMARY_SCHEMA_PATH.read_text(encoding="utf-8"))


def build_summary_validator():
    schema = load_summary_schema()
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def load_fixture(name):
    base_dir = FIXTURES_ROOT / name
    logs_dir = base_dir / "logs"
    state_dir = base_dir / "state"
    expected = json.loads((base_dir / "expected_summary.json").read_text(encoding="utf-8"))
    logs = {
        path.name: path.read_text(encoding="utf-8", errors="ignore")
        for path in sorted(logs_dir.iterdir())
        if path.is_file()
    }
    return {
        "scenario": (state_dir / "scenario.txt").read_text(encoding="utf-8").strip(),
        "state_version": (state_dir / "version.txt").read_text(encoding="utf-8").strip(),
        "run_metadata": json.loads((state_dir / "run_meta.json").read_text(encoding="utf-8")),
        "compose_files": [
            line.strip()
            for line in (state_dir / "compose_files.txt").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ],
        "logs": logs,
        "expected": expected,
        "pcap_bytes": expected["artifacts"]["pcap_bytes"],
    }


def stable_mqtt_raw(raw_mqtt):
    return {
        key: value
        for key, value in raw_mqtt.items()
        if key != "published"
    }


@pytest.mark.parametrize(
    ("fixture_name", "expected_keys"),
    FIXTURE_CASES,
)
def test_build_summary_matches_expected_fixture_contract(fixture_name, expected_keys):
    fixture = load_fixture(fixture_name)
    validator = build_summary_validator()

    summary = collector.build_summary(
        scenario=fixture["scenario"],
        logs=fixture["logs"],
        state_version=fixture["state_version"],
        pcap_bytes=fixture["pcap_bytes"],
        run_metadata=fixture["run_metadata"],
        compose_files=fixture["compose_files"],
    )

    validator.validate(summary)

    assert summary["meta"] == fixture["expected"]["meta"]
    assert summary["scenario"] == fixture["expected"]["scenario"]
    assert summary["warnings"] == fixture["expected"]["warnings"]
    assert summary["artifacts"] == fixture["expected"]["artifacts"]
    assert summary["evidence"] == fixture["expected"]["evidence"]
    assert stable_mqtt_raw(summary["raw"]["mqtt"]) == stable_mqtt_raw(fixture["expected"]["raw"]["mqtt"])
    assert summary["raw"]["coap"] == fixture["expected"]["raw"]["coap"]
    assert summary["raw"]["ota"] == fixture["expected"]["raw"]["ota"]
    assert summary["raw"]["dut"] == fixture["expected"]["raw"]["dut"]
    assert {key: summary["kpi"][key] for key in expected_keys} == {
        key: fixture["expected"]["kpi"][key] for key in expected_keys
    }


@pytest.mark.parametrize("fixture_name", FIXTURE_NAMES)
def test_fixture_expected_summaries_validate_metadata_contract(fixture_name):
    fixture = load_fixture(fixture_name)
    meta_schema = load_summary_schema()["properties"]["meta"]
    validator = Draft202012Validator(
        meta_schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )

    validator.validate(fixture["expected"]["meta"])
    assert fixture["expected"]["meta"]["run_id"].startswith("fixture-")
    assert fixture["expected"]["meta"]["compose_files"]


def test_parse_mqtt_matches_expected_fixture():
    fixture = load_fixture("mqtt-secure")
    expected = fixture["expected"]

    result = collector.parse_mqtt(
        scenario=fixture["scenario"],
        mqtt_log=fixture["logs"].get("mqtt.log", ""),
        attacks_log=fixture["logs"].get("attacks.log", ""),
        mqtt_control_log=fixture["logs"].get("mqtt_control.log", ""),
    )

    assert result["warnings"] == expected["warnings"]
    assert result["kpi"] == {
        "P1_mqtt_unauth_denied": expected["kpi"]["P1_mqtt_unauth_denied"],
        "P1_mqtt_unauth_success": expected["kpi"]["P1_mqtt_unauth_success"],
    }
    assert stable_mqtt_raw(result["raw"]) == stable_mqtt_raw(expected["raw"]["mqtt"])


def test_parse_coap_matches_expected_fixture():
    fixture = load_fixture("coap-secure")
    expected = fixture["expected"]

    result = collector.parse_coap(
        scenario=fixture["scenario"],
        coap_log=fixture["logs"].get("coap.log", ""),
        attacks_log=fixture["logs"].get("attacks.log", ""),
        coap_plain_probe_log=fixture["logs"].get("coap_plain_probe.log", ""),
        coap_baseline_probe_log=fixture["logs"].get("coap_baseline_probe.log", ""),
        coap_dtls_wrong_psk_log=fixture["logs"].get("coap_dtls_wrong_psk.log", ""),
        coap_dtls_ok_log=fixture["logs"].get("coap_dtls_ok.log", ""),
    )

    assert result["warnings"] == expected["warnings"]
    assert result["kpi"] == {
        "P2_coap_plain_gets": expected["kpi"]["P2_coap_plain_gets"],
        "P2_coap_plain_blocked": expected["kpi"]["P2_coap_plain_blocked"],
        "P2_coap_dtls_failures": expected["kpi"]["P2_coap_dtls_failures"],
        "P2_coap_dtls_ok": expected["kpi"]["P2_coap_dtls_ok"],
    }
    assert result["raw"] == expected["raw"]["coap"]


def test_coap_secure_fixture_uses_secure_only_endpoint_wording():
    coap_log = load_fixture("coap-secure")["logs"]["coap.log"]

    assert "Firewall: port 5683 BLOCKED" not in coap_log
    assert "CoAP DTLS PSK: 5683=CLOSED 5684=DTLS+PSK" in coap_log


def test_parse_ota_matches_expected_fixture():
    fixture = load_fixture("ota-secure")
    expected = fixture["expected"]

    result = collector.parse_ota(
        scenario=fixture["scenario"],
        ota_access_log=fixture["logs"].get("ota_access.log", ""),
        ota_evil_access_log=fixture["logs"].get("ota_evil_access.log", ""),
        ota_control_log=fixture["logs"].get("ota_control.log", ""),
        ota_attack_log=fixture["logs"].get("ota_attack.log", ""),
    )

    assert result["warnings"] == expected["warnings"]
    assert result["kpi"] == {
        "P3_ota_evil_applied": expected["kpi"]["P3_ota_evil_applied"],
        "P3_ota_evil_blocked": expected["kpi"]["P3_ota_evil_blocked"],
        "P3_ota_signed_ok": expected["kpi"]["P3_ota_signed_ok"],
    }
    assert result["raw"] == expected["raw"]["ota"]
    assert result["dut"] == {
        "ota_applied": expected["raw"]["dut"]["ota_applied"],
        "ota_blocked": expected["raw"]["dut"]["ota_blocked"],
        "ota_signed_ok": expected["raw"]["dut"]["ota_signed_ok"],
    }


def test_parse_mqtt_emits_warning_for_missing_control_log():
    result = collector.parse_mqtt(scenario="mqtt-secure", mqtt_log="", attacks_log="", mqtt_control_log="")

    assert "mqtt_control_log_missing" in result["warnings"]


def test_parse_coap_emits_warnings_for_missing_secure_probe_logs():
    result = collector.parse_coap(
        scenario="coap-secure",
        coap_log="",
        attacks_log="",
        coap_plain_probe_log="",
        coap_baseline_probe_log="",
        coap_dtls_wrong_psk_log="",
        coap_dtls_ok_log="",
    )

    assert result["warnings"] == [
        "coap_plain_probe_log_missing",
        "coap_dtls_wrong_psk_log_missing",
        "coap_dtls_ok_log_missing",
    ]


def test_parse_ota_emits_warnings_for_missing_secure_logs():
    result = collector.parse_ota(
        scenario="ota-secure",
        ota_access_log="",
        ota_evil_access_log="",
        ota_control_log="",
        ota_attack_log="",
    )

    assert result["warnings"] == [
        "ota_access_log_missing",
        "ota_evil_access_log_missing",
        "ota_control_log_missing",
        "ota_attack_log_missing",
    ]


def test_build_summary_baseline_validates_against_schema():
    validator = build_summary_validator()
    summary = collector.build_summary(
        scenario="mqtt-baseline",
        logs={"mqtt.log": "PUBLISH\n"},
        state_version="1.0.0",
        pcap_bytes={"mqtt": 4},
        run_metadata={
            "run_id": "20260410-182336",
            "git_commit": "a" * 40,
            "created_at": "2026-04-10T18:23:36Z",
        },
        compose_files=["docker-compose.yml"],
    )

    validator.validate(summary)
    assert summary["meta"]["profile"] == "baseline"


def test_build_summary_normalizes_invalid_created_at_format():
    validator = build_summary_validator()
    summary = collector.build_summary(
        scenario="mqtt-secure",
        run_metadata={
            "run_id": "20260410-182336",
            "git_commit": "a" * 40,
            "created_at": "not-a-date",
        },
        compose_files=["docker-compose.yml", "docker-compose.mqtt-secure.yml"],
    )

    validator.validate(summary)
    assert summary["meta"]["created_at"] == "2026-04-10T18:23:36Z"


def test_read_run_meta_infers_run_id_and_created_at_from_state_dir_when_missing(tmp_path):
    run_dir = tmp_path / "20260410-182336"
    state_dir = run_dir / "state"
    state_dir.mkdir(parents=True)

    assert collector.read_run_meta(state_dir) == {
        "run_id": "20260410-182336",
        "git_commit": "unknown",
        "created_at": "2026-04-10T18:23:36Z",
    }


def test_load_collection_inputs_reads_run_meta_and_compose_files_from_state(tmp_path):
    logs_dir = tmp_path / "logs"
    state_dir = tmp_path / "state"
    pcap_dir = tmp_path / "pcap"
    logs_dir.mkdir()
    state_dir.mkdir()
    pcap_dir.mkdir()

    (state_dir / "scenario.txt").write_text("mqtt-secure\n", encoding="utf-8")
    (state_dir / "version.txt").write_text("1.2.3\n", encoding="utf-8")
    (state_dir / "run_meta.json").write_text(
        json.dumps(
            {
                "run_id": "run-123",
                "git_commit": "a" * 40,
                "created_at": "2026-04-10T18:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (state_dir / "compose_files.txt").write_text(
        "docker-compose.yml\ndocker-compose.custom.yml\n",
        encoding="utf-8",
    )
    (logs_dir / "mqtt.log").write_text("PUBLISH\n", encoding="utf-8")
    (pcap_dir / "mqtt.pcap").write_bytes(b"abcd")

    scenario, logs, state_version, pcap_bytes, run_metadata, compose_files = collector.load_collection_inputs(
        logs_dir=logs_dir,
        state_dir=state_dir,
        pcap_dir=pcap_dir,
    )

    assert scenario == "mqtt-secure"
    assert logs["mqtt.log"] == "PUBLISH\n"
    assert state_version == "1.2.3"
    assert pcap_bytes["mqtt"] == 4
    assert run_metadata == {
        "run_id": "run-123",
        "git_commit": "a" * 40,
        "created_at": "2026-04-10T18:00:00Z",
    }
    assert compose_files == [
        "docker-compose.yml",
        "docker-compose.custom.yml",
    ]
