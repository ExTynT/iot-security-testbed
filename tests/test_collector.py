import importlib.util
import json
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_ROOT = PROJECT_ROOT / "tests" / "fixtures"
COLLECTOR_PATH = PROJECT_ROOT / "images" / "monitor-collector" / "collector.py"


def load_collector_module():
    spec = importlib.util.spec_from_file_location("monitor_collector", COLLECTOR_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


collector = load_collector_module()


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
    [
        (
            "mqtt-secure",
            {
                "P1_mqtt_unauth_denied",
                "P1_mqtt_unauth_success",
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
            "ota-secure",
            {
                "P3_ota_evil_applied",
                "P3_ota_evil_blocked",
                "P3_ota_signed_ok",
            },
        ),
    ],
)
def test_build_summary_matches_expected_secure_fixture(fixture_name, expected_keys):
    fixture = load_fixture(fixture_name)

    summary = collector.build_summary(
        scenario=fixture["scenario"],
        logs=fixture["logs"],
        state_version=fixture["state_version"],
        pcap_bytes=fixture["pcap_bytes"],
    )

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
