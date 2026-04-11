import importlib.util
import json
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ANALYZE_RESULTS_PATH = PROJECT_ROOT / "images" / "monitor-collector" / "analyze_results.py"


def load_analyze_results_module():
    spec = importlib.util.spec_from_file_location("analyze_results", ANALYZE_RESULTS_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


analyze_results = load_analyze_results_module()


def make_run(run_id, scenario, kpi, warnings=None):
    return {
        "run_id": run_id,
        "scenario": scenario,
        "kpi": kpi,
        "warnings": warnings or [],
    }


@pytest.mark.parametrize(
    ("scenario", "kpi", "expected_pass"),
    [
        (
            "mqtt-baseline",
            {"P1_mqtt_unauth_success": 30, "P1_mqtt_unauth_denied": 0},
            True,
        ),
        (
            "mqtt-secure",
            {"P1_mqtt_unauth_success": 0, "P1_mqtt_unauth_denied": 30},
            True,
        ),
        (
            "coap-baseline",
            {"P2_coap_plain_gets": 3},
            True,
        ),
        (
            "coap-secure",
            {
                "P2_coap_plain_gets": 0,
                "P2_coap_plain_blocked": 3,
                "P2_coap_dtls_failures": 5,
                "P2_coap_dtls_ok": 1,
            },
            True,
        ),
        (
            "ota-baseline",
            {"P3_ota_evil_applied": 1},
            True,
        ),
        (
            "ota-secure",
            {"P3_ota_evil_applied": 0, "P3_ota_evil_blocked": 1, "P3_ota_signed_ok": 1},
            True,
        ),
        (
            "ota-secure",
            {"P3_ota_evil_applied": 1, "P3_ota_evil_blocked": 0, "P3_ota_signed_ok": 1},
            False,
        ),
    ],
)
def test_evaluate_run_pass_applies_expected_binary_rules(scenario, kpi, expected_pass):
    run = make_run("run-1", scenario, kpi)

    result = analyze_results.evaluate_run_pass(run)

    assert result["passed"] is expected_pass
    assert result["scenario"] == scenario
    assert isinstance(result["checks"], list)
    assert result["checks"]


def test_evaluate_run_pass_fails_when_warnings_are_present():
    run = make_run(
        "run-2",
        "mqtt-secure",
        {"P1_mqtt_unauth_success": 0, "P1_mqtt_unauth_denied": 30},
        warnings=["mqtt_control_log_missing"],
    )

    result = analyze_results.evaluate_run_pass(run)

    assert result["passed"] is False
    assert "warnings_present" in result["failed_checks"]


def test_build_aggregate_summary_counts_runs_failures_and_success_rates():
    runs = [
        make_run("m1", "mqtt-baseline", {"P1_mqtt_unauth_success": 30, "P1_mqtt_unauth_denied": 0}),
        make_run("m2", "mqtt-baseline", {"P1_mqtt_unauth_success": 0, "P1_mqtt_unauth_denied": 5}),
        make_run("m3", "mqtt-secure", {"P1_mqtt_unauth_success": 0, "P1_mqtt_unauth_denied": 30}),
        make_run("c1", "coap-secure", {
            "P2_coap_plain_gets": 0,
            "P2_coap_plain_blocked": 3,
            "P2_coap_dtls_failures": 5,
            "P2_coap_dtls_ok": 1,
        }),
        make_run("c2", "coap-secure", {
            "P2_coap_plain_gets": 1,
            "P2_coap_plain_blocked": 2,
            "P2_coap_dtls_failures": 5,
            "P2_coap_dtls_ok": 1,
        }),
    ]

    aggregate = analyze_results.build_aggregate_summary(runs)

    assert aggregate["totals"] == {
        "runs": 5,
        "pass_count": 3,
        "fail_count": 2,
        "success_rate": 0.6,
        "warning_count": 0,
    }
    assert aggregate["scenarios"]["mqtt-baseline"] == {
        "runs": 2,
        "pass_count": 1,
        "fail_count": 1,
        "success_rate": 0.5,
        "warning_count": 0,
    }
    assert aggregate["scenarios"]["mqtt-secure"] == {
        "runs": 1,
        "pass_count": 1,
        "fail_count": 0,
        "success_rate": 1.0,
        "warning_count": 0,
    }
    assert aggregate["scenarios"]["coap-secure"] == {
        "runs": 2,
        "pass_count": 1,
        "fail_count": 1,
        "success_rate": 0.5,
        "warning_count": 0,
    }


def test_build_aggregate_markdown_contains_compact_success_table():
    aggregate = {
        "totals": {"runs": 6, "pass_count": 6, "fail_count": 0, "success_rate": 1.0, "warning_count": 0},
        "scenarios": {
            "mqtt-baseline": {"runs": 1, "pass_count": 1, "fail_count": 0, "success_rate": 1.0, "warning_count": 0},
            "mqtt-secure": {"runs": 1, "pass_count": 1, "fail_count": 0, "success_rate": 1.0, "warning_count": 0},
            "coap-baseline": {"runs": 1, "pass_count": 1, "fail_count": 0, "success_rate": 1.0, "warning_count": 0},
            "coap-secure": {"runs": 1, "pass_count": 1, "fail_count": 0, "success_rate": 1.0, "warning_count": 0},
            "ota-baseline": {"runs": 1, "pass_count": 1, "fail_count": 0, "success_rate": 1.0, "warning_count": 0},
            "ota-secure": {"runs": 1, "pass_count": 1, "fail_count": 0, "success_rate": 1.0, "warning_count": 0},
        },
    }

    markdown = analyze_results.build_aggregate_markdown(aggregate)

    assert "# Agregovana uspesnost behov" in markdown
    assert "| Scenar | Behy | PASS | FAIL | Warningy | Success rate |" in markdown
    assert "| mqtt-baseline | 1 | 1 | 0 | 0 | 100.0% |" in markdown
    assert "| ota-secure | 1 | 1 | 0 | 0 | 100.0% |" in markdown


def test_build_markdown_describes_coap_secure_as_disabled_plaintext_endpoint():
    runs = [
        make_run("c1", "coap-baseline", {"P2_coap_plain_gets": 3}),
        make_run(
            "c2",
            "coap-secure",
            {
                "P2_coap_plain_gets": 0,
                "P2_coap_plain_blocked": 3,
                "P2_coap_dtls_failures": 5,
                "P2_coap_dtls_ok": 1,
            },
        ),
    ]

    markdown = analyze_results.build_markdown(runs, selected_run_ids=[])

    assert "iptables" not in markdown.lower()
    assert "neexponuje plaintext endpoint na porte 5683" in markdown


def test_build_markdown_contains_explicit_success_rate_table():
    runs = [
        make_run("m1", "mqtt-baseline", {"P1_mqtt_unauth_success": 30, "P1_mqtt_unauth_denied": 0}),
        make_run("m2", "mqtt-baseline", {"P1_mqtt_unauth_success": 0, "P1_mqtt_unauth_denied": 5}),
        make_run(
            "m3",
            "mqtt-secure",
            {"P1_mqtt_unauth_success": 0, "P1_mqtt_unauth_denied": 30},
            warnings=["control_warning"],
        ),
    ]

    markdown = analyze_results.build_markdown(runs, selected_run_ids=[])

    assert "## 3. Explicitna uspesnost behov" in markdown
    assert "| Scenar | Behy | PASS | FAIL | Warningy | Success rate |" in markdown
    assert "| P1 MQTT Baseline | 2 | 1 | 1 | 0 | 50.0% |" in markdown
    assert "| P1 MQTT Secure | 1 | 0 | 1 | 1 | 0.0% |" in markdown


def test_write_aggregate_outputs_persists_json_and_markdown(tmp_path):
    aggregate = {
        "totals": {"runs": 2, "pass_count": 2, "fail_count": 0, "success_rate": 1.0, "warning_count": 0},
        "scenarios": {
            "mqtt-baseline": {"runs": 1, "pass_count": 1, "fail_count": 0, "success_rate": 1.0, "warning_count": 0},
            "mqtt-secure": {"runs": 1, "pass_count": 1, "fail_count": 0, "success_rate": 1.0, "warning_count": 0},
        },
    }
    json_path = tmp_path / "analysis-aggregate.json"
    markdown_path = tmp_path / "analysis-aggregate.md"

    analyze_results.write_aggregate_outputs(
        aggregate=aggregate,
        json_path=json_path,
        markdown_path=markdown_path,
    )

    assert json.loads(json_path.read_text(encoding="utf-8")) == aggregate
    assert "# Agregovana uspesnost potreb" not in markdown_path.read_text(encoding="utf-8")
    assert "# Agregovana uspesnost behov" in markdown_path.read_text(encoding="utf-8")
