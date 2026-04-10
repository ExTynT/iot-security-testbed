import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def read_text(path: str) -> str:
    return (PROJECT_ROOT / path).read_text(encoding="utf-8")


def service_block(compose_text: str, service_name: str) -> str:
    pattern = (
        rf"^  {re.escape(service_name)}:\n"
        rf"(?P<body>(?:^(?:    |\s*$).*\n)+)"
    )
    match = re.search(pattern, compose_text, flags=re.MULTILINE)
    assert match, f"service block not found: {service_name}"
    return match.group("body")


def test_base_compose_uses_native_runtime_hardening():
    compose = read_text("docker-compose.yml")

    mosquitto = service_block(compose, "mosquitto")
    assert "init: true" in mosquitto
    assert 'command: ["/usr/sbin/mosquitto", "-c", "/mosquitto/config/mosquitto.conf"]' in mosquitto
    assert "read_only: true" in mosquitto
    assert "cap_drop:" in mosquitto
    assert "healthcheck:" in mosquitto

    coap = service_block(compose, "coap")
    assert "init: true" in coap
    assert "read_only: true" in coap
    assert "cap_drop:" in coap
    assert "tmpfs:" in coap
    assert "healthcheck:" in coap

    ota = service_block(compose, "ota")
    assert "init: true" in ota
    assert "read_only: true" in ota
    assert "cap_drop:" in ota
    assert "tmpfs:" in ota
    assert "healthcheck:" in ota

    dut = service_block(compose, "dut")
    assert 'user: "10001:10001"' in dut
    assert "init: true" in dut
    assert "read_only: true" in dut
    assert "tmpfs:" in dut
    assert "cap_drop:" in dut
    assert "healthcheck:" in dut
    assert "condition: service_healthy" in dut

    attacker = service_block(compose, "attacker")
    assert 'user: "10002:10002"' in attacker
    assert "read_only: true" in attacker
    assert "cap_drop:" in attacker

    monitor_collector = service_block(compose, "monitor-collector")
    assert 'user: "10003:10003"' in monitor_collector
    assert "read_only: true" in monitor_collector
    assert "cap_drop:" in monitor_collector

    for sniffer in ("sniffer_mqtt", "sniffer_coap", "sniffer_ota", "sniffer_ota_evil"):
        block = service_block(compose, sniffer)
        assert "cap_drop:" in block
        assert "cap_add:" in block


def test_secure_overlays_override_healthchecks_with_runtime_specific_probes():
    mqtt_secure = read_text("docker-compose.mqtt-secure.yml")
    assert "healthcheck:" in service_block(mqtt_secure, "mosquitto")
    assert "/run/secrets/mqtt_device_password" in mqtt_secure

    coap_secure = read_text("docker-compose.coap-secure.yml")
    assert "cap_add:" not in coap_secure
    assert "healthcheck:" in service_block(coap_secure, "coap")
    assert '"$$coap_psk"' in coap_secure
    assert "5683=CLOSED 5684=DTLS+PSK" in coap_secure


def test_runners_use_health_aware_startup_and_wait_ready_is_minimal():
    run_case = read_text("scripts/run_case.sh")
    run_all = read_text("scripts/_run_all.sh")
    makefile = read_text("Makefile")
    wait_ready = read_text("scripts/wait_ready.sh")

    assert "up -d --wait" in run_case
    assert "up -d --wait" in run_all
    assert "up -d --wait" in makefile
    assert "retry_until" not in wait_ready
    assert "docker compose exec" not in wait_ready
