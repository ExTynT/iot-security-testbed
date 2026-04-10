import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DUT_PATH = PROJECT_ROOT / "images" / "dut" / "dut.py"


def load_dut_module():
    spec = importlib.util.spec_from_file_location("dut_module", DUT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


dut = load_dut_module()


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def write_firmware(tmp_path, name="firmware.bin", content=b"valid firmware payload"):
    firmware_path = tmp_path / name
    firmware_path.write_bytes(content)
    return firmware_path, content


def build_manifest(version="1.0.1", version_code=1001, file_name="firmware.bin", sha256=None):
    payload = b"valid firmware payload"
    return {
        "version": version,
        "version_code": version_code,
        "file": file_name,
        "sha256": sha256 or sha256_hex(payload),
    }


def current_state(version="1.0.0", version_code=1000):
    return {
        "version": version,
        "version_code": version_code,
        "applied_at": None,
    }


def assert_validation_error(reason, action):
    with pytest.raises(dut.OTAValidationError) as exc_info:
        action()
    assert exc_info.value.reason == reason


def test_read_secret_value_uses_file_when_present(tmp_path):
    secret_path = tmp_path / "mqtt_device_password.txt"
    secret_path.write_text("abc123\n", encoding="utf-8")

    value = dut.read_secret_value("", file_path=str(secret_path))

    assert value == "abc123"


def test_load_minisign_pubkey_reads_second_line_from_pub_file(tmp_path):
    pubkey_path = tmp_path / "minisign.pub"
    pubkey_path.write_text(
        "untrusted comment: minisign public key\nRWSTESTPUBLICKEY1234567890\n",
        encoding="utf-8",
    )

    value = dut.load_minisign_pubkey(pubkey="", pubkey_path=str(pubkey_path))

    assert value == "RWSTESTPUBLICKEY1234567890"


def test_write_version_state_creates_missing_parent_dir(tmp_path):
    version_path = tmp_path / "nested" / "state" / "version.json"

    state = dut.write_version_state("1.2.3", 123, path=str(version_path), applied_at="2026-04-10T00:00:00+00:00")

    assert version_path.exists()
    assert state == {
        "version": "1.2.3",
        "version_code": 123,
        "applied_at": "2026-04-10T00:00:00+00:00",
    }


def test_secure_candidate_accepts_valid_signed_hash_checked_newer_bundle(tmp_path):
    firmware_path, content = write_firmware(tmp_path)
    manifest = build_manifest(sha256=sha256_hex(content))

    result = dut.evaluate_downloaded_update(
        manifest=manifest,
        firmware_path=str(firmware_path),
        current_state=current_state(),
        secure_mode=True,
        signature_valid=True,
    )

    assert result == manifest


def test_secure_candidate_rejects_invalid_signature(tmp_path):
    firmware_path, content = write_firmware(tmp_path)
    manifest = build_manifest(sha256=sha256_hex(content))

    assert_validation_error(
        "SIGNATURE_INVALID",
        lambda: dut.evaluate_downloaded_update(
            manifest=manifest,
            firmware_path=str(firmware_path),
            current_state=current_state(),
            secure_mode=True,
            signature_valid=False,
        ),
    )


def test_secure_candidate_rejects_hash_mismatch(tmp_path):
    firmware_path, _ = write_firmware(tmp_path)
    manifest = build_manifest(sha256="0" * 64)

    assert_validation_error(
        "HASH_MISMATCH",
        lambda: dut.evaluate_downloaded_update(
            manifest=manifest,
            firmware_path=str(firmware_path),
            current_state=current_state(),
            secure_mode=True,
            signature_valid=True,
        ),
    )


def test_secure_candidate_rejects_manifest_missing_required_field(tmp_path):
    firmware_path, content = write_firmware(tmp_path)
    manifest = build_manifest(sha256=sha256_hex(content))
    manifest.pop("sha256")

    assert_validation_error(
        "MANIFEST_INVALID",
        lambda: dut.evaluate_downloaded_update(
            manifest=manifest,
            firmware_path=str(firmware_path),
            current_state=current_state(),
            secure_mode=True,
            signature_valid=True,
        ),
    )


def test_secure_candidate_rejects_older_version_code(tmp_path):
    firmware_path, content = write_firmware(tmp_path)
    manifest = build_manifest(version="0.9.0", version_code=999, sha256=sha256_hex(content))

    assert_validation_error(
        "ROLLBACK_BLOCKED",
        lambda: dut.evaluate_downloaded_update(
            manifest=manifest,
            firmware_path=str(firmware_path),
            current_state=current_state(),
            secure_mode=True,
            signature_valid=True,
        ),
    )


def test_baseline_candidate_skips_hash_and_rollback_checks(tmp_path):
    firmware_path, _ = write_firmware(tmp_path)
    manifest = build_manifest(version="0.9.0", version_code=999, sha256="f" * 64)

    result = dut.evaluate_downloaded_update(
        manifest=manifest,
        firmware_path=str(firmware_path),
        current_state=current_state(),
        secure_mode=False,
        signature_valid=True,
    )

    assert result == manifest


def test_ota_check_and_apply_baseline_applies_bundle_without_secure_checks(tmp_path, monkeypatch):
    firmware_bytes = b"baseline firmware payload"
    manifest = build_manifest(
        version="9.9.9-EVIL",
        version_code=9900,
        file_name="firmware_evil.bin",
        sha256=sha256_hex(firmware_bytes),
    )
    written_state = {}

    def fake_download(url, destination, timeout):
        path = Path(destination)
        if url.endswith("/manifest.json"):
            path.write_text(json.dumps(manifest), encoding="utf-8")
            return
        if url.endswith("/firmware_evil.bin"):
            path.write_bytes(firmware_bytes)
            return
        if url.endswith("/manifest.json.minisig"):
            path.write_bytes(b"")
            return
        raise AssertionError(f"Unexpected URL: {url}")

    def fake_read_state():
        return current_state()

    def fake_write_state(version, version_code, path=dut.VERSION_JSON_FILE, applied_at=None):
        written_state.update(
            {
                "version": version,
                "version_code": version_code,
                "applied_at": applied_at,
            }
        )
        return {
            "version": version,
            "version_code": version_code,
            "applied_at": applied_at or "now",
        }

    monkeypatch.setattr(dut, "download_file", fake_download)
    monkeypatch.setattr(dut, "read_version_state", fake_read_state)
    monkeypatch.setattr(dut, "write_version_state", fake_write_state)
    monkeypatch.setattr(dut, "is_secure_mode", lambda pubkey=None: False)

    result = dut.ota_check_and_apply("http://ota_evil")

    assert result is True
    assert written_state["version"] == "9.9.9-EVIL"
    assert written_state["version_code"] == 9900
