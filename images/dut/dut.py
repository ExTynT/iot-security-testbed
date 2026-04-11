"""Referenčný DUT klient pre MQTT telemetriu a OTA aktualizácie.

Modul simuluje jednoduché IoT zariadenie, ktoré publikuje verziu firmvéru,
prijíma OTA príkazy cez MQTT a podľa režimu scenára validuje manifest,
podpis a rollback ochranu.
"""

import hashlib
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone

MQTT_HOST = os.getenv("MQTT_HOST", "mosquitto")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
MQTT_USER = os.getenv("MQTT_USER", "")
MQTT_PASS_FILE = os.getenv("MQTT_PASS_FILE", "").strip()
MQTT_TLS_CA = os.getenv("MQTT_TLS_CA", "").strip()

OTA_BASE = os.getenv("OTA_BASE", "http://ota:8080")
MINISIGN_PUBKEY_FILE = os.getenv("MINISIGN_PUBKEY_FILE", "").strip()

STATE_DIR = "/state"
VERSION_JSON_FILE = f"{STATE_DIR}/version.json"
LEGACY_VERSION_FILE = f"{STATE_DIR}/version.txt"
DEFAULT_VERSION = "0.0.0"
DEFAULT_VERSION_CODE = 0
MANIFEST_REQUIRED_FIELDS = ("version", "version_code", "file", "sha256")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class OTAValidationError(Exception):
    """Výnimka pre deterministické odmietnutie OTA aktualizácie."""

    def __init__(self, reason, detail=""):
        """Uloží strojovo čitateľný dôvod zlyhania OTA validácie."""
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail


def read_secret_value(value="", file_path=""):
    """Načíta tajomstvo priamo z hodnoty alebo zo súboru."""
    secret_value = str(value).strip()
    if secret_value:
        return secret_value

    if not file_path:
        return ""

    try:
        with open(file_path, encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def load_minisign_pubkey(pubkey="", pubkey_path=""):
    """Načíta pinned minisign verejný kľúč zo stringu alebo zo súboru."""
    pubkey_value = str(pubkey).strip()
    if pubkey_value:
        return pubkey_value

    if not pubkey_path:
        return ""

    try:
        with open(pubkey_path, encoding="utf-8") as handle:
            lines = [line.strip() for line in handle.readlines() if line.strip()]
    except OSError:
        return ""

    if not lines:
        return ""
    if len(lines) >= 2 and lines[0].lower().startswith("untrusted comment"):
        return lines[1]
    return lines[0]


MQTT_PASS = read_secret_value(os.getenv("MQTT_PASS", ""), MQTT_PASS_FILE)
MINISIGN_PUBKEY = load_minisign_pubkey(os.getenv("MINISIGN_PUBKEY", "").strip(), MINISIGN_PUBKEY_FILE)


def ensure_parent_dir(path):
    """Vytvorí nadradený adresár pre cieľový súbor, ak ešte neexistuje."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def default_version_state():
    """Vráti počiatočný stav verzie DUT."""
    return {
        "version": DEFAULT_VERSION,
        "version_code": DEFAULT_VERSION_CODE,
        "applied_at": None,
    }


def normalize_version_code(value):
    """Normalizuje `version_code` na nezáporné celé číslo.

    Raises
    ------
    OTAValidationError
        Ak hodnota nie je celé číslo alebo je záporná.
    """
    try:
        version_code = int(value)
    except (TypeError, ValueError) as exc:
        raise OTAValidationError("MANIFEST_INVALID", f"invalid version_code={value!r}") from exc
    if version_code < 0:
        raise OTAValidationError("MANIFEST_INVALID", f"negative version_code={version_code}")
    return version_code


def read_version_state(path=VERSION_JSON_FILE):
    """Načíta stav verzie zo súboru JSON alebo zo starého textového fallbacku."""
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as handle:
                raw_state = json.load(handle)
            version = str(raw_state.get("version", DEFAULT_VERSION)).strip() or DEFAULT_VERSION
            version_code = normalize_version_code(raw_state.get("version_code", DEFAULT_VERSION_CODE))
            applied_at = raw_state.get("applied_at")
            return {
                "version": version,
                "version_code": version_code,
                "applied_at": applied_at,
            }
        except (json.JSONDecodeError, OSError, OTAValidationError):
            pass

    if os.path.exists(LEGACY_VERSION_FILE):
        try:
            with open(LEGACY_VERSION_FILE, encoding="utf-8") as handle:
                legacy_version = handle.read().strip() or DEFAULT_VERSION
            return {
                "version": legacy_version,
                "version_code": DEFAULT_VERSION_CODE,
                "applied_at": None,
            }
        except OSError:
            pass

    return default_version_state()


def write_version_state(version, version_code, path=VERSION_JSON_FILE, applied_at=None):
    """Zapíše stav verzie DUT v novom JSON formáte."""
    ensure_parent_dir(path)
    state = {
        "version": version,
        "version_code": int(version_code),
        "applied_at": applied_at or datetime.now(timezone.utc).isoformat(),
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, ensure_ascii=False)
    return state


def read_version():
    """Vráti aktuálnu verziu firmvéru."""
    return read_version_state()["version"]


def read_version_code():
    """Vráti aktuálny monotónny `version_code`."""
    return read_version_state()["version_code"]


def is_secure_mode(pubkey=MINISIGN_PUBKEY):
    """Rozhodne, či DUT beží v OTA secure profile."""
    return bool(pubkey.strip())


def reject_update(reason, detail=""):
    """Vypíše jednotný log pre odmietnutú OTA aktualizáciu."""
    if detail:
        print(f"OTA: {reason} - {detail}")
    else:
        print(f"OTA: {reason}")


def verify_manifest(path_manifest, pubkey=MINISIGN_PUBKEY):
    """Overí podpis OTA manifestu cez minisign.

    Raises
    ------
    OTAValidationError
        Ak podpis manifestu neprejde validáciou.
    """
    if not pubkey:
        print("OTA: MINISIGN_PUBKEY nie je nastaveny - overenie PRESKOCENE (baseline)")
        return True

    try:
        subprocess.check_call(
            ["minisign", "-Vm", path_manifest, "-P", pubkey],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except Exception as exc:
        raise OTAValidationError("SIGNATURE_INVALID", f"manifest signature verification failed: {exc}") from exc


def load_manifest(path_manifest):
    """Načíta OTA manifest z JSON súboru.

    Raises
    ------
    OTAValidationError
        Ak manifest nemožno načítať alebo parsovať.
    """
    try:
        with open(path_manifest, encoding="utf-8") as handle:
            return json.load(handle)
    except (json.JSONDecodeError, OSError) as exc:
        raise OTAValidationError("MANIFEST_INVALID", f"manifest load failed: {exc}") from exc


def validate_manifest(manifest):
    """Validuje povinné polia OTA manifestu.

    Returns
    -------
    dict
        Normalizovaný manifest s očistenými hodnotami.

    Raises
    ------
    OTAValidationError
        Ak manifest nespĺňa očakávanú štruktúru alebo obsah.
    """
    if not isinstance(manifest, dict):
        raise OTAValidationError("MANIFEST_INVALID", "manifest root must be an object")

    missing = [field for field in MANIFEST_REQUIRED_FIELDS if field not in manifest]
    if missing:
        raise OTAValidationError("MANIFEST_INVALID", f"missing fields: {', '.join(missing)}")

    version = str(manifest["version"]).strip()
    file_name = str(manifest["file"]).strip()
    sha256 = str(manifest["sha256"]).strip().lower()
    version_code = normalize_version_code(manifest["version_code"])

    if not version:
        raise OTAValidationError("MANIFEST_INVALID", "version is empty")
    if not file_name:
        raise OTAValidationError("MANIFEST_INVALID", "file is empty")
    if not SHA256_RE.match(sha256):
        raise OTAValidationError("MANIFEST_INVALID", "sha256 must be 64 lowercase hex chars")

    return {
        "version": version,
        "version_code": version_code,
        "file": file_name,
        "sha256": sha256,
    }


def compute_sha256(path_file):
    """Vypočíta SHA-256 hash súboru."""
    digest = hashlib.sha256()
    with open(path_file, "rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evaluate_downloaded_update(manifest, firmware_path, current_state, secure_mode, signature_valid=True):
    """Vyhodnotí, či stiahnutá OTA aktualizácia smie byť aplikovaná.

    V secure režime kontroluje podpis, hash a rollback ochranu.

    Raises
    ------
    OTAValidationError
        Ak aktualizácia porušuje niektorú validačnú podmienku.
    """
    if secure_mode and not signature_valid:
        raise OTAValidationError("SIGNATURE_INVALID", "manifest signature rejected")

    normalized_manifest = validate_manifest(manifest)

    if secure_mode:
        firmware_sha256 = compute_sha256(firmware_path)
        if firmware_sha256 != normalized_manifest["sha256"]:
            raise OTAValidationError(
                "HASH_MISMATCH",
                f"expected {normalized_manifest['sha256']} got {firmware_sha256}",
            )

        current_version_code = normalize_version_code(current_state.get("version_code", DEFAULT_VERSION_CODE))
        if normalized_manifest["version_code"] <= current_version_code:
            raise OTAValidationError(
                "ROLLBACK_BLOCKED",
                (
                    f"candidate version_code={normalized_manifest['version_code']} "
                    f"<= current version_code={current_version_code}"
                ),
            )

    return normalized_manifest


def download_file(url, destination, timeout):
    """Stiahne vzdialený súbor po častiach na lokálnu cestu."""
    import requests

    with requests.get(url, timeout=timeout, stream=True) as response:
        response.raise_for_status()
        with open(destination, "wb") as handle:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    handle.write(chunk)


def ota_check_and_apply(base):
    """Skontroluje server OTA repozitára a prípadne aplikuje nový firmvér.

    Returns
    -------
    bool
        `True`, ak DUT úspešne prešiel na novú verziu, inak `False`.
    """
    secure_mode = is_secure_mode()
    manifest_url = f"{base}/manifest.json"
    signature_url = f"{base}/manifest.json.minisig"
    manifest_path = "/tmp/manifest.json"
    signature_path = "/tmp/manifest.json.minisig"
    firmware_path = "/tmp/fw.bin"

    try:
        download_file(manifest_url, manifest_path, timeout=(3.05, 5))
    except Exception as exc:
        print(f"OTA: chyba stiahnutia manifestu - {exc}")
        return False

    signature_valid = True
    if secure_mode:
        try:
            download_file(signature_url, signature_path, timeout=(3.05, 5))
            verify_manifest(manifest_path, MINISIGN_PUBKEY)
        except OTAValidationError as exc:
            reject_update(exc.reason, exc.detail)
            return False
        except Exception as exc:
            reject_update("SIGNATURE_INVALID", f"signature download failed: {exc}")
            return False
    else:
        with open(signature_path, "wb") as handle:
            handle.write(b"")

    try:
        manifest = load_manifest(manifest_path)
        validated_manifest = validate_manifest(manifest)
    except OTAValidationError as exc:
        reject_update(exc.reason, exc.detail)
        return False

    current_state = read_version_state()
    if not secure_mode and validated_manifest["version"] == current_state["version"]:
        print("OTA: verzia rovnaka - nic nerobim")
        return False

    try:
        download_file(f"{base}/{validated_manifest['file']}", firmware_path, timeout=(3.05, 10))
    except Exception as exc:
        print(f"OTA: chyba stiahnutia firmware - {exc}")
        return False

    try:
        validated_manifest = evaluate_downloaded_update(
            manifest=validated_manifest,
            firmware_path=firmware_path,
            current_state=current_state,
            secure_mode=secure_mode,
            signature_valid=signature_valid,
        )
    except OTAValidationError as exc:
        reject_update(exc.reason, exc.detail)
        return False

    new_state = write_version_state(
        version=validated_manifest["version"],
        version_code=validated_manifest["version_code"],
    )
    print(
        "OTA: aplikovane -> verzia "
        f"{new_state['version']} (version_code={new_state['version_code']}, server={base})"
    )
    return True


def on_connect(client, userdata, flags, rc, properties=None):
    """MQTT callback po úspešnom pripojení klienta."""
    print("MQTT connected rc=", rc)
    client.subscribe("cmd/ota")


def on_message(client, userdata, msg):
    """Spracuje MQTT správu a spustí OTA workflow pre tému `cmd/ota`."""
    global OTA_BASE
    if msg.topic == "cmd/ota":
        payload = msg.payload.decode("utf-8", errors="ignore").strip()
        if payload:
            print(f"OTA: cmd/ota payload={payload!r} -> pouzijem ako OTA_BASE")
            OTA_BASE = payload
        ota_check_and_apply(OTA_BASE)


def ensure_state_initialized():
    """Inicializuje stavový súbor verzie, ak ešte neexistuje."""
    ensure_parent_dir(VERSION_JSON_FILE)
    if not os.path.exists(VERSION_JSON_FILE):
        current = read_version_state()
        write_version_state(
            version=current["version"],
            version_code=current["version_code"],
            applied_at=current.get("applied_at") or datetime.now(timezone.utc).isoformat(),
        )


def main():
    """Spustí MQTT klienta DUT a periodické publikovanie telemetrie."""
    import paho.mqtt.client as mqtt

    ensure_state_initialized()

    client = mqtt.Client()
    if MQTT_USER:
        client.username_pw_set(MQTT_USER, MQTT_PASS)

    if MQTT_TLS_CA:
        client.tls_set(ca_certs=MQTT_TLS_CA)
        print(f"MQTT TLS zapnute, CA={MQTT_TLS_CA}")

    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(MQTT_HOST, MQTT_PORT, 60)
    client.loop_start()

    while True:
        client.publish("telemetry/version", read_version())
        time.sleep(5)


if __name__ == "__main__":
    main()
