import os, time, json, subprocess, requests
import paho.mqtt.client as mqtt

MQTT_HOST    = os.getenv("MQTT_HOST", "mosquitto")
MQTT_PORT    = int(os.getenv("MQTT_PORT", "1883"))
MQTT_USER    = os.getenv("MQTT_USER", "")
MQTT_PASS    = os.getenv("MQTT_PASS", "")
MQTT_TLS_CA  = os.getenv("MQTT_TLS_CA", "").strip()

OTA_BASE        = os.getenv("OTA_BASE", "http://ota")
MINISIGN_PUBKEY = os.getenv("MINISIGN_PUBKEY", "").strip()

STATE_DIR    = "/state"
VERSION_FILE = f"{STATE_DIR}/version.txt"

os.makedirs(STATE_DIR, exist_ok=True)
if not os.path.exists(VERSION_FILE):
    with open(VERSION_FILE, "w") as f:
        f.write("0.0.0")

def read_version():
    return open(VERSION_FILE).read().strip()

def write_version(v):
    with open(VERSION_FILE, "w") as f:
        f.write(v)

def verify_manifest(path_manifest: str) -> bool:
    # Baseline (MINISIGN_PUBKEY prázdny) → žiadne overenie, aktualizácia prebehne
    if not MINISIGN_PUBKEY:
        print("OTA: MINISIGN_PUBKEY nie je nastavený – overenie PRESKOČENÉ (baseline)")
        return True
    # Secure – vyžaduj .minisig a overuj podpis
    try:
        subprocess.check_call(["minisign", "-Vm", path_manifest, "-P", MINISIGN_PUBKEY])
        return True
    except Exception as e:
        print(f"OTA: overenie podpisu zlyhalo – {e}")
        return False

def ota_check_and_apply(base: str):
    m_url = f"{base}/manifest.json"
    s_url = f"{base}/manifest.json.minisig"

    try:
        m = requests.get(m_url, timeout=5)
        m.raise_for_status()
        with open("/tmp/manifest.json", "wb") as f:
            f.write(m.content)
    except Exception as e:
        print(f"OTA: chyba stiahnutia manifestu – {e}")
        return

    try:
        s = requests.get(s_url, timeout=5)
        s.raise_for_status()
        with open("/tmp/manifest.json.minisig", "wb") as f:
            f.write(s.content)
    except Exception as e:
        if MINISIGN_PUBKEY:
            print(f"OTA: chyba stiahnutia podpisu – {e}")
            return
        # Bez pubkey: .minisig neexistuje je OK, vytvoríme prázdny placeholder
        open("/tmp/manifest.json.minisig", "wb").close()

    ok = verify_manifest("/tmp/manifest.json")
    if not ok:
        print("OTA: podpis NEPLATNÝ – aktualizácia ZAMIETNUTÁ")
        return

    manifest = json.loads(open("/tmp/manifest.json").read())
    new_ver  = manifest["version"]
    file_name = manifest["file"]

    if new_ver == read_version():
        print("OTA: verzia rovnaká – nič nerobím")
        return

    try:
        fw = requests.get(f"{base}/{file_name}", timeout=10)
        fw.raise_for_status()
        open("/tmp/fw.bin", "wb").write(fw.content)
    except Exception as e:
        print(f"OTA: chyba stiahnutia firmware – {e}")
        return

    write_version(new_ver)
    print(f"OTA: aplikované -> verzia {new_ver} (zo servera {base})")

def on_connect(client, userdata, flags, rc, properties=None):
    print("MQTT connected rc=", rc)
    client.subscribe("cmd/ota")

def on_message(client, userdata, msg):
    global OTA_BASE
    if msg.topic == "cmd/ota":
        payload = msg.payload.decode("utf-8", errors="ignore").strip()
        if payload:
            # Attacker môže presmerovať DUT na ľubovoľný OTA server
            print(f"OTA: cmd/ota payload={payload!r} → použijem ako OTA_BASE")
            OTA_BASE = payload
        ota_check_and_apply(OTA_BASE)

client = mqtt.Client()
if MQTT_USER:
    client.username_pw_set(MQTT_USER, MQTT_PASS)

# TLS – ak je nastavený CA certifikát, overujeme broker
if MQTT_TLS_CA:
    client.tls_set(ca_certs=MQTT_TLS_CA)
    print(f"MQTT TLS zapnuté, CA={MQTT_TLS_CA}")

client.on_connect = on_connect
client.on_message = on_message
client.connect(MQTT_HOST, MQTT_PORT, 60)
client.loop_start()

while True:
    ver = read_version()
    client.publish("telemetry/version", ver)
    time.sleep(5)
