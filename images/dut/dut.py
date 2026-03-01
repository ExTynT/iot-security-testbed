import os, time, json, subprocess, requests
import paho.mqtt.client as mqtt

MQTT_HOST = os.getenv("MQTT_HOST", "mosquitto")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
MQTT_USER = os.getenv("MQTT_USER", "")
MQTT_PASS = os.getenv("MQTT_PASS", "")

OTA_BASE = os.getenv("OTA_BASE", "http://ota")
MINISIGN_PUBKEY = os.getenv("MINISIGN_PUBKEY", "").strip()

STATE_DIR = "/state"
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
    # minisign očakáva <file>.minisig vedľa súboru; overenie cez public key.
    if not MINISIGN_PUBKEY:
        return False
    try:
        subprocess.check_call(["minisign", "-Vm", path_manifest, "-P", MINISIGN_PUBKEY])
        return True
    except Exception:
        return False

def ota_check_and_apply():
    # stiahni manifest + signature
    m_url = f"{OTA_BASE}/manifest.json"
    s_url = f"{OTA_BASE}/manifest.json.minisig"

    m = requests.get(m_url, timeout=5)
    m.raise_for_status()
    with open("/tmp/manifest.json", "wb") as f:
        f.write(m.content)

    s = requests.get(s_url, timeout=5)
    s.raise_for_status()
    with open("/tmp/manifest.json.minisig", "wb") as f:
        f.write(s.content)

    ok = verify_manifest("/tmp/manifest.json")
    if not ok:
        print("OTA: podpis NEPLATNÝ – aktualizácia ZAMIETNUTÁ")
        return

    manifest = json.loads(open("/tmp/manifest.json").read())
    new_ver = manifest["version"]
    file_name = manifest["file"]

    if new_ver == read_version():
        print("OTA: verzia rovnaká – nič nerobím")
        return

    fw = requests.get(f"{OTA_BASE}/{file_name}", timeout=10)
    fw.raise_for_status()
    open("/tmp/fw.bin", "wb").write(fw.content)

    # "apply" = len zapíš verziu (v reálnom DUT by to bola flash/update)
    write_version(new_ver)
    print(f"OTA: aplikované -> verzia {new_ver}")

def on_connect(client, userdata, flags, rc, properties=None):
    print("MQTT connected rc=", rc)
    client.subscribe("cmd/ota")

def on_message(client, userdata, msg):
    if msg.topic == "cmd/ota":
        ota_check_and_apply()

client = mqtt.Client()
if MQTT_USER:
    client.username_pw_set(MQTT_USER, MQTT_PASS)

client.on_connect = on_connect
client.on_message = on_message
client.connect(MQTT_HOST, MQTT_PORT, 60)
client.loop_start()

while True:
    # telemetria
    ver = read_version()
    client.publish("telemetry/version", ver)
    time.sleep(5)
