import os, json, re, time

LOGS = "/logs"
RESULTS = "/results"

def read(path):
    try: return open(path, "r", errors="ignore").read()
    except: return ""

mqtt = read(f"{LOGS}/mqtt.log")
coap = read(f"{LOGS}/coap.log")
dut  = read(f"{LOGS}/dut.log")
ota  = read(f"{LOGS}/ota_access.log")

summary = {
  "mqtt": {
    "denied": len(re.findall(r"deny|denied", mqtt, re.I)),
    "published": len(re.findall(r"publish", mqtt, re.I)),
  },
  "coap": {
    "dtls_alerts": len(re.findall(r"alert|handshake", coap, re.I)),
  },
  "ota": {
    "requests": len(re.findall(r"GET", ota)),
  },
  "dut": {
    "ota_applied": len(re.findall(r"aplikované", dut, re.I)),
    "ota_blocked": len(re.findall(r"ZAMIETNUTÁ", dut, re.I)),
  }
}

os.makedirs(RESULTS, exist_ok=True)
open(f"{RESULTS}/summary.json", "w").write(json.dumps(summary, indent=2, ensure_ascii=False))
open(f"{RESULTS}/report.md", "w").write("# Run report\n\n```json\n"+json.dumps(summary, indent=2, ensure_ascii=False)+"\n```\n")
print("collector: summary.json a report.md vytvorené")
time.sleep(2)
