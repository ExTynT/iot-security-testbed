COMPOSE = docker compose
BASE    = -f docker-compose.yml
MQTT_S  = -f docker-compose.yml -f docker-compose.mqtt-secure.yml
COAP_S  = -f docker-compose.yml -f docker-compose.coap-secure.yml
OTA_S   = -f docker-compose.yml -f docker-compose.ota-secure.yml

# Počet replikácií pre make replicate-<scenár> (predvolene 3)
N ?= 3

.PHONY: build down ps logs \
        mqtt-baseline mqtt-secure \
        coap-baseline coap-secure \
        ota-baseline ota-secure \
        gen-passwd report analyze clean help \
        replicate-mqtt replicate-coap replicate-ota

# ─── Build všetkých imidžov ───────────────────────────────────────────────────
build:
	$(COMPOSE) $(BASE) build

# ─── MQTT Baseline (P1 – bez ochrán) ─────────────────────────────────────────
mqtt-baseline:
	scripts/new_run.sh
	@echo "mqtt-baseline" > runs/$$(grep '^RUN_ID=' .env | cut -d= -f2)/state/scenario.txt
	$(COMPOSE) $(BASE) up -d
	@sleep 5
	bash scripts/mqtt_baseline_attack.sh
	docker compose run --rm monitor-collector
	@echo "Artefakty: runs/$$(grep '^RUN_ID=' .env | cut -d= -f2)/{logs,pcap,results}"
	$(COMPOSE) $(BASE) down --remove-orphans

# ─── MQTT Secure (P1 – TLS 8883 + ACL + heslo) ───────────────────────────────
mqtt-secure:
	@test -f configs/mqtt/secure/passwd || (echo "Chyba: spusti 'make gen-passwd' najprv" && exit 1)
	scripts/new_run.sh
	@echo "mqtt-secure" > runs/$$(grep '^RUN_ID=' .env | cut -d= -f2)/state/scenario.txt
	$(COMPOSE) $(MQTT_S) up -d
	@sleep 5
	bash scripts/mqtt_secure_attack_unauth.sh
	bash scripts/mqtt_secure_control_auth.sh
	docker compose run --rm monitor-collector
	@echo "Artefakty: runs/$$(grep '^RUN_ID=' .env | cut -d= -f2)/{logs,pcap,results}"
	$(COMPOSE) $(MQTT_S) down --remove-orphans

# ─── CoAP Baseline (P2 – bez DTLS) ───────────────────────────────────────────
coap-baseline:
	scripts/new_run.sh
	@echo "coap-baseline" > runs/$$(grep '^RUN_ID=' .env | cut -d= -f2)/state/scenario.txt
	$(COMPOSE) $(BASE) up -d
	@sleep 5
	bash scripts/coap_baseline_attack.sh
	docker compose run --rm monitor-collector
	@echo "Artefakty: runs/$$(grep '^RUN_ID=' .env | cut -d= -f2)/{logs,pcap,results}"
	$(COMPOSE) $(BASE) down --remove-orphans

# ─── CoAP Secure (P2 – DTLS/PSK, 5683 blokovaný) ────────────────────────────
coap-secure:
	scripts/new_run.sh
	@echo "coap-secure" > runs/$$(grep '^RUN_ID=' .env | cut -d= -f2)/state/scenario.txt
	$(COMPOSE) $(COAP_S) up -d
	@sleep 5
	bash scripts/coap_secure_attack_plain_should_fail.sh
	bash scripts/coap_secure_attack_wrong_psk.sh
	bash scripts/coap_secure_attack_ok_psk.sh
	docker compose run --rm monitor-collector
	@echo "Artefakty: runs/$$(grep '^RUN_ID=' .env | cut -d= -f2)/{logs,pcap,results}"
	$(COMPOSE) $(COAP_S) down --remove-orphans

# ─── OTA Baseline (P3 – bez overenia podpisu) ────────────────────────────────
ota-baseline:
	scripts/new_run.sh
	@echo "ota-baseline" > runs/$$(grep '^RUN_ID=' .env | cut -d= -f2)/state/scenario.txt
	$(COMPOSE) $(BASE) up -d
	@sleep 5
	bash scripts/ota_attack_evil.sh
	docker compose run --rm monitor-collector
	@echo "Artefakty: runs/$$(grep '^RUN_ID=' .env | cut -d= -f2)/{logs,pcap,results}"
	$(COMPOSE) $(BASE) down --remove-orphans

# ─── OTA Secure (P3 – minisign podpis) ───────────────────────────────────────
ota-secure: _ota-keys
	scripts/new_run.sh
	@echo "ota-secure" > runs/$$(grep '^RUN_ID=' .env | cut -d= -f2)/state/scenario.txt
	@PUBKEY=$$(sed -n '2p' configs/ota/minisign.pub); \
	sed -i "s|^MINISIGN_PUBKEY=.*|MINISIGN_PUBKEY=$$PUBKEY|" .env
	$(COMPOSE) $(OTA_S) up -d
	@sleep 5
	$(COMPOSE) $(OTA_S) up -d --force-recreate dut
	@sleep 3
	bash scripts/ota_attack_evil.sh
	docker compose run --rm monitor-collector
	@echo "Artefakty: runs/$$(grep '^RUN_ID=' .env | cut -d= -f2)/{logs,pcap,results}"
	$(COMPOSE) $(OTA_S) down --remove-orphans

# ─── Generovanie minisign kľúčov (ak ešte neexistujú) ────────────────────────
_ota-keys:
	@test -f configs/ota/minisign.pub || \
	  (printf '\n\n' | tools/minisign/minisign-win64/minisign.exe \
	    -G -p configs/ota/minisign.pub -s configs/ota/minisign.key)
	@test -f configs/ota/repo/manifest.json.minisig || \
	  (printf '\n' | tools/minisign/minisign-win64/minisign.exe \
	    -S -s configs/ota/minisign.key -m configs/ota/repo/manifest.json)

# ─── Replikácie (N opakovaní každého scenára) ─────────────────────────────────
replicate-mqtt:
	@for i in $$(seq 1 $(N)); do \
	  echo "=== MQTT replikácia $$i/$(N) ==="; \
	  $(MAKE) mqtt-baseline; \
	  $(MAKE) mqtt-secure; \
	done

replicate-coap:
	@for i in $$(seq 1 $(N)); do \
	  echo "=== CoAP replikácia $$i/$(N) ==="; \
	  $(MAKE) coap-baseline; \
	  $(MAKE) coap-secure; \
	done

replicate-ota:
	@for i in $$(seq 1 $(N)); do \
	  echo "=== OTA replikácia $$i/$(N) ==="; \
	  $(MAKE) ota-baseline; \
	  $(MAKE) ota-secure; \
	done

replicate-all:
	@for i in $$(seq 1 $(N)); do \
	  echo "=== Replikácia $$i/$(N) ==="; \
	  $(MAKE) mqtt-baseline; \
	  $(MAKE) mqtt-secure; \
	  $(MAKE) coap-baseline; \
	  $(MAKE) coap-secure; \
	  $(MAKE) ota-baseline; \
	  $(MAKE) ota-secure; \
	done

# ─── Pomocné ──────────────────────────────────────────────────────────────────
gen-passwd:
	scripts/gen_mqtt_passwd.sh

down:
	$(COMPOSE) $(BASE) down --remove-orphans || true

ps:
	$(COMPOSE) $(BASE) ps

logs:
	$(COMPOSE) $(BASE) logs --tail=200

report:
	docker compose run --rm monitor-collector
	@echo "Výsledky: runs/$$(grep '^RUN_ID=' .env | cut -d= -f2)/results/"

analyze:
	@mkdir -p runs/figures
	@MSYS_NO_PATHCONV=1 docker compose run --rm \
	  -v "$$(cygpath -w $$(pwd))/runs:/runs" \
	  --entrypoint python \
	  monitor-collector /app/analyze_results.py \
	  | tee runs/analysis.md
	@echo ""
	@echo "Analyza ulozena: runs/analysis.md"
	@echo "Grafy ulozene:   runs/figures/"

clean:
	$(COMPOSE) $(BASE) down -v --remove-orphans || true
	docker system prune -f

help:
	@echo "Použitie: make <cieľ>"
	@echo ""
	@echo "  Kompletné scenáre (up → útok → zber → down):"
	@echo "    mqtt-baseline      P1: MQTT bez ochrán  (KPI: unauth_denied=0)"
	@echo "    mqtt-secure        P1: MQTT TLS+ACL     (KPI: unauth_denied>0)"
	@echo "    coap-baseline      P2: CoAP bez DTLS    (KPI: plain_gets>0)"
	@echo "    coap-secure        P2: CoAP DTLS/PSK    (KPI: dtls_failures>0)"
	@echo "    ota-baseline       P3: OTA bez podpisu  (KPI: evil_applied>0)"
	@echo "    ota-secure         P3: OTA minisign     (KPI: evil_blocked>0)"
	@echo ""
	@echo "  Replikácie (N=3 predvolene, zmeň cez N=5):"
	@echo "    replicate-mqtt     3× mqtt-baseline + mqtt-secure"
	@echo "    replicate-coap     3× coap-baseline + coap-secure"
	@echo "    replicate-ota      3× ota-baseline  + ota-secure"
	@echo "    replicate-all      3× všetky scenáre naraz"
	@echo ""
	@echo "  Analýza výsledkov:"
	@echo "    analyze            Agreguj všetky runs/ → runs/analysis.md"
	@echo ""
	@echo "  Ostatné:"
	@echo "    build              Zostav všetky Docker imidže"
	@echo "    gen-passwd         Vygeneruj configs/mqtt/secure/passwd"
	@echo "    report             Spusti collector pre aktuálny run"
	@echo "    down               Zastav všetky kontajnery"
	@echo "    clean              Vymaž kontajnery, volumes, Docker cache"
