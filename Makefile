# IoT Security Testbed - Makefile
# Použitie: make [baseline|secure|down|test|report]

.PHONY: baseline secure down test report clean

# Nový beh + baseline
baseline:
	@echo "=== Starting baseline profile ==="
	scripts/new_run.sh
	docker compose build
	docker compose up -d

# Nový beh + secure
secure:
	@echo "=== Starting secure profile ==="
	scripts/new_run.sh
	docker compose -f docker-compose.yml -f docker-compose.secure.yml build
	docker compose -f docker-compose.yml -f docker-compose.secure.yml up -d

# Zastavenie všetkých služieb
down:
	@echo "=== Stopping all services ==="
	docker compose down
	docker compose -f docker-compose.yml -f docker-compose.secure.yml down

# Smoke test
test:
	@echo "=== Running smoke tests ==="
	scripts/smoke_test.sh

# Generovanie reportu
report:
	@echo "=== Generating report ==="
	docker compose run --rm monitor-collector
	@echo "Report available in runs/$$RUN_ID/results/"

# Cleanup
clean:
	@echo "=== Cleaning up ==="
	docker compose down -v --remove-orphans
	docker system prune -f

# Help
help:
	@echo "Available targets:"
	@echo "  baseline  - Start new run with baseline profile"
	@echo "  secure    - Start new run with secure profile (TLS/DTLS)"
	@echo "  down      - Stop all services"
	@echo "  test      - Run smoke tests"
	@echo "  report    - Generate report from collector"
	@echo "  clean     - Remove containers and volumes"
