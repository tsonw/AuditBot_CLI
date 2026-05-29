# ====== VARIABLES ======
VENV = venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip
COMPOSE = docker compose -f lab/docker-compose.yml
VULN_COMPOSE = docker compose -f lab/vulnerability/docker-compose.yml
DHCP_SCENARIOS = normal no-offer no-ack rogue pool-exhausted
NVD_START_YEAR ?= 2002

# ====== SETUP ======
venv:
	python3 -m venv $(VENV)

install:
	$(PIP) install -r requirements.txt

freeze:
	$(PIP) freeze > requirements.txt

# ====== RUN ======
run:
	sudo PYTHONDONTWRITEBYTECODE=1 $(PYTHON) main.py

# ====== DEV ======
activate:
	@echo "Run: source venv/bin/activate"

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +

# ====== TEST (nếu có pytest) ======
test:
	$(PYTHON) -m pytest

dhcp-sim:
	$(PYTHON) tools/generate_dhcp_pcap.py $(SCENARIO)

dhcp-sim-all:
	@for scenario in $(DHCP_SCENARIOS); do \
		$(PYTHON) tools/generate_dhcp_pcap.py $$scenario; \
	done

dhcp-analyze:
	$(PYTHON) -c "from engines.dhcp_analyzer import analyze_dhcp_pcap; analyze_dhcp_pcap('$(FILE)')"

# ====== NVD DATABASE ======
db-full-update: venv install
	$(PYTHON) -m main nvd-init --start-year $(NVD_START_YEAR)
	$(PYTHON) -m main nvd-update

dhcp-test-pcaps: dhcp-sim-all
	@for scenario in $(DHCP_SCENARIOS); do \
		echo "=== DHCP scenario: $$scenario ==="; \
		$(PYTHON) -c "from engines.dhcp_analyzer import analyze_dhcp_pcap; analyze_dhcp_pcap('output/pcaps/dhcp_$$scenario.pcap')"; \
	done

dhcp-normal:
	$(PYTHON) tools/generate_dhcp_pcap.py normal
	$(PYTHON) -c "from engines.dhcp_analyzer import analyze_dhcp_pcap; analyze_dhcp_pcap('output/pcaps/dhcp_normal.pcap')"

dhcp-no-offer:
	$(PYTHON) tools/generate_dhcp_pcap.py no-offer
	$(PYTHON) -c "from engines.dhcp_analyzer import analyze_dhcp_pcap; analyze_dhcp_pcap('output/pcaps/dhcp_no-offer.pcap')"

dhcp-no-ack:
	$(PYTHON) tools/generate_dhcp_pcap.py no-ack
	$(PYTHON) -c "from engines.dhcp_analyzer import analyze_dhcp_pcap; analyze_dhcp_pcap('output/pcaps/dhcp_no-ack.pcap')"

dhcp-rogue:
	$(PYTHON) tools/generate_dhcp_pcap.py rogue
	$(PYTHON) -c "from engines.dhcp_analyzer import analyze_dhcp_pcap; analyze_dhcp_pcap('output/pcaps/dhcp_rogue.pcap')"

dhcp-pool-exhausted:
	$(PYTHON) tools/generate_dhcp_pcap.py pool-exhausted
	$(PYTHON) -c "from engines.dhcp_analyzer import analyze_dhcp_pcap; analyze_dhcp_pcap('output/pcaps/dhcp_pool-exhausted.pcap')"

# ====== DOCKER LAB ======
lab-up:
	$(COMPOSE) up -d --build

lab-down:
	$(COMPOSE) down

lab-ps:
	$(COMPOSE) ps

lab-shell:
	$(COMPOSE) exec auditbot bash

lab-menu:
	$(COMPOSE) exec auditbot python -B -c "from core.menu import menu; menu()"

lab-vuln-scan:
	$(COMPOSE) exec auditbot python -B -c "from core.menu import _run_local_nvd_vulnerability_scan_menu; _run_local_nvd_vulnerability_scan_menu()"

lab-scan:
	$(COMPOSE) exec auditbot python -B -c "from engines.discovery import run_discovery; from collectors.raw_writer import write_raw_file; data = run_discovery(); output = write_raw_file(data, 'lab_discovery'); print(f'Lab discovery JSON exported: {output}')"

# ====== VULNERABILITY DOCKER LAB ======
vuln-lab-up:
	$(VULN_COMPOSE) up -d --build

vuln-lab-down:
	$(VULN_COMPOSE) down

vuln-lab-ps:
	$(VULN_COMPOSE) ps

vuln-lab-shell:
	$(VULN_COMPOSE) exec auditbot bash

vuln-lab-menu:
	$(VULN_COMPOSE) exec auditbot python -B -c "from core.menu import menu; menu()"

vuln-lab-nmap:
	$(VULN_COMPOSE) exec auditbot nmap -sV --version-all -p 21,80,8081,10000 172.28.50.10-13

vuln-lab-scan:
	$(VULN_COMPOSE) exec auditbot python -B -c "from core.menu import _run_local_nvd_vulnerability_scan_menu; _run_local_nvd_vulnerability_scan_menu()"
