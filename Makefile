# ====== VARIABLES ======
VENV = venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip
COMPOSE = docker compose -f lab/docker-compose.yml

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

dhcp-analyze:
	$(PYTHON) -c "from engines.dhcp_analyzer import analyze_dhcp_pcap; analyze_dhcp_pcap('$(FILE)')"

dhcp-normal:
	$(PYTHON) tools/generate_dhcp_pcap.py normal
	$(PYTHON) -c "from engines.dhcp_analyzer import analyze_dhcp_pcap; analyze_dhcp_pcap('outputs/pcaps/dhcp_normal.pcap')"

dhcp-no-offer:
	$(PYTHON) tools/generate_dhcp_pcap.py no-offer
	$(PYTHON) -c "from engines.dhcp_analyzer import analyze_dhcp_pcap; analyze_dhcp_pcap('outputs/pcaps/dhcp_no-offer.pcap')"

dhcp-no-ack:
	$(PYTHON) tools/generate_dhcp_pcap.py no-ack
	$(PYTHON) -c "from engines.dhcp_analyzer import analyze_dhcp_pcap; analyze_dhcp_pcap('outputs/pcaps/dhcp_no-ack.pcap')"

dhcp-rogue:
	$(PYTHON) tools/generate_dhcp_pcap.py rogue
	$(PYTHON) -c "from engines.dhcp_analyzer import analyze_dhcp_pcap; analyze_dhcp_pcap('outputs/pcaps/dhcp_rogue.pcap')"

dhcp-pool-exhausted:
	$(PYTHON) tools/generate_dhcp_pcap.py pool-exhausted
	$(PYTHON) -c "from engines.dhcp_analyzer import analyze_dhcp_pcap; analyze_dhcp_pcap('outputs/pcaps/dhcp_pool-exhausted.pcap')"

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

lab-scan:
	$(COMPOSE) exec auditbot python -B -c "from engines.discovery import run_discovery; from collectors.raw_writer import write_raw_file; data = run_discovery(); output = write_raw_file(data, 'lab_discovery'); print(f'Lab discovery JSON exported: {output}')"
