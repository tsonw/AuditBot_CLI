# AuditBot Docker Lab

This lab creates an isolated, multi-segment infrastructure for testing AuditBot discovery.

## Topology

```text
corp_net 10.10.10.0/24
  auditbot             10.10.10.250
  edge-gateway         10.10.10.2     Ubuntu, also on dmz_net + mgmt_net
  corp-app-01          10.10.10.10    Debian, also on mgmt_net
  corp-db-01           10.10.10.20    Ubuntu, also on mgmt_net
  dmz-proxy-01         10.10.10.30    Debian, also on dmz_net
  user-workstation-01  10.10.10.50    Debian, also on user_net

dmz_net 10.10.20.0/24
  auditbot             10.10.20.250
  edge-gateway         10.10.20.2
  dmz-proxy-01         10.10.20.10
  dmz-api-01           10.10.20.20    Ubuntu
  vuln-web-01          10.10.20.49    vulnerable scanner test host
  mgmt-monitor-01      10.10.20.30    Ubuntu, also on mgmt_net

mgmt_net 10.10.30.0/24
  auditbot             10.10.30.250
  edge-gateway         10.10.30.2
  mgmt-monitor-01      10.10.30.10
  corp-app-01          10.10.30.110
  corp-db-01           10.10.30.120

user_net 10.10.40.0/24
  auditbot             10.10.40.250
  user-workstation-01  10.10.40.10
```

Each Linux host is built from a Debian or Ubuntu base image. Hosts run SSH, optional nginx, Python HTTP servers, and TCP banner listeners across common audit ports such as `80`, `443`, `445`, `3000`, `3306`, `5000`, `5432`, `5672`, `5900`, `6379`, `8000-9000`, `9200`, `9300`, and `10000`.

`vuln-web-01` is a dedicated vulnerability-scanner test host. It exposes controlled banner-only services for detection testing:

- `21/tcp`: vsFTPd `2.3.4`
- `8081/tcp`: Apache httpd `2.4.49`

These services are synthetic lab banners only. They are intended to help Nmap produce recognizable product/version/CPE data so AuditBot's CVE analysis can populate vulnerability findings without adding exploit behavior to the lab.

`auditbot` is attached to all lab networks and has `NET_RAW`/`NET_ADMIN`, so ARP discovery can see hosts in each subnet.

## Commands

```bash
make lab-up
make lab-ps
make lab-menu
make lab-vuln-scan
make lab-scan
make lab-shell
make lab-down
```

`make lab-menu` opens the full interactive AuditBot menu inside the `auditbot` container.

`make lab-vuln-scan` runs a fresh discovery scan inside the `auditbot` container, saves the discovery JSON, then runs local NVD analysis and writes results under `output/`.

`make lab-scan` runs infrastructure discovery inside the `auditbot` container and exports JSON to `output/raw/lab_discovery_<timestamp>.json`.
