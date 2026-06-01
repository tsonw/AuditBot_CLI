# AuditBot CLI

AuditBot CLI là công cụ kiểm toán mạng nội bộ chạy bằng Python. Tool tập trung vào ba nhóm tác vụ chính:

- Discovery hạ tầng mạng bằng ARP, IPv6 neighbor discovery và Nmap.
- Chẩn đoán DHCP bằng capture trực tiếp hoặc phân tích PCAP.
- Phân tích lỗ hổng offline bằng local NVD SQLite database.

Tool không chạy exploit, brute force, DoS hoặc probe xâm nhập. Kết quả phân tích lỗ hổng dựa trên service/product/version thu được từ scan và dữ liệu NVD local.

## Tính Năng Chính

- Comprehensive Audit: chạy tổng thể từ discovery, DHCP diagnostics tới vulnerability scan.
- Infrastructure Discovery: phát hiện network, host, hostname, OS, port, service và version.
- DHCP Diagnostics: hỗ trợ local diagnostic, passive monitor, active probe và phân tích PCAP.
- Local NVD Vulnerability Scan: lookup CVE offline bằng SQLite database.
- Notable Vulnerabilities Table: hiển thị bảng CVE đáng chú ý với CRITICAL/HIGH hoặc CVSS >= 7.0.
- PDF Report: xuất báo cáo PDF sau comprehensive audit nếu người dùng chọn.
- Docker Lab: có lab thường và vulnerability lab để test trong môi trường cô lập.

## Yêu Cầu

Máy host cần có:

- Python 3.10+
- Nmap
- tshark/Wireshark CLI nếu dùng capture DHCP trực tiếp
- Docker và Docker Compose nếu chạy lab

Trên macOS, một số thao tác capture packet cần quyền BPF/root. Nếu cần quyền root, chạy `make run SUDO=sudo`.

## Cài Đặt

Tạo virtualenv và cài dependencies:

```bash
make venv
make install
```

Hoặc chạy thủ công:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Chạy Tool

Mở menu chính:

```bash
make run
```

Hoặc:

```bash
PYTHONDONTWRITEBYTECODE=1 venv/bin/python main.py
```

Menu hiện tại:

```text
1. Comprehensive Audit (DHCP + Vulnerability Scan)
2. Infrastructure Discovery (ARP + Nmap)
3. DHCP Diagnostics
4. Draw topology (last scan)
5. Vulnerability Scan with Local NVD Database
6. Init NVD Local Database hoặc Update NVD Local Database
7. Help
8. Exit
```

Option 6 thay đổi tự động:

- Nếu chưa có DB: hiện `Init NVD Local Database`.
- Nếu đã có DB: hiện `Update NVD Local Database (Latest Modified Feed)`.

Khi chưa init DB, menu sẽ hiển thị cảnh báo đỏ in đậm để nhắc người dùng init trước khi scan lỗ hổng.

## Local NVD Database

AuditBot dùng database SQLite local tại:

```text
data/nvd/db/nvd_vulnerabilities.db
```

### Khởi Tạo Lần Đầu

Chạy:

```bash
venv/bin/python -m main nvd-init
```

Hoặc dùng Makefile:

```bash
make db-full-update
```

Mặc định dữ liệu được tải từ năm 2002. Có thể đổi năm bắt đầu:

```bash
make db-full-update NVD_START_YEAR=2024
```

### Cập Nhật Sau Khi Đã Có DB

Nếu database đã được khởi tạo, không cần init lại. Chỉ cần update:

```bash
venv/bin/python -m main nvd-update
```

Trong menu, chọn:

```text
6. Update NVD Local Database (Latest Modified Feed)
```

Nếu không có Internet khi update, tool sẽ hiện cảnh báo rõ ràng và không làm crash flow.

### Cảnh Báo DB Cũ

Trước khi scan lỗ hổng, tool kiểm tra thời điểm local DB được import/update lần cuối.

- DB mới 1-2 ngày: không cảnh báo.
- DB cũ từ 3 ngày trở lên: hiển thị cảnh báo đỏ và khuyến nghị chạy update.

## Comprehensive Audit

Option này dùng cho kiểm toán tổng thể.

Luồng chạy:

```text
Detect network
-> Infrastructure discovery
-> Passive DHCP client monitor
-> Local NVD vulnerability analysis
-> Export raw JSON
-> Hỏi có xuất PDF report không
```

Nếu chọn IPv6-only, DHCP diagnostics sẽ được skip vì module DHCP hiện tập trung vào DHCPv4.

Cuối flow, tool hỏi:

```text
Export PDF report?
1. Yes
2. No
Select [2]:
```

Nếu chọn `1`, tool sẽ in đường dẫn PDF đã xuất.

## Vulnerability Scan

Vulnerability scan hiện chỉ dùng module local NVD mới.

Luồng chạy:

```text
Discovery scan
-> lưu raw JSON
-> phân tích service/product/version
-> lookup CVE trong SQLite DB
-> xuất JSON report
-> hiển thị bảng notable vulnerabilities
```

Bảng notable vulnerabilities hiển thị các CVE:

- CRITICAL
- HIGH
- CVSS >= 7.0

Các cột chính:

```text
Host | Service | Product | CVE | Score | Severity | Recommendation
```

## DHCP Diagnostics

Menu DHCP hỗ trợ:

```text
1. Local DHCP diagnostic
2. Passive monitor clients
3. Active DHCP probe
4. Analyze PCAP file
```

Kết quả DHCP có thể nhận diện các trạng thái như:

- DHCP_NORMAL
- DHCP_NO_OFFER
- DHCP_OFFER_NO_ACK
- DHCP_NAK_RECEIVED
- ROGUE_DHCP_DETECTED
- DHCP_SHORT_LEASE_TIME
- DHCP_POOL_EXHAUSTED
- IP_CONFLICT_DETECTED
- APIPA_ASSIGNED
- GATEWAY_UNREACHABLE_AFTER_DHCP

## Output

Tất cả artifact runtime mới được ghi dưới thư mục:

```text
output/
```

Cấu trúc chính:

```text
output/
  raw/                         Raw JSON discovery/comprehensive audit
  pcaps/                       PCAP capture hoặc PCAP test
  reports/                     PDF reports
  vuln/                        Vulnerability JSON reports
```

Ví dụ:

```text
output/raw/comprehensive_audit_<timestamp>.json
output/raw/discovery_<timestamp>.json
output/pcaps/dhcp_capture_<timestamp>.pcap
output/reports/auditbot_comprehensive_audit_report_<timestamp>.pdf
output/vuln/vulnerability_report.json
```

Vulnerability report mặc định:

```text
output/vuln/vulnerability_report.json
```

Nếu file đã tồn tại, tool tự tạo suffix để tránh ghi đè:

```text
output/vuln/vulnerability_report_1.json
output/vuln/vulnerability_report_2.json
```

Raw JSON, PDF và PCAP cũng có cơ chế tránh trùng tên khi chạy nhiều lần cùng timestamp.

## CLI Commands

Hiển thị help:

```bash
venv/bin/python -m main --help
```

Khởi tạo NVD DB:

```bash
venv/bin/python -m main nvd-init
```

Cập nhật NVD DB:

```bash
venv/bin/python -m main nvd-update
```

Phân tích vuln từ file scan JSON có sẵn:

```bash
venv/bin/python -m main vuln-check output/raw/discovery_<timestamp>.json
```

Chỉ định file output:

```bash
venv/bin/python -m main vuln-check output/raw/discovery_<timestamp>.json --output-file output/vuln/custom_report.json
```

## Makefile Commands

Setup:

```bash
make venv
make install
```

Run menu:

```bash
make run
```

Test bằng unittest:

```bash
PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s test -p 'test_*.py'
```

Nếu môi trường đã có pytest:

```bash
make test
```

NVD database:

```bash
make db-full-update
make db-full-update NVD_START_YEAR=2024
```

DHCP PCAP simulation:

```bash
make dhcp-sim SCENARIO=normal
make dhcp-sim-all
make dhcp-test-pcaps
make dhcp-normal
make dhcp-no-offer
make dhcp-no-ack
make dhcp-rogue
make dhcp-pool-exhausted
```

Analyze custom PCAP:

```bash
make dhcp-analyze FILE=output/pcaps/dhcp_normal.pcap
```

## Docker Lab

Chạy lab thường:

```bash
make lab-up
make lab-ps
make lab-menu
make lab-scan
make lab-vuln-scan
make lab-shell
make lab-down
```

`make lab-menu` mở menu AuditBot trong container.

`make lab-scan` chạy infrastructure discovery và xuất JSON vào `output/raw/`.

`make lab-vuln-scan` chạy vulnerability scan local NVD.

## Vulnerability Docker Lab

Vulnerability lab là môi trường cô lập để test scanner với service banner được dựng sẵn.

Chạy:

```bash
make vuln-lab-up
make vuln-lab-ps
make vuln-lab-menu
make vuln-lab-nmap
make vuln-lab-scan
make vuln-lab-shell
make vuln-lab-down
```

Các target chính:

- `make vuln-lab-menu`: mở menu trong vulnerability lab.
- `make vuln-lab-nmap`: kiểm tra banner/service bằng Nmap.
- `make vuln-lab-scan`: chạy local NVD vulnerability scan trong lab.

## Cấu Trúc Project

```text
cli/                         Typer CLI commands
collectors/                  Raw JSON writer
config/                      NVD config và project paths
core/                        Menu, flow, topology
engines/                     Discovery, DHCP, capture engines
lab/                         Docker labs
reports/                     PDF report generator
scanners/                    Network and ARP scanners
tools/                       Utility scripts
utils/                       Banner/env helpers
vulnerabilities/             Local NVD importer, lookup, analyzer
test/                        Unit tests
```

## Lưu Ý An Toàn

- Chỉ scan các mạng/lab mà bạn có quyền kiểm tra.
- DHCP active probe chỉ gửi DHCP Discover và không nhận lease.
- Vulnerability scan không khai thác lỗ hổng, chỉ đối chiếu service/version với NVD local.
- Packet capture có thể cần quyền root/BPF.

## Troubleshooting

### Không Thấy Option Init DB

Nếu DB đã tồn tại, menu sẽ ẩn Init và chỉ hiện Update. File DB nằm ở:

```text
data/nvd/db/nvd_vulnerabilities.db
```

### Update DB Báo Không Có Internet

Kết nối Internet rồi chạy lại:

```bash
venv/bin/python -m main nvd-update
```

### Nmap Không Chạy

Kiểm tra Nmap đã cài chưa:

```bash
nmap --version
```

### Capture DHCP Lỗi Permission

Chạy menu bằng:

```bash
make run SUDO=sudo
```

hoặc đảm bảo user có quyền BPF/capture packet.

### Không Có CVE Trong Report

Một số nguyên nhân thường gặp:

- Chưa init/update NVD database.
- Nmap không phát hiện được product/version.
- Service không có CPE phù hợp trong matcher.
- Version phát hiện không nằm trong range bị ảnh hưởng.

## Generated Files Và Git

Các dữ liệu lớn/runtime không được commit:

- `data/nvd/raw/`
- `data/nvd/cache/`
- `data/nvd/db/`
- `output/`
- `outputs/`
- `*.pcap`, `*.pcapng`, `*.pdf`

File `.env.example` vẫn được giữ để làm mẫu cấu hình.
