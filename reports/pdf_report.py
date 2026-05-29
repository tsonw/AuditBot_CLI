import textwrap
from datetime import datetime
from pathlib import Path


PAGE_WIDTH = 595
PAGE_HEIGHT = 842
MARGIN = 42
LINE_HEIGHT = 13


def generate_full_flow_report(data, output_dir="output/reports"):
       output_path = _report_path(output_dir)
       lines = _build_report_lines(data)
       pages = _paginate(lines)
       _write_pdf(output_path, pages)
       return str(output_path)


def _report_path(output_dir):
       directory = Path(output_dir)
       directory.mkdir(parents=True, exist_ok=True)
       timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
       output_path = directory / f"auditbot_comprehensive_audit_report_{timestamp}.pdf"
       counter = 1

       while output_path.exists():
              output_path = directory / f"auditbot_comprehensive_audit_report_{timestamp}_{counter}.pdf"
              counter += 1

       return output_path


def _build_report_lines(data):
       lines = []
       _title(lines, "AuditBot Comprehensive Audit Report")
       _kv(lines, "Generated at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
       _kv(lines, "IP mode", data.get("ip_mode") or "-")
       _kv(lines, "Raw JSON", data.get("raw_file") or "-")
       _blank(lines)

       _section(lines, "Infrastructure Discovery")
       _discovery_lines(lines, data.get("network_results") or [])

       _blank(lines)
       _section(lines, "DHCP Diagnostics")
       _dhcp_lines(lines, data.get("dhcp_diagnostics") or {})

       _blank(lines)
       _section(lines, "Vulnerability Analysis")
       _vulnerability_lines(lines, data.get("vulnerability_analysis") or {})

       return lines


def _discovery_lines(lines, network_results):
       if not network_results:
              _text(lines, "No discovery data was collected.")
              return

       for index, network in enumerate(network_results, start=1):
              _subsection(lines, f"Network {index}: {network.get('network') or '-'}")
              _kv(lines, "Family", network.get("family") or "-")
              _kv(lines, "Interface", network.get("interface") or "-")
              _kv(lines, "Gateway", network.get("gateway") or "-")
              _kv(lines, "Scan method", network.get("scan_method") or "-")
              _kv(lines, "Hosts found", network.get("hosts_found", len(network.get("hosts") or [])))

              for error in network.get("errors") or []:
                     _text(lines, f"Warning: {error.get('error') or '-'}")

              hosts = network.get("hosts") or []
              if not hosts:
                     _text(lines, "No hosts discovered in this network.")
                     _blank(lines)
                     continue

              for host_index, host in enumerate(hosts, start=1):
                     label = host.get("hostname") or host.get("ip") or f"host-{host_index}"
                     _text(lines, f"Host {host_index}: {label}", size=11, font="bold")
                     _kv(lines, "Asset ID", host.get("asset_id") or "-")
                     _kv(lines, "Interface ID", host.get("interface_id") or "-")
                     _kv(lines, "Identity source", host.get("identity_source") or "-")
                     _kv(lines, "Identity confidence", host.get("identity_confidence") or "-")
                     _kv(lines, "Identity reason", host.get("identity_reason") or "-")
                     _kv(lines, "IP", _ip_with_prefix(host.get("ip"), host.get("source_network")))
                     _kv(lines, "Hostname", host.get("hostname") or "-")
                     _kv(lines, "OS", host.get("os") or "-")
                     _kv(lines, "Family", host.get("family") or "-")
                     _kv(lines, "MAC", host.get("mac") or "-")
                     _kv(lines, "Interface", host.get("source_interface") or "-")
                     _kv(lines, "Gateway", host.get("source_gateway") or "-")
                     _kv(lines, "Discovery method", host.get("discovery_method") or "-")

                     services = _service_lines(host)
                     if services:
                            _text(lines, "Services:", size=10, font="bold")
                            for service in services:
                                   _text(lines, f"- {service}")
                     else:
                            _text(lines, "Services: no open ports recorded")

                     _blank(lines)


def _dhcp_lines(lines, dhcp):
       if not dhcp:
              _text(lines, "No DHCP diagnostics were collected.")
              return

       if dhcp.get("skipped"):
              _kv(lines, "Status", "skipped")
              _kv(lines, "Reason", dhcp.get("reason") or "-")
              return

       if dhcp.get("error"):
              _kv(lines, "Status", "error")
              _kv(lines, "Error", dhcp.get("error") or "-")
              return

       _kv(lines, "Mode", dhcp.get("mode") or "-")
       _kv(lines, "PCAP", dhcp.get("file") or "-")

       summary = dhcp.get("summary") or {}
       if summary:
              _subsection(lines, "Global Summary")
              _kv(lines, "Discover", summary.get("discover", 0))
              _kv(lines, "Offer", summary.get("offer", 0))
              _kv(lines, "Request", summary.get("request", 0))
              _kv(lines, "ACK", summary.get("ack", 0))
              _kv(lines, "NAK", summary.get("nak", 0))
              _kv(lines, "DHCP servers", _join(summary.get("dhcp_servers_detected") or []))
              _kv(lines, "Routers", _join(summary.get("dhcp_routers") or []))
              _kv(lines, "Relay agents", _join(summary.get("relay_agents") or []))
              _kv(lines, "Lease duration", summary.get("lease_duration_seconds") or "unknown")

       auditbot = dhcp.get("auditbot") or dhcp.get("client") or {}
       if auditbot:
              _subsection(lines, "AuditBot Host Context")
              _kv(lines, "Interface", auditbot.get("interface") or "-")
              _kv(lines, "Current IP", auditbot.get("current_ip") or "-")
              _kv(lines, "Network", auditbot.get("network") or "-")
              _kv(lines, "Gateway", auditbot.get("gateway") or "-")
              _kv(lines, "MAC", auditbot.get("mac") or "-")
              _kv(lines, "Gateway ping", auditbot.get("gateway_ping_result") or "unknown")
              _kv(lines, "Packet loss", _packet_loss(auditbot))

       conclusion = dhcp.get("conclusion")
       if conclusion:
              _subsection(lines, "Local Conclusion")
              _kv(lines, "Status", conclusion.get("status") or "-")
              _kv(lines, "Severity", conclusion.get("severity") or "-")
              _kv(lines, "Probable cause", conclusion.get("probable_cause") or "-")
              _kv(lines, "Confidence", conclusion.get("confidence") or "-")

       clients = dhcp.get("clients") or []
       _subsection(lines, "Client Sessions")
       if not clients:
              _text(lines, "No DHCP client sessions were observed.")
              return

       for index, client in enumerate(clients, start=1):
              conclusion = client.get("conclusion") or {}
              _text(lines, f"Client {index}: {client.get('client_mac') or '-'}", size=11, font="bold")
              _kv(lines, "Hostname", _join(client.get("hostnames") or []))
              _kv(lines, "Transactions", len(client.get("transaction_ids") or []))
              _kv(lines, "D/O/R/A/N", _dora(client))
              _kv(lines, "Requested IP", _join(client.get("requested_ips") or []))
              _kv(lines, "Offered/ACKed IP", _join(client.get("offered_or_acked_ips") or []))
              _kv(lines, "Server", _join(client.get("servers") or []))
              _kv(lines, "Router", _join(client.get("routers") or []))
              _kv(lines, "Lease", client.get("lease_duration_seconds") or "-")
              _kv(lines, "Status", conclusion.get("status") or "-")
              _kv(lines, "Severity", conclusion.get("severity") or "-")
              _kv(lines, "Probable cause", conclusion.get("probable_cause") or "-")
              _kv(lines, "Confidence", conclusion.get("confidence") or "-")
              _blank(lines)


def _service_lines(host):
       services = host.get("services") or {}
       output = []

       for port in host.get("ports") or []:
              service = services.get(str(port)) or services.get(port) or {}
              protocol = service.get("protocol") or "tcp"
              name = service.get("name") or "unknown"
              state = service.get("state") or "open"
              detail = " ".join(
                     value
                     for value in [
                            service.get("product"),
                            service.get("version"),
                            service.get("extrainfo"),
                     ]
                     if value
              )
              label = f"{port}/{protocol} {name}"
              if detail:
                     label = f"{label} ({detail})"
              output.append(f"{label} [{state}]")

       return output


def _vulnerability_lines(lines, vulnerability):
       if not vulnerability:
              _text(lines, "No vulnerability analysis was collected.")
              return

       if vulnerability.get("error"):
              _kv(lines, "Status", "error")
              _kv(lines, "Error", vulnerability.get("error") or "-")
              return

       _kv(lines, "Report JSON", vulnerability.get("report_file") or "-")
       _kv(lines, "Services analyzed", vulnerability.get("services_analyzed", 0))
       _kv(lines, "Vulnerabilities matched", vulnerability.get("vulnerabilities_matched", 0))
       _kv(lines, "Notable vulnerabilities", vulnerability.get("notable_count", 0))

       database = vulnerability.get("database") or {}
       if database:
              _subsection(lines, "NVD Database")
              _kv(lines, "Source", database.get("source") or "-")
              _kv(lines, "Last CVE modified date", database.get("last_update") or "-")
              _kv(lines, "Last local import", database.get("last_imported_at") or "-")

       notable = vulnerability.get("notable") or []
       if not notable:
              _text(lines, "No CRITICAL/HIGH or CVSS >= 7.0 vulnerabilities were highlighted.")
              return

       _subsection(lines, "Top Notable Findings")
       for index, item in enumerate(notable, start=1):
              cve = item.get("cve_id") or "-"
              score = item.get("cvss_score") or "-"
              severity = item.get("severity") or "-"
              _text(lines, f"{index}. {cve} ({severity}, CVSS {score}) on {_vulnerability_service(item)}")
              _kv(lines, "Recommendation", item.get("recommendation") or "-")


def _vulnerability_service(item):
       host = item.get("hostname") or item.get("host") or "-"
       port = item.get("port") or "-"
       protocol = item.get("protocol") or "tcp"
       service = item.get("service") or "-"
       product = " ".join(value for value in [item.get("product"), item.get("version")] if value)
       label = f"{host} {port}/{protocol}:{service}"

       if product:
              label = f"{label} ({product})"

       return label


def _paginate(lines):
       pages = []
       page = []
       y = PAGE_HEIGHT - MARGIN

       for item in lines:
              text, size, font = item
              wrapped = _wrap_text(text, size)

              for line in wrapped:
                     if y < MARGIN:
                            pages.append(page)
                            page = []
                            y = PAGE_HEIGHT - MARGIN

                     page.append((line, size, font, MARGIN, y))
                     y -= LINE_HEIGHT if size <= 10 else LINE_HEIGHT + 3

       if page:
              pages.append(page)

       return pages or [[("No report content.", 10, "regular", MARGIN, PAGE_HEIGHT - MARGIN)]]


def _write_pdf(output_path, pages):
       objects = []
       objects.append("<< /Type /Catalog /Pages 2 0 R >>")
       objects.append(None)
       objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
       objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")

       page_object_ids = []

       for page in pages:
              content = _page_content(page)
              content_id = len(objects) + 2
              page_id = len(objects) + 1
              page_object_ids.append(page_id)
              objects.append(
                     "<< /Type /Page /Parent 2 0 R "
                     "/MediaBox [0 0 595 842] "
                     "/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
                     f"/Contents {content_id} 0 R >>"
              )
              objects.append(
                     f"<< /Length {len(content.encode('latin-1', errors='replace'))} >>\n"
                     f"stream\n{content}\nendstream"
              )

       kids = " ".join(f"{object_id} 0 R" for object_id in page_object_ids)
       objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_object_ids)} >>"

       _serialize_pdf(output_path, objects)


def _serialize_pdf(output_path, objects):
       chunks = [b"%PDF-1.4\n"]
       offsets = [0]

       for index, obj in enumerate(objects, start=1):
              offsets.append(sum(len(chunk) for chunk in chunks))
              chunks.append(f"{index} 0 obj\n".encode("latin-1"))
              chunks.append(obj.encode("latin-1", errors="replace"))
              chunks.append(b"\nendobj\n")

       xref_offset = sum(len(chunk) for chunk in chunks)
       chunks.append(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
       chunks.append(b"0000000000 65535 f \n")

       for offset in offsets[1:]:
              chunks.append(f"{offset:010d} 00000 n \n".encode("latin-1"))

       chunks.append(
              (
                     "trailer\n"
                     f"<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
                     "startxref\n"
                     f"{xref_offset}\n"
                     "%%EOF\n"
              ).encode("latin-1")
       )

       output_path.write_bytes(b"".join(chunks))


def _page_content(page):
       commands = []

       for text, size, font, x, y in page:
              font_id = "F2" if font == "bold" else "F1"
              commands.append(
                     f"BT /{font_id} {size} Tf 1 0 0 1 {x} {y} Tm ({_pdf_escape(text)}) Tj ET"
              )

       return "\n".join(commands)


def _wrap_text(text, size):
       if text == "":
              return [""]

       width = 82 if size <= 10 else 66
       return textwrap.wrap(str(text), width=width, replace_whitespace=False) or [""]


def _pdf_escape(value):
       text = str(value).encode("latin-1", errors="replace").decode("latin-1")
       return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _title(lines, text):
       _text(lines, text, size=16, font="bold")


def _section(lines, text):
       _text(lines, text, size=14, font="bold")


def _subsection(lines, text):
       _text(lines, text, size=12, font="bold")


def _kv(lines, key, value):
       _text(lines, f"{key}: {value}")


def _text(lines, text, size=10, font="regular"):
       lines.append((str(text), size, font))


def _blank(lines):
       lines.append(("", 10, "regular"))


def _join(values):
       return ", ".join(str(value) for value in values if value) or "-"


def _dora(client):
       return (
              f"{client.get('discover', 0)}/"
              f"{client.get('offer', 0)}/"
              f"{client.get('request', 0)}/"
              f"{client.get('ack', 0)}/"
              f"{client.get('nak', 0)}"
       )


def _packet_loss(auditbot):
       if auditbot.get("packet_loss") is None:
              return "unknown"
       return f"{auditbot['packet_loss']}%"


def _ip_with_prefix(ip_value, network_value):
       if not ip_value:
              return "-"

       if not network_value or "/" not in str(network_value):
              return ip_value

       return f"{ip_value}/{str(network_value).rsplit('/', 1)[1]}"
