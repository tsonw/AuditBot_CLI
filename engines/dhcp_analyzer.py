import json
import os
import random
import re
import subprocess
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import netifaces
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeRemainingColumn
from rich.table import Table
from scapy.all import BOOTP, DHCP, Ether, IP, UDP, AsyncSniffer, get_if_hwaddr, sendp
from scapy.error import Scapy_Exception

from scanners.network import get_local_network

console = Console()

DEFAULT_DHCP_CAPTURE_DURATION_SECONDS = 60
DHCP_CAPTURE_FILTER = "udp port 67 or udp port 68"
DHCP_MODE_LOCAL = "local"
DHCP_MODE_PASSIVE = "passive"
DHCP_MODE_ACTIVE = "active"
DHCP_MODE_PCAP = "pcap"

DHCP_MESSAGE_TYPES = {
       "1": "discover",
       "2": "offer",
       "3": "request",
       "5": "ack",
       "6": "nak",
}

ACTION_TEXT = {
       "DHCP_NORMAL": [
              "No action required if the client is stable.",
              "Continue monitoring lease renewal if the issue is intermittent.",
       ],
       "DHCP_NO_OFFER": [
              "Check whether the DHCP server is running.",
              "Check whether the DHCP scope/pool still has free IPs.",
              "Check the client VLAN.",
              "Check DHCP relay or ip helper configuration.",
              "Check whether firewall/ACL rules block UDP ports 67/68.",
              "Check switch port or Wi-Fi packet drops.",
       ],
       "DHCP_OFFER_NO_ACK": [
              "Check packets from client to server.",
              "Check packets from server to client.",
              "Check relay/firewall between client and DHCP server.",
              "Check switch port, VLAN, and packet loss.",
              "Capture DHCP traffic on both client and server sides if possible.",
       ],
       "DHCP_NAK_RECEIVED": [
              "Clear the old lease on the client.",
              "Renew the DHCP lease.",
              "Check whether the client requests an IP from the wrong subnet.",
              "Check DHCP reservations.",
              "Check the current VLAN/subnet of the client.",
              "Check DHCP server logs for the NAK reason.",
       ],
       "ROGUE_DHCP_DETECTED": [
              "Identify the legitimate DHCP server.",
              "Find the unexpected device serving DHCP.",
              "Check secondary routers, VMs, containers, hotspots, or mispatched devices.",
              "Enable DHCP Snooping on switches if supported.",
              "Block the unauthorized DHCP server.",
       ],
       "DHCP_SHORT_LEASE_TIME": [
              "Check lease time configuration on the DHCP scope.",
              "Increase lease time if this is not a lab/test environment.",
              "Check whether a DHCP policy gives short leases to this client group.",
       ],
       "DHCP_POOL_EXHAUSTED": [
              "Expand the DHCP pool.",
              "Reduce lease time if appropriate.",
              "Remove stale leases that are no longer used.",
              "Check whether unknown devices consume many leases.",
              "Redesign the subnet if client count has grown.",
       ],
       "IP_CONFLICT_DETECTED": [
              "Find the device using the duplicate IP.",
              "Check which device uses a static IP inside the DHCP pool.",
              "Keep static IP ranges outside the DHCP pool.",
              "Clear the conflicting lease.",
              "Renew the DHCP lease on the affected client.",
       ],
       "APIPA_ASSIGNED": [
              "Check whether DHCP Discover packets are sent.",
              "Check whether DHCP Offer packets return.",
              "Check DHCP server, VLAN, relay, and firewall.",
              "Check physical or Wi-Fi connectivity.",
       ],
       "GATEWAY_UNREACHABLE_AFTER_DHCP": [
              "Check whether the gateway is online.",
              "Check the client VLAN.",
              "Check subnet mask and default gateway delivered by DHCP.",
              "Check the switch port.",
              "Check internal firewall rules.",
              "Check routing.",
       ],
       "POSSIBLE_VLAN_OR_RELAY_ISSUE": [
              "Check the client VLAN ID.",
              "Check DHCP relay/ip helper configuration.",
              "Check routing between client VLAN and DHCP server.",
              "Check ACL/firewall rules between VLANs.",
              "Capture packets on both client-side and server-side links.",
       ],
       "NETWORK_INSTABILITY_OR_PACKET_LOSS": [
              "Check switch port error/drop/CRC counters.",
              "Check cabling.",
              "Check Wi-Fi signal if the client uses Wi-Fi.",
              "Check interface flapping.",
              "Check packet loss to the gateway and DHCP server.",
              "Capture traffic for a longer period.",
       ],
       "INSUFFICIENT_DATA": [
              "Capture DHCP traffic while renewing the client lease.",
              "Provide DHCP server logs if available.",
              "Provide DHCP pool free IP count if available.",
              "Run the diagnostic from the affected client network.",
       ],
}


def _run_command(cmd, timeout=10):
       try:
              return subprocess.run(
                     cmd,
                     capture_output=True,
                     text=True,
                     check=False,
                     timeout=timeout,
              )
       except FileNotFoundError:
              return None
       except subprocess.TimeoutExpired:
              return subprocess.CompletedProcess(cmd, 124, "", "command timed out")


def _parse_int(value):
       try:
              return int(str(value).strip())
       except (TypeError, ValueError):
              return None


def _first_non_empty(*values):
       for value in values:
              if value not in (None, "", "0.0.0.0"):
                     return value
       return None


def _is_apipa(ip_address):
       return bool(ip_address and ip_address.startswith("169.254."))


def _get_default_gateway():
       gateways = netifaces.gateways()
       default_gateway = gateways.get("default", {}).get(netifaces.AF_INET)

       if not default_gateway:
              return None, None

       return default_gateway[0], default_gateway[1]


def _get_interface_mac(interface):
       if not interface:
              return None

       iface_data = netifaces.ifaddresses(interface)
       link_data = iface_data.get(netifaces.AF_LINK, [])

       if not link_data:
              return None

       return link_data[0].get("addr")


def get_client_ip_context():
       try:
              network = get_local_network()
       except RuntimeError:
              network = {}

       gateway, gateway_interface = _get_default_gateway()
       interface = network.get("interface") or gateway_interface

       return {
              "interface": interface,
              "current_ip": network.get("ip"),
              "netmask": network.get("netmask"),
              "network": network.get("network"),
              "gateway": gateway,
              "mac": _get_interface_mac(interface),
       }


def capture_dhcp_traffic(duration_seconds=DEFAULT_DHCP_CAPTURE_DURATION_SECONDS, interface=None):
       Path("outputs/pcaps").mkdir(parents=True, exist_ok=True)

       filename = f"outputs/pcaps/dhcp_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
       capture_interface = interface or get_client_ip_context().get("interface")

       if not capture_interface:
              raise RuntimeError("No active IPv4 interface found for DHCP capture.")

       console.print(
              f"[cyan]Capturing DHCP traffic:[/cyan] {capture_interface} "
              f"for {duration_seconds}s"
       )

       cmd = [
              "tshark",
              "-i", capture_interface,
              "-f", DHCP_CAPTURE_FILTER,
              "-a", f"duration:{duration_seconds}",
              "-w", filename,
       ]

       try:
              process = subprocess.Popen(
                     cmd,
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE,
                     text=True,
              )
       except FileNotFoundError as exc:
              raise RuntimeError("tshark is not installed or not available in PATH.") from exc

       with Progress(
              SpinnerColumn(),
              TextColumn("[progress.description]{task.description}"),
              BarColumn(),
              TimeRemainingColumn(),
              console=console,
       ) as progress:
              task = progress.add_task("DHCP capture", total=duration_seconds)
              started_at = time.monotonic()

              while process.poll() is None:
                     elapsed = min(time.monotonic() - started_at, duration_seconds)
                     progress.update(task, completed=elapsed)
                     time.sleep(0.25)

              elapsed = min(time.monotonic() - started_at, duration_seconds)
              completed = duration_seconds if process.returncode == 0 else elapsed
              progress.update(task, completed=completed)

       stdout, stderr = process.communicate()

       if process.returncode != 0:
              details = stderr.strip() or stdout.strip() or "unknown tshark error"
              if "BPF" in details or "/dev/bpf" in details or "Operation not permitted" in details:
                     raise RuntimeError(
                            "DHCP capture needs root/BPF permissions. Run: make run"
                     )
              raise RuntimeError(f"DHCP capture failed: {details}")

       os.chmod(filename, 0o644)
       console.print(f"[green]DHCP capture saved:[/green] {filename}")
       return filename


def _read_dhcp_packets(file_path):
       path = Path(file_path)

       if not path.exists():
              raise RuntimeError(f"PCAP file does not exist: {file_path}")

       if not path.is_file():
              raise RuntimeError(f"PCAP path is not a file: {file_path}")

       cmd = [
              "tshark",
              "-r", str(path),
              "-Y", "dhcp.option.dhcp",
              "-T", "fields",
              "-E", "separator=\t",
              "-E", "occurrence=f",
              "-e", "frame.time_epoch",
              "-e", "eth.src",
              "-e", "eth.dst",
              "-e", "ip.src",
              "-e", "ip.dst",
              "-e", "dhcp.id",
              "-e", "dhcp.hw.mac_addr",
              "-e", "dhcp.client_hardware_address",
              "-e", "dhcp.ip.client",
              "-e", "dhcp.ip.your",
              "-e", "dhcp.ip.relay",
              "-e", "dhcp.option.dhcp",
              "-e", "dhcp.option.dhcp_server_id",
              "-e", "dhcp.option.requested_ip_address",
              "-e", "dhcp.option.router",
              "-e", "dhcp.option.ip_address_lease_time",
              "-e", "dhcp.option.hostname",
       ]

       try:
              result = subprocess.run(cmd, capture_output=True, text=True, check=False)
       except FileNotFoundError as exc:
              raise RuntimeError("tshark is not installed or not available in PATH.") from exc

       if result.returncode != 0:
              details = result.stderr.strip() or result.stdout.strip() or "unknown tshark error"
              if "permission" in details.lower():
                     raise RuntimeError(
                            f"Cannot read PCAP file. Check file permissions: {file_path}"
                     )
              raise RuntimeError(f"DHCP analysis failed: {details}")

       packets = []
       fields = [
              "time_epoch",
              "eth_src",
              "eth_dst",
              "ip_src",
              "ip_dst",
              "transaction_id",
              "client_hw_mac",
              "client_mac",
              "client_ip",
              "your_ip",
              "relay_agent",
              "message_type",
              "server_id",
              "requested_ip",
              "router",
              "lease_time",
              "hostname",
       ]

       for line in result.stdout.splitlines():
              if not line.strip():
                     continue

              values = line.split("\t")
              packet = {}

              for index, field in enumerate(fields):
                     packet[field] = values[index].strip() if index < len(values) else ""

              packet["message_name"] = DHCP_MESSAGE_TYPES.get(
                     packet["message_type"],
                     "other",
              )
              packets.append(packet)

       return packets


def _read_arp_table():
       mappings = defaultdict(set)

       result = _run_command(["ip", "neigh", "show"])
       if result and result.returncode == 0:
              for line in result.stdout.splitlines():
                     parts = line.split()

                     if not parts:
                            continue

                     ip_address = parts[0]
                     mac_address = None

                     if "lladdr" in parts:
                            index = parts.index("lladdr")
                            if index + 1 < len(parts):
                                   mac_address = parts[index + 1].lower()

                     if mac_address:
                            mappings[ip_address].add(mac_address)

       result = _run_command(["arp", "-an"])
       if result and result.returncode == 0:
              for line in result.stdout.splitlines():
                     ip_match = re.search(r"\(([^)]+)\)", line)
                     mac_match = re.search(
                            r"at\s+([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})",
                            line,
                     )

                     if ip_match and mac_match:
                            mappings[ip_match.group(1)].add(mac_match.group(1).lower())

       return {ip: sorted(macs) for ip, macs in mappings.items()}


def _detect_ip_conflicts(arp_table, current_ip=None, local_mac=None):
       conflicts = {}

       for ip_address, macs in arp_table.items():
              if len(set(macs)) > 1:
                     conflicts[ip_address] = macs

       if current_ip and local_mac:
              macs = {mac.lower() for mac in arp_table.get(current_ip, [])}
              normalized_local_mac = local_mac.lower()

              if macs and any(mac != normalized_local_mac for mac in macs):
                     conflicts[current_ip] = sorted(macs | {normalized_local_mac})

       return conflicts


def _ping_gateway(gateway):
       if not gateway:
              return "unknown", None

       result = _run_command(["ping", "-c", "4", "-W", "1", gateway], timeout=6)

       if not result:
              return "unknown", None

       output = f"{result.stdout}\n{result.stderr}"
       loss_match = re.search(r"(\d+(?:\.\d+)?)%\s+packet loss", output)
       packet_loss = float(loss_match.group(1)) if loss_match else None

       if result.returncode == 0:
              return "success", packet_loss

       return "failed", packet_loss


def _read_optional_context():
       pool_free_ips = _parse_int(os.getenv("AUDITBOT_DHCP_POOL_FREE_IPS"))
       server_status = os.getenv("AUDITBOT_DHCP_SERVER_STATUS")
       logs = os.getenv("AUDITBOT_DHCP_SERVER_LOGS", "")
       logs_file = os.getenv("AUDITBOT_DHCP_SERVER_LOGS_FILE")

       if logs_file:
              try:
                     logs = Path(logs_file).read_text()
              except OSError:
                     logs = logs or ""

       return {
              "dhcp_pool_free_ips": pool_free_ips,
              "dhcp_server_status": server_status,
              "dhcp_server_logs": logs,
       }


def _normalize_mac(value):
       if not value:
              return None

       value = str(value).strip().lower()
       if not value:
              return None

       return value.replace("-", ":")


def _packet_client_mac(packet):
       return _normalize_mac(
              _first_non_empty(
                     packet.get("client_hw_mac"),
                     packet.get("client_mac"),
                     packet.get("eth_src"),
              )
       )


def _packet_server(packet):
       return _first_non_empty(packet.get("server_id"), packet.get("ip_src"))


def _empty_client_summary(client_mac):
       return {
              "client_mac": client_mac or "-",
              "hostnames": set(),
              "transaction_ids": set(),
              "discover": 0,
              "offer": 0,
              "request": 0,
              "ack": 0,
              "nak": 0,
              "other": 0,
              "servers": set(),
              "requested_ips": set(),
              "offered_or_acked_ips": set(),
              "routers": set(),
              "relay_agents": set(),
              "lease_times": [],
              "first_seen": None,
              "last_seen": None,
       }


def _add_packet_to_client_summary(summary, packet):
       name = packet["message_name"]
       summary[name if name in {"discover", "offer", "request", "ack", "nak"} else "other"] += 1

       if packet.get("hostname"):
              summary["hostnames"].add(packet["hostname"])

       if packet.get("transaction_id"):
              summary["transaction_ids"].add(packet["transaction_id"])

       requested_ip = _first_non_empty(packet.get("requested_ip"))
       if requested_ip:
              summary["requested_ips"].add(requested_ip)

       offered_or_acked_ip = _first_non_empty(packet.get("your_ip"))
       if offered_or_acked_ip:
              summary["offered_or_acked_ips"].add(offered_or_acked_ip)

       router = _first_non_empty(packet.get("router"))
       if router:
              summary["routers"].add(router)

       relay_agent = _first_non_empty(packet.get("relay_agent"))
       if relay_agent:
              summary["relay_agents"].add(relay_agent)

       if name in {"offer", "ack", "nak"}:
              server = _packet_server(packet)
              if server:
                     summary["servers"].add(server)

       lease_time = _parse_int(packet.get("lease_time"))
       if lease_time is not None:
              summary["lease_times"].append(lease_time)

       try:
              timestamp = float(packet["time_epoch"]) if packet.get("time_epoch") else None
       except (TypeError, ValueError):
              timestamp = None
       if timestamp is not None:
              summary["first_seen"] = timestamp if summary["first_seen"] is None else min(summary["first_seen"], timestamp)
              summary["last_seen"] = timestamp if summary["last_seen"] is None else max(summary["last_seen"], timestamp)


def _finalize_client_summary(summary):
       lease_times = summary.pop("lease_times")
       summary["hostnames"] = sorted(summary["hostnames"])
       summary["transaction_ids"] = sorted(summary["transaction_ids"])
       summary["servers"] = sorted(summary["servers"])
       summary["requested_ips"] = sorted(summary["requested_ips"])
       summary["offered_or_acked_ips"] = sorted(summary["offered_or_acked_ips"])
       summary["routers"] = sorted(summary["routers"])
       summary["relay_agents"] = sorted(summary["relay_agents"])
       summary["lease_duration_seconds"] = min(lease_times) if lease_times else None
       return summary


def summarize_dhcp_clients(packets):
       clients = {}

       for packet in packets:
              client_mac = _packet_client_mac(packet)
              if not client_mac:
                     continue

              summary = clients.setdefault(client_mac, _empty_client_summary(client_mac))
              _add_packet_to_client_summary(summary, packet)

       return [
              _finalize_client_summary(summary)
              for summary in sorted(clients.values(), key=lambda item: item["client_mac"])
       ]


def _client_conclusion(status, severity, probable_cause, evidence, confidence):
       return _conclusion(status, severity, probable_cause, evidence, confidence)


def classify_dhcp_client(summary, context=None):
       context = context or {}
       evidence = {
              "client_mac": summary["client_mac"],
              "hostnames": summary["hostnames"],
              "transaction_ids": summary["transaction_ids"],
              "discover_count": summary["discover"],
              "offer_count": summary["offer"],
              "request_count": summary["request"],
              "ack_count": summary["ack"],
              "nak_count": summary["nak"],
              "dhcp_servers_detected": summary["servers"],
              "requested_ips": summary["requested_ips"],
              "offered_or_acked_ips": summary["offered_or_acked_ips"],
              "routers": summary["routers"],
              "relay_agents": summary["relay_agents"],
              "lease_duration_seconds": summary["lease_duration_seconds"],
              "dhcp_pool_free_ips": context.get("dhcp_pool_free_ips"),
       }

       if len(summary["servers"]) > 1:
              return _client_conclusion(
                     "ROGUE_DHCP_DETECTED",
                     "critical",
                     "Multiple DHCP servers answered this client.",
                     evidence,
                     0.95,
              )

       if _pool_exhausted(context):
              return _client_conclusion(
                     "DHCP_POOL_EXHAUSTED",
                     "critical",
                     "DHCP pool appears to have no available addresses.",
                     evidence,
                     0.9 if context.get("dhcp_pool_free_ips") == 0 else 0.75,
              )

       if context.get("active_probe") and summary["offer"] > 0:
              return _client_conclusion(
                     "DHCP_NORMAL",
                     "low",
                     "DHCP server responded to AuditBot's Discover with an Offer; no Request/ACK was sent by design.",
                     evidence,
                     0.8,
              )

       if summary["nak"] > 0:
              return _client_conclusion(
                     "DHCP_NAK_RECEIVED",
                     "high",
                     "DHCP server rejected this client's request with a NAK.",
                     evidence,
                     0.95,
              )

       if summary["lease_duration_seconds"] is not None and summary["lease_duration_seconds"] < 600:
              return _client_conclusion(
                     "DHCP_SHORT_LEASE_TIME",
                     "medium",
                     "DHCP lease time for this client is shorter than 10 minutes.",
                     evidence,
                     0.9,
              )

       if summary["ack"] > 0 and summary["nak"] == 0:
              return _client_conclusion(
                     "DHCP_NORMAL",
                     "low",
                     "This client received a DHCP ACK.",
                     evidence,
                     0.85,
              )

       if summary["discover"] > 0 and summary["offer"] == 0:
              return _client_conclusion(
                     "DHCP_NO_OFFER",
                     "high",
                     "This client sent DHCP Discover but no DHCP Offer was observed.",
                     evidence,
                     0.9,
              )

       if summary["offer"] > 0 and summary["ack"] == 0 and summary["nak"] == 0:
              return _client_conclusion(
                     "DHCP_OFFER_NO_ACK",
                     "high",
                     "A DHCP Offer was observed but this client's lease was not completed with ACK.",
                     evidence,
                     0.9,
              )

       if summary["request"] > 0 and summary["ack"] == 0 and summary["nak"] == 0:
              return _client_conclusion(
                     "DHCP_OFFER_NO_ACK",
                     "high",
                     "This client requested a lease but no ACK was observed.",
                     evidence,
                     0.75,
              )

       return _client_conclusion(
              "INSUFFICIENT_DATA",
              "unknown",
              "Not enough DHCP traffic was observed for this client.",
              evidence,
              0.35,
       )


def classify_dhcp_clients(client_summaries, context=None):
       return [
              {
                     **summary,
                     "conclusion": classify_dhcp_client(summary, context),
              }
              for summary in client_summaries
       ]


def _summarize_packets(packets):
       counts = {
              "discover": 0,
              "offer": 0,
              "request": 0,
              "ack": 0,
              "nak": 0,
              "other": 0,
       }
       servers = set()
       lease_times = []
       routers = set()
       relays = set()
       requested_ips = set()
       offered_or_acked_ips = set()

       for packet in packets:
              name = packet["message_name"]
              counts[name if name in counts else "other"] += 1

              requested_ip = _first_non_empty(packet.get("requested_ip"))
              if requested_ip:
                     requested_ips.add(requested_ip)

              offered_or_acked_ip = _first_non_empty(packet.get("your_ip"))
              if offered_or_acked_ip:
                     offered_or_acked_ips.add(offered_or_acked_ip)

              router = _first_non_empty(packet.get("router"))
              if router:
                     routers.add(router)

              relay_agent = _first_non_empty(packet.get("relay_agent"))
              if relay_agent:
                     relays.add(relay_agent)

              if name in {"offer", "ack", "nak"}:
                     server = _first_non_empty(packet.get("server_id"), packet.get("ip_src"))
                     if server:
                            servers.add(server)

              lease_time = _parse_int(packet.get("lease_time"))
              if lease_time is not None:
                     lease_times.append(lease_time)

       return {
              **counts,
              "dhcp_servers_detected": sorted(servers),
              "lease_duration_seconds": min(lease_times) if lease_times else None,
              "dhcp_routers": sorted(routers),
              "relay_agents": sorted(relays),
              "requested_ips": sorted(requested_ips),
              "offered_or_acked_ips": sorted(offered_or_acked_ips),
       }


def _pool_exhausted(context):
       if context.get("dhcp_pool_free_ips") == 0:
              return True

       logs = (context.get("dhcp_server_logs") or "").lower()
       return any(
              marker in logs
              for marker in [
                     "no free leases",
                     "pool exhausted",
                     "no available addresses",
              ]
       )


def _possible_vlan_or_relay_issue(summary, context):
       if summary["discover"] <= 0 or summary["offer"] != 0:
              return False

       if context.get("dhcp_server_status") != "running":
              return False

       free_ips = context.get("dhcp_pool_free_ips")
       if free_ips is not None and free_ips <= 0:
              return False

       return bool(summary.get("relay_agents")) or free_ips is not None


def _network_instability(summary, context):
       packet_loss = context.get("packet_loss")

       if packet_loss is not None and packet_loss > 10:
              return True

       if summary["discover"] >= 5 and summary["ack"] == 0:
              return True

       if summary["discover"] >= 5 and summary["ack"] > 0 and summary["discover"] > summary["ack"] * 3:
              return True

       return False


def _conclusion(status, severity, probable_cause, evidence, confidence):
       return {
              "status": status,
              "severity": severity,
              "probable_cause": probable_cause,
              "evidence": evidence,
              "recommended_actions": ACTION_TEXT[status],
              "confidence": confidence,
       }


def classify_dhcp_diagnosis(summary, context):
       evidence = {
              "discover_count": summary["discover"],
              "offer_count": summary["offer"],
              "request_count": summary["request"],
              "ack_count": summary["ack"],
              "nak_count": summary["nak"],
              "current_ip": context.get("current_ip"),
              "is_apipa": context.get("is_apipa"),
              "dhcp_servers_detected": summary["dhcp_servers_detected"],
              "gateway": context.get("gateway"),
              "gateway_ping_result": context.get("gateway_ping_result"),
              "lease_duration_seconds": summary["lease_duration_seconds"],
              "dhcp_pool_free_ips": context.get("dhcp_pool_free_ips"),
              "ip_conflicts": context.get("ip_conflicts"),
              "packet_loss": context.get("packet_loss"),
              "relay_agents": summary["relay_agents"],
       }

       if len(summary["dhcp_servers_detected"]) > 1:
              return _conclusion(
                     "ROGUE_DHCP_DETECTED",
                     "critical",
                     "Multiple DHCP servers answered in the same diagnostic window.",
                     evidence,
                     0.95,
              )

       if _pool_exhausted(context):
              return _conclusion(
                     "DHCP_POOL_EXHAUSTED",
                     "critical",
                     "DHCP pool appears to have no available addresses.",
                     evidence,
                     0.9 if context.get("dhcp_pool_free_ips") == 0 else 0.75,
              )

       if context.get("ip_conflicts"):
              return _conclusion(
                     "IP_CONFLICT_DETECTED",
                     "high",
                     "The same IP appears with multiple MAC addresses or conflicts with the local client.",
                     evidence,
                     0.85,
              )

       if context.get("is_apipa") and summary["offer"] == 0:
              return _conclusion(
                     "DHCP_NO_OFFER",
                     "high",
                     "Client is using APIPA and no DHCP Offer was observed after Discover.",
                     evidence,
                     0.9,
              )

       if context.get("is_apipa"):
              return _conclusion(
                     "APIPA_ASSIGNED",
                     "high",
                     "Client is using APIPA, which indicates DHCP did not provide a usable address.",
                     evidence,
                     0.85,
              )

       if summary["nak"] > 0:
              return _conclusion(
                     "DHCP_NAK_RECEIVED",
                     "high",
                     "DHCP server rejected the client request with a NAK.",
                     evidence,
                     0.95,
              )

       if summary["lease_duration_seconds"] is not None and summary["lease_duration_seconds"] < 600:
              return _conclusion(
                     "DHCP_SHORT_LEASE_TIME",
                     "medium",
                     "DHCP lease time is shorter than 10 minutes.",
                     evidence,
                     0.9,
              )

       dora_complete = (
              summary["discover"] >= 1
              and summary["offer"] >= 1
              and summary["request"] >= 1
              and summary["ack"] >= 1
       )

       if (
              dora_complete
              and context.get("current_ip")
              and context.get("gateway")
              and context.get("gateway_ping_result") == "failed"
       ):
              return _conclusion(
                     "GATEWAY_UNREACHABLE_AFTER_DHCP",
                     "high",
                     "DHCP completed but the default gateway is unreachable.",
                     evidence,
                     0.85,
              )

       if (
              dora_complete
              and context.get("current_ip")
              and not context.get("is_apipa")
              and summary["dhcp_servers_detected"]
              and context.get("gateway")
              and context.get("gateway_ping_result") == "success"
              and not context.get("ip_conflicts")
       ):
              return _conclusion(
                     "DHCP_NORMAL",
                     "low",
                     "DHCP DORA completed and the client can reach its gateway.",
                     evidence,
                     0.9,
              )

       if _possible_vlan_or_relay_issue(summary, context):
              return _conclusion(
                     "POSSIBLE_VLAN_OR_RELAY_ISSUE",
                     "high",
                     "DHCP server appears available but no Offer reached the client.",
                     evidence,
                     0.7,
              )

       if summary["discover"] > 0 and summary["offer"] == 0:
              return _conclusion(
                     "DHCP_NO_OFFER",
                     "high",
                     "Client sent DHCP Discover but no DHCP Offer was observed.",
                     evidence,
                     0.9,
              )

       if (
              summary["discover"] > 0
              and summary["offer"] > 0
              and summary["ack"] == 0
              and summary["nak"] == 0
       ):
              return _conclusion(
                     "DHCP_OFFER_NO_ACK",
                     "high",
                     "DHCP Offer was observed but the lease was not completed with ACK.",
                     evidence,
                     0.9,
              )

       if _network_instability(summary, context):
              severity = "high" if (context.get("packet_loss") or 0) > 30 else "medium"
              return _conclusion(
                     "NETWORK_INSTABILITY_OR_PACKET_LOSS",
                     severity,
                     "Packet loss or repeated incomplete DHCP attempts suggest unstable connectivity.",
                     evidence,
                     0.75,
              )

       return _conclusion(
              "INSUFFICIENT_DATA",
              "unknown",
              "Available evidence is not enough to classify a DHCP failure confidently.",
              evidence,
              0.35,
       )


def _join_values(values):
       return ", ".join(str(value) for value in values if value) or "-"


def _dora_counts(row):
       return (
              f"{row['discover']}/"
              f"{row['offer']}/"
              f"{row['request']}/"
              f"{row['ack']}/"
              f"{row['nak']}"
       )


def _render_client_sessions(client_results):
       table = Table(title="DHCP Client Sessions")
       table.add_column("Client MAC")
       table.add_column("Hostname")
       table.add_column("TxIDs", justify="right")
       table.add_column("D/O/R/A/N")
       table.add_column("Requested IP")
       table.add_column("Offered/ACKed IP")
       table.add_column("Server")
       table.add_column("Router")
       table.add_column("Lease")
       table.add_column("Status")
       table.add_column("Confidence")

       if not client_results:
              table.add_row("-", "-", "0", "0/0/0/0/0", "-", "-", "-", "-", "-", "INSUFFICIENT_DATA", "0")
              console.print(table)
              return

       for row in client_results:
              conclusion = row["conclusion"]
              lease_time = row.get("lease_duration_seconds")
              table.add_row(
                     row.get("client_mac") or "-",
                     _join_values(row.get("hostnames") or []),
                     str(len(row.get("transaction_ids") or [])),
                     _dora_counts(row),
                     _join_values(row.get("requested_ips") or []),
                     _join_values(row.get("offered_or_acked_ips") or []),
                     _join_values(row.get("servers") or []),
                     _join_values(row.get("routers") or []),
                     str(lease_time) if lease_time is not None else "-",
                     conclusion["status"],
                     str(conclusion["confidence"]),
              )

       console.print(table)


def _render_global_summary(file_path, summary, context=None):
       context = context or {}
       table = Table(title="DHCP Global Summary")
       table.add_column("Check")
       table.add_column("Result")

       table.add_row("PCAP", str(file_path))
       table.add_row("AuditBot interface", context.get("interface") or "-")
       table.add_row("AuditBot IP", context.get("current_ip") or "-")
       table.add_row("DHCP Discover", str(summary["discover"]))
       table.add_row("DHCP Offer", str(summary["offer"]))
       table.add_row("DHCP Request", str(summary["request"]))
       table.add_row("DHCP ACK", str(summary["ack"]))
       table.add_row("DHCP NAK", str(summary["nak"]))
       table.add_row("DHCP servers", ", ".join(summary["dhcp_servers_detected"]) or "-")
       table.add_row("Routers", ", ".join(summary["dhcp_routers"]) or "-")
       table.add_row("Relay agents", ", ".join(summary["relay_agents"]) or "-")
       table.add_row(
              "Lease time",
              str(summary["lease_duration_seconds"]) if summary["lease_duration_seconds"] is not None else "unknown",
       )
       table.add_row(
              "Pool free IPs",
              str(context.get("dhcp_pool_free_ips")) if context.get("dhcp_pool_free_ips") is not None else "unknown",
       )

       console.print(table)


def _render_diagnostics(file_path, summary, context, conclusion):
       flow_table = Table(title="DHCP DORA Diagnostics")
       flow_table.add_column("Check")
       flow_table.add_column("Result")

       flow_table.add_row("PCAP", str(file_path))
       flow_table.add_row("AuditBot interface", context.get("interface") or "-")
       flow_table.add_row("AuditBot IP", context.get("current_ip") or "-")
       flow_table.add_row("APIPA", "yes" if context.get("is_apipa") else "no")
       flow_table.add_row("DHCP Discover", str(summary["discover"]))
       flow_table.add_row("DHCP Offer", str(summary["offer"]))
       flow_table.add_row("DHCP Request", str(summary["request"]))
       flow_table.add_row("DHCP ACK", str(summary["ack"]))
       flow_table.add_row("DHCP NAK", str(summary["nak"]))
       flow_table.add_row("DHCP servers", ", ".join(summary["dhcp_servers_detected"]) or "-")
       flow_table.add_row(
              "Lease time",
              str(summary["lease_duration_seconds"]) if summary["lease_duration_seconds"] is not None else "unknown",
       )
       flow_table.add_row(
              "Pool free IPs",
              str(context.get("dhcp_pool_free_ips")) if context.get("dhcp_pool_free_ips") is not None else "unknown",
       )
       flow_table.add_row("IP conflicts", json.dumps(context.get("ip_conflicts") or {}))
       flow_table.add_row("Gateway", context.get("gateway") or "-")
       flow_table.add_row("Gateway ping", context.get("gateway_ping_result") or "unknown")
       flow_table.add_row(
              "Packet loss",
              f"{context['packet_loss']}%" if context.get("packet_loss") is not None else "unknown",
       )

       console.print(flow_table)

       conclusion_table = Table(title="DHCP Diagnostic Conclusion")
       conclusion_table.add_column("Field")
       conclusion_table.add_column("Value")
       conclusion_table.add_row("status", conclusion["status"])
       conclusion_table.add_row("severity", conclusion["severity"])
       conclusion_table.add_row("probable_cause", conclusion["probable_cause"])
       conclusion_table.add_row("confidence", str(conclusion["confidence"]))
       conclusion_table.add_row("recommended_actions", "\n".join(conclusion["recommended_actions"]))
       console.print(conclusion_table)


def _mac_to_bytes(mac_address):
       return bytes(int(part, 16) for part in mac_address.split(":"))


def _dhcp_option(packet, option_name):
       if DHCP not in packet:
              return None

       for option in packet[DHCP].options:
              if not isinstance(option, tuple) or len(option) != 2:
                     continue

              key, value = option
              if key == option_name:
                     return value

       return None


def _active_probe_offer_to_packet(packet, xid, client_mac):
       if BOOTP not in packet or DHCP not in packet:
              return None

       if packet[BOOTP].xid != xid:
              return None

       message_type = _dhcp_option(packet, "message-type")
       if message_type not in {2, "offer"}:
              return None

       return {
              "time_epoch": str(time.time()),
              "eth_src": packet[Ether].src if Ether in packet else "",
              "eth_dst": packet[Ether].dst if Ether in packet else "",
              "ip_src": packet[IP].src if IP in packet else "",
              "ip_dst": packet[IP].dst if IP in packet else "",
              "transaction_id": hex(xid),
              "client_mac": client_mac,
              "client_ip": "",
              "your_ip": packet[BOOTP].yiaddr,
              "relay_agent": packet[BOOTP].giaddr if packet[BOOTP].giaddr != "0.0.0.0" else "",
              "message_type": "2",
              "server_id": _dhcp_option(packet, "server_id") or "",
              "requested_ip": "",
              "router": _dhcp_option(packet, "router") or "",
              "lease_time": str(_dhcp_option(packet, "lease_time") or ""),
              "hostname": "",
              "message_name": "offer",
       }


def run_active_dhcp_probe(duration_seconds=10, interface=None):
       context = get_client_ip_context()
       capture_interface = interface or context.get("interface")

       if not capture_interface:
              raise RuntimeError("No active IPv4 interface found for DHCP probe.")

       try:
              client_mac = get_if_hwaddr(capture_interface)
       except Exception:
              client_mac = context.get("mac")

       if not client_mac:
              raise RuntimeError("Cannot determine interface MAC for DHCP probe.")

       xid = random.randint(1, 0xFFFFFFFF)
       discover = (
              Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
              / IP(src="0.0.0.0", dst="255.255.255.255")
              / UDP(sport=68, dport=67)
              / BOOTP(chaddr=_mac_to_bytes(client_mac), xid=xid, flags=0x8000)
              / DHCP(options=[
                     ("message-type", "discover"),
                     ("param_req_list", [1, 3, 6, 15, 51, 54]),
                     "end",
              ])
       )

       console.print(
              f"[cyan]Active DHCP probe:[/cyan] sending Discover on {capture_interface} "
              f"and listening for {duration_seconds}s"
       )

       try:
              sniffer = AsyncSniffer(
                     iface=capture_interface,
                     filter=DHCP_CAPTURE_FILTER,
              )
              sniffer.start()
              time.sleep(0.25)
              sendp(discover, iface=capture_interface, verbose=0)
              time.sleep(duration_seconds)
              offers = sniffer.stop()
       except PermissionError as exc:
              raise RuntimeError("Active DHCP probe needs root/raw socket permissions. Run: make run") from exc
       except Scapy_Exception as exc:
              if "Permission denied" in str(exc):
                     raise RuntimeError("Active DHCP probe needs root/raw socket permissions. Run: make run") from exc
              raise RuntimeError(f"Active DHCP probe failed: {exc}") from exc

       packets = [
              packet
              for packet in (
                     _active_probe_offer_to_packet(offer, xid, client_mac)
                     for offer in offers
              )
              if packet
       ]

       summary = _summarize_packets(packets)
       probe_context = _read_optional_context()
       probe_context["active_probe"] = True
       client_results = classify_dhcp_clients(
              summarize_dhcp_clients(packets),
              probe_context,
       )

       _render_global_summary("active probe", summary, context)
       _render_client_sessions(client_results)

       if not packets:
              console.print("[yellow]No DHCP Offer observed for the active probe.[/yellow]")

       return {
              "mode": DHCP_MODE_ACTIVE,
              "summary": summary,
              "clients": client_results,
              "probe": {
                     "interface": capture_interface,
                     "client_mac": client_mac,
                     "transaction_id": hex(xid),
              },
       }


def run_passive_dhcp_monitor(file_path=None, duration_seconds=DEFAULT_DHCP_CAPTURE_DURATION_SECONDS, interface=None):
       mode = DHCP_MODE_PCAP if file_path else DHCP_MODE_PASSIVE

       if not file_path:
              file_path = capture_dhcp_traffic(duration_seconds=duration_seconds, interface=interface)

       packets = _read_dhcp_packets(file_path)
       summary = _summarize_packets(packets)
       context = get_client_ip_context()
       context.update(_read_optional_context())
       client_summaries = summarize_dhcp_clients(packets)
       client_results = classify_dhcp_clients(client_summaries, context)

       _render_global_summary(file_path, summary, context)
       _render_client_sessions(client_results)

       return {
              "mode": mode,
              "file": str(file_path),
              "summary": summary,
              "clients": client_results,
              "auditbot": context,
       }


def run_local_dhcp_diagnostics(file_path=None, duration_seconds=DEFAULT_DHCP_CAPTURE_DURATION_SECONDS, interface=None):
       if not file_path:
              file_path = capture_dhcp_traffic(duration_seconds=duration_seconds, interface=interface)

       packets = _read_dhcp_packets(file_path)
       summary = _summarize_packets(packets)
       context = get_client_ip_context()
       optional_context = _read_optional_context()
       gateway_from_dhcp = summary["dhcp_routers"][0] if summary["dhcp_routers"] else None

       if gateway_from_dhcp:
              context["gateway"] = gateway_from_dhcp

       context.update(optional_context)
       context["is_apipa"] = _is_apipa(context.get("current_ip"))
       context["arp_table"] = _read_arp_table()
       context["ip_conflicts"] = _detect_ip_conflicts(
              context["arp_table"],
              current_ip=context.get("current_ip"),
              local_mac=context.get("mac"),
       )
       context["gateway_ping_result"], context["packet_loss"] = _ping_gateway(context.get("gateway"))

       conclusion = classify_dhcp_diagnosis(summary, context)
       client_results = classify_dhcp_clients(
              summarize_dhcp_clients(packets),
              context,
       )

       _render_diagnostics(file_path, summary, context, conclusion)
       _render_client_sessions(client_results)
       return {
              "mode": DHCP_MODE_LOCAL,
              "file": str(file_path),
              "summary": summary,
              "clients": client_results,
              "client": context,
              "conclusion": conclusion,
       }


def run_dhcp_diagnostics(
       file_path=None,
       duration_seconds=DEFAULT_DHCP_CAPTURE_DURATION_SECONDS,
       interface=None,
       mode=DHCP_MODE_LOCAL,
):
       if mode == DHCP_MODE_ACTIVE:
              return run_active_dhcp_probe(duration_seconds=duration_seconds, interface=interface)

       if mode in {DHCP_MODE_PASSIVE, DHCP_MODE_PCAP}:
              return run_passive_dhcp_monitor(
                     file_path=file_path,
                     duration_seconds=duration_seconds,
                     interface=interface,
              )

       return run_local_dhcp_diagnostics(
              file_path=file_path,
              duration_seconds=duration_seconds,
              interface=interface,
       )


def analyze_dhcp_pcap(file_path):
       return run_dhcp_diagnostics(file_path=file_path, mode=DHCP_MODE_PCAP)
