from engines.dhcp_services.rules.registry import default_client_rules


def normalize_mac(value):
       if not value:
              return None

       value = str(value).strip().lower()
       if not value:
              return None

       return value.replace("-", ":")


def first_non_empty(*values):
       for value in values:
              if value not in (None, "", "0.0.0.0"):
                     return value
       return None


def parse_int(value):
       try:
              return int(str(value).strip())
       except (TypeError, ValueError):
              return None


def packet_client_mac(packet):
       return normalize_mac(
              first_non_empty(
                     packet.get("client_hw_mac"),
                     packet.get("client_mac"),
                     packet.get("eth_src"),
              )
       )


def packet_server(packet):
       return first_non_empty(packet.get("server_id"), packet.get("ip_src"))


def empty_client_summary(client_mac):
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


def add_packet_to_client_summary(summary, packet):
       name = packet["message_name"]
       summary[name if name in {"discover", "offer", "request", "ack", "nak"} else "other"] += 1

       if packet.get("hostname"):
              summary["hostnames"].add(packet["hostname"])

       if packet.get("transaction_id"):
              summary["transaction_ids"].add(packet["transaction_id"])

       requested_ip = first_non_empty(packet.get("requested_ip"))
       if requested_ip:
              summary["requested_ips"].add(requested_ip)

       offered_or_acked_ip = first_non_empty(packet.get("your_ip"))
       if offered_or_acked_ip:
              summary["offered_or_acked_ips"].add(offered_or_acked_ip)

       router = first_non_empty(packet.get("router"))
       if router:
              summary["routers"].add(router)

       relay_agent = first_non_empty(packet.get("relay_agent"))
       if relay_agent:
              summary["relay_agents"].add(relay_agent)

       if name in {"offer", "ack", "nak"}:
              server = packet_server(packet)
              if server:
                     summary["servers"].add(server)

       lease_time = parse_int(packet.get("lease_time"))
       if lease_time is not None:
              summary["lease_times"].append(lease_time)

       try:
              timestamp = float(packet["time_epoch"]) if packet.get("time_epoch") else None
       except (TypeError, ValueError):
              timestamp = None

       if timestamp is not None:
              summary["first_seen"] = timestamp if summary["first_seen"] is None else min(summary["first_seen"], timestamp)
              summary["last_seen"] = timestamp if summary["last_seen"] is None else max(summary["last_seen"], timestamp)


def finalize_client_summary(summary):
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
              client_mac = packet_client_mac(packet)
              if not client_mac:
                     continue

              summary = clients.setdefault(client_mac, empty_client_summary(client_mac))
              add_packet_to_client_summary(summary, packet)

       return [
              finalize_client_summary(summary)
              for summary in sorted(clients.values(), key=lambda item: item["client_mac"])
       ]


class DHCPClientClassifier:
       def __init__(self, action_text, rules=None):
              self.action_text = action_text
              self.rules = rules or default_client_rules()

       def classify_many(self, client_summaries, context=None):
              return [
                     {
                            **summary,
                            "conclusion": self.classify(summary, context),
                     }
                     for summary in client_summaries
              ]

       def classify(self, summary, context=None):
              context = context or {}
              for rule in self.rules:
                     if rule.matches(summary, context):
                            return rule.classify(summary, context, self.action_text)

              raise RuntimeError("No DHCP client classification rule matched")
