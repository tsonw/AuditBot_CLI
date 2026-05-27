import json

from rich.console import Console
from rich.table import Table

console = Console()


def join_values(values):
       return ", ".join(str(value) for value in values if value) or "-"


def dora_counts(row):
       return (
              f"{row['discover']}/"
              f"{row['offer']}/"
              f"{row['request']}/"
              f"{row['ack']}/"
              f"{row['nak']}"
       )


def render_client_sessions(client_results):
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
                     join_values(row.get("hostnames") or []),
                     str(len(row.get("transaction_ids") or [])),
                     dora_counts(row),
                     join_values(row.get("requested_ips") or []),
                     join_values(row.get("offered_or_acked_ips") or []),
                     join_values(row.get("servers") or []),
                     join_values(row.get("routers") or []),
                     str(lease_time) if lease_time is not None else "-",
                     conclusion["status"],
                     str(conclusion["confidence"]),
              )

       console.print(table)


def render_global_summary(file_path, summary, context=None):
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


def render_diagnostics(file_path, summary, context, conclusion):
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
