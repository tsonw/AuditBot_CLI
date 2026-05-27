class DHCPClientRule:
       status = "INSUFFICIENT_DATA"
       severity = "unknown"
       confidence = 0.35
       probable_cause = "Not enough DHCP traffic was observed for this client."

       def matches(self, summary, context):
              raise NotImplementedError

       def classify(self, summary, context, action_text):
              return {
                     "status": self.status,
                     "severity": self.severity,
                     "probable_cause": self.probable_cause,
                     "evidence": evidence_from_summary(summary, context),
                     "recommended_actions": action_text[self.status],
                     "confidence": self.confidence,
              }


def evidence_from_summary(summary, context):
       return {
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


def pool_exhausted(context):
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
