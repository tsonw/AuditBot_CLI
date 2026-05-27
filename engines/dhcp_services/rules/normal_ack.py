from engines.dhcp_services.rules.base import DHCPClientRule


class NormalAckRule(DHCPClientRule):
       status = "DHCP_NORMAL"
       severity = "low"
       probable_cause = "This client received a DHCP ACK."
       confidence = 0.85

       def matches(self, summary, context):
              return summary["ack"] > 0 and summary["nak"] == 0
