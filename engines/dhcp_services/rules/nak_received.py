from engines.dhcp_services.rules.base import DHCPClientRule


class NakReceivedRule(DHCPClientRule):
       status = "DHCP_NAK_RECEIVED"
       severity = "high"
       probable_cause = "DHCP server rejected this client's request with a NAK."
       confidence = 0.95

       def matches(self, summary, context):
              return summary["nak"] > 0
