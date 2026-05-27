from engines.dhcp_services.rules.base import DHCPClientRule


class InsufficientDataRule(DHCPClientRule):
       status = "INSUFFICIENT_DATA"
       severity = "unknown"
       probable_cause = "Not enough DHCP traffic was observed for this client."
       confidence = 0.35

       def matches(self, summary, context):
              return True
