from engines.dhcp_services.rules.base import DHCPClientRule


class RogueDhcpRule(DHCPClientRule):
       status = "ROGUE_DHCP_DETECTED"
       severity = "critical"
       probable_cause = "Multiple DHCP servers answered this client."
       confidence = 0.95

       def matches(self, summary, context):
              return len(summary["servers"]) > 1
