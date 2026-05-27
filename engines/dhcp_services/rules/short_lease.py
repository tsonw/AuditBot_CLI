from engines.dhcp_services.rules.base import DHCPClientRule


class ShortLeaseRule(DHCPClientRule):
       status = "DHCP_SHORT_LEASE_TIME"
       severity = "medium"
       probable_cause = "DHCP lease time for this client is shorter than 10 minutes."
       confidence = 0.9

       def matches(self, summary, context):
              return (
                     summary["lease_duration_seconds"] is not None
                     and summary["lease_duration_seconds"] < 600
              )
