from engines.dhcp_services.rules.base import DHCPClientRule


class ActiveProbeOfferRule(DHCPClientRule):
       status = "DHCP_NORMAL"
       severity = "low"
       probable_cause = "DHCP server responded to AuditBot's Discover with an Offer; no Request/ACK was sent by design."
       confidence = 0.8

       def matches(self, summary, context):
              return bool(context.get("active_probe")) and summary["offer"] > 0
