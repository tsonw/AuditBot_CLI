from engines.dhcp_services.rules.base import DHCPClientRule


class NoOfferRule(DHCPClientRule):
       status = "DHCP_NO_OFFER"
       severity = "high"
       probable_cause = "This client sent DHCP Discover but no DHCP Offer was observed."
       confidence = 0.9

       def matches(self, summary, context):
              return summary["discover"] > 0 and summary["offer"] == 0
