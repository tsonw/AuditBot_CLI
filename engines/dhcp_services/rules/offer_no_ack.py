from engines.dhcp_services.rules.base import DHCPClientRule


class OfferNoAckRule(DHCPClientRule):
       status = "DHCP_OFFER_NO_ACK"
       severity = "high"
       probable_cause = "A DHCP Offer was observed but this client's lease was not completed with ACK."
       confidence = 0.9

       def matches(self, summary, context):
              return summary["offer"] > 0 and summary["ack"] == 0 and summary["nak"] == 0


class RequestNoAckRule(DHCPClientRule):
       status = "DHCP_OFFER_NO_ACK"
       severity = "high"
       probable_cause = "This client requested a lease but no ACK was observed."
       confidence = 0.75

       def matches(self, summary, context):
              return summary["request"] > 0 and summary["ack"] == 0 and summary["nak"] == 0
