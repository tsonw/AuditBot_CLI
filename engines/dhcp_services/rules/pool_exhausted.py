from engines.dhcp_services.rules.base import DHCPClientRule, pool_exhausted


class PoolExhaustedRule(DHCPClientRule):
       status = "DHCP_POOL_EXHAUSTED"
       severity = "critical"
       probable_cause = "DHCP pool appears to have no available addresses."

       def matches(self, summary, context):
              return pool_exhausted(context)

       def classify(self, summary, context, action_text):
              result = super().classify(summary, context, action_text)
              result["confidence"] = 0.9 if context.get("dhcp_pool_free_ips") == 0 else 0.75
              return result
