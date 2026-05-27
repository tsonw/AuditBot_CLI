from engines.dhcp_services.rules.active_probe import ActiveProbeOfferRule
from engines.dhcp_services.rules.insufficient_data import InsufficientDataRule
from engines.dhcp_services.rules.nak_received import NakReceivedRule
from engines.dhcp_services.rules.no_offer import NoOfferRule
from engines.dhcp_services.rules.normal_ack import NormalAckRule
from engines.dhcp_services.rules.offer_no_ack import OfferNoAckRule, RequestNoAckRule
from engines.dhcp_services.rules.pool_exhausted import PoolExhaustedRule
from engines.dhcp_services.rules.rogue_dhcp import RogueDhcpRule
from engines.dhcp_services.rules.short_lease import ShortLeaseRule


def default_client_rules():
       return [
              RogueDhcpRule(),
              PoolExhaustedRule(),
              ActiveProbeOfferRule(),
              NakReceivedRule(),
              ShortLeaseRule(),
              NormalAckRule(),
              NoOfferRule(),
              OfferNoAckRule(),
              RequestNoAckRule(),
              InsufficientDataRule(),
       ]
