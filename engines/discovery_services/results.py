from engines.discovery_services.identity import assign_asset_identities


def clean_services(services):
       clean = {}

       for port, service in (services or {}).items():
              clean[str(port)] = {
                     key: service.get(key)
                     for key in ["protocol", "state", "name", "product", "version", "extrainfo", "cpe"]
                     if service.get(key)
              }

       return clean


def clean_host(host):
       clean = {
              "ip": host.get("ip"),
              "hostname": host.get("hostname"),
              "asset_id": host.get("asset_id"),
              "interface_id": host.get("interface_id"),
              "identity_source": host.get("identity_source"),
              "identity_confidence": host.get("identity_confidence"),
              "identity_reason": host.get("identity_reason"),
              "os": host.get("os"),
              "family": host.get("family"),
              "mac": host.get("mac"),
              "source_interface": host.get("source_interface"),
              "source_network": host.get("source_network"),
              "source_gateway": host.get("source_gateway"),
              "discovery_method": host.get("discovery_method"),
              "ports": host.get("ports") or [],
              "services": clean_services(host.get("services")),
       }

       return {
              key: value
              for key, value in clean.items()
              if value not in (None, "", {}, [])
       }


def clean_error(error):
       clean = {
              "network": error.get("network"),
              "interface": error.get("interface"),
              "error": error.get("error"),
       }

       return {
              key: value
              for key, value in clean.items()
              if value not in (None, "")
       }


def build_network_results(networks, hosts, errors):
       assign_asset_identities(hosts)
       results = []

       for net in networks:
              network = net["network"]
              interface = net.get("interface")
              network_hosts = [
                     host
                     for host in hosts
                     if host.get("source_network") == network
                     and host.get("source_interface") == interface
              ]
              network_errors = [
                     error
                     for error in errors
                     if error.get("network") == network
                     and error.get("interface") == interface
              ]

              result = {
                     "network": net.get("network"),
                     "family": net.get("family"),
                     "interface": net.get("interface"),
                     "gateway": net.get("via"),
                     "scan_method": net.get("scan_method"),
                     "hosts_found": len(network_hosts),
                     "hosts": [clean_host(host) for host in network_hosts],
                     "errors": [clean_error(error) for error in network_errors],
              }

              results.append({
                     key: value
                     for key, value in result.items()
                     if value not in (None, "", [], {})
              })

       return results
