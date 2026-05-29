def assign_asset_identities(hosts):
       groups = {}

       for host in hosts:
              host["interface_id"] = interface_id(host)
              hostname = _normalized_hostname(host)

              if hostname:
                     groups.setdefault(hostname, []).append(host)
              else:
                     _assign_fallback_asset_identity(host)

       for hostname, hostname_hosts in groups.items():
              _assign_hostname_asset_identity(hostname, hostname_hosts)

       return hosts


def interface_id(host):
       mac = _normalized_mac(host)
       if mac:
              return f"mac:{mac}"

       ip = host.get("ip")
       if ip:
              return f"ip:{ip}"

       interface = host.get("source_interface") or "unknown-interface"
       network = host.get("source_network") or "unknown-network"
       return f"interface:{interface}|network:{network}"


def _assign_hostname_asset_identity(hostname, hosts):
       networks = {
              host.get("source_network")
              for host in hosts
              if host.get("source_network")
       }
       interfaces = {
              host.get("interface_id")
              for host in hosts
              if host.get("interface_id")
       }

       should_split = len(hosts) > 1 and len(interfaces) > 1 and len(networks) <= 1

       for host in hosts:
              if should_split:
                     host["asset_id"] = f"hostname:{hostname}|{host['interface_id']}"
                     host["identity_source"] = "hostname+interface"
                     host["identity_confidence"] = "weak"
                     host["identity_reason"] = (
                            "same hostname appears on multiple interfaces in the same network; "
                            "kept separate to avoid merging duplicate hosts"
                     )
              else:
                     host["asset_id"] = f"hostname:{hostname}"
                     host["identity_source"] = "hostname"
                     host["identity_confidence"] = "inferred"
                     host["identity_reason"] = (
                            "same hostname is treated as one asset; interfaces remain separate"
                     )


def _assign_fallback_asset_identity(host):
       mac = _normalized_mac(host)

       if mac:
              host["asset_id"] = f"mac:{mac}"
              host["identity_source"] = "mac"
              host["identity_confidence"] = "exact"
              host["identity_reason"] = "no hostname observed; MAC address used as asset identity"
              return

       ip = host.get("ip")
       if ip:
              host["asset_id"] = f"ip:{ip}"
              host["identity_source"] = "ip"
              host["identity_confidence"] = "weak"
              host["identity_reason"] = "no hostname or MAC observed; IP address used as fallback identity"
              return

       host["asset_id"] = host.get("interface_id") or "unknown"
       host["identity_source"] = "unknown"
       host["identity_confidence"] = "weak"
       host["identity_reason"] = "insufficient identity evidence"


def _normalized_hostname(host):
       hostname = (host.get("hostname") or "").strip().lower()
       return hostname or None


def _normalized_mac(host):
       mac = (host.get("mac") or "").strip().lower()
       return mac or None
