import ipaddress
import subprocess


class IPv6NeighborDiscoveryService:
       def scan(self, net):
              interface = net.get("interface")
              command = ["ip", "-6", "neigh", "show"]

              if interface:
                     command.extend(["dev", interface])

              try:
                     result = subprocess.run(
                            command,
                            capture_output=True,
                            text=True,
                            check=False,
                     )
              except FileNotFoundError:
                     return self._scan_macos_neighbors(net)

              if result.returncode != 0:
                     details = result.stderr.strip() or "ip -6 neigh failed"
                     raise RuntimeError(details)

              if result.stdout.strip() and "lladdr" not in result.stdout:
                     macos_hosts = self._scan_macos_neighbors(net)
                     if macos_hosts:
                            return macos_hosts

              network = ipaddress.IPv6Network(net["network"], strict=False)
              hosts = []
              seen = set()

              for line in result.stdout.splitlines():
                     parts = line.split()

                     if not parts:
                            continue

                     ip_value = parts[0].split("%", 1)[0]

                     try:
                            ip = ipaddress.IPv6Address(ip_value)
                     except ValueError:
                            continue

                     if ip not in network:
                            continue

                     states = {part.lower() for part in parts}
                     if states & {"failed", "incomplete", "permanent"}:
                            continue

                     mac = None
                     if "lladdr" in parts:
                            index = parts.index("lladdr")
                            if index + 1 < len(parts):
                                   mac = parts[index + 1].lower()

                     key = (ip_value, mac)
                     if key in seen:
                            continue

                     seen.add(key)
                     hosts.append(self._host(ip_value, mac, net))

              return hosts

       def _scan_macos_neighbors(self, net):
              interface = net.get("interface")

              try:
                     result = subprocess.run(
                            ["ndp", "-an"],
                            capture_output=True,
                            text=True,
                            check=False,
                     )
              except FileNotFoundError as exc:
                     raise RuntimeError("IPv6 neighbor discovery requires ip or ndp") from exc

              if result.returncode != 0:
                     details = result.stderr.strip() or "ndp -an failed"
                     raise RuntimeError(details)

              network = ipaddress.IPv6Network(net["network"], strict=False)
              hosts = []
              seen = set()

              for line in result.stdout.splitlines():
                     parts = line.split()

                     if len(parts) < 2:
                            continue

                     raw_ip = parts[0].strip("()")
                     scoped_interface = None

                     if "%" in raw_ip:
                            raw_ip, scoped_interface = raw_ip.split("%", 1)

                     row_interface = scoped_interface
                     if len(parts) > 2 and not row_interface:
                            row_interface = parts[2]

                     if interface and row_interface and row_interface != interface:
                            continue

                     states = {part.lower() for part in parts}
                     if "permanent" in states or "(incomplete)" in states or "incomplete" in states:
                            continue

                     try:
                            ip = ipaddress.IPv6Address(raw_ip)
                     except ValueError:
                            continue

                     if ip not in network:
                            continue

                     mac = parts[1].lower()
                     if mac in {"(incomplete)", "incomplete", "permanent"}:
                            mac = None

                     key = (raw_ip, mac)
                     if key in seen:
                            continue

                     seen.add(key)
                     hosts.append(self._host(raw_ip, mac, net))

              return hosts

       def _host(self, ip_value, mac, net):
              return {
                     "ip": ip_value,
                     "family": "IPv6",
                     "mac": mac,
                     "source_interface": net.get("interface"),
                     "source_network": net["network"],
                     "source_gateway": net.get("via"),
                     "discovery_method": "ndp",
              }
