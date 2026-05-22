import argparse
from pathlib import Path

from scapy.all import BOOTP, DHCP, Ether, IP, UDP, wrpcap


CLIENT_MAC = "02:00:00:00:00:10"
SERVER_MAC = "02:00:00:00:00:02"
ROGUE_MAC = "02:00:00:00:00:03"

CLIENT_IP = "0.0.0.0"
BROADCAST_IP = "255.255.255.255"
SERVER_IP = "192.168.56.2"
ROGUE_SERVER_IP = "192.168.56.3"
LEASE_IP = "192.168.56.100"


def mac_to_bytes(mac_address):
    return bytes(int(part, 16) for part in mac_address.split(":"))


def dhcp_packet(message_type, src_mac, src_ip, dst_ip, xid, server_id=None, requested_ip=None):
    options = [("message-type", message_type)]

    if server_id:
        options.append(("server_id", server_id))

    if requested_ip:
        options.append(("requested_addr", requested_ip))

    options.append("end")

    return (
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=67 if src_ip != CLIENT_IP else 68, dport=68 if src_ip != CLIENT_IP else 67)
        / BOOTP(chaddr=mac_to_bytes(CLIENT_MAC), xid=xid, yiaddr=LEASE_IP if message_type in {2, 5} else "0.0.0.0")
        / DHCP(options=options)
    )


def build_scenario(name):
    xid = 0x12345678

    discover = dhcp_packet(1, CLIENT_MAC, CLIENT_IP, BROADCAST_IP, xid)
    offer = dhcp_packet(2, SERVER_MAC, SERVER_IP, BROADCAST_IP, xid, server_id=SERVER_IP)
    request = dhcp_packet(3, CLIENT_MAC, CLIENT_IP, BROADCAST_IP, xid, server_id=SERVER_IP, requested_ip=LEASE_IP)
    ack = dhcp_packet(5, SERVER_MAC, SERVER_IP, BROADCAST_IP, xid, server_id=SERVER_IP)

    if name == "normal":
        return [discover, offer, request, ack]

    if name == "no-offer":
        return [
            dhcp_packet(1, CLIENT_MAC, CLIENT_IP, BROADCAST_IP, xid + index)
            for index in range(3)
        ]

    if name == "no-ack":
        return [discover, offer, request]

    if name == "rogue":
        rogue_offer = dhcp_packet(
            2,
            ROGUE_MAC,
            ROGUE_SERVER_IP,
            BROADCAST_IP,
            xid,
            server_id=ROGUE_SERVER_IP,
        )
        return [discover, offer, rogue_offer, request, ack]

    if name == "pool-exhausted":
        return [
            dhcp_packet(1, CLIENT_MAC, CLIENT_IP, BROADCAST_IP, xid + index)
            for index in range(5)
        ]

    raise ValueError(f"Unknown DHCP scenario: {name}")


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic DHCP PCAPs for local AuditBot testing.")
    parser.add_argument(
        "scenario",
        choices=["normal", "no-offer", "no-ack", "rogue", "pool-exhausted"],
        help="DHCP scenario to generate.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output PCAP path. Defaults to outputs/pcaps/dhcp_<scenario>.pcap.",
    )
    args = parser.parse_args()

    output = Path(args.output or f"outputs/pcaps/dhcp_{args.scenario}.pcap")
    output.parent.mkdir(parents=True, exist_ok=True)

    wrpcap(str(output), build_scenario(args.scenario))
    print(output)


if __name__ == "__main__":
    main()
