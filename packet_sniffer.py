import socket
import struct
import datetime


def get_protocol_name(protocol):
    protocols = {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
    }
    return protocols.get(protocol, f"Other ({protocol})")


def packet_sniffer(packet_count=10):
    """
    Capture basic IPv4 packet metadata.
    Use only on your own machine or an authorized lab network.
    """

    try:
        sniffer = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_IP
        )

        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        sniffer.bind((local_ip, 0))

        # Receive IPv4 headers only.
        sniffer.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_HDRINCL,
            1
        )

        # Receive packets.
        sniffer.ioctl(
            socket.SIO_RCVALL,
            socket.RCVALL_ON
        )

        print("=" * 60)
        print("        PACKET SNIFFER")
        print("=" * 60)
        print(f"Listening on: {local_ip}")
        print(f"Packets to capture: {packet_count}")
        print("-" * 60)

        captured = 0

        while captured < packet_count:

            raw_data, addr = sniffer.recvfrom(65535)

            # IPv4 header
            ip_header = raw_data[0:20]

            iph = struct.unpack(
                "!BBHHHBBH4s4s",
                ip_header
            )

            version_ihl = iph[0]
            ttl = iph[5]
            protocol = iph[6]

            source = socket.inet_ntoa(iph[8])
            destination = socket.inet_ntoa(iph[9])

            timestamp = datetime.datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            captured += 1

            print(f"\nPacket #{captured}")
            print(f"Time        : {timestamp}")
            print(f"Source      : {source}")
            print(f"Destination : {destination}")
            print(f"Protocol    : {get_protocol_name(protocol)}")
            print(f"TTL         : {ttl}")
            print(f"Packet Size : {len(raw_data)} bytes")

        sniffer.ioctl(
            socket.SIO_RCVALL,
            socket.RCVALL_OFF
        )

        sniffer.close()

        print("\n" + "=" * 60)
        print(f"Capture completed: {captured} packets")
        print("=" * 60)

    except PermissionError:
        print("\nERROR: Administrator privileges are required.")
        print("Run PowerShell or VS Code as Administrator.")

    except Exception as e:
        print(f"\nERROR: {e}")


if __name__ == "__main__":
    packet_sniffer(10)