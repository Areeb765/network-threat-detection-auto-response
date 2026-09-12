from scapy.all import sniff, TCP, UDP
from datetime import datetime

packet_counts = {}
ports_seen = {}

PORT_SCAN_THRESHOLD = 5


def log_threat(source_ip, threat_type):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open("logs/threats.log", "a") as log_file:
        log_file.write(
            f"[{timestamp}] {threat_type} | Source IP: {source_ip}\n"
        )


def process_packet(packet):

    if packet.haslayer("IP"):

        source_ip = packet["IP"].src
        destination_ip = packet["IP"].dst

        if source_ip in packet_counts:
            packet_counts[source_ip] += 1
        else:
            packet_counts[source_ip] = 1

        if source_ip not in ports_seen:
            ports_seen[source_ip] = set()

        print("Source IP:", source_ip)
        print("Destination IP:", destination_ip)

        if packet.haslayer(TCP):
            destination_port = packet[TCP].dport

            print("Protocol: TCP")
            print("Source Port:", packet[TCP].sport)
            print("Destination Port:", destination_port)

            ports_seen[source_ip].add(destination_port)

        elif packet.haslayer(UDP):
            destination_port = packet[UDP].dport

            print("Protocol: UDP")
            print("Source Port:", packet[UDP].sport)
            print("Destination Port:", destination_port)

            ports_seen[source_ip].add(destination_port)

        else:
            print("Protocol: Other")

        print("Packets seen from this IP:", packet_counts[source_ip])
        print("Destination ports seen from this IP:", ports_seen[source_ip])

        if len(ports_seen[source_ip]) >= PORT_SCAN_THRESHOLD:
            print("WARNING: Possible port scan detected from", source_ip)
            log_threat(source_ip, "Possible Port Scan")

        print("--------------------")


def main():

    print("Starting network monitor...")

    sniff(prn=process_packet, store=False, count=10)


if __name__ == "__main__":

    main()
