from scapy.all import sniff, TCP, UDP

packet_counts = {}
ports_seen = {}

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
            print("Protocol: TCP")
            print("Source Port:", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)

            ports_seen[source_ip].add(packet[TCP].dport)

        elif packet.haslayer(UDP):
            print("Protocol: UDP")
            print("Source Port:", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)

            ports_seen[source_ip].add(packet[UDP].dport)

        else:
            print("Protocol: Other")

        print("Packets seen from this IP:", packet_counts[source_ip])
        print("Destination ports seen from this IP:", ports_seen[source_ip])
        print("--------------------")

def main():

    print("Starting network monitor...")

    sniff(prn=process_packet, store=False, count=10)

if __name__ == "__main__":

    main()
