from scapy.all import sniff, TCP, UDP

def process_packet(packet):
    if packet.haslayer("IP"):
        print("Source IP:", packet["IP"].src)
        print("Destination IP:", packet["IP"].dst)

        if packet.haslayer(TCP):
            print("Protocol: TCP")
            print("Source Port:", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)

        elif packet.haslayer(UDP):
            print("Protocol: UDP")
            print("Source Port:", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)

        else:
            print("Protocol: Other")

        print("--------------------")

def main():
    print("Starting network monitor...")
    sniff(prn=process_packet, store=False, count=10)

if __name__ == "__main__":
    main()
