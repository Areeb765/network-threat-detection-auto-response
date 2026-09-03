from scapy.all import sniff

def process_packet(packet):
    if packet.haslayer("IP"):
        print("Source IP:", packet["IP"].src)
        print("Destination IP:", packet["IP"].dst)
        print("--------------------")

def main():
    print("Starting network monitor...")
    sniff(prn=process_packet, store=False, count=10)

if __name__ == "__main__":
    main()
