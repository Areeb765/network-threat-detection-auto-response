from scapy.all import sniff

def process_packet(packet):
    print(packet.summary())

def main():
    print("Starting network monitor...")
    sniff(prn=process_packet, store=False, count=10)

if __name__ == "__main__":
    main()
