from scapy.all import IP, TCP
from detector import process_packet

test_ports = [21, 22, 23, 80, 443]

for port in test_ports:
    packet = IP(src="10.0.0.50", dst="127.0.0.1") / TCP(
        sport=50000,
        dport=port
    )

    process_packet(packet)
