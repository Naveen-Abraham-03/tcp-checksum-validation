from scapy.all import rdpcap, TCP, IP, raw

packets = rdpcap(r"C:\Users\tacti\Downloads\2024-08-15-traffic-analysis-exercise.pcap\my_capture.pcapng")

for i, pkt in enumerate(packets):
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        original = pkt[TCP].chksum

        # Remove checksum to force recalculation
        del pkt[TCP].chksum
        rebuilt = pkt.__class__(raw(pkt))
        calculated = rebuilt[TCP].chksum

        if original == calculated:
            print(f"Packet {i}: Original={hex(original)}, Calculated={hex(calculated)} -> CORRECT")
        else:
            print(f"Packet {i}: Original={hex(original)}, Calculated={hex(calculated)} -> INCORRECT")
