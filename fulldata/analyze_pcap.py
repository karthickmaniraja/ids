from scapy.all import rdpcap
from collections import Counter

# Path to your saved .pcapng file
pcap_file = r"C:\Users\Ashwi\OneDrive\Desktop\IDS Project\netdata.pcapng"

# Read packets from the .pcapng file
packets = rdpcap(pcap_file)

# Packet analysis
print(f"Total packets captured: {len(packets)}\n")

# Counters for analysis
protocol_counts = Counter()
src_ip_counts = Counter()
dst_ip_counts = Counter()

for packet in packets:
    # Check if the packet has an IP layer
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        proto = packet["IP"].proto  # Protocol (e.g., TCP/UDP)
        
        # Update counts
        src_ip_counts[src_ip] += 1
        dst_ip_counts[dst_ip] += 1
        protocol_counts[proto] += 1

# Display results
print("Top Source IPs:")
for ip, count in src_ip_counts.most_common(5):
    print(f"{ip}: {count} packets")

print("\nTop Destination IPs:")
for ip, count in dst_ip_counts.most_common(5):
    print(f"{ip}: {count} packets")

print("\nProtocol Usage:")
for proto, count in protocol_counts.items():
    print(f"Protocol {proto}: {count} packets")
