from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import datetime

print("="*60)
print("         BASIC NETWORK SNIFFER")
print("="*60)

packet_count = 0

def analyze_packet(packet):
    global packet_count
    packet_count += 1

    timestamp = datetime.datetime.now().strftime("%H:%M:%S")

    print(f"\n[Packet #{packet_count}] - {timestamp}")
    print("-" * 50)

    # IP Layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        print(f"  Source IP      : {src_ip}")
        print(f"  Destination IP : {dst_ip}")
        print(f"  TTL            : {ip_layer.ttl}")

        # TCP
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"  Protocol       : TCP")
            print(f"  Source Port    : {tcp_layer.sport}")
            print(f"  Dest Port      : {tcp_layer.dport}")
            flags = tcp_layer.flags
            print(f"  TCP Flags      : {flags}")

            # Identify common services
            port = tcp_layer.dport
            if port == 80:
                print(f"  Service        : HTTP (Web Traffic)")
            elif port == 443:
                print(f"  Service        : HTTPS (Secure Web)")
            elif port == 22:
                print(f"  Service        : SSH")
            elif port == 21:
                print(f"  Service        : FTP")
            elif port == 53:
                print(f"  Service        : DNS")

        # UDP
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"  Protocol       : UDP")
            print(f"  Source Port    : {udp_layer.sport}")
            print(f"  Dest Port      : {udp_layer.dport}")

        # ICMP (Ping)
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            print(f"  Protocol       : ICMP (Ping/Traceroute)")
            print(f"  ICMP Type      : {icmp_layer.type}")
            print(f"  ICMP Code      : {icmp_layer.code}")

        else:
            print(f"  Protocol       : Other (Proto #{ip_layer.proto})")

    # Payload
    if Raw in packet:
        raw_data = packet[Raw].load
        try:
            decoded = raw_data.decode("utf-8", errors="replace")
            preview = decoded[:100].replace('\n', ' ').replace('\r', '')
            print(f"  Payload        : {preview}")
        except:
            print(f"  Payload (hex)  : {raw_data[:30].hex()}")

    print("-" * 50)


# --- Main ---
print("\n[*] Starting packet capture...")
print("[*] Press CTRL+C to stop.\n")

try:
    sniff(filter="ip", prn=analyze_packet, store=False, count=0)
except KeyboardInterrupt:
    print(f"\n\n[*] Capture stopped.")
    print(f"[*] Total packets captured: {packet_count}")
    print("="*60)
except PermissionError:
    print("\n[!] ERROR: Run Command Prompt as Administrator!")
    print("[!] Right-click CMD → 'Run as administrator'")
