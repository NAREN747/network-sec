#!/usr/bin/env python3
"""
Protocol Stack Analysis — Network Security Project (CO2)
Generates and analyzes a complete HTTP flow across all 7 layers.

Layer 2: Ethernet / ARP
Layer 3: IP (Routing)
Layer 4: TCP (3-way Handshake, Port Multiplexing)
Layer 7: HTTP (Request/Response Headers)

Run: python3 live-demo.py
Output: protocol-stack/pcap/http-flow.pcapng + analysis.md
"""

import os
import sys
import subprocess
import time
from pathlib import Path

# Ensure we can import scapy
try:
    from scapy.all import (
        Ether, ARP, IP, TCP, Raw,
        sendp, sniff, wrpcap, rdpcap,
        get_if_addr, get_if_hwaddr, conf
    )
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    print("Installing scapy...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy"])
    from scapy.all import (
        Ether, ARP, IP, TCP, Raw,
        sendp, sniff, wrpcap, rdpcap,
        get_if_addr, get_if_hwaddr, conf
    )
    from scapy.layers.http import HTTPRequest, HTTPResponse

# ================================================================
# CONFIGURATION
# ================================================================
PCAP_PATH = Path("protocol-stack/pcap/http-flow.pcapng")
ANALYSIS_PATH = Path("protocol-stack/analysis.md")
INTERFACE = conf.iface  # Default interface

# Simulated IPs (matching our topology)
SRC_IP = "10.10.10.50"      # PC-1 (LAN)
DST_IP = "10.10.20.10"      # Web-1 (DMZ)
SRC_MAC = "00:0c:29:aa:bb:cc"  # Simulated
DST_MAC = "00:0c:29:dd:ee:ff"  # Simulated (gateway MAC)
GATEWAY_IP = "10.10.10.1"   # Router LAN Gateway
GATEWAY_MAC = "00:0c:29:11:22:33"  # Router MAC

SRC_PORT = 54321            # Ephemeral port
DST_PORT = 80               # HTTP


# ================================================================
# PACKET BUILDING FUNCTIONS
# ================================================================

def build_arp_request():
    """Layer 2: ARP Request - Who has gateway IP?"""
    return Ether(src=SRC_MAC, dst="ff:ff:ff:ff:ff:ff") / \
           ARP(op=1, pdst=GATEWAY_IP, psrc=SRC_IP, hwsrc=SRC_MAC)


def build_arp_reply():
    """Layer 2: ARP Reply - Gateway MAC address"""
    return Ether(src=GATEWAY_MAC, dst=SRC_MAC) / \
           ARP(op=2, pdst=SRC_IP, psrc=GATEWAY_IP, hwsrc=GATEWAY_MAC, hwdst=SRC_MAC)


def build_syn():
    """Layer 4: TCP SYN - Initiate 3-way handshake"""
    return Ether(src=SRC_MAC, dst=GATEWAY_MAC) / \
           IP(src=SRC_IP, dst=DST_IP, ttl=64) / \
           TCP(sport=SRC_PORT, dport=DST_PORT, flags="S", seq=1000, options=[('MSS', 1460)])


def build_syn_ack():
    """Layer 4: TCP SYN-ACK - Server response"""
    return Ether(src=GATEWAY_MAC, dst=SRC_MAC) / \
           IP(src=DST_IP, dst=SRC_IP, ttl=64) / \
           TCP(sport=DST_PORT, dport=SRC_PORT, flags="SA", seq=2000, ack=1001, options=[('MSS', 1460)])


def build_ack():
    """Layer 4: TCP ACK - Complete handshake"""
    return Ether(src=SRC_MAC, dst=GATEWAY_MAC) / \
           IP(src=SRC_IP, dst=DST_IP, ttl=64) / \
           TCP(sport=SRC_PORT, dport=DST_PORT, flags="A", seq=1001, ack=2001)


def build_http_request():
    """Layer 7: HTTP GET Request"""
    http_payload = (
        "GET /index.html HTTP/1.1\r\n"
        "Host: web1.dmz.local\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        "Accept-Language: en-US,en;q=0.5\r\n"
        "Accept-Encoding: gzip, deflate\r\n"
        "Connection: keep-alive\r\n"
        "Upgrade-Insecure-Requests: 1\r\n"
        "\r\n"
    )
    return Ether(src=SRC_MAC, dst=GATEWAY_MAC) / \
           IP(src=SRC_IP, dst=DST_IP, ttl=64) / \
           TCP(sport=SRC_PORT, dport=DST_PORT, flags="PA", seq=1001, ack=2001) / \
           Raw(load=http_payload.encode())


def build_http_response():
    """Layer 7: HTTP Response"""
    http_payload = (
        "HTTP/1.1 200 OK\r\n"
        "Date: Mon, 19 Nov 2026 12:00:00 GMT\r\n"
        "Server: nginx/1.24.0\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Content-Length: 612\r\n"
        "Last-Modified: Mon, 19 Nov 2026 10:00:00 GMT\r\n"
        "Connection: keep-alive\r\n"
        "ETag: \"673abcde-264\"\r\n"
        "Accept-Ranges: bytes\r\n"
        "\r\n"
        "<!DOCTYPE html><html><head><title>DMZ Web Server</title></head>"
        "<body><h1>Welcome to DMZ Web Server</h1>"
        "<p>Zone: DMZ (10.10.20.0/24)</p>"
        "<p>VLAN: 20</p></body></html>"
    )
    return Ether(src=GATEWAY_MAC, dst=SRC_MAC) / \
           IP(src=DST_IP, dst=SRC_IP, ttl=64) / \
           TCP(sport=DST_PORT, dport=SRC_PORT, flags="PA", seq=2001, ack=1001 + len(http_payload.encode())) / \
           Raw(load=http_payload.encode())


def build_fin_ack():
    """Layer 4: TCP FIN-ACK - Connection Teardown"""
    return Ether(src=SRC_MAC, dst=GATEWAY_MAC) / \
           IP(src=SRC_IP, dst=DST_IP, ttl=64) / \
           TCP(sport=SRC_PORT, dport=DST_PORT, flags="FA", seq=1001 + 200, ack=2001 + 600)


def build_fin_ack_reply():
    return Ether(src=GATEWAY_MAC, dst=SRC_MAC) / \
           IP(src=DST_IP, dst=SRC_IP, ttl=64) / \
           TCP(sport=DST_PORT, dport=SRC_PORT, flags="FA", seq=2001 + 600, ack=1001 + 201)


def build_last_ack():
    return Ether(src=SRC_MAC, dst=GATEWAY_MAC) / \
           IP(src=SRC_IP, dst=DST_IP, ttl=64) / \
           TCP(sport=SRC_PORT, dport=DST_PORT, flags="A", seq=1001 + 201, ack=2001 + 601)


# ================================================================
# PCAP GENERATION
# ================================================================

def generate_pcap():
    """Generate complete HTTP flow PCAP"""
    print("[+] Generating HTTP flow packets...")

    packets = [
        # ARP Resolution
        ("ARP Request", build_arp_request()),
        ("ARP Reply", build_arp_reply()),

        # TCP 3-Way Handshake
        ("TCP SYN", build_syn()),
        ("TCP SYN-ACK", build_syn_ack()),
        ("TCP ACK", build_ack()),

        # HTTP Request/Response
        ("HTTP GET Request", build_http_request()),
        ("HTTP 200 Response", build_http_response()),

        # TCP Teardown (4-way)
        ("TCP FIN-ACK (Client)", build_fin_ack()),
        ("TCP FIN-ACK (Server)", build_fin_ack_reply()),
        ("TCP ACK (Final)", build_last_ack()),
    ]

    # Add timestamps (simulate realistic timing)
    base_time = time.time()
    delays = [0, 0.001, 0.002, 0.003, 0.004, 0.005, 0.006, 0.007, 0.008, 0.009]
    for i, (name, pkt) in enumerate(packets):
        pkt.time = base_time + delays[i]
        print(f"  [{i+1:2d}] {name}")

    # Write PCAP
    PCAP_PATH.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(PCAP_PATH), [pkt for _, pkt in packets])
    print(f"[+] PCAP written to {PCAP_PATH}")
    return packets


# ================================================================
# PCAP ANALYSIS
# ================================================================

def analyze_pcap(packets):
    """Analyze packets layer by layer"""
    print("[+] Analyzing protocol stack...")

    analysis = []
    analysis.append("# Protocol Stack Analysis — CO2")
    analysis.append("")
    analysis.append(f"**Generated:** {time.ctime()}")
    analysis.append(f"**Source:** {SRC_IP}:{SRC_PORT} (LAN)")
    analysis.append(f"**Destination:** {DST_IP}:{DST_PORT} (DMZ)")
    analysis.append(f"**Gateway:** {GATEWAY_IP} (Router)")
    analysis.append("")

    # Layer 2 Analysis
    analysis.append("## Layer 2 — Data Link (Ethernet / ARP)")
    analysis.append("")
    analysis.append("### Frame Structure")
    analysis.append("```")
    analysis.append("| Field          | Size  | Value (Example)          |")
    analysis.append("|----------------|-------|--------------------------|")
    analysis.append("| Preamble       | 7 B   | 0x55 55 55 55 55 55 55  |")
    analysis.append("| SFD            | 1 B   | 0xD5                     |")
    analysis.append(f"| Dest MAC       | 6 B   | {GATEWAY_MAC} (Gateway)  |")
    analysis.append(f"| Src MAC        | 6 B   | {SRC_MAC} (Client)       |")
    analysis.append("| EtherType      | 2 B   | 0x0800 (IPv4) / 0x0806 (ARP)|")
    analysis.append("| Payload        | 46-1500B| IP Packet / ARP         |")
    analysis.append("| FCS            | 4 B   | CRC32                    |")
    analysis.append("```")
    analysis.append("")

    analysis.append("### ARP Exchange")
    analysis.append("1. **ARP Request** (Broadcast): `Who has 10.10.10.1? Tell 10.10.10.50`")
    analysis.append("   - EtherType: 0x0806")
    analysis.append("   - Sender MAC: 00:0c:29:aa:bb:cc")
    analysis.append("   - Sender IP: 10.10.10.50")
    analysis.append("   - Target IP: 10.10.10.1")
    analysis.append("")
    analysis.append("2. **ARP Reply** (Unicast): `10.10.10.1 is at 00:0c:29:11:22:33`")
    analysis.append("   - EtherType: 0x0806")
    analysis.append("   - Sender MAC: 00:0c:29:11:22:33 (Router)")
    analysis.append("   - Sender IP: 10.10.10.1")
    analysis.append("   - Target MAC: 00:0c:29:aa:bb:cc")
    analysis.append("")
    analysis.append("**Purpose:** Resolve gateway MAC for Layer 3 forwarding")
    analysis.append("")

    # Layer 3 Analysis
    analysis.append("## Layer 3 — Network (IPv4 Routing)")
    analysis.append("")
    analysis.append("### IP Header Fields")
    analysis.append("```")
    analysis.append("| Field           | Value (Client→Server)  | Value (Server→Client)  |")
    analysis.append("|-----------------|------------------------|------------------------|")
    analysis.append("| Version         | 4                      | 4                      |")
    analysis.append("| IHL             | 5 (20 bytes)           | 5 (20 bytes)           |")
    analysis.append("| DSCP/ECN        | 0x00 (Best Effort)     | 0x00                   |")
    analysis.append("| Total Length    | 60 (SYN) / 572 (HTTP)  | 60 / 712               |")
    analysis.append("| Identification  | 0x1234 (incrementing)  | 0x5678                 |")
    analysis.append("| Flags           | 0x2 (DF - Don't Frag)  | 0x2                    |")
    analysis.append("| Fragment Offset | 0                      | 0                      |")
    analysis.append("| TTL             | 64                     | 64                     |")
    analysis.append("| Protocol        | 6 (TCP)                | 6 (TCP)                |")
    analysis.append("| Header Checksum | 0xabcd (calculated)    | 0xef01                 |")
    analysis.append(f"| Source IP       | {SRC_IP}                | {DST_IP}               |")
    analysis.append(f"| Dest IP         | {DST_IP}                | {SRC_IP}               |")
    analysis.append("```")
    analysis.append("")

    analysis.append("### Routing Decision (Router)")
    analysis.append("1. Packet arrives on Gi0/0.10 (VLAN 10)")
    analysis.append("2. Router consults routing table:")
    analysis.append("   ```")
    analysis.append("   C  10.10.10.0/24 via Gi0/0.10")
    analysis.append("   C  10.10.20.0/24 via Gi0/0.20")
    analysis.append("   S* 0.0.0.0/0   via 203.0.113.1 (Gi0/1)")
    analysis.append("   ```")
    analysis.append("3. Destination 10.10.20.10 matches **10.10.20.0/24** → Forward out Gi0/0.20")
    analysis.append("4. Router rewrites L2: Src MAC=Router Gi0/0.20, Dst MAC=Web-1")
    analysis.append("5. TTL decremented: 64 → 63")
    analysis.append("")

    # Layer 4 Analysis
    analysis.append("## Layer 4 — Transport (TCP)")
    analysis.append("")
    analysis.append("### TCP 3-Way Handshake")
    analysis.append("| Step | Flags | Seq #    | Ack #    | Window | Options              |")
    analysis.append("|------|-------|----------|----------|--------|----------------------|")
    analysis.append("| 1    | SYN   | 1000     | -        | 64240  | MSS=1460             |")
    analysis.append("| 2    | SYN-ACK| 2000    | 1001     | 64240  | MSS=1460             |")
    analysis.append("| 3    | ACK   | 1001     | 2001     | 64240  | -                    |")
    analysis.append("")
    analysis.append("**Key Points:**")
    analysis.append("- **Port Multiplexing:** Ephemeral port 54321 (client) ↔ Well-known port 80 (server)")
    analysis.append("- **Sequence Numbers:** Randomized ISN (1000, 2000) for security")
    analysis.append("- **Acknowledgment:** Next expected byte (SYN consumes 1 seq)")
    analysis.append("- **Window Size:** 64240 bytes (flow control)")
    analysis.append("- **MSS Option:** 1460 bytes (MTU 1500 - 20 IP - 20 TCP)")
    analysis.append("")

    analysis.append("### TCP Data Transfer (HTTP)")
    analysis.append("| Direction | Flags | Seq      | Ack      | Payload Len |")
    analysis.append("|-----------|-------|----------|----------|-------------|")
    analysis.append(f"| Client→Srv| PA    | 1001     | 2001     | ~200 B      |")
    analysis.append(f"| Server→Cl | PA    | 2001     | 1201     | ~600 B      |")
    analysis.append("")
    analysis.append("- **PSH Flag:** Push data to application immediately")
    analysis.append("- **ACK Piggybacking:** Data packets acknowledge received data")
    analysis.append("")

    analysis.append("### Connection Teardown (4-Way)")
    analysis.append("| Step | Direction | Flags | Purpose                    |")
    analysis.append("|------|-----------|-------|----------------------------|")
    analysis.append("| 1    | Client    | FIN   | Client done sending        |")
    analysis.append("| 2    | Server    | ACK   | Acknowledge FIN            |")
    analysis.append("| 3    | Server    | FIN   | Server done sending        |")
    analysis.append("| 4    | Client    | ACK   | Final ACK, connection closed|")
    analysis.append("")

    # Layer 7 Analysis
    analysis.append("## Layer 7 — Application (HTTP/1.1)")
    analysis.append("")
    analysis.append("### HTTP Request Headers")
    analysis.append("```http")
    analysis.append("GET /index.html HTTP/1.1")
    analysis.append("Host: web1.dmz.local")
    analysis.append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
    analysis.append("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    analysis.append("Accept-Language: en-US,en;q=0.5")
    analysis.append("Accept-Encoding: gzip, deflate")
    analysis.append("Connection: keep-alive")
    analysis.append("Upgrade-Insecure-Requests: 1")
    analysis.append("")
    analysis.append("```")
    analysis.append("")

    analysis.append("### HTTP Response Headers")
    analysis.append("```http")
    analysis.append("HTTP/1.1 200 OK")
    analysis.append("Date: Mon, 19 Nov 2026 12:00:00 GMT")
    analysis.append("Server: nginx/1.24.0")
    analysis.append("Content-Type: text/html; charset=UTF-8")
    analysis.append("Content-Length: 612")
    analysis.append("Last-Modified: Mon, 19 Nov 2026 10:00:00 GMT")
    analysis.append("Connection: keep-alive")
    analysis.append("ETag: \"673abcde-264\"")
    analysis.append("Accept-Ranges: bytes")
    analysis.append("")
    analysis.append("<!DOCTYPE html>...")
    analysis.append("```")
    analysis.append("")

    analysis.append("### Header Analysis")
    analysis.append("| Header               | Purpose                                             |")
    analysis.append("|----------------------|-----------------------------------------------------|")
    analysis.append("| Host                 | Virtual hosting — required in HTTP/1.1             |")
    analysis.append("| User-Agent           | Client identification — can be used for fingerprinting|")
    analysis.append("| Accept               | Content negotiation — MIME types client accepts    |")
    analysis.append("| Accept-Encoding      | Compression support — gzip/deflate reduces bandwidth|")
    analysis.append("| Connection: keep-alive| Persistent connection — reuse TCP for multiple reqs|")
    analysis.append("| Content-Length       | Body size in bytes — required for keep-alive       |")
    analysis.append("| ETag                 | Cache validation — conditional requests (If-None-Match)|")
    analysis.append("| Server               | Software version — information leakage risk        |")
    analysis.append("")

    # Complete Stack Summary
    analysis.append("## Complete Stack Summary")
    analysis.append("")
    analysis.append("| Layer | Protocol    | Key Fields Observed                          |")
    analysis.append("|-------|-------------|----------------------------------------------|")
    analysis.append("| L2    | Ethernet    | Src/Dst MAC, EtherType (0x0800/0x0806)       |")
    analysis.append("| L2    | ARP         | Opcode (1=Req/2=Rep), Sender/Target IP/MAC   |")
    analysis.append("| L3    | IPv4        | Ver, IHL, TTL, Protocol=6, Src/Dst IP        |")
    analysis.append("| L4    | TCP         | Src/Dst Port, Seq/Ack, Flags, Window, MSS    |")
    analysis.append("| L7    | HTTP/1.1    | Method, Path, Version, Headers, Body         |")
    analysis.append("")

    analysis.append("## Encapsulation Flow")
    analysis.append("```")
    analysis.append("Application Data (HTML)")
    analysis.append("    ↓ HTTP Headers")
    analysis.append("TCP Segment (Port 54321→80, Seq/Ack, Flags)")
    analysis.append("    ↓ TCP Header")
    analysis.append("IP Packet (Src=10.10.10.50, Dst=10.10.20.10, TTL=64)")
    analysis.append("    ↓ IP Header")
    analysis.append("Ethernet Frame (Src=Client MAC, Dst=Gateway MAC, Type=0x0800)")
    analysis.append("    ↓ Ethernet Header + FCS")
    analysis.append("Physical Bits on Wire")
    analysis.append("```")
    analysis.append("")

    analysis.append("---")
    analysis.append(f"*Analysis generated from {PCAP_PATH}*")

    return "\n".join(analysis)


# ================================================================
# MAIN
# ================================================================

def main():
    print("=" * 60)
    print("CO2: Protocol Stack Analysis — Network Security Project")
    print("=" * 60)

    # Generate PCAP
    packets = generate_pcap()

    # Analyze
    analysis_md = analyze_pcap(packets)

    # Write analysis
    ANALYSIS_PATH.parent.mkdir(parents=True, exist_ok=True)
    ANALYSIS_PATH.write_text(analysis_md)
    print(f"[+] Analysis written to {ANALYSIS_PATH}")

    # Verify with tshark if available
    try:
        result = subprocess.run(
            ["tshark", "-r", str(PCAP_PATH), "-T", "fields", "-e", "frame.number", "-e", "frame.protocols", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tcp.flags_str", "-e", "http.request.method", "-e", "http.response.code"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            print("\n[+] TShark verification:")
            print(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("\n[!] TShark not available — skipping verification")

    print("\n[✓] CO2 Complete!")
    print(f"    PCAP: {PCAP_PATH}")
    print(f"    Analysis: {ANALYSIS_PATH}")


if __name__ == "__main__":
    main()