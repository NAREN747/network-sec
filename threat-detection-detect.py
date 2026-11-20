#!/usr/bin/env python3
"""
Network Threat Detection Engine — Network Security Project (CO4)
Ingests network traffic (PCAP or live), extracts payloads, and matches signatures.

Features:
- TCP stream reassembly for HTTP (ports 80, 443, 8080, 8443)
- Signature matching from YAML (XSS, SQLi, Path Traversal, CMD Injection, Scans, Beaconing)
- JSONL output (SIEM-ready)
- TLS awareness (flags encrypted, doesn't false positive)
"""

import argparse
import json
import re
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    print("Installing pyyaml...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyyaml"])
    import yaml

try:
    from scapy.all import (
        Ether, IP, TCP, UDP, Raw,
        rdpcap, sniff, conf
    )
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.tls.all import TLS
except ImportError:
    print("Installing scapy...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy"])
    from scapy.all import (
        Ether, IP, TCP, UDP, Raw,
        rdpcap, sniff, conf
    )
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.tls.all import TLS


# ================================================================
# DATA CLASSES
# ================================================================

@dataclass
class Signature:
    id: str
    name: str
    pattern: str
    severity: str
    description: str
    category: str
    compiled: re.Pattern = None
    threshold: dict = None

    def __post_init__(self):
        self.compiled = re.compile(self.pattern, re.IGNORECASE | re.DOTALL)


@dataclass
class Alert:
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    category: str
    signature_id: str
    signature_name: str
    severity: str
    description: str
    matched_content: str
    packet_summary: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(',', ':'))


@dataclass
class FlowKey:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port))

    def reverse(self):
        return FlowKey(self.dst_ip, self.src_ip, self.dst_port, self.src_port)


# ================================================================
# SIGNATURE ENGINE
# ================================================================

class SignatureEngine:
    def __init__(self, signatures_path: Path):
        self.signatures = []
        self.categories = defaultdict(list)
        self._load_signatures(signatures_path)

    def _load_signatures(self, path: Path):
        with open(path) as f:
            data = yaml.safe_load(f)

        for category, sigs in data.items():
            for sig_data in sigs:
                # Skip threshold-only signatures (behavioral detection)
                if 'pattern' not in sig_data:
                    continue
                sig = Signature(
                    id=sig_data['id'],
                    name=sig_data['name'],
                    pattern=sig_data['pattern'],
                    severity=sig_data['severity'],
                    description=sig_data['description'],
                    category=category,
                    threshold=sig_data.get('threshold')
                )
                self.signatures.append(sig)
                self.categories[category].append(sig)

        print(f"[+] Loaded {len(self.signatures)} signatures across {len(self.categories)} categories")

    def match(self, payload: str, category_filter: Optional[str] = None) -> list:
        """Match payload against signatures, return list of matched signatures"""
        matches = []
        categories = [category_filter] if category_filter else self.categories.keys()

        for cat in categories:
            for sig in self.categories.get(cat, []):
                match = sig.compiled.search(payload)
                if match:
                    matched_text = match.group(0)[:200]  # Limit length
                    matches.append((sig, matched_text))

        return matches


# ================================================================
# TCP STREAM REASSEMBLY
# ================================================================

class StreamReassembler:
    """Reassembles TCP streams for HTTP payload inspection"""

    def __init__(self, http_ports=None):
        self.http_ports = http_ports or {80, 443, 8080, 8443}
        self.streams = {}  # FlowKey -> bytearray
        self.stream_state = {}  # FlowKey -> dict(seq, ack, established)

    def process_packet(self, pkt) -> Optional[bytes]:
        """Process a packet, return reassembled payload if complete HTTP message"""
        if TCP not in pkt:
            return None

        tcp = pkt[TCP]
        ip = pkt[IP] if IP in pkt else None
        if not ip:
            return None

        # Only reassemble HTTP ports
        if tcp.dport not in self.http_ports and tcp.sport not in self.http_ports:
            return None

        # Skip TLS (port 443/8443) - flag but don't reassemble
        if tcp.dport in {443, 8443} or tcp.sport in {443, 8443}:
            return b"TLS_ENCRYPTED"

        flow_key = FlowKey(ip.src, ip.dst, tcp.sport, tcp.dport)
        rev_key = flow_key.reverse()

        # Initialize stream
        if flow_key not in self.streams:
            self.streams[flow_key] = bytearray()
            self.stream_state[flow_key] = {'syn_seen': False, 'established': False}

        state = self.stream_state[flow_key]
        payload = bytes(tcp.payload) if Raw in tcp else b''

        # Track connection state
        if tcp.flags & 0x02:  # SYN
            state['syn_seen'] = True
            state['seq'] = tcp.seq
        if tcp.flags & 0x10:  # ACK
            if state['syn_seen']:
                state['established'] = True

        # Only reassemble established connections with payload
        if state['established'] and payload:
            self.streams[flow_key].extend(payload)

            # Check for HTTP message completion (double CRLF)
            data = bytes(self.streams[flow_key])
            if b'\r\n\r\n' in data:
                # Found complete HTTP headers, extract up to Content-Length or end
                return self._extract_http_message(flow_key, data)

        return None

    def _extract_http_message(self, flow_key: FlowKey, data: bytes) -> bytes:
        """Extract complete HTTP request/response from stream"""
        header_end = data.find(b'\r\n\r\n')
        if header_end == -1:
            return None

        headers = data[:header_end + 4]
        body_start = header_end + 4

        # Parse Content-Length
        content_length = 0
        for line in headers.split(b'\r\n'):
            if line.lower().startswith(b'content-length:'):
                try:
                    content_length = int(line.split(b':')[1].strip())
                except (ValueError, IndexError):
                    pass

        total_needed = body_start + content_length
        if len(data) >= total_needed:
            # Complete message available
            message = data[:total_needed]
            # Remove consumed bytes from buffer
            self.streams[flow_key] = bytearray(data[total_needed:])
            return message

        return None  # Wait for more data


# ================================================================
# SCAN/BEACON DETECTOR
# ================================================================

class AnomalyDetector:
    """Detects port scans, beaconing, and other behavioral anomalies"""

    def __init__(self):
        self.syn_tracker = defaultdict(lambda: deque(maxlen=1000))  # src_ip -> [(dst_port, timestamp)]
        self.port_sweep_tracker = defaultdict(lambda: deque(maxlen=1000))  # dst_port -> [(src_ip, timestamp)]
        self.connection_tracker = defaultdict(lambda: deque(maxlen=1000))  # dst_ip -> [timestamps]

    def process_packet(self, pkt) -> list:
        alerts = []

        if TCP not in pkt or IP not in pkt:
            return alerts

        tcp = pkt[TCP]
        ip = pkt[IP]
        now = float(pkt.time) if hasattr(pkt, 'time') else time.time()

        # SYN Flood / Port Scan detection
        if tcp.flags & 0x02 and not (tcp.flags & 0x10):  # SYN only, no ACK
            self.syn_tracker[ip.src].append((tcp.dport, now))
            self._check_syn_flood(ip.src, now, alerts)

        # Port Sweep detection (horizontal scan)
        self.port_sweep_tracker[tcp.dport].append((ip.src, now))
        self._check_port_sweep(tcp.dport, now, alerts)

        # Beaconing detection
        self.connection_tracker[ip.dst].append(now)
        self._check_beaconing(ip.src, ip.dst, now, alerts)

        return alerts

    def _check_syn_flood(self, src_ip: str, now: float, alerts: list):
        window = 5.0  # 5 seconds
        cutoff = now - window
        recent = [(p, t) for p, t in self.syn_tracker[src_ip] if t > cutoff]
        unique_ports = set(p for p, t in recent)

        if len(unique_ports) >= 20:
            # Only alert once per source IP (use a flag)
            if not getattr(self, '_syn_flood_alerted', set()):
                self._syn_flood_alerted = set()
            if src_ip not in self._syn_flood_alerted:
                self._syn_flood_alerted.add(src_ip)
                alerts.append(Alert(
                    timestamp=datetime.fromtimestamp(now).isoformat(),
                    src_ip=src_ip,
                    dst_ip="MULTIPLE",
                    src_port=0,
                    dst_port=0,
                    protocol="TCP",
                    category="network_scan",
                    signature_id="syn-flood",
                    signature_name="SYN Flood / Port Scan",
                    severity="high",
                    description=f"{len(unique_ports)} unique destination ports in {window}s",
                    matched_content=f"Ports: {sorted(unique_ports)[:20]}",
                    packet_summary=f"SYN scan from {src_ip}"
                ))

    def _check_port_sweep(self, dst_port: int, now: float, alerts: list):
        window = 10.0
        cutoff = now - window
        recent = [(s, t) for s, t in self.port_sweep_tracker[dst_port] if t > cutoff]
        unique_srcs = set(s for s, t in recent)

        if len(unique_srcs) >= 50:
            alerts.append(Alert(
                timestamp=datetime.fromtimestamp(now).isoformat(),
                src_ip="MULTIPLE",
                dst_ip="MULTIPLE",
                src_port=0,
                dst_port=dst_port,
                protocol="TCP",
                category="network_scan",
                signature_id="port-sweep",
                signature_name="Port Sweep (Horizontal Scan)",
                severity="high",
                description=f"{len(unique_srcs)} unique sources to port {dst_port} in {window}s",
                matched_content=f"Sources: {list(unique_srcs)[:10]}",
                packet_summary=f"Port sweep on port {dst_port}"
            ))

    def _check_beaconing(self, src_ip: str, dst_ip: str, now: float, alerts: list):
        window = 30 * 60  # 30 minutes
        cutoff = now - window
        recent = [t for t in self.connection_tracker[dst_ip] if t > cutoff]

        if len(recent) >= 6:
            # Check interval regularity
            intervals = [recent[i+1] - recent[i] for i in range(len(recent)-1)]
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
            variance_pct = (variance ** 0.5 / avg_interval) * 100 if avg_interval > 0 else 100

            if variance_pct <= 10:  # Within 10% variance
                alerts.append(Alert(
                    timestamp=datetime.fromtimestamp(now).isoformat(),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=0,
                    dst_port=0,
                    protocol="TCP",
                    category="beaconing",
                    signature_id="regular-beacon",
                    signature_name="Regular Interval Beaconing",
                    severity="high",
                    description=f"Regular connections every {avg_interval:.1f}s (±{variance_pct:.1f}%)",
                    matched_content=f"Intervals: {[f'{i:.1f}' for i in intervals[:5]]}",
                    packet_summary=f"Possible C2 beacon {src_ip} -> {dst_ip}"
                ))


# ================================================================
# MAIN DETECTION ENGINE
# ================================================================

class ThreatDetector:
    def __init__(self, signatures_path: Path, output_jsonl: bool = True):
        self.signature_engine = SignatureEngine(signatures_path)
        self.stream_reassembler = StreamReassembler()
        self.anomaly_detector = AnomalyDetector()
        self.output_jsonl = output_jsonl
        self.alerts = []
        self.packet_count = 0
        self.tls_count = 0

    def process_pcap(self, pcap_path: Path):
        """Process packets from a PCAP file"""
        print(f"[+] Reading PCAP: {pcap_path}")
        packets = rdpcap(str(pcap_path))
        print(f"[+] Loaded {len(packets)} packets")

        for pkt in packets:
            self.process_packet(pkt)

        self._print_summary()

    def process_live(self, interface: str, count: int = 0):
        """Process live packets from interface"""
        print(f"[+] Starting live capture on {interface}")
        sniff(iface=interface, prn=self.process_packet, store=0, count=count)
        self._print_summary()

    def process_packet(self, pkt):
        self.packet_count += 1

        # Anomaly detection (scan/beacon)
        anomaly_alerts = self.anomaly_detector.process_packet(pkt)
        for alert in anomaly_alerts:
            self._emit_alert(alert)

        # Skip non-IP
        if IP not in pkt:
            return

        ip = pkt[IP]
        # Convert scapy EDecimal time to float
        pkt_time = float(pkt.time) if hasattr(pkt, 'time') else time.time()

        # TCP Stream Reassembly + Signature Matching
        if TCP in pkt:
            reassembled = self.stream_reassembler.process_packet(pkt)

            if reassembled == b"TLS_ENCRYPTED":
                self.tls_count += 1
                # Still analyze the raw payload for TLS packets (for SNI, etc)
                raw_payload = bytes(pkt[TCP].payload) if Raw in pkt[TCP] else b''
                if raw_payload:
                    self._analyze_payload(raw_payload, pkt, pkt_time)
                return

            if reassembled:
                self._analyze_payload(reassembled, pkt, pkt_time)
            else:
                # Also check raw payload for packets that don't complete HTTP messages
                raw_payload = bytes(pkt[TCP].payload) if Raw in pkt[TCP] else b''
                if raw_payload:
                    self._analyze_payload(raw_payload, pkt, pkt_time)

        # UDP (DNS, etc.)
        elif UDP in pkt:
            udp = pkt[UDP]
            payload = bytes(udp.payload) if Raw in udp else b''
            if payload:
                self._analyze_payload(payload, pkt, pkt_time)

    def _analyze_payload(self, payload: bytes, pkt, pkt_time: float):
        """Analyze payload against signatures"""
        try:
            # Decode payload (handle various encodings)
            text = self._decode_payload(payload)
            if not text:
                return

            # URL decode for evasion detection
            from urllib.parse import unquote
            text_decoded = unquote(text)

            # Match signatures
            matches = self.signature_engine.match(text)
            matches += self.signature_engine.match(text_decoded)

            # Deduplicate by signature_id + src_ip + dst_ip + matched_content
            seen = set()
            for sig, matched_content in matches:
                key = (sig.id, pkt[IP].src, pkt[IP].dst, matched_content[:50])
                if key in seen:
                    continue
                seen.add(key)

                alert = Alert(
                    timestamp=datetime.fromtimestamp(pkt_time).isoformat(),
                    src_ip=pkt[IP].src,
                    dst_ip=pkt[IP].dst,
                    src_port=pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0),
                    dst_port=pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0),
                    protocol="TCP" if TCP in pkt else "UDP",
                    category=sig.category,
                    signature_id=sig.id,
                    signature_name=sig.name,
                    severity=sig.severity,
                    description=sig.description,
                    matched_content=matched_content,
                    packet_summary=f"{pkt[IP].src}:{pkt[TCP].sport if TCP in pkt else pkt[UDP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport if TCP in pkt else pkt[UDP].dport}"
                )
                self._emit_alert(alert)

        except Exception as e:
            pass  # Silently skip decode errors

    def _decode_payload(self, payload: bytes) -> str:
        """Try multiple decodings"""
        for encoding in ['utf-8', 'latin-1', 'ascii']:
            try:
                return payload.decode(encoding)
            except UnicodeDecodeError:
                continue
        return payload.decode('utf-8', errors='ignore')

    def _emit_alert(self, alert: Alert):
        self.alerts.append(alert)
        if self.output_jsonl:
            print(alert.to_json())

    def _print_summary(self):
        print(f"\n[+] Processing complete")
        print(f"    Packets processed: {self.packet_count}")
        print(f"    TLS encrypted flows: {self.tls_count}")
        print(f"    Alerts generated: {len(self.alerts)}")

        # Summary by severity
        by_severity = defaultdict(int)
        for a in self.alerts:
            by_severity[a.severity] += 1
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            if by_severity[sev]:
                print(f"    {sev.capitalize()}: {by_severity[sev]}")


# ================================================================
# TEST PCAP GENERATOR
# ================================================================

def generate_test_pcap(output_path: Path):
    """Generate a test PCAP with known attack payloads"""
    from scapy.all import Ether, IP, TCP, Raw, wrpcap

    print(f"[+] Generating test PCAP: {output_path}")

    # Fixed MAC addresses to avoid ARP resolution delays
    SRC_MAC = "00:0c:29:aa:bb:cc"
    DST_MAC = "00:0c:29:dd:ee:ff"
    ATTACKER_MAC = "00:0c:29:11:22:33"

    packets = []

    # Normal HTTP
    packets.append(Ether(src=SRC_MAC, dst=DST_MAC)/
                   IP(src="10.10.10.50", dst="10.10.20.10")/
                   TCP(sport=54321, dport=80, flags="PA", seq=1001)/
                   Raw(b"GET /index.html HTTP/1.1\r\nHost: web1.dmz.local\r\n\r\n"))

    # XSS: <script>alert(1)</script>
    packets.append(Ether(src=SRC_MAC, dst=DST_MAC)/
                   IP(src="10.10.10.51", dst="10.10.20.10")/
                   TCP(sport=54322, dport=80, flags="PA", seq=2001)/
                   Raw(b"GET /search?q=<script>alert(1)</script> HTTP/1.1\r\nHost: web1.dmz.local\r\n\r\n"))

    # XSS: onerror
    packets.append(Ether(src=SRC_MAC, dst=DST_MAC)/
                   IP(src="10.10.10.52", dst="10.10.20.10")/
                   TCP(sport=54323, dport=80, flags="PA", seq=3001)/
                   Raw(b"GET /?img=<img src=x onerror=alert(1)> HTTP/1.1\r\nHost: web1.dmz.local\r\n\r\n"))

    # XSS: URL encoded
    packets.append(Ether(src=SRC_MAC, dst=DST_MAC)/
                   IP(src="10.10.10.53", dst="10.10.20.10")/
                   TCP(sport=54324, dport=80, flags="PA", seq=4001)/
                   Raw(b"GET /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\r\nHost: web1.dmz.local\r\n\r\n"))

    # XSS: javascript: protocol
    packets.append(Ether(src=SRC_MAC, dst=DST_MAC)/
                   IP(src="10.10.10.53", dst="10.10.20.10")/
                   TCP(sport=54324, dport=80, flags="PA", seq=4002)/
                   Raw(b"GET /?url=javascript:alert(1) HTTP/1.1\r\nHost: web1.dmz.local\r\n\r\n"))

    # SQLi: ' OR '1'='1
    packets.append(Ether(src=SRC_MAC, dst=DST_MAC)/
                   IP(src="10.10.10.54", dst="10.10.20.10")/
                   TCP(sport=54325, dport=80, flags="PA", seq=5001)/
                   Raw(b"POST /login HTTP/1.1\r\nHost: web1.dmz.local\r\nContent-Length: 27\r\n\r\nuser=admin' OR '1'='1&pass=x"))

    # SQLi: UNION SELECT
    packets.append(Ether(src=SRC_MAC, dst=DST_MAC)/
                   IP(src="10.10.10.55", dst="10.10.20.10")/
                   TCP(sport=54326, dport=80, flags="PA", seq=6001)/
                   Raw(b"GET /products?id=1 UNION SELECT username,password FROM users HTTP/1.1\r\nHost: web1.dmz.local\r\n\r\n"))

    # Path Traversal: ../etc/passwd
    packets.append(Ether(src=SRC_MAC, dst=DST_MAC)/
                   IP(src="10.10.10.56", dst="10.10.20.10")/
                   TCP(sport=54327, dport=80, flags="PA", seq=7001)/
                   Raw(b"GET /download?file=../../../etc/passwd HTTP/1.1\r\nHost: web1.dmz.local\r\n\r\n"))

    # Command Injection: ; cat /etc/passwd
    packets.append(Ether(src=SRC_MAC, dst=DST_MAC)/
                   IP(src="10.10.10.57", dst="10.10.20.10")/
                   TCP(sport=54328, dport=80, flags="PA", seq=8001)/
                   Raw(b"GET /ping?host=8.8.8.8;cat+/etc/passwd HTTP/1.1\r\nHost: web1.dmz.local\r\n\r\n"))

    # Port Scan: SYN packets to many ports (from attacker)
    for i, port in enumerate(range(1, 25)):
        packets.append(Ether(src=ATTACKER_MAC, dst=DST_MAC)/
                       IP(src="203.0.113.200", dst="10.10.20.10")/
                       TCP(sport=12345+i, dport=port, flags="S", seq=10000+i))

    wrpcap(str(output_path), packets)
    print(f"[+] Test PCAP written with {len(packets)} packets")


# ================================================================
# MAIN
# ================================================================

def main():
    parser = argparse.ArgumentParser(description="Network Threat Detection Engine (CO4)")
    parser.add_argument("--pcap", "-p", help="Input PCAP file to analyze")
    parser.add_argument("--live", "-l", help="Live capture interface")
    parser.add_argument("--count", "-c", type=int, default=0, help="Packet count for live capture (0=infinite)")
    parser.add_argument("--signatures", "-s", default="threat-detection/signatures.yaml", help="Signatures YAML file")
    parser.add_argument("--generate-test", "-g", action="store_true", help="Generate test PCAP")
    parser.add_argument("--output", "-o", help="Output test PCAP path")
    parser.add_argument("--no-jsonl", action="store_true", help="Disable JSONL output")

    args = parser.parse_args()

    sig_path = Path(args.signatures)
    if not sig_path.exists():
        print(f"[-] Signatures file not found: {sig_path}")
        sys.exit(1)

    if args.generate_test:
        out_path = Path(args.output) if args.output else Path("threat-detection/test.pcapng")
        generate_test_pcap(out_path)
        return

    detector = ThreatDetector(sig_path, output_jsonl=not args.no_jsonl)

    if args.pcap:
        detector.process_pcap(Path(args.pcap))
    elif args.live:
        detector.process_live(args.live, args.count)
    else:
        parser.print_help()
        print("\nExample:")
        print("  python detect.py --pcap threat-detection/test.pcapng")
        print("  python detect.py --generate-test --output threat-detection/test.pcapng")


if __name__ == "__main__":
    main()