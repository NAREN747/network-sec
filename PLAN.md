# Network Security Project - Implementation Plan

## Project Overview
Four-course outcome (CO) deliverables covering perimeter architecture, protocol stack analysis, router configuration, and threat detection.

---

## CO1: Perimeter Architecture (LAN / DMZ / Internet)

### Deliverables
- `architecture/diagram.svg` - Visual topology (dark-themed SVG via architecture-diagram skill)
- `architecture/subnetting.md` - IP plan, VLAN IDs, routing table
- `architecture/zone-policy.md` - Allowed/denied traffic matrix between zones

### Implementation Approach
1. **Subnetting Design** (RFC 1918 private space):
   - LAN (Employees): `10.10.10.0/24` — VLAN 10
   - DMZ (Public Web): `10.10.20.0/24` — VLAN 20
   - Mgmt/Router: `10.10.0.0/24` — VLAN 99 (router-on-a-stick)
   - ISP/Internet: `203.0.113.0/24` (TEST-NET-3, RFC 5737)

2. **VLAN Segmentation**:
   - Access ports: VLAN 10 (employee PCs), VLAN 20 (web servers)
   - Trunk port: Router sub-interfaces (RoAS) for inter-VLAN routing
   - Native VLAN 99 unused for security

3. **Zone Policy Matrix**:
   | Source → Dest | LAN | DMZ | Internet | Mgmt |
   |---------------|-----|-----|----------|------|
   | LAN           | ✓   | HTTP/HTTPS | HTTP/HTTPS/DNS | SSH (admin only) |
   | DMZ           | ✗   | ✓   | HTTP/HTTPS (updates) | ✗ |
   | Internet      | ✗   | HTTP/HTTPS | ✓ | ✗ |
   | Mgmt          | SSH | SSH | ✗ | ✓ |

### Why This Approach
- **RoAS** keeps hardware minimal (single router, one physical link) — ideal for Packet Tracer/GNS3 labs
- **TEST-NET-3** for "Internet" avoids using real public IPs in simulation
- **Explicit deny-by-default** zone policy mirrors real firewall rulebases (Palo Alto, FortiGate, Cisco ASA)

---

## CO2: Protocol Stack Analysis

### Deliverables
- `protocol-stack/pcap/` - Captured traffic files (`.pcapng`)
- `protocol-stack/analysis.md` - Layer-by-layer breakdown with screenshots
- `protocol-stack/live-demo.py` - Python script generating/analyzing live traffic

### Implementation Approach
1. **Traffic Generation** (in lab topology):
   - PC (LAN) → Web Server (DMZ): HTTP GET
   - Capture on router trunk interface

2. **Layer Analysis**:
   - **L2 (Ethernet/ARP)**: Frame structure, MAC addressing, ARP request/reply for gateway MAC
   - **L3 (IP)**: Header fields (TTL, protocol, fragmentation), routing decision across subnets
   - **L4 (TCP)**: 3-way handshake (SYN, SYN-ACK, ACK), port multiplexing (ephemeral → 80), sequence/ack numbers
   - **L7 (HTTP)**: Request/response headers, payload, stateless nature

3. **Tools**: `tshark`/`tcpdump` for capture, `scapy` for programmatic analysis, Wireshark for GUI inspection

### Why This Approach
- **Real captures** > textbook diagrams — shows actual header values, timing, retransmissions
- **Single flow** (PC→Web) exercises every layer cleanly without noise
- **Scapy script** makes it reproducible and automatable for grading/demo

---

## CO3: Router Configuration (Packet Tracer / GNS3)

### Deliverables
- `router-config/topology.pkt` (Packet Tracer) OR `topology.gns3` (GNS3)
- `router-config/running-config.txt` - Full `show running-config` output
- `router-config/cli-log.txt` - Step-by-step configuration commands

### Implementation Approach
**Platform**: Cisco Packet Tracer (widely available, no VM overhead)

**Topology**:
```
[PC-LAN]──(VLAN10)──[SW-ACCESS]──(Trunk)──[RTR-EDGE]──(VLAN20)──[SW-DMZ]──[WEB-SRV]
                                      │
                                      └──(ISP)──[CLOUD/INTERNET]
```

**Configuration Steps**:
1. **Hostname & basics**: `hostname RTR-EDGE`, `enable secret`, `service password-encryption`
2. **VLANs on Switch**: `vlan 10,20,99`, assign access ports
3. **Router Sub-interfaces (RoAS)**:
   ```
   interface Gig0/0.10
    encapsulation dot1Q 10
    ip address 10.10.10.1 255.255.255.0
   interface Gig0/0.20
    encapsulation dot1Q 20
    ip address 10.10.20.1 255.255.255.0
   interface Gig0/0.99
    encapsulation dot1Q 99
    ip address 10.10.0.1 255.255.255.0
   ```
4. **WAN Interface**: `ip address 203.0.113.2 255.255.255.252` (point-to-point to ISP)
5. **Default Route**: `ip route 0.0.0.0 0.0.0.0 203.0.113.1`
6. **ACLs** (applied inbound on each sub-interface):
   - `ACL-LAN-IN`: Permit LAN→DMZ/Internet HTTP/HTTPS/DNS; deny LAN→Mgmt except admin host
   - `ACL-DMZ-IN`: Permit DMZ→Internet updates; deny DMZ→LAN
   - `ACL-WAN-IN`: Permit Internet→DMZ HTTP/HTTPS; established TCP; deny all else
7. **Verification**: `ping` across zones, `show access-lists`, `show ip route`

### Why This Approach
- **RoAS** is the standard CCNA-level inter-VLAN method — minimal ports, clear sub-interface mapping
- **Named ACLs** (extended) are more readable/maintainable than numbered
- **Inbound application** on each zone interface = zone-based firewall logic without ZBFW complexity

---

## CO4: Python Threat Detection Script

### Deliverables
- `threat-detection/detect.py` - Main detection engine
- `threat-detection/signatures.yaml` - Externalized rule set
- `threat-detection/test.pcapng` - Sample malicious traffic for validation
- `threat-detection/requirements.txt` - Dependencies
- `threat-detection/README.md` - Usage, extending rules, output format

### Implementation Approach
1. **Architecture**:
   - `PacketCapture` class: wraps `pyshark`/`scapy` for live or offline (.pcap) ingestion
   - `PayloadExtractor`: reassembles TCP streams, handles HTTP chunked encoding, URL-decodes
   - `SignatureEngine`: loads YAML rules, compiles regex, matches per-payload
   - `AlertEmitter`: JSON lines output (SIEM-friendly), optional syslog/STDOUT

2. **Signature Categories** (in `signatures.yaml`):
   - **XSS**: `<script>`, `onerror=`, `onload=`, `javascript:`, `eval(`, `alert(`, `document.cookie`
   - **Encoded evasion**: `%3Cscript%3E`, `&#x3C;`, `\u003c`, double-encoded
   - **SQLi**: `' OR '1'='1`, `UNION SELECT`, `DROP TABLE`, `--`, `;--`
   - **Path Traversal**: `../`, `..\`, `%2e%2e%2f`
   - **Port Scan**: SYN-only bursts, >20 unique dst ports from same src in 5s
   - **Beaconing**: Regular interval connections to same dst (C2 pattern)

3. **Performance**:
   - Stream reassembly only for ports 80/443/8080/8443 (HTTP family)
   - Skip encrypted TLS payloads (flag as `tls_encrypted` — no false positives)
   - Bloom filter for seen flows to avoid re-processing

4. **Testing**:
   - Generate test PCAP with `scapy`: HTTP GET with XSS payloads, nmap SYN scan
   - Validate detection rate, zero false positives on clean traffic

### Why This Approach
- **YAML rules** = non-coders can tune signatures without touching Python
- **Stream reassembly** catches split-payload attacks (evade single-packet regex)
- **JSONL output** integrates with ELK, Splunk, Loki — production-ready
- **TLS awareness** avoids wasting CPU on opaque traffic

---

## File Structure

```
network-security-project/
├── PLAN.md                    # This file
├── architecture/
│   ├── diagram.svg
│   ├── subnetting.md
│   └── zone-policy.md
├── protocol-stack/
│   ├── pcap/
│   │   └── http-flow.pcapng
│   ├── analysis.md
│   └── live-demo.py
├── router-config/
│   ├── topology.pkt
│   ├── running-config.txt
│   └── cli-log.txt
└── threat-detection/
    ├── detect.py
    ├── signatures.yaml
    ├── test.pcapng
    ├── requirements.txt
    └── README.md
```

---

## Execution Order

1. **CO1** (Architecture) — Foundation for all others; defines IPs/VLANs used in CO3/CO2
2. **CO3** (Router Config) — Builds the lab topology; produces the network CO2/CO4 run on
3. **CO2** (Protocol Analysis) — Runs traffic through CO3 topology, captures for CO4
4. **CO4** (Threat Detection) — Consumes CO2 captures + synthetic malicious PCAPs

---

## Dependencies

| Component | Tool/Library | Install |
|-----------|--------------|---------|
| Diagram | `architecture-diagram` skill (SVG) | Built-in |
| Packet Capture | `tshark` (Wireshark CLI) | `choco install wireshark` |
| Packet Gen/Analysis | `scapy`, `pyshark` | `pip install scapy pyshark` |
| YAML Rules | `pyyaml` | `pip install pyyaml` |
| Router Sim | Cisco Packet Tracer 8.x | Cisco NetAcad download |

---

## Success Criteria

| CO | Pass Condition |
|----|----------------|
| CO1 | Diagram renders; subnetting math checks out; zone policy covers all 16 source→dest pairs |
| CO2 | PCAP shows complete L2→L7 flow; analysis.md identifies every header field with values |
| CO3 | Topology loads in Packet Tracer; `ping` works LAN↔DMZ↔Internet; ACLs block per policy |
| CO4 | `detect.py --pcap test.pcapng` outputs JSONL alerts for every injected attack; 0 false positives on clean PCAP |

---

## Next Steps (When Approved)

1. Create `architecture/` deliverables using `architecture-diagram` skill
2. Build Packet Tracer topology, capture `running-config.txt` and `cli-log.txt`
3. Generate protocol-stack PCAP via lab, write `analysis.md`
4. Implement `detect.py` with `signatures.yaml`, validate on test PCAP

---