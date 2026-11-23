# Network Threat Detection Engine (CO4)

Python-based network traffic analyzer that ingests PCAP files or live captures, reassembles TCP streams, and detects security threats using signature matching.

## Features

- **TCP Stream Reassembly**: Reconstructs HTTP flows across multiple packets (ports 80, 443, 8080, 8443)
- **Signature-Based Detection**: YAML-configurable rules for XSS, SQLi, Path Traversal, Command Injection
- **Behavioral Analysis**: Port scan detection (SYN flood, horizontal sweep), beaconing/C2 detection
- **TLS Awareness**: Flags encrypted traffic without false positives
- **JSONL Output**: SIEM-ready structured alerts
- **Deduplication**: Prevents duplicate alerts for same signature/src/dst/content

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Analyze PCAP file
```bash
python threat-detection/detect.py --pcap threat-detection/test.pcapng
```

### Generate test PCAP
```bash
python threat-detection/detect.py --generate-test --output threat-detection/test.pcapng
```

### Live capture (requires admin/root)
```bash
python detect.py --live Ethernet --count 1000
```

## Output Format (JSONL)

Each alert is a single JSON line:

```json
{
  "timestamp": "2026-11-19T15:40:05.041540",
  "src_ip": "10.10.10.54",
  "dst_ip": "10.10.20.10",
  "src_port": 54325,
  "dst_port": 80,
  "protocol": "TCP",
  "category": "sqli",
  "signature_id": "sqli-classic",
  "signature_name": "Classic OR 1=1",
  "severity": "high",
  "description": "Classic tautology injection",
  "matched_content": "' OR '1'='1",
  "packet_summary": "10.10.10.54:54325 -> 10.10.20.10:80"
}
```

## Signature Categories

| Category | Signatures | Type | Description |
|----------|------------|------|-------------|
| **xss** | 12 | Payload | Cross-site scripting vectors |
| **sqli** | 8 | Payload | SQL injection patterns |
| **path_traversal** | 5 | Payload | Directory traversal attempts |
| **cmd_injection** | 4 | Payload | OS command injection |
| **network_scan** | 3 | Behavioral | Port scanning detection (SYN flood, port sweep, nmap) |
| **beaconing** | 2 | Behavioral | C2 beaconing detection (regular interval, DNS tunneling) |
| **tls** | 1 | Behavioral | Encrypted traffic flagging |

**Total: 29 payload signatures + 6 behavioral detectors**

## Extending Signatures

Edit `signatures.yaml` to add custom rules:

```yaml
xss:
  - id: "xss-custom"
    name: "Custom XSS Pattern"
    pattern: "(?i)your-regex-here"
    severity: "high"
    description: "Your description"
```

Pattern flags: `(?i)` = case insensitive. Use raw strings for backslashes.

## Detection Logic

### Signature Matching
- Raw payload + URL-decoded payload both checked
- Regex patterns with `re.IGNORECASE | re.DOTALL`
- Deduplication by (signature_id, src_ip, dst_ip, matched_content_prefix)

### TCP Stream Reassembly
- Tracks SYN → SYN-ACK → ACK handshake
- Buffers payload data per flow (5-tuple)
- Emits complete HTTP messages on double-CRLF + Content-Length
- Skips TLS ports (443, 8443) - flags as `TLS_ENCRYPTED`

### Anomaly Detection
- **SYN Flood**: >20 unique dst ports from same src in 5s
- **Port Sweep**: >50 unique src IPs to same dst port in 10s
- **Beaconing**: ≥6 connections to same dst at regular intervals (±10%) over 30min

## Example Alerts

```bash
# XSS Detection
{"timestamp":"...","src_ip":"10.10.10.51","category":"xss","signature_id":"xss-script-tag","signature_name":"Script Tag Injection","severity":"high","matched_content":"<script>alert(1)</script>",...}

# SQL Injection
{"timestamp":"...","src_ip":"10.10.10.55","category":"sqli","signature_id":"sqli-union","signature_name":"UNION SELECT","severity":"high","matched_content":"UNION SELECT",...}

# Path Traversal
{"timestamp":"...","src_ip":"10.10.10.56","category":"path_traversal","signature_id":"path-trav-etc-passwd","signature_name":"/etc/passwd Access","severity":"critical","matched_content":"/etc/passwd",...}

# Port Scan
{"timestamp":"...","src_ip":"203.0.113.200","category":"network_scan","signature_id":"syn-flood","signature_name":"SYN Flood / Port Scan","severity":"high","matched_content":"Ports: [1, 2, 3, ...]",...}
```

## Integration

Pipe JSONL to SIEM (Elasticsearch, Splunk, Loki):

```bash
python detect.py --pcap traffic.pcapng | jq -c . | curl -X POST -H "Content-Type: application/json" -d @- http://siem:port/ingest
```

## Project Structure

```
threat-detection/
├── detect.py              # Main detection engine
├── signatures.yaml        # Signature definitions
├── requirements.txt       # Dependencies
├── test.pcapng           # Generated test traffic
└── README.md             # This file
```