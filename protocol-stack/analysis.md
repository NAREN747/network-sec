# Protocol Stack Analysis — CO2

**Generated:** Fri Nov 20 10:01:32 2026
**Source:** 10.10.10.50:54321 (LAN)
**Destination:** 10.10.20.10:80 (DMZ)
**Gateway:** 10.10.10.1 (Router)

## Layer 2 — Data Link (Ethernet / ARP)

### Frame Structure
```
| Field          | Size  | Value (Example)          |
|----------------|-------|--------------------------|
| Preamble       | 7 B   | 0x55 55 55 55 55 55 55  |
| SFD            | 1 B   | 0xD5                     |
| Dest MAC       | 6 B   | 00:0c:29:11:22:33 (Gateway)  |
| Src MAC        | 6 B   | 00:0c:29:aa:bb:cc (Client)       |
| EtherType      | 2 B   | 0x0800 (IPv4) / 0x0806 (ARP)|
| Payload        | 46-1500B| IP Packet / ARP         |
| FCS            | 4 B   | CRC32                    |
```

### ARP Exchange
1. **ARP Request** (Broadcast): `Who has 10.10.10.1? Tell 10.10.10.50`
   - EtherType: 0x0806
   - Sender MAC: 00:0c:29:aa:bb:cc
   - Sender IP: 10.10.10.50
   - Target IP: 10.10.10.1

2. **ARP Reply** (Unicast): `10.10.10.1 is at 00:0c:29:11:22:33`
   - EtherType: 0x0806
   - Sender MAC: 00:0c:29:11:22:33 (Router)
   - Sender IP: 10.10.10.1
   - Target MAC: 00:0c:29:aa:bb:cc

**Purpose:** Resolve gateway MAC for Layer 3 forwarding

## Layer 3 — Network (IPv4 Routing)

### IP Header Fields
```
| Field           | Value (Client→Server)  | Value (Server→Client)  |
|-----------------|------------------------|------------------------|
| Version         | 4                      | 4                      |
| IHL             | 5 (20 bytes)           | 5 (20 bytes)           |
| DSCP/ECN        | 0x00 (Best Effort)     | 0x00                   |
| Total Length    | 60 (SYN) / 572 (HTTP)  | 60 / 712               |
| Identification  | 0x1234 (incrementing)  | 0x5678                 |
| Flags           | 0x2 (DF - Don't Frag)  | 0x2                    |
| Fragment Offset | 0                      | 0                      |
| TTL             | 64                     | 64                     |
| Protocol        | 6 (TCP)                | 6 (TCP)                |
| Header Checksum | 0xabcd (calculated)    | 0xef01                 |
| Source IP       | 10.10.10.50                | 10.10.20.10               |
| Dest IP         | 10.10.20.10                | 10.10.10.50               |
```

### Routing Decision (Router)
1. Packet arrives on Gi0/0.10 (VLAN 10)
2. Router consults routing table:
   ```
   C  10.10.10.0/24 via Gi0/0.10
   C  10.10.20.0/24 via Gi0/0.20
   S* 0.0.0.0/0   via 203.0.113.1 (Gi0/1)
   ```
3. Destination 10.10.20.10 matches **10.10.20.0/24** → Forward out Gi0/0.20
4. Router rewrites L2: Src MAC=Router Gi0/0.20, Dst MAC=Web-1
5. TTL decremented: 64 → 63

## Layer 4 — Transport (TCP)

### TCP 3-Way Handshake
| Step | Flags | Seq #    | Ack #    | Window | Options              |
|------|-------|----------|----------|--------|----------------------|
| 1    | SYN   | 1000     | -        | 64240  | MSS=1460             |
| 2    | SYN-ACK| 2000    | 1001     | 64240  | MSS=1460             |
| 3    | ACK   | 1001     | 2001     | 64240  | -                    |

**Key Points:**
- **Port Multiplexing:** Ephemeral port 54321 (client) ↔ Well-known port 80 (server)
- **Sequence Numbers:** Randomized ISN (1000, 2000) for security
- **Acknowledgment:** Next expected byte (SYN consumes 1 seq)
- **Window Size:** 64240 bytes (flow control)
- **MSS Option:** 1460 bytes (MTU 1500 - 20 IP - 20 TCP)

### TCP Data Transfer (HTTP)
| Direction | Flags | Seq      | Ack      | Payload Len |
|-----------|-------|----------|----------|-------------|
| Client→Srv| PA    | 1001     | 2001     | ~200 B      |
| Server→Cl | PA    | 2001     | 1201     | ~600 B      |

- **PSH Flag:** Push data to application immediately
- **ACK Piggybacking:** Data packets acknowledge received data

### Connection Teardown (4-Way)
| Step | Direction | Flags | Purpose                    |
|------|-----------|-------|----------------------------|
| 1    | Client    | FIN   | Client done sending        |
| 2    | Server    | ACK   | Acknowledge FIN            |
| 3    | Server    | FIN   | Server done sending        |
| 4    | Client    | ACK   | Final ACK, connection closed|

## Layer 7 — Application (HTTP/1.1)

### HTTP Request Headers
```http
GET /index.html HTTP/1.1
Host: web1.dmz.local
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1

```

### HTTP Response Headers
```http
HTTP/1.1 200 OK
Date: Mon, 19 Nov 2026 12:00:00 GMT
Server: nginx/1.24.0
Content-Type: text/html; charset=UTF-8
Content-Length: 612
Last-Modified: Mon, 19 Nov 2026 10:00:00 GMT
Connection: keep-alive
ETag: "673abcde-264"
Accept-Ranges: bytes

<!DOCTYPE html>...
```

### Header Analysis
| Header               | Purpose                                             |
|----------------------|-----------------------------------------------------|
| Host                 | Virtual hosting — required in HTTP/1.1             |
| User-Agent           | Client identification — can be used for fingerprinting|
| Accept               | Content negotiation — MIME types client accepts    |
| Accept-Encoding      | Compression support — gzip/deflate reduces bandwidth|
| Connection: keep-alive| Persistent connection — reuse TCP for multiple reqs|
| Content-Length       | Body size in bytes — required for keep-alive       |
| ETag                 | Cache validation — conditional requests (If-None-Match)|
| Server               | Software version — information leakage risk        |

## Complete Stack Summary

| Layer | Protocol    | Key Fields Observed                          |
|-------|-------------|----------------------------------------------|
| L2    | Ethernet    | Src/Dst MAC, EtherType (0x0800/0x0806)       |
| L2    | ARP         | Opcode (1=Req/2=Rep), Sender/Target IP/MAC   |
| L3    | IPv4        | Ver, IHL, TTL, Protocol=6, Src/Dst IP        |
| L4    | TCP         | Src/Dst Port, Seq/Ack, Flags, Window, MSS    |
| L7    | HTTP/1.1    | Method, Path, Version, Headers, Body         |

## Encapsulation Flow
```
Application Data (HTML)
    ↓ HTTP Headers
TCP Segment (Port 54321→80, Seq/Ack, Flags)
    ↓ TCP Header
IP Packet (Src=10.10.10.50, Dst=10.10.20.10, TTL=64)
    ↓ IP Header
Ethernet Frame (Src=Client MAC, Dst=Gateway MAC, Type=0x0800)
    ↓ Ethernet Header + FCS
Physical Bits on Wire
```

---
*Analysis generated from protocol-stack\pcap\http-flow.pcapng*