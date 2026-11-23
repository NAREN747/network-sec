# Network Security Project - Router Configuration Lab Guide (CO3)

## Overview
This guide documents the step-by-step configuration of the Packet Tracer topology for the Network Security Project. The topology implements a perimeter network with LAN, DMZ, Management, and Internet zones using Router-on-a-Stick (RoAS) and zone-based ACLs.

## Topology

```
[PC-LAN]──(VLAN10)──[SW-CORE]──(Trunk)──[RTR-EDGE]──(VLAN20)──[SW-DMZ]──[WEB-SRV]
                                      │
                                      └──(ISP)──[CLOUD/INTERNET]
```

**Devices:**
- **RTR-EDGE** (Cisco 2911): Edge router with RoAS sub-interfaces
- **SW-CORE** (Cisco 3560-24PS): Core switch with VLANs and trunk
- **ISP-RTR** (Cisco 2911): Simulates Internet / upstream ISP
- **PCs/Servers**: Connected to appropriate VLANs on SW-CORE

## IP Addressing Plan

| Zone | Network | VLAN | Gateway | Usable Range |
|------|---------|------|---------|--------------|
| LAN | 10.10.10.0/24 | 10 | 10.10.10.1 | .10 - .254 |
| DMZ | 10.10.20.0/24 | 20 | 10.10.20.1 | .10 - .254 |
| Mgmt | 10.10.0.0/24 | 99 | 10.10.0.1 | .10 - .254 |
| WAN (ISP) | 203.0.113.0/30 | - | 203.0.113.1 | .1 - .2 |
| Public | 203.0.113.96/27 | - | 203.0.113.97 | .98 - .126 |

## Device IP Assignments

| Device | IP | Gateway | DNS | VLAN | Switch Port |
|--------|-----|---------|-----|------|-------------|
| PC1 | 10.10.10.50 | 10.10.10.1 | 10.10.20.20 | 10 | Fa0/1 |
| PC2 | 10.10.10.51 | 10.10.10.1 | 10.10.20.20 | 10 | Fa0/2 |
| PC3 | 10.10.10.52 | 10.10.10.1 | 10.10.20.20 | 10 | Fa0/3 |
| PC4 | 10.10.10.53 | 10.10.10.1 | 10.10.20.20 | 10 | Fa0/4 |
| PC5 | 10.10.10.54 | 10.10.10.1 | 10.10.20.20 | 10 | Fa0/5 |
| PC6 | 10.10.10.55 | 10.10.10.1 | 10.10.20.20 | 10 | Fa0/6 |
| PC7 | 10.10.10.56 | 10.10.10.1 | 10.10.20.20 | 10 | Fa0/7 |
| PC8 | 10.10.10.57 | 10.10.10.1 | 10.10.20.20 | 10 | Fa0/8 |
| PC9 | 10.10.10.58 | 10.10.10.1 | 10.10.20.20 | 10 | Fa0/9 |
| LB | 10.10.20.10 | 10.10.20.1 | 10.10.20.20 | 20 | Fa0/10 |
| Web-1 | 10.10.20.20 | 10.10.20.1 | 10.10.20.20 | 20 | Fa0/11 |
| DNS | 10.10.20.30 | 10.10.20.1 | 10.10.20.20 | 20 | Fa0/12 |
| Web-2 | 10.10.20.40 | 10.10.20.1 | 10.10.20.20 | 20 | Fa0/13 |
| App-1 | 10.10.20.50 | 10.10.20.1 | 10.10.20.20 | 20 | Fa0/14 |
| App-2 | 10.10.20.60 | 10.10.20.1 | 10.10.20.20 | 20 | Fa0/15 |
| Admin | 10.10.0.10 | 10.10.0.1 | 10.10.20.20 | 99 | Fa0/16 |
| SIEM | 10.10.0.20 | 10.10.0.1 | 10.10.20.20 | 99 | Fa0/17 |
| PC-MGMT-1 | 10.10.0.30 | 10.10.0.1 | 10.10.20.20 | 99 | Fa0/18 |
| PC-MGMT-2 | 10.10.0.40 | 10.10.0.1 | 10.10.20.20 | 99 | Fa0/19 |
| PC-MGMT-3 | 10.10.0.50 | 10.10.0.1 | 10.10.20.20 | 99 | Fa0/20 |
| PC-MGMT-4 | 10.10.0.60 | 10.10.0.1 | 10.10.20.20 | 99 | Fa0/21 |
| PC-MGMT-5 | 10.10.0.70 | 10.10.0.1 | 10.10.20.20 | 99 | Fa0/22 |
| PUBLIC-PC | 203.0.113.100 | 203.0.113.97 | 8.8.8.8 | - | ISP Gi0/1 |

## Configuration Steps

### 1. ISP-RTR
```bash
# Paste router-config/isp-rtr.txt into ISP-RTR CLI
```

### 2. SW-CORE
```bash
# Paste router-config/sw-core.txt into SW-CORE CLI
# Verify: show vlan brief, show interfaces trunk, show interfaces status
```

### 3. RTR-EDGE
```bash
enable
configure terminal
# Paste router-config/running-config.txt
# Wait for SSH key generation to complete
```

### 4. Configure End Devices
Set static IP, mask, gateway, DNS on each PC/Server via Desktop > IP Configuration.

## Verification Tests

Run each test from the device's Desktop tab. Use Command Prompt for pings/ssh, Web Browser for HTTP.

| # | From | Action | Expected | Purpose |
|---|------|--------|----------|---------|
| 1 | PC1 | `ping 10.10.20.5` | **PASS** | LAN → DMZ (HTTP server) |
| 2 | PC1 | `ping 203.0.113.1` | **PASS** | LAN → Internet (default route) |
| 3 | PC2 | `ssh -l admin 10.10.0.1` | **FAIL** | Non-admin LAN → Mgmt blocked |
| 4 | Admin | `ssh -l admin 10.10.0.1` (pw: Cisco123) | **PASS** | Admin → Mgmt allowed |
| 5 | Web-1 | `ping 10.10.10.50` | **FAIL** | DMZ → LAN blocked |
| 6 | PUBLIC-PC | Browser: `http://10.10.20.5` | **PASS** | Internet → DMZ web allowed |
| 7 | PUBLIC-PC | `ping 10.10.10.50` | **FAIL** | Internet → LAN blocked |

**Notes:**
- First ping may timeout due to ARP; run twice before calling fail.
- "Destination host unreachable" = routing issue; "Request timed out" = ACL/firewall block.
- Failed tests (3, 5, 7) are **expected to fail** — they prove the firewall rules work.

## Post-Test Verification

On RTR-EDGE:
```bash
show access-lists          # Check hit counters on ACLs
show ip route              # Verify routing table
show ip interface brief    # All interfaces up/up
```

Save the Packet Tracer file as `Network_Security_Project.pkt` in the project root.

## Files in This Directory

| File | Description |
|------|-------------|
| `running-config.txt` | RTR-EDGE full running config (RoAS, ACLs, SSH) |
| `isp-rtr.txt` | ISP-RTR config (WAN link + public subnet) |
| `sw-core.txt` | SW-CORE config (VLANs, trunk, SVI) |
| `lab-guide.md` | This file |
| `topology-build-guide.md` | *(Legacy - deprecated, use lab-guide.md)* |
| `cli-log.txt` | *(Legacy - deprecated)* |

## Troubleshooting

| Symptom | Check |
|---------|-------|
| Sub-interfaces down | SW-CORE trunk not configured; `show interfaces trunk` |
| PC can't reach gateway | Wrong VLAN assignment; `show vlan brief` |
| SSH fails | `crypto key generate rsa` not completed; wait for key gen |
| Internet unreachable | Default route missing; `show ip route` on RTR-EDGE |
| DMZ web unreachable | ACL-WAN-IN not permitting HTTP/HTTPS; `show access-lists` |

## ACL Summary (RTR-EDGE)

| ACL | Interface (in) | Policy |
|-----|----------------|--------|
| ACL-LAN-IN | Gi0/0.10 | Permit LAN→DMZ/Internet HTTP/HTTPS/DNS; Deny LAN→Mgmt except Admin |
| ACL-DMZ-IN | Gi0/0.20 | Permit DMZ→Internet updates; Deny DMZ→LAN |
| ACL-MGMT-IN | Gi0/0.99 | Permit Mgmt↔Mgmt SSH; Permit Admin→LAN/DMZ; Deny all else |
| ACL-WAN-IN | Gi0/1 | Permit Internet→DMZ HTTP/HTTPS; Established TCP; Deny all else |

---
*Generated for Network Security Project CO3 - Router Configuration*