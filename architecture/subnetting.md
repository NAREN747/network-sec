# Subnetting Plan — Network Security Project (CO1)

## Overview
RFC 1918 private address space + RFC 5737 TEST-NET-3 for simulated Internet.

---

## Address Allocation Table

| Zone | Network | CIDR | Usable Hosts | VLAN ID | Gateway IP | Purpose |
|------|---------|------|--------------|---------|------------|---------|
| **Management** | 10.10.0.0 | /24 | 254 | 99 | 10.10.0.1 | Router, Switch, Firewall, SIEM, Admin |
| **LAN (Internal)** | 10.10.10.0 | /24 | 254 | 10 | 10.10.10.1 | Employee workstations, internal servers, AD |
| **DMZ (Public)** | 10.10.20.0 | /24 | 254 | 20 | 10.10.20.1 | Web servers, DNS, Mail, WAF, LB |
| **WAN (ISP Link)** | 203.0.113.0 | /30 | 2 | — | 203.0.113.1 (ISP) / 203.0.113.2 (Edge) | Point-to-point to ISP |

---

## Subnetting Math

### Management: 10.10.0.0/24
- Network: `10.10.0.0`
- First usable: `10.10.0.1` (Router Gi0/0.99)
- Last usable: `10.10.0.254`
- Broadcast: `10.10.0.255`
- Mask: `255.255.255.0` (255.255.255.0 = /24)

### LAN: 10.10.10.0/24
- Network: `10.10.10.0`
- First usable: `10.10.10.1` (Router Gi0/0.10)
- DHCP pool: `10.10.10.50` – `10.10.10.200`
- Static reservations: `10.10.10.2`–`10.10.10.49` (servers, printers, AD)
- Last usable: `10.10.10.254`
- Broadcast: `10.10.10.255`
- Mask: `255.255.255.0`

### DMZ: 10.10.20.0/24
- Network: `10.10.20.0`
- First usable: `10.10.20.1` (Router Gi0/0.20)
- Static assignments:
  - `10.10.20.5` — Load Balancer (HAProxy)
  - `10.10.20.10` — Web Server 1
  - `10.10.20.11` — Web Server 2
  - `10.10.20.20` — DNS Server
  - `10.10.20.25` — Mail Relay
  - `10.10.20.30` — WAF/Proxy
- Last usable: `10.10.20.254`
- Broadcast: `10.10.20.255`
- Mask: `255.255.255.0`

### WAN: 203.0.113.0/30
- Network: `203.0.113.0`
- Usable: `203.0.113.1` (ISP), `203.0.113.2` (Edge Router Gi0/1)
- Broadcast: `203.0.113.3`
- Mask: `255.255.255.252`

---

## VLAN Design

| VLAN ID | Name | Subnet | Port Type | Description |
|---------|------|--------|-----------|-------------|
| 10 | LAN_USERS | 10.10.10.0/24 | Access | Employee workstations, printers, IoT |
| 20 | DMZ_SERVERS | 10.10.20.0/24 | Access | Public-facing servers (web, DNS, mail) |
| 99 | MGMT_CTRL | 10.10.0.0/24 | Access (Mgmt ports) | Router, Switch, Firewall, SIEM, Admin |
| 1 | DEFAULT | — | Access (unused) | Shutdown / unused ports |
| 999 | NATIVE_TRUNK | — | Trunk native | Unused — security best practice |

---

## Router-on-a-Stick (RoAS) Interface Mapping

```
Physical: GigabitEthernet0/0  →  Trunk to Core Switch (VLANs 10,20,99)

Sub-interfaces:
  Gi0/0.10   encapsulation dot1Q 10   ip address 10.10.10.1 255.255.255.0   ! LAN Gateway
  Gi0/0.20   encapsulation dot1Q 20   ip address 10.10.20.1 255.255.255.0   ! DMZ Gateway
  Gi0/0.99   encapsulation dot1Q 99   ip address 10.10.0.1  255.255.255.0   ! Mgmt Gateway

WAN:
  Gi0/1      ip address 203.0.113.2 255.255.255.252   ! ISP Link
```

---

## Routing Table (Edge Router)

| Network | Next Hop / Interface | Metric | Source |
|---------|---------------------|--------|--------|
| 10.10.0.0/24 | Gi0/0.99 (Connected) | 0 | Connected |
| 10.10.10.0/24 | Gi0/0.10 (Connected) | 0 | Connected |
| 10.10.20.0/24 | Gi0/0.20 (Connected) | 0 | Connected |
| 203.0.113.0/30 | Gi0/1 (Connected) | 0 | Connected |
| 0.0.0.0/0 | 203.0.113.1 (ISP) | 1 | Static (Default) |

---

## Core Switch VLAN Configuration

```cisco
! VLAN Definitions
vlan 10
 name LAN_USERS
vlan 20
 name DMZ_SERVERS
vlan 99
 name MGMT_CTRL

! Access Ports (Examples)
interface range Gi1/0/1 - 24
 switchport mode access
 switchport access vlan 10
 spanning-tree portfast
!
interface range Gi1/0/25 - 36
 switchport mode access
 switchport access vlan 20
 spanning-tree portfast
!
interface range Gi1/0/37 - 40
 switchport mode access
 switchport access vlan 99
 spanning-tree portfast

! Trunk to Router (RoAS)
interface Gi1/0/48
 switchport mode trunk
 switchport trunk allowed vlan 10,20,99
 switchport trunk native vlan 999
 spanning-tree portfast trunk

! SVI for Management (optional L3 on switch)
interface Vlan99
 ip address 10.10.0.2 255.255.255.0
 no shutdown
```

---

## Design Rationale

1. **/24 per zone** — 254 hosts each; room for growth, simple mask math, aligns with CCNA lab conventions
2. **10.10.x.0 pattern** — Easy to remember; 3rd octet = zone ID (0=mgmt, 10=lan, 20=dmz)
3. **VLAN 99 for management** — High number avoids default VLAN 1; isolated from user traffic
4. **TEST-NET-3 (203.0.113.0/24)** — RFC 5737 reserved for documentation; no conflict with real Internet
5. **RoAS vs. L3 Switch** — RoAS chosen for lab simplicity (single router, clear sub-interface mapping). Production would use L3 switch SVIs for wire-speed inter-VLAN.
6. **Native VLAN 999 unused** — Prevents VLAN hopping attacks; all trunked VLANs tagged

---

## Future Expansion Notes

| Need | Change |
|------|--------|
| More DMZ servers | Add VLAN 21 (10.10.21.0/24), new sub-interface Gi0/0.21 |
| Guest WiFi | Add VLAN 30 (10.10.30.0/24), isolate with ACL (Internet only) |
| Voice VLAN | Add VLAN 40 (10.10.40.0/24), QoS priority on switch ports |
| Site-to-site VPN | Add tunnel interface, crypto map, new /30 per tunnel |
| IPv6 | Add `2001:db8::/32` (doc prefix) mirrors: `2001:db8:10::/64` LAN, `2001:db8:20::/64` DMZ |

---

## Verification Checklist

- [ ] All subnets non-overlapping
- [ ] Gateway IPs are first usable in each /24
- [ ] VLAN IDs unique and documented
- [ ] RoAS sub-interfaces match VLAN IDs 1:1
- [ ] Default route points to ISP next-hop
- [ ] Native VLAN on trunk ≠ any user VLAN
- [ ] Management VLAN accessible only from admin host
- [ ] DMZ servers have static IPs (no DHCP)
- [ ] WAN /30 uses only 2 IPs (ISP + Edge)