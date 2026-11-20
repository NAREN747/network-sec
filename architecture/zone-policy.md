# Zone Policy Matrix — Network Security Project (CO1)

## Purpose
Defines allowed/denied traffic between all security zones. Implemented as extended ACLs on router sub-interfaces (inbound) and/or zone-based firewall policies.

---

## Zone Definitions

| Zone | CIDR | VLAN | Interface | Description |
|------|------|------|-----------|-------------|
| **INTERNET** | 203.0.113.0/24 | — | Gi0/1 (WAN) | Untrusted external network |
| **DMZ** | 10.10.20.0/24 | 20 | Gi0/0.20 | Public-facing services |
| **LAN** | 10.10.10.0/24 | 10 | Gi0/0.10 | Internal employee network |
| **MGMT** | 10.10.0.0/24 | 99 | Gi0/0.99 | Management / control plane |

---

## Complete Policy Matrix (16 Source→Destination Pairs)

| # | Source Zone | Dest Zone | Action | Protocol/Ports | Notes |
|---|-------------|-----------|--------|----------------|-------|
| 1 | INTERNET | DMZ | **PERMIT** | TCP 80, 443 | Public web access (HTTP/HTTPS) |
| 2 | INTERNET | DMZ | **PERMIT** | TCP 25, 587 | Mail submission (if mail relay exposed) |
| 3 | INTERNET | DMZ | **PERMIT** | UDP 53 | Public DNS queries |
| 4 | INTERNET | DMZ | **PERMIT** | TCP ESTABLISHED | Return traffic for outbound DMZ connections |
| 5 | INTERNET | LAN | **DENY** | ALL | No direct Internet→LAN access |
| 6 | INTERNET | MGMT | **DENY** | ALL | Management never exposed to Internet |
| 7 | DMZ | INTERNET | **PERMIT** | TCP 80, 443 | OS/package updates, API calls |
| 8 | DMZ | INTERNET | **PERMIT** | UDP 53 | External DNS resolution |
| 9 | DMZ | INTERNET | **PERMIT** | UDP 123 | NTP time sync |
| 10 | DMZ | INTERNET | **PERMIT** | TCP 25, 587 | Outbound mail delivery |
| 11 | DMZ | LAN | **DENY** | ALL | DMZ cannot initiate into LAN (compromise containment) |
| 12 | DMZ | MGMT | **DENY** | ALL | DMZ cannot reach management plane |
| 13 | LAN | DMZ | **PERMIT** | TCP 80, 443 | Employee web access to internal apps in DMZ |
| 14 | LAN | INTERNET | **PERMIT** | TCP 80, 443 | General web browsing |
| 15 | LAN | INTERNET | **PERMIT** | UDP 53 | DNS resolution |
| 16 | LAN | INTERNET | **PERMIT** | TCP 443, 8443 | HTTPS APIs, SaaS apps |
| 17 | LAN | MGMT | **PERMIT** | TCP 22 | **ONLY** from Admin Host (10.10.10.50) → SSH to mgmt devices |
| 18 | LAN | MGMT | **DENY** | ALL | All other LAN→Mgmt blocked |
| 19 | MGMT | LAN | **PERMIT** | TCP 22, 443, 161, 514 | Admin SSH, HTTPS, SNMP, Syslog collection |
| 20 | MGMT | DMZ | **PERMIT** | TCP 22, 443, 161, 514 | Admin SSH, HTTPS, SNMP, Syslog collection |
| 21 | MGMT | INTERNET | **PERMIT** | UDP 123 | NTP (if mgmt NTP serves Internet) |
| 22 | MGMT | INTERNET | **DENY** | ALL | No other Mgmt→Internet |

---

## ACL Implementation (Cisco IOS Extended Named ACLs)

### ACL-INTERNET-IN (Applied INBOUND on Gi0/1 — WAN)
```cisco
ip access-list extended ACL-INTERNET-IN
 ! Allow public web to DMZ
 permit tcp any host 10.10.20.5 eq 80      ! LB HTTP
 permit tcp any host 10.10.20.5 eq 443     ! LB HTTPS
 permit tcp any host 10.10.20.10 eq 80     ! Web1 HTTP
 permit tcp any host 10.10.20.10 eq 443    ! Web1 HTTPS
 permit tcp any host 10.10.20.11 eq 80     ! Web2 HTTP
 permit tcp any host 10.10.20.11 eq 443    ! Web2 HTTPS
 ! Allow DNS to DMZ
 permit udp any host 10.10.20.20 eq 53
 ! Allow Mail to DMZ (if exposed)
 permit tcp any host 10.10.20.25 eq 25
 permit tcp any host 10.10.20.25 eq 587
 ! Allow established/related return traffic
 permit tcp any any established
 permit udp any any eq 53
 ! Deny all else (implicit)
! interface Gi0/1
!  ip access-group ACL-INTERNET-IN in
```

### ACL-DMZ-IN (Applied INBOUND on Gi0/0.20 — DMZ)
```cisco
ip access-list extended ACL-DMZ-IN
 ! DMZ → Internet: Updates, DNS, NTP, Mail
 permit tcp 10.10.20.0 0.0.0.255 any eq 80
 permit tcp 10.10.20.0 0.0.0.255 any eq 443
 permit udp 10.10.20.0 0.0.0.255 any eq 53
 permit udp 10.10.20.0 0.0.0.255 any eq 123
 permit tcp 10.10.20.0 0.0.0.255 any eq 25
 permit tcp 10.10.20.0 0.0.0.255 any eq 587
 ! DMZ → LAN: DENY (implicit)
 ! DMZ → Mgmt: DENY (implicit)
 ! Allow established return traffic for DMZ-initiated
 permit tcp any 10.10.20.0 0.0.0.255 established
! interface Gi0/0.20
!  ip access-group ACL-DMZ-IN in
```

### ACL-LAN-IN (Applied INBOUND on Gi0/0.10 — LAN)
```cisco
ip access-list extended ACL-LAN-IN
 ! LAN → DMZ: Web access
 permit tcp 10.10.10.0 0.0.0.255 host 10.10.20.5 eq 80
 permit tcp 10.10.10.0 0.0.0.255 host 10.10.20.5 eq 443
 permit tcp 10.10.10.0 0.0.0.255 host 10.10.20.10 eq 80
 permit tcp 10.10.10.0 0.0.0.255 host 10.10.20.10 eq 443
 permit tcp 10.10.10.0 0.0.0.255 host 10.10.20.11 eq 80
 permit tcp 10.10.10.0 0.0.0.255 host 10.10.20.11 eq 443
 ! LAN → Internet: Web, DNS, HTTPS APIs
 permit tcp 10.10.10.0 0.0.0.255 any eq 80
 permit tcp 10.10.10.0 0.0.0.255 any eq 443
 permit tcp 10.10.10.0 0.0.0.255 any eq 8443
 permit udp 10.10.10.0 0.0.0.255 any eq 53
 ! LAN → Mgmt: ONLY Admin Host (10.10.10.50) SSH
 permit tcp host 10.10.10.50 10.10.0.0 0.0.0.255 eq 22
 ! Deny all other LAN→Mgmt (implicit)
! interface Gi0/0.10
!  ip access-group ACL-LAN-IN in
```

### ACL-MGMT-IN (Applied INBOUND on Gi0/0.99 — MGMT)
```cisco
ip access-list extended ACL-MGMT-IN
 ! Mgmt → LAN: Admin, monitoring, config mgmt
 permit tcp 10.10.0.0 0.0.0.255 10.10.10.0 0.0.0.255 eq 22
 permit tcp 10.10.0.0 0.0.0.255 10.10.10.0 0.0.0.255 eq 443
 permit udp 10.10.0.0 0.0.0.255 10.10.10.0 0.0.0.255 eq 161
 permit udp 10.10.0.0 0.0.0.255 10.10.10.0 0.0.0.255 eq 514
 ! Mgmt → DMZ: Admin, monitoring, config mgmt
 permit tcp 10.10.0.0 0.0.0.255 10.10.20.0 0.0.0.255 eq 22
 permit tcp 10.10.0.0 0.0.0.255 10.10.20.0 0.0.0.255 eq 443
 permit udp 10.10.0.0 0.0.0.255 10.10.20.0 0.0.0.255 eq 161
 permit udp 10.10.0.0 0.0.0.255 10.10.20.0 0.0.0.255 eq 514
 ! Mgmt → Internet: NTP only (if applicable)
 permit udp 10.10.0.0 0.0.0.255 any eq 123
 ! Deny all else (implicit)
! interface Gi0/0.99
!  ip access-group ACL-MGMT-IN in
```

---

## Zone-Based Firewall Alternative (ZBFW)

If using Zone-Based Policy Firewall (modern Cisco IOS), replace ACLs with:

```cisco
! Define Zones
zone security INTERNET
zone security DMZ
zone security LAN
zone security MGMT

! Define Class Maps (match traffic)
class-map type inspect match-any INTERNET-TO-DMZ-WEB
 match access-group name INTERNET-DMZ-WEB-ACL
class-map type inspect match-any DMZ-TO-INTERNET-UPDATES
 match access-group name DMZ-INTERNET-UPDATES-ACL
class-map type inspect match-any LAN-TO-DMZ-WEB
 match access-group name LAN-DMZ-WEB-ACL
class-map type inspect match-any LAN-TO-INTERNET
 match access-group name LAN-INTERNET-ACL
class-map type inspect match-any MGMT-TO-ALL
 match access-group name MGMT-ALL-ACL

! Define Policy Maps
policy-map type inspect INTERNET-TO-DMZ-PMAP
 class type inspect INTERNET-TO-DMZ-WEB
  inspect
 class class-default
  drop

policy-map type inspect DMZ-TO-INTERNET-PMAP
 class type inspect DMZ-TO-INTERNET-UPDATES
  inspect
 class class-default
  drop

policy-map type inspect LAN-TO-DMZ-PMAP
 class type inspect LAN-TO-DMZ-WEB
  inspect
 class type inspect LAN-TO-INTERNET
  inspect
 class class-default
  drop

policy-map type inspect MGMT-TO-ALL-PMAP
 class type inspect MGMT-TO-ALL
  inspect
 class class-default
  drop

! Define Zone Pairs (Source → Destination)
zone-pair security INTERNET-TO-DMZ source INTERNET destination DMZ
 service-policy type inspect INTERNET-TO-DMZ-PMAP

zone-pair security DMZ-TO-INTERNET source DMZ destination INTERNET
 service-policy type inspect DMZ-TO-INTERNET-PMAP

zone-pair security LAN-TO-DMZ source LAN destination DMZ
 service-policy type inspect LAN-TO-DMZ-PMAP

zone-pair security LAN-TO-INTERNET source LAN destination INTERNET
 service-policy type inspect LAN-TO-DMZ-PMAP  ! Reuse or separate

zone-pair security MGMT-TO-LAN source MGMT destination LAN
 service-policy type inspect MGMT-TO-ALL-PMAP

zone-pair security MGMT-TO-DMZ source MGMT destination DMZ
 service-policy type inspect MGMT-TO-ALL-PMAP

! Assign Interfaces to Zones
interface Gi0/1
 zone-member security INTERNET
interface Gi0/0.20
 zone-member security DMZ
interface Gi0/0.10
 zone-member security LAN
interface Gi0/0.99
 zone-member security MGMT
```

---

## Testing & Verification

### Ping/Connectivity Tests (Expected Results)

| Test | Source | Dest | Expected | ACL/ZBFW Rule |
|------|--------|------|----------|---------------|
| 1 | Public User (Internet) | Web LB (DMZ) | **PASS** (TCP 80/443) | ACL-INTERNET-IN permit |
| 2 | Public User (Internet) | Workstation (LAN) | **FAIL** | ACL-INTERNET-IN implicit deny |
| 3 | Attacker (Internet) | Admin Host (MGMT) | **FAIL** | ACL-INTERNET-IN implicit deny |
| 4 | Web Server (DMZ) | ubuntu.com (Internet) | **PASS** (TCP 80/443) | ACL-DMZ-IN permit |
| 5 | Web Server (DMZ) | Workstation (LAN) | **FAIL** | ACL-DMZ-IN implicit deny |
| 6 | Workstation (LAN) | Web LB (DMZ) | **PASS** (TCP 80/443) | ACL-LAN-IN permit |
| 7 | Workstation (LAN) | Google (Internet) | **PASS** (TCP 80/443, UDP 53) | ACL-LAN-IN permit |
| 8 | Workstation (LAN) | Router Mgmt (MGMT) | **FAIL** (unless 10.10.10.50) | ACL-LAN-IN permit host 10.10.10.50 |
| 9 | Admin Host (MGMT) | Router (MGMT) | **PASS** (SSH) | ACL-MGMT-IN permit |
| 10 | Admin Host (MGMT) | Web Server (DMZ) | **PASS** (SSH/HTTPS) | ACL-MGMT-IN permit |
| 11 | SIEM (MGMT) | All zones | **PASS** (Syslog UDP 514) | ACL-MGMT-IN permit UDP 514 |

### Verification Commands
```cisco
! Check ACL hit counts
show access-lists ACL-INTERNET-IN
show access-lists ACL-DMZ-IN
show access-lists ACL-LAN-IN
show access-lists ACL-MGMT-IN

! ZBFW verification
show zone-pair security
show policy-map type inspect zone-pair
show zone security

! Test connectivity
ping 10.10.20.5 source 10.10.10.50   ! LAN→DMZ
ping 203.0.113.100 source 10.10.10.50 ! LAN→Internet
telnet 10.10.20.5 80                  ! TCP port test
```

---

## Change Management

| Change | Impact | ACLs to Update |
|--------|--------|----------------|
| New DMZ web server | Add IP to ACL-INTERNET-IN, ACL-LAN-IN | 2 |
| New admin host | Add host to ACL-LAN-IN (SSH to MGMT) | 1 |
| Block specific country | Add deny GEOIP to ACL-INTERNET-IN (requires ZBFW + class-map) | 1 |
| Enable SNMP monitoring from Mgmt | Already permitted (UDP 161) | 0 |
| Add Guest WiFi VLAN | New zone, new zone-pairs, new ACLs | 4+ |

---

## Security Principles Applied

1. **Default Deny** — Implicit deny at end of every ACL; explicit permits only
2. **Least Privilege** — Only required ports/protocols allowed per zone pair
3. **Containment** — DMZ cannot initiate to LAN or MGMT (prevents lateral movement)
4. **Management Isolation** — MGMT zone only reachable from designated admin host
5. **No Direct Internet→LAN** — All Internet traffic terminates at DMZ or Firewall
6. **Stateful Inspection** — `established` keyword (ACL) or `inspect` (ZBFW) for return traffic
7. **Logging** — Add `log` to deny statements for SIEM correlation (not shown above for brevity)

---

## References

- NIST SP 800-41 Rev 1: Guidelines on Firewalls and Firewall Policy
- Cisco: Zone-Based Policy Firewall Configuration Guide
- RFC 1918: Address Allocation for Private Internets
- RFC 5737: TEST-NET-3 (203.0.113.0/24) for Documentation