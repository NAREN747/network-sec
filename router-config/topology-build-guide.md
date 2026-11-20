# Packet Tracer Topology Build Guide
# Network Security Project — CO3: Router Configuration
# File: topology.pkt (to be created in Cisco Packet Tracer 8.x)
# ================================================================

## Topology Overview
```
                                    ┌─────────────────────┐
                                    │      INTERNET       │
                                    │   203.0.113.0/24    │
                                    │  (TEST-NET-3)       │
                                    └──────────┬──────────┘
                                               │
                                    ┌──────────▼──────────┐
                                    │    ISP ROUTER       │
                                    │   203.0.113.1/30    │
                                    └──────────┬──────────┘
                                               │ WAN Link
                                               │ 203.0.113.0/30
                                    ┌──────────▼──────────┐
                                    │   EDGE ROUTER       │
                                    │   (RTR-EDGE)        │
                                    │  Gi0/1: 203.0.113.2 │
                                    │  Gi0/0: Trunk       │
                                    └──────────┬──────────┘
                                               │ Trunk (VLANs 10,20,99)
                    ┌──────────────────────────┼──────────────────────────┐
                    │                          │                          │
           ┌────────▼────────┐         ┌───────▼───────┐         ┌───────▼───────┐
           │  CORE SWITCH  │         │  CORE SWITCH  │         │  CORE SWITCH  │
           │  (SW-CORE)    │         │  (SW-CORE)    │         │  (SW-CORE)    │
           │  Catalyst 9300│         │  Catalyst 9300│         │  Catalyst 9300│
           └───────┬───────┘         └───────┬───────┘         └───────┬───────┘
                   │                         │                         │
       ┌───────────┼───────────┐    ┌────────┼────────┐      ┌─────────┼─────────┐
       ▼           ▼           ▼    ▼        ▼        ▼      ▼         ▼         ▼
  ┌───────┐  ┌────────┐ ┌───────┐  ┌──────┐ ┌──────┐ ┌────┐ ┌──────┐ ┌──────┐ ┌──────┐
  │VLAN 10│  │VLAN 10 │ │VLAN 10│  │VLAN20│ │VLAN20│ │V20 │ │VLAN99│ │VLAN99│ │VLAN99│
  │Access │  │Access  │ │Access │  │Access│ │Access│ │Acc │ │Access│ │Access│ │Access│
  └───┬───┘  └────┬───┘ └───┬───┘  └──┬───┘ └──┬───┘ └─┬──┘ └──┬───┘ └──┬───┘ └──┬───┘
      │           │         │         │        │       │      │       │       │
      ▼           ▼         ▼         ▼        ▼       ▼      ▼       ▼       ▼
  ┌───────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌─────┐ ┌──────┐ ┌────────┐ ┌──────┐ ┌────────┐
  │ PC-1  │ │ PC-2   │ │Printer │ │Web-1   │ │Web-2│ │ LB   │ │ Router │ │ SIEM │ │ Admin  │
  │10.10. │ │10.10.  │ │10.10.  │ │10.10.  │ │10.10│ │10.10.│ │Gi0/0.99│ │10.10.│ │10.10.  │
  │10.50  │ │10.51   │ │10.100  │ │20.10   │ │20.11│ │20.5  │ │10.10.0.1│ │0.10  │ │0.50    │
  └───────┘ └────────┘ └────────┘ └────────┘ └─────┘ └──────┘ └────────┘ └──────┘ └────────┘

  LAN ZONE          DMZ ZONE              MANAGEMENT ZONE
  10.10.10.0/24     10.10.20.0/24         10.10.0.0/24
  VLAN 10           VLAN 20               VLAN 99
```

---

## Device List & Configuration

### 1. EDGE ROUTER (RTR-EDGE)
- **Model**: Cisco 4321 ISR (or 2911 in Packet Tracer)
- **Interfaces**:
  - GigabitEthernet0/0 → Trunk to Core Switch
  - GigabitEthernet0/1 → WAN to ISP Router
- **Sub-interfaces on Gi0/0**:
  - Gi0/0.10 — dot1Q 10 — 10.10.10.1/24 (LAN Gateway)
  - Gi0/0.20 — dot1Q 20 — 10.10.20.1/24 (DMZ Gateway)
  - Gi0/0.99 — dot1Q 99 — 10.10.0.1/24 (Mgmt Gateway)
- **Config**: See `running-config.txt` and `cli-log.txt`

### 2. CORE SWITCH (SW-CORE)
- **Model**: Cisco Catalyst 9300 (or 3560/3650 in Packet Tracer)
- **VLANs**: 10 (LAN), 20 (DMZ), 99 (MGMT), 999 (Native - unused)
- **Ports**:
  - Gi1/0/1-24 → Access VLAN 10 (Employee devices)
  - Gi1/0/25-36 → Access VLAN 20 (DMZ Servers)
  - Gi1/0/37-40 → Access VLAN 99 (Mgmt Devices)
  - Gi1/0/48 → Trunk to Router (Allowed: 10,20,99; Native: 999)
- **SVI (Optional L3)**: Vlan99 — 10.10.0.2/24

### 3. ISP ROUTER (ISP-RTR)
- **Model**: Generic Router / 2911
- **Interface**: Gi0/0 — 203.0.113.1/30 (toward Edge Router)
- **Config**: Minimal — just IP and default route to "Internet cloud"

### 4. END DEVICES

#### LAN Zone (VLAN 10, 10.10.10.0/24, Gateway 10.10.10.1)
| Device | IP | Gateway | DNS | Role |
|--------|-----|---------|-----|------|
| PC-1 (Windows) | 10.10.10.50 | 10.10.10.1 | 10.10.20.20 | Admin Workstation |
| PC-2 (Linux) | 10.10.10.51 | 10.10.10.1 | 10.10.20.20 | Employee Workstation |
| Printer | 10.10.10.100 | 10.10.10.1 | 10.10.20.20 | Network Printer |
| Internal App | 10.10.10.10 | 10.10.10.1 | 10.10.20.20 | Intranet Server |
| AD/DHCP/DNS | 10.10.10.5 | 10.10.10.1 | 127.0.0.1 | Domain Controller |
| File Server | 10.10.10.20 | 10.10.10.1 | 10.10.20.20 | SMB/NFS |
| Database | 10.10.10.30 | 10.10.10.1 | 10.10.20.20 | PostgreSQL |
| Backup | 10.10.10.40 | 10.10.10.1 | 10.10.20.20 | Veeam/Restic |
| SIEM (LAN) | 10.10.10.15 | 10.10.10.1 | 10.10.20.20 | Wazuh/ELK Collector |

#### DMZ Zone (VLAN 20, 10.10.20.0/24, Gateway 10.10.20.1)
| Device | IP | Gateway | DNS | Role |
|--------|-----|---------|-----|------|
| LB (HAProxy) | 10.10.20.5 | 10.10.20.1 | 10.10.20.20 | Load Balancer |
| Web-1 (Nginx) | 10.10.20.10 | 10.10.20.1 | 10.10.20.20 | Web Server 1 |
| Web-2 (Nginx) | 10.10.20.11 | 10.10.20.1 | 10.10.20.20 | Web Server 2 |
| DNS (Bind9) | 10.10.20.20 | 10.10.20.1 | 127.0.0.1 | Authoritative DNS |
| Mail (Postfix) | 10.10.20.25 | 10.10.20.1 | 10.10.20.20 | Mail Relay |
| WAF (ModSecurity) | 10.10.20.30 | 10.10.20.1 | 10.10.20.20 | WAF/Reverse Proxy |

#### Management Zone (VLAN 99, 10.10.0.0/24, Gateway 10.10.0.1)
| Device | IP | Gateway | DNS | Role |
|--------|-----|---------|-----|------|
| Router Gi0/0.99 | 10.10.0.1 | — | — | Router Mgmt Interface |
| Switch SVI Vlan99 | 10.10.0.2 | 10.10.0.1 | 10.10.0.20 | Switch Mgmt |
| SIEM Central | 10.10.0.10 | 10.10.0.1 | 10.10.0.20 | Splunk/ELK |
| Admin Host | 10.10.0.50 | 10.10.0.1 | 10.10.0.20 | Jump Box / Bastion |
| NTP Server | 10.10.0.20 | 10.10.0.1 | 10.10.0.20 | Chrony/NTPD |
| Ansible/GitOps | 10.10.0.30 | 10.10.0.1 | 10.10.0.20 | Config Mgmt |
| Vuln Scanner | 10.10.0.40 | 10.10.0.1 | 10.10.0.20 | OpenVAS/Nessus |

#### Internet Zone (203.0.113.0/24)
| Device | IP | Role |
|--------|-----|------|
| ISP Router | 203.0.113.1 | ISP Gateway |
| Public User | 203.0.113.100 | Legitimate Browser |
| Attacker | 203.0.113.200 | Kali / Botnet |

---

## Packet Tracer Build Steps

### Step 1: Create Devices
1. Open Packet Tracer 8.x
2. **Logical Workspace** → Add devices:
   - 1 × Router (4321 or 2911) → Rename "RTR-EDGE"
   - 1 × Switch (3560/3650/9300) → Rename "SW-CORE"
   - 1 × Router (Generic/2911) → Rename "ISP-RTR"
   - 9 × PC/Server (for LAN zone)
   - 6 × Server (for DMZ zone)
   - 7 × PC/Server (for Mgmt zone)
   - 2 × PC (for Internet zone)
   - 1 × Cloud (optional, for "Internet" visual)

### Step 2: Cable Connections
```
RTR-EDGE Gi0/1  ──────────────────  ISP-RTR Gi0/0          (Copper Straight-through)
RTR-EDGE Gi0/0  ──────────────────  SW-CORE Gi1/0/48       (Copper Straight-through)

SW-CORE Gi1/0/1-24   ────────  LAN Devices (PC-1, PC-2, Printer, App, AD, File, DB, Backup, SIEM-LAN)
SW-CORE Gi1/0/25-36  ────────  DMZ Devices (LB, Web-1, Web-2, DNS, Mail, WAF)
SW-CORE Gi1/0/37-40  ────────  Mgmt Devices (SIEM, Admin, NTP, Ansible, Scanner)
```

### Step 3: Configure ISP Router
```
ISP-RTR> en
ISP-RTR# conf t
ISP-RTR(config)# hostname ISP-RTR
ISP-RTR(config)# interface GigabitEthernet0/0
ISP-RTR(config-if)# ip address 203.0.113.1 255.255.255.252
ISP-RTR(config-if)# no shutdown
ISP-RTR(config-if)# exit
ISP-RTR(config)# ip route 0.0.0.0 0.0.0.0 203.0.113.2  ! Point to Edge (simplified)
ISP-RTR(config)# end
ISP-RTR# wr
```

### Step 4: Configure Core Switch (SW-CORE)
```
SW-CORE> en
SW-CORE# conf t
SW-CORE(config)# hostname SW-CORE
SW-CORE(config)# vlan 10
SW-CORE(config-vlan)# name LAN_USERS
SW-CORE(config-vlan)# exit
SW-CORE(config)# vlan 20
SW-CORE(config-vlan)# name DMZ_SERVERS
SW-CORE(config-vlan)# exit
SW-CORE(config)# vlan 99
SW-CORE(config-vlan)# name MGMT_CTRL
SW-CORE(config-vlan)# exit
SW-CORE(config)# vlan 999
SW-CORE(config-vlan)# name NATIVE_UNUSED
SW-CORE(config-vlan)# exit

! Access Ports - LAN (Gi1/0/1-24)
SW-CORE(config)# interface range GigabitEthernet1/0/1 - 24
SW-CORE(config-if-range)# switchport mode access
SW-CORE(config-if-range)# switchport access vlan 10
SW-CORE(config-if-range)# spanning-tree portfast
SW-CORE(config-if-range)# exit

! Access Ports - DMZ (Gi1/0/25-36)
SW-CORE(config)# interface range GigabitEthernet1/0/25 - 36
SW-CORE(config-if-range)# switchport mode access
SW-CORE(config-if-range)# switchport access vlan 20
SW-CORE(config-if-range)# spanning-tree portfast
SW-CORE(config-if-range)# exit

! Access Ports - Mgmt (Gi1/0/37-40)
SW-CORE(config)# interface range GigabitEthernet1/0/37 - 40
SW-CORE(config-if-range)# switchport mode access
SW-CORE(config-if-range)# switchport access vlan 99
SW-CORE(config-if-range)# spanning-tree portfast
SW-CORE(config-if-range)# exit

! Trunk to Router (Gi1/0/48)
SW-CORE(config)# interface GigabitEthernet1/0/48
SW-CORE(config-if)# switchport mode trunk
SW-CORE(config-if)# switchport trunk allowed vlan 10,20,99
SW-CORE(config-if)# switchport trunk native vlan 999
SW-CORE(config-if)# spanning-tree portfast trunk
SW-CORE(config-if)# exit

! Optional: SVI for Mgmt
SW-CORE(config)# interface Vlan99
SW-CORE(config-if)# ip address 10.10.0.2 255.255.255.0
SW-CORE(config-if)# no shutdown
SW-CORE(config-if)# exit

SW-CORE(config)# ip default-gateway 10.10.0.1
SW-CORE(config)# end
SW-CORE# wr
```

### Step 5: Configure Edge Router (RTR-EDGE)
- Use the full config from `running-config.txt`
- Or follow `cli-log.txt` step by step

### Step 6: Configure End Device IPs
Set static IPs on each device per the tables above.
- **Gateway** = respective zone gateway (10.10.10.1 / 10.10.20.1 / 10.10.0.1)
- **DNS** = 10.10.20.20 (DMZ DNS) for all except DNS server itself

### Step 7: Test Connectivity
```
! From PC-1 (LAN Admin)
ping 10.10.20.5      ! LAN → DMZ LB (PASS)
ping 203.0.113.1     ! LAN → Internet (PASS)
ping 10.10.0.1       ! LAN → Router Mgmt (FAIL - not admin host? wait, 10.10.10.50 IS admin)
ssh -l admin 10.10.0.1  ! SSH to Router (PASS)

! From PC-2 (LAN Non-Admin)
ping 10.10.20.5      ! PASS
ping 203.0.113.1     ! PASS
ssh -l admin 10.10.0.1  ! FAIL (ACL blocks)

! From Web-1 (DMZ)
ping 203.0.113.1     ! DMZ → Internet (PASS)
ping 10.10.10.50     ! DMZ → LAN (FAIL)

! From Public User (Internet)
ping 10.10.20.5      ! Internet → DMZ (PASS - ICMP not in ACL, but TCP 80/443 would)
telnet 10.10.20.5 80 ! PASS
ping 10.10.10.50     ! Internet → LAN (FAIL)
```

---

## Packet Tracer File Notes

### Saving the Topology
1. After building and testing: **File → Save As**
2. Name: `topology.pkt`
3. Location: `C:\Users\naren\network-security-project\router-config\topology.pkt`

### Version Compatibility
- Created in: **Cisco Packet Tracer 8.2.1**
- Compatible with: **8.x** (may need minor adjustments for 7.x)
- IOS Version: **15.2(4)M5** (2911) or **17.3.1** (4321/9300)

### Known Packet Tracer Limitations
| Feature | Status | Workaround |
|---------|--------|------------|
| Zone-Based Firewall (ZBFW) | ❌ Not supported | Use ACLs (as implemented) |
| IPv6 | ✅ Supported | Add if needed |
| SNMP v3 | ⚠️ Limited | Use v2c (as implemented) |
| Syslog to PC | ⚠️ Use Server device | Use "Server" type for SIEM |
| 4321/9300 models | ✅ In 8.x | Use 2911/3560 in older versions |

---

## Verification Checklist (Post-Build)

- [ ] All devices powered on (green lights)
- [ ] All switch ports correct VLAN (hover shows VLAN)
- [ ] Trunk port shows "Trunk" + allowed VLANs
- [ ] Router sub-interfaces up/up with correct IPs
- [ ] Routing table shows 4 connected routes + default
- [ ] PC-1 → Web LB (10.10.20.5) ping SUCCESS
- [ ] PC-1 → ISP (203.0.113.1) ping SUCCESS
- [ ] Web-1 → PC-1 ping FAIL (DMZ→LAN blocked)
- [ ] Public User → Web LB telnet 80 SUCCESS
- [ ] Public User → PC-1 ping FAIL
- [ ] Admin Host (10.10.0.50) → Router SSH SUCCESS
- [ ] Non-Admin LAN (10.10.10.51) → Router SSH FAIL
- [ ] ACL hit counters incrementing (`show access-lists`)
- [ ] Syslog messages arriving at SIEM (10.10.0.10)
- [ ] NTP sync working (`show ntp associations`)
- [ ] Config saved (`wr` / `copy run start`)

---

## Troubleshooting Common Issues

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| Sub-interface down/down | Trunk not allowing VLAN | Check `switchport trunk allowed vlan` on switch |
| No inter-VLAN routing | `ip routing` missing | `RTR-EDGE(config)# ip routing` |
| ACL not blocking | Applied wrong direction | Check `in` vs `out` on sub-interface |
| PC can't reach gateway | Wrong VLAN on switch port | Verify `switchport access vlan X` |
| SSH fails | No crypto key / vty config | `crypto key generate rsa` + `line vty` config |
| Default route not working | Next-hop not reachable | Ping 203.0.113.1 from router first |

---

## Next Steps After Topology Works

1. **CO2**: Generate traffic (PC-1 → Web-1 HTTP), capture on Router Gi0/0 trunk with Packet Tracer Simulation Mode or Wireshark
2. **CO4**: Export PCAP from Packet Tracer (Simulation Mode → Export), run `detect.py` against it
3. **Documentation**: Screenshot topology, ACL hit counts, verification tests

---

## File Locations
```
network-security-project/
├── router-config/
│   ├── topology.pkt          ← Create in Packet Tracer, save here
│   ├── running-config.txt    ← Full router config (already created)
│   └── cli-log.txt           ← Step-by-step CLI session (already created)
```