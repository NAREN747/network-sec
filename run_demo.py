#!/usr/bin/env python3
"""
Unified Demo Runner — Network Security Project
Runs all 4 Course Outcomes (CO1-CO4) in sequence.
"""

import argparse
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent


def run_co1_architecture():
    """CO1: Perimeter Architecture - Display diagram and policy"""
    print("\n" + "=" * 60)
    print("CO1: PERIMETER ARCHITECTURE")
    print("=" * 60)
    print("Topology: LAN (10.10.10.0/24, VLAN 10) -> DMZ (10.10.20.0/24, VLAN 20)")
    print("          Mgmt (10.10.0.0/24, VLAN 99) -> Internet (203.0.113.0/24)")
    print("\nFiles:")
    print("  architecture/diagram.html     - Dark-themed SVG topology")
    print("  architecture/subnetting.md    - IP plan & VLAN assignments")
    print("  architecture/zone-policy.md   - Zone policy matrix (deny-by-default)")
    print("\nOpen architecture/diagram.html in browser to view topology.")


def run_co2_protocol_stack():
    """CO2: Protocol Stack Analysis - Generate PCAP and analysis"""
    print("\n" + "=" * 60)
    print("CO2: PROTOCOL STACK ANALYSIS")
    print("=" * 60)
    script = PROJECT_ROOT / "protocol-stack" / "live-demo.py"
    if script.exists():
        print(f"Running {script}...")
        subprocess.run([sys.executable, str(script)], cwd=PROJECT_ROOT)
    else:
        print(f"Script not found: {script}")


def run_co3_router_config():
    """CO3: Router Configuration - Show configs and test results"""
    print("\n" + "=" * 60)
    print("CO3: ROUTER CONFIGURATION (Packet Tracer)")
    print("=" * 60)
    print("Topology: PC-LAN --(VLAN10)-- SW-CORE --(Trunk)-- RTR-EDGE --(VLAN20)-- SW-DMZ -- Web-SRV")
    print("                          |")
    print("                          +--(ISP)-- Internet")
    print("\nConfig files:")
    print("  router-config/running-config.txt   - RTR-EDGE full running config")
    print("  router-config/isp-rtr.txt          - ISP-RTR config")
    print("  router-config/sw-core.txt          - SW-CORE config")
    print("  router-config/lab-guide.md         - Step-by-step build guide")
    print("\nKey features:")
    print("  - Router-on-a-Stick (RoAS) with 3 sub-interfaces")
    print("  - 8 named extended ACLs applied inbound per zone")
    print("  - Zone policy enforced: LAN<->DMZ HTTP/HTTPS/DNS, Internet->DMZ web only")
    print("\nVerification tests (run in Packet Tracer):")
    print("  1. PC1 -> ping 10.10.20.5 (Web-1)        [PASS]")
    print("  2. PC1 -> ping 203.0.113.1 (Internet)    [PASS]")
    print("  3. PC2 -> ssh admin@10.10.0.1 (Mgmt)     [BLOCKED]")
    print("  4. Admin -> ssh admin@10.10.0.1           [PASS]")
    print("  5. Web-1 -> ping 10.10.10.50 (LAN)       [BLOCKED]")
    print("  6. PUBLIC-PC -> http://10.10.20.5         [PASS]")
    print("  7. PUBLIC-PC -> ping 10.10.10.50         [BLOCKED]")


def run_co4_threat_detection():
    """CO4: Threat Detection - Run detector on test PCAP"""
    print("\n" + "=" * 60)
    print("CO4: PYTHON THREAT DETECTION ENGINE")
    print("=" * 60)
    script = PROJECT_ROOT / "threat-detection" / "detect.py"
    pcap = PROJECT_ROOT / "threat-detection" / "test.pcapng"
    sigs = PROJECT_ROOT / "threat-detection" / "signatures.yaml"

    if script.exists() and pcap.exists() and sigs.exists():
        print(f"Running detector on {pcap}...")
        subprocess.run([
            sys.executable, str(script),
            "--pcap", str(pcap),
            "--signatures", str(sigs)
        ], cwd=PROJECT_ROOT)
    else:
        print("Required files not found:")
        print(f"  Script: {script.exists()}")
        print(f"  PCAP: {pcap.exists()}")
        print(f"  Signatures: {sigs.exists()}")


def run_all():
    """Run all COs in sequence"""
    run_co1_architecture()
    run_co2_protocol_stack()
    run_co3_router_config()
    run_co4_threat_detection()
    print("\n" + "=" * 60)
    print("ALL COURSE OUTCOMES COMPLETE")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Network Security Project - Unified Demo Runner")
    parser.add_argument("--co1", action="store_true", help="Run CO1: Perimeter Architecture")
    parser.add_argument("--co2", action="store_true", help="Run CO2: Protocol Stack Analysis")
    parser.add_argument("--co3", action="store_true", help="Run CO3: Router Configuration")
    parser.add_argument("--co4", action="store_true", help="Run CO4: Threat Detection")
    parser.add_argument("--all", action="store_true", help="Run all COs (default)")

    args = parser.parse_args()

    if args.co1 or (not any([args.co1, args.co2, args.co3, args.co4, args.all])):
        run_co1_architecture()
    if args.co2 or args.all:
        run_co2_protocol_stack()
    if args.co3 or args.all:
        run_co3_router_config()
    if args.co4 or args.all:
        run_co4_threat_detection()
    if args.all:
        print("\n" + "=" * 60)
        print("ALL COURSE OUTCOMES COMPLETE")
        print("=" * 60)


if __name__ == "__main__":
    main()