#!/usr/bin/env python3
"""
Network Security Project - Unified Demo Runner
Runs all components as a single integrated demo.
"""

import subprocess
import sys
import os
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent

def run(cmd, cwd=None, desc=""):
    """Run command and show output."""
    print(f"\n{'='*60}")
    print(f"▶ {desc or cmd}")
    print(f"{'='*60}")
    result = subprocess.run(cmd, shell=True, cwd=cwd or PROJECT_ROOT, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr and result.returncode != 0:
        print(f"STDERR: {result.stderr}", file=sys.stderr)
    return result.returncode == 0

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║     NETWORK SECURITY PROJECT — UNIFIED DEMO                  ║
║     Perimeter Architecture | Protocol Analysis | Router      ║
║     Config | Threat Detection — Single Pipeline               ║
╚══════════════════════════════════════════════════════════════╝
""")

    # 1. Install dependencies
    print("\n📦 Installing dependencies...")
    run("pip install -q pyyaml scapy", desc="Install pyyaml, scapy")

    # 2. Architecture: Open diagram (non-blocking)
    print("\n🏗️  CO1: Perimeter Architecture")
    diagram = PROJECT_ROOT / "architecture" / "diagram.html"
    if diagram.exists():
        print(f"   Diagram: {diagram}")
        print("   Opening in browser...")
        if sys.platform == "win32":
            os.startfile(str(diagram))
        else:
            subprocess.Popen(["xdg-open", str(diagram)])
    else:
        print("   ⚠️  diagram.html not found")

    # 3. Protocol Stack: Generate PCAP + Analysis
    print("\n📡 CO2: Protocol Stack Analysis")
    ok = run(
        "python protocol-stack/live-demo.py",
        cwd=PROJECT_ROOT,
        desc="Generate HTTP flow PCAP + analysis.md"
    )
    if not ok:
        print("   ⚠️  Protocol stack generation had issues")

    # 4. Threat Detection: Generate test PCAP with attacks
    print("\n🛡️  CO4: Threat Detection — Generate Test Traffic")
    run(
        "python threat-detection/detect.py --generate-test --output threat-detection/test.pcapng",
        cwd=PROJECT_ROOT,
        desc="Create test PCAP with XSS, SQLi, Path Traversal, CMD Injection, Port Scan"
    )

    # 5. Threat Detection: Run on generated attack PCAP
    print("\n🔍 CO4: Threat Detection — Scan Attack PCAP")
    run(
        "python threat-detection/detect.py --pcap threat-detection/test.pcapng",
        cwd=PROJECT_ROOT,
        desc="Detect threats in generated test traffic"
    )

    # 6. Threat Detection: Run on protocol-stack capture
    print("\n🔍 CO4: Threat Detection — Scan Protocol Stack PCAP")
    pcap_path = PROJECT_ROOT / "protocol-stack" / "pcap" / "http-flow.pcapng"
    if pcap_path.exists():
        run(
            f"python threat-detection/detect.py --pcap {pcap_path}",
            cwd=PROJECT_ROOT,
            desc="Detect threats in normal HTTP flow (should be clean)"
        )

    # 7. Show Router Config summary
    print("\n🔧 CO3: Router Configuration")
    config = PROJECT_ROOT / "router-config" / "running-config.txt"
    if config.exists():
        lines = config.read_text().splitlines()
        print(f"   Config: {config} ({len(lines)} lines)")
        print("   Key sections:")
        for line in lines:
            if line.strip().startswith(("hostname", "interface", "ip access-list", "ip route")):
                print(f"     {line.strip()}")
    else:
        print("   ⚠️  running-config.txt not found")

    # 8. Summary
    print("""
╔══════════════════════════════════════════════════════════════╗
║     DEMO COMPLETE                                            ║
╠══════════════════════════════════════════════════════════════╣
║  Generated Files:                                            ║
║    protocol-stack/pcap/http-flow.pcapng   - Normal HTTP flow ║
║    protocol-stack/analysis.md             - Layer analysis   ║
║    threat-detection/test.pcapng           - Attack traffic   ║
║    architecture/diagram.html              - Interactive topo ║
║    router-config/running-config.txt       - Cisco IOS config ║
║                                                              ║
║  Next Steps:                                                 ║
║    1. Open diagram.html in browser for topology              ║
║    2. Build topology in Packet Tracer using                  ║
║       router-config/topology-build-guide.md                  ║
║    3. Load test.pcapng in Wireshark to inspect attacks       ║
║    4. Run: python threat-detection/detect.py --live <iface>  ║
╚══════════════════════════════════════════════════════════════╝
""")

if __name__ == "__main__":
    main()