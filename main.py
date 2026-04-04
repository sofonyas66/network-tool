"""
main.py
CLI entry point for the Behavioral Network Fingerprinting Tool.

Usage:
    sudo python3 main.py --target 192.168.1.1 --ports 1-1024
    sudo python3 main.py --target 192.168.1.1 --ports 22,80,443 --decoy --dashboard
    sudo python3 main.py --range 192.168.1.0/24 --ports 80,443 --output results.json
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import sys
import threading
import time
import webbrowser
from functools import partial
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Any

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

DASHBOARD_DIR = Path(__file__).parent / "dashboard"
_scan_results: list[dict] = []   # Shared results store for the dashboard server


# ──────────────────────────────────────────────────────────────────────────────
#  Argument parsing
# ──────────────────────────────────────────────────────────────────────────────

def parse_ports(port_str: str) -> list[int]:
    """Parse '22,80,443' or '1-1024' or '22,80,8000-9000' into a list."""
    ports: set[int] = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def parse_targets(args: argparse.Namespace) -> list[str]:
    """Return a flat list of IP strings to scan."""
    targets: list[str] = []
    if args.target:
        targets.append(args.target)
    if args.range:
        net = ipaddress.ip_network(args.range, strict=False)
        targets.extend(str(h) for h in net.hosts())
    return targets


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netfp",
        description="Behavioral Network Fingerprinting Tool — SYN scan + OS fingerprint + 3D dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 main.py --target 192.168.1.1 --ports 1-1024
  sudo python3 main.py --range 10.0.0.0/24 --ports 22,80,443 --dashboard
  sudo python3 main.py --target 10.0.0.1 --ports 80,443 --decoy --output out.json
""",
    )
    # Target
    tgt = p.add_argument_group("Target")
    tgt.add_argument("--target", metavar="IP",    help="Single target IP address")
    tgt.add_argument("--range",  metavar="CIDR",  help="Target CIDR range (e.g. 192.168.1.0/24)")
    # Ports
    p.add_argument("--ports", default="1-1024", metavar="PORTS",
                   help="Ports to scan: '22,80,443' or '1-1024' (default: 1-1024)")
    # Scan options
    p.add_argument("--rate",    type=float, default=100.0, metavar="PPS",
                   help="Packets per second (Poisson mean, default: 100)")
    p.add_argument("--timeout", type=float, default=2.0,   metavar="SECS",
                   help="Seconds to wait after final packet (default: 2)")
    p.add_argument("--iface",   metavar="IFACE",
                   help="Network interface to use (default: auto-detect)")
    # Modules
    p.add_argument("--banner",  action="store_true", help="Grab service banners on open ports")
    p.add_argument("--ssl",     action="store_true", help="Probe TLS certificates on port 443")
    p.add_argument("--decoy",   action="store_true",
                   help="Enable decoy mode (inject spoofed packets) — USE ONLY ON AUTHORIZED TARGETS")
    # Output / UI
    p.add_argument("--dashboard", action="store_true",
                   help="Launch the 3D web dashboard after scan")
    p.add_argument("--output",  metavar="FILE",
                   help="Save JSON results to file")
    # Misc
    p.add_argument("--legacy",  action="store_true",
                   help="Legacy mode: limit CPU/RAM usage (<50MB), slower scan rate")
    p.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return p


# ──────────────────────────────────────────────────────────────────────────────
#  Dashboard HTTP server
# ──────────────────────────────────────────────────────────────────────────────

class DashboardHandler(SimpleHTTPRequestHandler):
    """Serve static dashboard files + a /results JSON API endpoint."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DASHBOARD_DIR), **kwargs)

    def do_GET(self):
        if self.path == "/results":
            body = json.dumps(_scan_results).encode()
            self.send_response(200)
            self.send_header("Content-Type",   "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
        else:
            super().do_GET()

    def log_message(self, fmt, *args):  # suppress access logs
        pass


def start_dashboard_server(host: str = "127.0.0.1", port: int = 8765) -> HTTPServer:
    server = HTTPServer((host, port), DashboardHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


# ──────────────────────────────────────────────────────────────────────────────
#  Main scan orchestration
# ──────────────────────────────────────────────────────────────────────────────

def scan_target(
    ip: str,
    ports: list[int],
    args: argparse.Namespace,
    decoy_engine=None,
) -> dict:
    from scanner.engine import SynScanner

    log.info("↗  Scanning %s  [%d ports]", ip, len(ports))

    scanner = SynScanner(
        target=ip,
        ports=ports,
        timeout=args.timeout,
        rate=args.rate if not args.legacy else min(args.rate, 10),
        iface=args.iface,
        legacy=args.legacy,
    )

    # If decoy mode is active, monkey-patch the sender to inject decoys first
    if decoy_engine:
        _wrap_sender_with_decoys(scanner, decoy_engine, ip)

    result = scanner.run()

    # ── Post-processing on open ports ────────────────────────────
    open_ports = [pr for pr in result.ports if pr.state == "open"]
    log.info("   ✓  %s — %d open port(s)", ip, len(open_ports))

    for pr in open_ports:
        if args.banner:
            from scanner.banner import grab_banner
            pr.banner = grab_banner(ip, pr.port)

        if args.ssl and pr.port == 443:
            from scanner.ssl_probe import probe_ssl
            pr.ssl_info = probe_ssl(ip, 443).to_dict()

    return result.to_dict()


def _wrap_sender_with_decoys(scanner, decoy_engine, ip: str):
    """
    Patch SynScanner._sender so DecoyEngine.inject_decoys() is called
    before each real SYN packet is sent.
    """
    original_sender = scanner._sender

    def patched_sender(seq_to_port):
        from scapy.all import IP, TCP, send, conf  # type: ignore
        import random, time

        conf.verb = 0
        mean_interval = 1.0 / max(scanner.rate, 1)

        for seq, pr in seq_to_port.items():
            decoy_engine.inject_decoys(ip, pr.port)

            pkt = (
                IP(dst=ip)
                / TCP(
                    dport=pr.port,
                    sport=random.randint(1024, 65535),
                    seq=seq,
                    flags="S",
                    window=65535,
                    options=[
                        ("MSS", 1460),
                        ("SAckOK", ""),
                        ("Timestamp", (int(time.time() * 1000) & 0xFFFFFFFF, 0)),
                        ("NOP", None),
                        ("WScale", 7),
                    ],
                )
            )
            try:
                send(pkt, iface=scanner.iface, verbose=False)
            except Exception as exc:
                log.warning("Send error on port %d: %s", pr.port, exc)

            sleep_time = random.expovariate(1.0 / mean_interval)
            if scanner.legacy:
                sleep_time = max(sleep_time, 0.1)
            time.sleep(sleep_time)

        scanner._done_sending.set()

    scanner._sender = patched_sender


# ──────────────────────────────────────────────────────────────────────────────
#  Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.target and not args.range:
        parser.error("Specify at least one of --target or --range")

    targets = parse_targets(args)
    if not targets:
        log.error("No valid target IPs resolved.")
        return 1

    ports = parse_ports(args.ports)
    log.info("Targets: %d IP(s)  |  Ports: %d  |  Rate: %.0f pps", len(targets), len(ports), args.rate)

    # Decoy warning
    if args.decoy:
        log.warning("⚠  DECOY MODE ENABLED — Ensure you are authorized to scan %s", ", ".join(targets))
        from scanner.decoy import DecoyEngine
        decoy_engine = DecoyEngine(iface=args.iface)
    else:
        decoy_engine = None

    # Dashboard server (start early so it's ready when scan finishes)
    server = None
    if args.dashboard:
        server = start_dashboard_server()
        log.info("🌐  Dashboard ready at http://127.0.0.1:8765")

    # Run scans
    for ip in targets:
        try:
            result = scan_target(ip, ports, args, decoy_engine=decoy_engine)
            _scan_results.append(result)
        except PermissionError as e:
            log.error("%s", e)
            return 1
        except Exception as e:
            log.error("Scan failed for %s: %s", ip, e)

    # Save JSON output
    if args.output:
        out_path = Path(args.output)
        out_path.write_text(json.dumps(_scan_results, indent=2))
        log.info("💾  Results saved to %s", out_path)

    # Pretty-print summary to terminal
    _print_summary(_scan_results)

    # Open dashboard in browser
    if args.dashboard and server:
        webbrowser.open("http://127.0.0.1:8765")
        log.info("Press Ctrl+C to stop the dashboard server.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("Shutting down.")
            server.shutdown()

    return 0


def _print_summary(results: list[dict]) -> None:
    print("\n" + "═" * 60)
    print("  SCAN SUMMARY")
    print("═" * 60)
    for host in results:
        ip = host.get("target", "?")
        open_ports = [p for p in host.get("ports", []) if p["state"] == "open"]
        print(f"\n  Host: {ip}  ({len(open_ports)} open port(s))")
        for p in open_ports:
            fp  = p.get("fingerprint") or {}
            os_ = fp.get("os_guess", "Unknown")
            conf_ = fp.get("confidence", "?")
            virt = "🐳 " if fp.get("virtualized") else ""
            lb   = "⚡LB " if fp.get("load_balancer_suspected") else ""
            banner = p.get("banner") or ""
            ssl_  = p.get("ssl_info") or {}
            cn    = ssl_.get("cn", "")
            exp   = "⚠ EXPIRED" if ssl_.get("expired") else ""
            ss    = "⚠ SELF-SIGNED" if ssl_.get("self_signed") else ""

            line = f"    [{p['state'].upper():8}] :{p['port']:<6} {virt}{lb}{os_} ({conf_})"
            if banner:
                line += f"\n             Banner: {banner[:80]}"
            if cn:
                line += f"\n             TLS CN: {cn}  days_left={ssl_.get('days_remaining','?')} {exp}{ss}"
            print(line)
    print("\n" + "═" * 60 + "\n")


if __name__ == "__main__":
    sys.exit(main())
