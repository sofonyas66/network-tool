"""
scanner/engine.py
Non-blocking SYN scanner using Scapy.

Two threads run concurrently:
  - Sender  : crafts IP/TCP SYN packets with Poisson-jittered timing
  - Sniffer : captures SYN-ACK / RST-ACK replies via AsyncSniffer

Sequence numbers are used to correlate requests ↔ responses.
"""
from __future__ import annotations

import logging
import os
import random
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

# Scapy is imported inside functions to allow the rest of the app to load
# without root privileges when only the banner or SSL modules are used.
try:
    from scapy.all import (  # type: ignore
        IP, TCP, AsyncSniffer, conf, send
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from .fingerprint import Fingerprinter, FingerprintResult


@dataclass
class PortResult:
    ip: str
    port: int
    state: str = "filtered"          # open / closed / filtered
    banner: Optional[str] = None
    ssl_info: Optional[dict] = None
    fingerprint: Optional[dict] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


@dataclass
class ScanResult:
    target: str
    ttl_samples: List[int] = field(default_factory=list)
    ports: List[PortResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "ttl_samples": self.ttl_samples,
            "ports": [p.to_dict() for p in self.ports],
        }


class SynScanner:
    """
    Performs a raw-socket SYN scan of one host across a list of ports.

    Parameters
    ----------
    target    : Destination IP address string.
    ports     : List of port numbers to scan.
    timeout   : Seconds to wait after the last packet for straggler replies.
    rate      : Average SYN packets per second (Poisson mean interval = 1/rate).
    iface     : Network interface to bind to (None = Scapy auto-detect).
    legacy    : Limit resource usage (100 ms inter-packet floor, serial send).
    """

    def __init__(
        self,
        target: str,
        ports: List[int],
        timeout: float = 2.0,
        rate: float = 100.0,
        iface: Optional[str] = None,
        legacy: bool = False,
    ) -> None:
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is not installed. Run: pip install scapy")
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.rate = rate
        self.iface = iface
        self.legacy = legacy

        # seq_num → PortResult mapping so sniffer can correlate responses
        self._pending: Dict[int, PortResult] = {}
        self._lock = threading.Lock()
        self._done_sending = threading.Event()

        # Collect TTL values for load-balancer analysis
        self._ttl_samples: List[int] = []

    # ──────────────────────────────────────────────────────────────
    #  Public API
    # ──────────────────────────────────────────────────────────────

    def run(self) -> ScanResult:
        """Execute the scan and return a ScanResult."""
        if os.geteuid() != 0:
            raise PermissionError(
                "Raw socket SYN scan requires root privileges. Run with sudo."
            )
        result = ScanResult(target=self.target)

        # Pre-populate results dict
        for port in self.ports:
            pr = PortResult(ip=self.target, port=port)
            seq = random.randint(1_000_000, 2_147_483_647)
            with self._lock:
                self._pending[seq] = pr
            result.ports.append(pr)

        # Build a quick seq → PortResult lookup (won't change after this)
        seq_to_port = dict(self._pending)

        # ── Sniffer ───────────────────────────────────────────────
        bpf = f"tcp and src host {self.target}"
        sniffer = AsyncSniffer(
            filter=bpf,
            prn=lambda pkt: self._handle_reply(pkt, seq_to_port),
            iface=self.iface,
            store=False,
        )
        sniffer.start()

        # ── Sender ────────────────────────────────────────────────
        sender_thread = threading.Thread(
            target=self._sender, args=(seq_to_port,), daemon=True
        )
        sender_thread.start()
        sender_thread.join()

        # Wait for straggler replies
        time.sleep(self.timeout)
        sniffer.stop()

        result.ttl_samples = list(self._ttl_samples)
        return result

    # ──────────────────────────────────────────────────────────────
    #  Internal helpers
    # ──────────────────────────────────────────────────────────────

    def _sender(self, seq_to_port: Dict[int, PortResult]) -> None:
        """Send SYN packets with Poisson-distributed inter-packet jitter."""
        mean_interval = 1.0 / max(self.rate, 1)
        conf.verb = 0  # suppress Scapy output

        for seq, pr in seq_to_port.items():
            pkt = (
                IP(dst=self.target)
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
                send(pkt, iface=self.iface, verbose=False)
            except Exception as exc:
                log.warning("Send error on port %d: %s", pr.port, exc)

            # Poisson jitter: sleep time drawn from exponential distribution
            sleep_time = random.expovariate(1.0 / mean_interval)
            if self.legacy:
                sleep_time = max(sleep_time, 0.1)  # floor at 100ms in legacy mode
            time.sleep(sleep_time)

        self._done_sending.set()

    def _handle_reply(self, pkt: Any, seq_to_port: Dict[int, PortResult]) -> None:
        """Callback invoked by AsyncSniffer for each captured packet."""
        try:
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                return

            ip_layer  = pkt.getlayer(IP)
            tcp_layer = pkt.getlayer(TCP)

            # Only care about packets from our target
            if ip_layer.src != self.target:
                return

            # The target echoes our ISN as its ack_num - 1
            their_ack = tcp_layer.ack
            original_seq = their_ack - 1

            with self._lock:
                pr = seq_to_port.get(original_seq)

            if pr is None:
                return  # Not our packet

            flags = tcp_layer.flags
            ttl   = ip_layer.ttl

            # Collect TTL for load-balancer analysis
            self._ttl_samples.append(ttl)

            if flags & 0x12:  # SYN-ACK → OPEN
                pr.state = "open"
                # Run fingerprinter
                fp = Fingerprinter.analyze(
                    ttl=ttl,
                    window=tcp_layer.window,
                    options=tcp_layer.options,
                    ttl_samples=self._ttl_samples,
                )
                pr.fingerprint = fp.to_dict()

                # Send RST to close the half-open connection gracefully
                rst = (
                    IP(dst=self.target)
                    / TCP(
                        dport=pr.port,
                        sport=tcp_layer.dport,
                        seq=their_ack,
                        flags="R",
                    )
                )
                try:
                    send(rst, iface=self.iface, verbose=False)
                except Exception:
                    pass

            elif flags & 0x14:  # RST-ACK → CLOSED
                pr.state = "closed"

        except Exception as exc:
            log.debug("Reply handler error: %s", exc)
