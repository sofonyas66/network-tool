"""
scanner/decoy.py
Decoy module — for every real SYN packet, inject N decoy SYN packets
with spoofed source IPs to obscure the true scanner.

⚠  WARNING: Sending spoofed packets at targets you do not own is illegal
   in most jurisdictions.  Use ONLY on networks/hosts you are authorized
   to test.  This module requires root privileges.
"""
from __future__ import annotations

import random
import logging
import time

log = logging.getLogger(__name__)

_DECOY_POOLS: list[tuple[int, int, int, int]] = [
    # Google Public DNS range (8.8.x.x)
    (8, 8, 0, 255),
    # Cloudflare (1.1.x.x)
    (1, 1, 0, 255),
    # AWS (52.x.x.x)
    (52, 0, 0, 255),
    # Akamai (23.x.x.x)
    (23, 0, 0, 255),
    # NASA (128.102.x.x)
    (128, 102, 0, 255),
]


def _random_decoy_ip() -> str:
    """Pick a random IP from the decoy pool."""
    a, b, c_max, d_max = random.choice(_DECOY_POOLS)
    c = random.randint(0, c_max)
    d = random.randint(1, d_max)
    return f"{a}.{b}.{c}.{d}"


class DecoyEngine:
    """
    Wraps a SYN scan with decoy injection.

    Parameters
    ----------
    n_decoys : Number of decoy packets per real packet (default 5).
    iface    : Network interface to use.
    """

    def __init__(self, n_decoys: int = 5, iface: str | None = None) -> None:
        self.n_decoys = n_decoys
        self.iface = iface

        try:
            from scapy.all import IP, TCP, send  # type: ignore
            self._IP = IP
            self._TCP = TCP
            self._send = send
        except ImportError:
            raise RuntimeError("Scapy is required for decoy mode. pip install scapy")

    def inject_decoys(self, real_dst: str, real_port: int) -> None:
        """
        Fire n_decoys SYN packets from random spoofed source IPs toward
        the same destination and port, immediately before the real packet.
        """
        for _ in range(self.n_decoys):
            src = _random_decoy_ip()
            pkt = (
                self._IP(src=src, dst=real_dst)
                / self._TCP(
                    sport=random.randint(1024, 65535),
                    dport=real_port,
                    seq=random.randint(100_000, 2_147_483_647),
                    flags="S",
                    window=random.choice([8192, 16384, 65535]),
                )
            )
            try:
                self._send(pkt, iface=self.iface, verbose=False)
            except Exception as exc:
                log.debug("Decoy send error (%s→%s:%d): %s", src, real_dst, real_port, exc)

            # Small gap so decoys and real packet don't bunch together
            time.sleep(random.uniform(0.001, 0.005))
