"""
scanner/fingerprint.py
Behavioral OS/kernel fingerprinting based on TTL, window size, and TCP options.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Tuple, Any
import statistics

# ──────────────────────────────────────────────────────────────
#  Known TCP/IP stack signature database
#  Keys: (window_size, mss) — None means "any"
# ──────────────────────────────────────────────────────────────
_SIGS: list[dict] = [
    # Linux 4.x / 5.x / 6.x kernel (common desktop & server)
    {"os": "Linux 4.x/5.x/6.x", "ttl": 64,  "window": 65535, "mss": None,  "wscale": 7,  "virtualized": False},
    {"os": "Linux 4.x/5.x/6.x", "ttl": 64,  "window": 29200, "mss": 1460,  "wscale": 7,  "virtualized": False},
    {"os": "Linux 4.x/5.x/6.x", "ttl": 64,  "window": 43690, "mss": 1460,  "wscale": 7,  "virtualized": False},
    # Linux inside Docker / LXC container
    {"os": "Linux (Container)",  "ttl": 64,  "window": 65535, "mss": 1460,  "wscale": None, "virtualized": True},
    # Linux inside KVM / VMware
    {"os": "Linux (KVM/VMware)", "ttl": 64,  "window": 65535, "mss": 1460,  "wscale": 8,   "virtualized": True},
    # Windows 10/11 / Server 2019+
    {"os": "Windows 10/11/2019+","ttl": 128, "window": 65535, "mss": 1460,  "wscale": 8,   "virtualized": False},
    {"os": "Windows 10/11/2019+","ttl": 128, "window": 64240, "mss": 1460,  "wscale": 8,   "virtualized": False},
    # Windows Server 2008/2012
    {"os": "Windows Server 2008/2012","ttl": 128,"window": 8192,"mss": 1460,"wscale": None,"virtualized": False},
    # FreeBSD / macOS
    {"os": "FreeBSD/macOS",      "ttl": 64,  "window": 65535, "mss": 1460,  "wscale": 6,   "virtualized": False},
    # OpenBSD
    {"os": "OpenBSD",            "ttl": 255, "window": 16384, "mss": None,  "wscale": None, "virtualized": False},
    # Cisco IOS
    {"os": "Cisco IOS",          "ttl": 255, "window": 4128,  "mss": 536,   "wscale": None, "virtualized": False},
    # Embedded / IoT
    {"os": "Embedded/IoT Linux", "ttl": 64,  "window": 5840,  "mss": 536,   "wscale": None, "virtualized": False},
]

# Standard initial TTL values by OS family
_EXPECTED_TTLS = [64, 128, 255]


@dataclass
class FingerprintResult:
    os_guess: str = "Unknown"
    ttl_observed: int = 0
    ttl_expected: int = 0
    hop_distance: int = 0
    window_size: int = 0
    mss: Optional[int] = None
    wscale: Optional[int] = None
    virtualized: bool = False
    load_balancer_suspected: bool = False
    confidence: str = "low"       # low / medium / high
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class Fingerprinter:
    """
    Stateless fingerprinting helper.  Call `analyze()` with the raw TCP
    header fields extracted from a SYN-ACK response.
    """

    @staticmethod
    def _nearest_base_ttl(observed: int) -> int:
        """Return the most likely initial TTL for the observed value."""
        candidates = [t for t in _EXPECTED_TTLS if t >= observed]
        return min(candidates) if candidates else 255

    @staticmethod
    def _parse_tcp_options(opts: List[Tuple[str, Any]]) -> Tuple[Optional[int], Optional[int]]:
        """Return (mss, wscale) extracted from a Scapy TCP options list."""
        mss = wscale = None
        for name, val in (opts or []):
            if name == "MSS":
                mss = int(val)
            elif name == "WScale":
                wscale = int(val)
        return mss, wscale

    @staticmethod
    def analyze(
        ttl: int,
        window: int,
        options: Optional[List[Tuple[str, Any]]] = None,
        ttl_samples: Optional[List[int]] = None,
    ) -> FingerprintResult:
        """
        Analyze a single SYN-ACK response and return a FingerprintResult.

        Parameters
        ----------
        ttl          : Observed IP TTL from the response packet.
        window       : TCP window size from the response.
        options      : Scapy-style list of (name, value) TCP options.
        ttl_samples  : Multiple TTL observations across packets to the same
                       target — used for load-balancer detection.
        """
        result = FingerprintResult(ttl_observed=ttl, window_size=window)

        mss, wscale = Fingerprinter._parse_tcp_options(options or [])
        result.mss = mss
        result.wscale = wscale

        # ── Hop distance ─────────────────────────────────────────────────
        base_ttl = Fingerprinter._nearest_base_ttl(ttl)
        result.ttl_expected = base_ttl
        result.hop_distance = base_ttl - ttl
        if result.hop_distance < 0:
            result.hop_distance = 0
            result.notes.append("TTL anomaly: observed TTL exceeds expected base — possible spoofing.")

        # ── Load-balancer detection ───────────────────────────────────────
        if ttl_samples and len(ttl_samples) >= 3:
            variance = statistics.stdev(ttl_samples)
            if variance >= 2:
                result.load_balancer_suspected = True
                result.notes.append(
                    f"TTL variance {variance:.1f} across {len(ttl_samples)} samples — load balancer suspected."
                )

        # ── Signature matching ────────────────────────────────────────────
        best_score = -1
        best_sig = None
        for sig in _SIGS:
            score = 0
            # TTL match against nearest base
            if Fingerprinter._nearest_base_ttl(ttl) == sig["ttl"]:
                score += 3
            # Window match
            if window == sig["window"]:
                score += 3
            # MSS match (if sig specifies)
            if sig["mss"] is not None and mss == sig["mss"]:
                score += 2
            # WScale match (if sig specifies)
            if sig["wscale"] is not None and wscale == sig["wscale"]:
                score += 1
            if score > best_score:
                best_score = score
                best_sig = sig

        if best_sig:
            result.os_guess = best_sig["os"]
            result.virtualized = best_sig["virtualized"]
            if best_score >= 7:
                result.confidence = "high"
            elif best_score >= 4:
                result.confidence = "medium"
            else:
                result.confidence = "low"

        return result
