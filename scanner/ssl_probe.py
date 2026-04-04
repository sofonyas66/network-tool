"""
scanner/ssl_probe.py
SSL/TLS certificate inspector.  Connects to host:port via TLS and
extracts certificate metadata without verifying the chain.
"""
from __future__ import annotations

import datetime
import socket
import ssl
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class SSLInfo:
    host: str
    port: int
    cn: Optional[str] = None
    san: list[str] = None          # type: ignore[assignment]
    issuer: Optional[str] = None
    subject_org: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    self_signed: bool = False
    expired: bool = False
    days_remaining: Optional[int] = None
    protocol: Optional[str] = None
    cipher: Optional[str] = None
    error: Optional[str] = None

    def __post_init__(self):
        if self.san is None:
            self.san = []

    def to_dict(self) -> dict:
        return asdict(self)


def probe_ssl(host: str, port: int = 443, timeout: float = 5.0) -> SSLInfo:
    """
    Connect to host:port via TLS (without verifying the certificate) and
    return an SSLInfo dataclass with all metadata.
    """
    info = SSLInfo(host=host, port=port)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                info.protocol = tls.version()
                cipher_info = tls.cipher()
                info.cipher = cipher_info[0] if cipher_info else None

                cert = tls.getpeercert()
                if not cert:
                    info.error = "No certificate returned"
                    return info

                # Common Name
                for rdn in cert.get("subject", []):
                    for key, val in rdn:
                        if key == "commonName":
                            info.cn = val
                        elif key == "organizationName":
                            info.subject_org = val

                # Issuer
                issuer_parts = []
                for rdn in cert.get("issuer", []):
                    for key, val in rdn:
                        if key in ("organizationName", "commonName"):
                            issuer_parts.append(val)
                info.issuer = " / ".join(issuer_parts) if issuer_parts else None

                # SANs
                for name_type, value in cert.get("subjectAltName", []):
                    if name_type == "DNS":
                        info.san.append(value)

                # Validity window
                fmt = "%b %d %H:%M:%S %Y %Z"
                nb_raw = cert.get("notBefore", "")
                na_raw = cert.get("notAfter", "")
                now = datetime.datetime.now(datetime.timezone.utc)

                if nb_raw:
                    nb = datetime.datetime.strptime(nb_raw, fmt)
                    info.not_before = nb.isoformat()
                if na_raw:
                    na = datetime.datetime.strptime(na_raw, fmt)
                    info.not_after = na.isoformat()
                    delta = na - now
                    info.days_remaining = delta.days
                    info.expired = delta.days < 0

                # Self-signed: subject CN == issuer CN
                subject_cns = [
                    v for rdn in cert.get("subject", [])
                    for k, v in rdn if k == "commonName"
                ]
                issuer_cns = [
                    v for rdn in cert.get("issuer", [])
                    for k, v in rdn if k == "commonName"
                ]
                info.self_signed = bool(
                    subject_cns and issuer_cns and subject_cns == issuer_cns
                )

    except ssl.SSLError as exc:
        info.error = f"SSL error: {exc}"
    except OSError as exc:
        info.error = f"Connection error: {exc}"
    except Exception as exc:
        info.error = f"Unexpected error: {exc}"

    return info
