"""
scanner/banner.py
Simple banner grabber — connects to an open TCP port and reads
the first 1024 bytes of data the service sends on greeting.
"""
from __future__ import annotations

import socket


_DEFAULT_TIMEOUT = 3.0

# Some services won't send a banner unless we send a probe first.
# Map port → bytes to send before reading.
_PROBES: dict[int, bytes] = {
    80:  b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8080:b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    443: b"",   # SSL handled separately
    21:  b"",   # FTP sends banner on connect
    25:  b"",   # SMTP sends banner on connect
    110: b"",   # POP3
    143: b"",   # IMAP
    23:  b"",   # Telnet
}


def grab_banner(host: str, port: int, timeout: float = _DEFAULT_TIMEOUT) -> str | None:
    """
    Connect to host:port and return the service banner (up to 1024 bytes),
    stripped of non-printable characters.  Returns None on failure.
    """
    probe = _PROBES.get(port, b"")
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if probe:
                sock.sendall(probe)
            data = _recv_until(sock, max_bytes=1024)
        return _clean(data)
    except (OSError, socket.timeout):
        return None


# ──────────────────────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────────────────────

def _recv_until(sock: socket.socket, max_bytes: int) -> bytes:
    """Read from socket until max_bytes received or timeout."""
    buf = b""
    sock.settimeout(2.0)
    try:
        while len(buf) < max_bytes:
            chunk = sock.recv(max_bytes - len(buf))
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    return buf


def _clean(data: bytes) -> str:
    """Decode bytes to string, replacing non-UTF8 bytes."""
    text = data.decode("utf-8", errors="replace")
    # Strip null bytes and condense whitespace
    text = text.replace("\x00", "").strip()
    return text[:512]  # Cap display length
