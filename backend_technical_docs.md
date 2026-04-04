# NetFP Backend Technical Documentation

This document covers the core backend architecture and components of the **Behavioral Network Fingerprinting Tool (NetFP)**. The system is designed to perform stealthy, asynchronous network scanning and passive target profiling using raw sockets.

---

## 1. Core Architecture Overview

The backend uses a **custom, non-blocking SYN scanner** written in Python using `scapy`. 
Standard `connect()` scans rely on the host OS's TCP/IP stack to complete the 3-way handshake, which is easily logged by target systems and takes considerable time. This tool bypasses the OS stack entirely by crafting raw IP/TCP packets, sending solitary `SYN` frames, and sniffing for the raw `SYN-ACK` responses on the wire.

### Data Flow Pattern
1. **Target Parsing ([main.py](file:///home/klythron/Documents/network-tool/main.py))**: Resolves CIDR ranges to individual IP addresses and parses port lists.
2. **Scanner Orchestration ([main.py](file:///home/klythron/Documents/network-tool/main.py))**: Iterates through targets and invokes the [SynScanner](file:///home/klythron/Documents/network-tool/scanner/engine.py#64-251).
3. **Execution ([engine.py](file:///home/klythron/Documents/network-tool/scanner/engine.py))**: Two isolated threads (Sender and Sniffer) operate concurrently on raw sockets.
4. **Post-Processing**: Open ports are relayed to [banner.py](file:///home/klythron/Documents/network-tool/scanner/banner.py) and [ssl_probe.py](file:///home/klythron/Documents/network-tool/scanner/ssl_probe.py) for application-layer analysis.
5. **UI Relay**: Final results are dumped to stdout, JSON files, or stored in memory for the Dashboard API endpoint.

---

## 2. Scapy Engine ([scanner/engine.py](file:///home/klythron/Documents/network-tool/scanner/engine.py))

The heartbeat of the tool is the [SynScanner](file:///home/klythron/Documents/network-tool/scanner/engine.py#64-251) class, which manages raw socket I/O using Scapy's `AsyncSniffer` and [send()](file:///home/klythron/Documents/network-tool/scanner/engine.py#155-190).

### Asynchronous Concurrency Model
The engine operates using an asynchronous send/receive split model rather than waiting for individual port responses sequentially:
- **Sniffer Thread (`AsyncSniffer`)**: Starts capturing *first*, using a tight BPF filter (`tcp and src host <target>`). It runs asynchronously and invokes a callback hook [_handle_reply()](file:///home/klythron/Documents/network-tool/scanner/engine.py#191-251) for every packet.
- **Sender Thread ([_sender](file:///home/klythron/Documents/network-tool/scanner/engine.py#155-190))**: Generates and sends `SYN` packets one after the other.

### Stateful Correlation via Sequence Numbers
Since packets are sent concurrently, the Sniffer needs a reliable method to figure out which received `SYN-ACK` corresponds to which requested port. This is solved statelessly:
1. When generating a request, the Sender assigns a random, unique **Sequence Number (ISN)** to the packet (`seq=seq`).
2. It registers this `seq` in a thread-safe `_pending` dictionary mapped to a [PortResult](file:///home/klythron/Documents/network-tool/scanner/engine.py#36-48) object.
3. According to RFC 793, when the target responds with a `SYN-ACK`, it sets its Acknowledgment Number (`ack`) to the initiator's Sequence Number **+ 1**.
4. The Sniffer reads the incoming `ack`, subtracts 1, and retrieves the corresponding [PortResult](file:///home/klythron/Documents/network-tool/scanner/engine.py#36-48) state.

### Evasion & Stealth (Poisson Jitter)
To bypass simple rate limiting and Intrusion Detection Systems (IDS), the Sender thread does not send packets at constant intervals. Instead, the inter-packet delay is drawn from an **exponential distribution** derived from the desired packet rate (`random.expovariate(1.0 / mean_interval)`). This creates a realistic, Poisson-distributed arrival time for bursts that blends in with legitimate network traffic patterns.

---

## 3. Behavioral OS Fingerprinting ([scanner/fingerprint.py](file:///home/klythron/Documents/network-tool/scanner/fingerprint.py))

Instead of sending malformed packets or utilizing active OS detection techniques (like nmap's OS scan module), NetFP relies exclusively on **Passive Fingerprinting** analyzing the TCP fields returned natively during the handshake.

The [Fingerprinter](file:///home/klythron/Documents/network-tool/scanner/fingerprint.py#60-156) extracts several TCP/IP stack "signatures":
- **`TTL` (Time To Live)**: Used to determine OS family and hop distance.
  - Linux typically bases TTL on 64.
  - Windows typically uses 128.
  - Cisco/Networking gear uses 255.
- **TCP Window Size**: Varies drastically between operating systems (e.g., Linux common `65535` or `29200` vs Windows Server `8192`).
- **TCP Options (`MSS`, `WScale`)**: Network stack configurations are often unique to specific kernel versions.

### Load Balancer Detection
The backend keeps an array of observed `TTL` values `_ttl_samples` across all packets from a single target machine. 
If the standard deviation of `TTL` instances exceeds a defined threshold (`variance >= 2`), it strongly suggests that the target IP is an Anycast gateway or Load Balancer proxying traffic to multiple backend servers located at drastically different hop distances.

---

## 4. Decoy Injection ([scanner/decoy.py](file:///home/klythron/Documents/network-tool/scanner/decoy.py))

When the `--decoy` flag is enabled, the tool obscures the user's real IP address from target logs.

The [DecoyEngine](file:///home/klythron/Documents/network-tool/scanner/decoy.py#40-86) works by **monkey-patching** the [_sender](file:///home/klythron/Documents/network-tool/scanner/engine.py#155-190) method inside the [engine.py](file:///home/klythron/Documents/network-tool/scanner/engine.py). For every legitimate `SYN` packet launched at the target, the engine fires a rapid volley of `N` spoofed packets utilizing randomized source IPs (e.g., Google DNS range `8.8.x.x` or AWS IPs `52.x.x.x`). 
This forces a target firewall administrator to manually parse thousands of logs to determine the true scanner amongst crowds of randomly spoofed noise. 

*Note: Since the source IP is forged, the responses for decoy packets are routed back to the spoofed entity, not the scanner.*

---

## 5. Application-Layer Probes

If a port is verified as [open](file:///home/klythron/Documents/network-tool/dashboard/app.js#183-190) via the SYN scan, [main.py](file:///home/klythron/Documents/network-tool/main.py) conditionally invokes specialized analyzers. Note that these utilize standard Python `socket` connections rather than raw packets to negotiate the full 3-way handshake and communicate application data.

### Banner Grabber ([scanner/banner.py](file:///home/klythron/Documents/network-tool/scanner/banner.py))
- Initiates a brief connection.
- Holds a hardcoded array of protocol probes (`_PROBES`). For example, if checking Port 80, it actively fires a `GET / HTTP/1.0` payload to bait the web server into returning a `Server:` header.
- Decodes the first 1024 bytes and cleans any anomalous UTF-8 characters.

### TLS / SSL Inspector ([scanner/ssl_probe.py](file:///home/klythron/Documents/network-tool/scanner/ssl_probe.py))
- Designed specifically for Port 443 (HTTPS) checks.
- Uses `ssl.CERT_NONE` to bypass certificate authorities, actively reading invalid or self-signed certs.
- Extracts standard fields: `commonName` (CN), `subjectAltName` (SAN), `issuer`, and deeply cross-references CNs to automatically identify `self_signed` status and validate expiration markers.
