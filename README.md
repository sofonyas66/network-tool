# NetFP — Behavioral Network Fingerprinting Tool

A raw-socket SYN scanner with passive OS fingerprinting, service banner grabbing, TLS certificate inspection, and a real-time 3D web dashboard — all from the terminal.

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3dd6f5?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-e040fb?style=flat-square)

## Features

| Feature | Description |
|---------|-------------|
| **SYN Scan** | Non-blocking raw-socket scan with Poisson-jittered timing to evade IDS |
| **OS Fingerprinting** | Behavioral detection via TTL, TCP window size, MSS, and WScale options |
| **Banner Grabbing** | Connects to open ports and captures service greeting banners |
| **TLS Inspection** | Extracts certificate CN, SANs, issuer, expiry, and detects self-signed certs |
| **Decoy Mode** | Injects spoofed SYN packets from randomized source IPs to obscure the scanner |
| **Load Balancer Detection** | Analyzes TTL variance across responses to flag suspected load balancers |
| **3D Dashboard** | Interactive Three.js visualization with host orbits, port satellites, and hover tooltips |
| **Legacy Mode** | Resource-constrained mode for low-power devices (capped rate, serial send) |

## Requirements

- **Python 3.10+**
- **Root / sudo** — Raw sockets require elevated privileges
- **Scapy ≥ 2.5.0**

## Installation

### Recommended: Virtual Environment (Isolated Installation)

```bash
# Clone the repository
git clone https://github.com/your-username/network-tool.git
cd network-tool

# Create a virtual environment
python3 -m venv venv

# Activate the virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install the package itself (this makes the `netfp` command available)
pip install -e .

# Verify installation
netfp --help

# When done, deactivate the environment
deactivate

## Usage

> ⚠️ **This tool sends raw SYN packets. Only scan networks and hosts you are authorized to test.**

### Single target

```bash
sudo python3 main.py --target 192.168.1.1 --ports 1-1024
```

### CIDR range scan

```bash
sudo python3 main.py --range 192.168.1.0/24 --ports 22,80,443
```

### Full scan with dashboard + banner + TLS

```bash
sudo python3 main.py --target 10.0.0.1 --ports 22,80,443 --banner --ssl --dashboard
```

### Decoy mode (authorized targets only)

```bash
sudo python3 main.py --target 10.0.0.1 --ports 80,443 --decoy --output results.json
```

### All options

```
Usage: netfp [options]

Target:
  --target IP          Single target IP address
  --range  CIDR        Target CIDR range (e.g. 192.168.1.0/24)

Scan:
  --ports  PORTS       Ports: '22,80,443' or '1-1024' (default: 1-1024)
  --rate   PPS         Packets per second (default: 100)
  --timeout SECS       Post-scan wait for straggler replies (default: 2)
  --iface  IFACE       Network interface (default: auto-detect)

Modules:
  --banner             Grab service banners on open ports
  --ssl                Probe TLS certificates on port 443
  --decoy              Inject decoy packets (authorized targets only)

Output:
  --dashboard          Launch 3D web dashboard after scan
  --output FILE        Save JSON results to file
  --legacy             Low-resource mode (<50 MB, slower rate)
  --verbose            Debug logging
```

## 3D Dashboard

When launched with `--dashboard`, a local HTTP server starts at `http://127.0.0.1:8765` serving an interactive Three.js visualization:

- **Host spheres** orbit a central hub, colored by detected OS
- **Port satellites** orbit each host node
- **Hover tooltips** show OS guess, hop distance, virtualization status
- **Side panel** with stats, host list, and syntax-highlighted JSON viewer
- **Export** button to download results as JSON

## Project Structure

```
network-tool/
├── main.py                 # CLI entry point & scan orchestrator
├── requirements.txt
├── pyproject.toml
├── scanner/
│   ├── __init__.py
│   ├── engine.py           # SYN scanner (Scapy AsyncSniffer)
│   ├── fingerprint.py      # OS fingerprinting engine
│   ├── banner.py           # TCP banner grabber
│   ├── ssl_probe.py        # TLS certificate inspector
│   └── decoy.py            # Decoy packet injector
└── dashboard/
    ├── index.html
    ├── style.css
    └── app.js              # Three.js 3D visualization
```

## License

MIT — Use responsibly and only on authorized targets.
