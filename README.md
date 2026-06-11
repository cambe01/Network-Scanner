# 🔍 Python Network Scanner

A modular, concurrent TCP network scanner built in pure Python. Designed to discover live hosts on a network, identify open ports, and capture service banners all from the command line.

> ⚠️ **Legal notice:** Only scan networks and devices you own or have explicit written permission to test. Unauthorised scanning may be illegal under the Computer Misuse Act (UK) and equivalent laws elsewhere.

---

## Features

- **Host discovery** — ping sweep to identify live devices before scanning
- **TCP port scanning** — connect-based scan; no raw sockets, no root required
- **Banner grabbing** — reads the service greeting to identify software versions (e.g. `SSH-2.0-OpenSSH_8.9`, `nginx/1.24`)
- **Reverse DNS** — resolves IPs to hostnames where available
- **Concurrent scanning** — uses Python's `ThreadPoolExecutor` to scan multiple hosts and ports in parallel
- **Flexible targets** — accepts single IPs, CIDR ranges, and last-octet ranges
- **Coloured terminal output** — clear, readable results with a live progress bar
- **Cross-platform** — works on Linux, macOS, and Windows

---

## Project Structure

```
network_scanner/
├── main.py          # CLI entry point — argument parsing and orchestration
├── parser.py        # Converts user input into lists of IPs and port numbers
├── ping.py          # ICMP ping check and concurrent ping sweep
├── port_scanner.py  # TCP connect scan and banner grabbing
├── reporter.py      # All terminal output: results, progress bar, header/footer
├── utils.py         # Shared constants (colours, service name map, DNS lookup)
└── __init__.py      # Package exports
```

Each module has a single responsibility, making the codebase easy to read, test, and extend.

---

## How It Works

### 1. Parsing (`parser.py`)
The user supplies a target like `192.168.1.0/24` or `192.168.1.1-50`. The parser expands this into a flat list of individual IP strings using Python's built-in `ipaddress` module. Port specifications (`22,80,443` or `1-1024`) are similarly expanded into a sorted list of integers.

### 2. Ping Sweep (`ping.py`)
Before scanning ports, each host is tested with a single ICMP ping using the OS `ping` binary (no elevated privileges needed). This filters out dead IPs early, saving significant time on large subnets. The sweep runs concurrently across all targets using a thread pool.

### 3. Port Scanning (`port_scanner.py`)
For each live host, the scanner attempts a TCP `connect()` to every target port. This is the same technique used by tools like Nmap's `-sT` mode. Up to 50 port probes run in parallel per host. If a connection succeeds, a `\r\n` is sent and the first line of any response is captured as a **banner** often revealing the service name and version.

### 4. Reporting (`reporter.py`)
Results are collected and printed in ascending IP order once scanning completes. A live progress bar updates during the scan. Open ports are shown with their service name and any captured banner.

---

## Installation

Python 3.10+ is required. No external dependencies are needed for core functionality.

```bash
git clone https://github.com/your-username/network-scanner.git
cd network-scanner
```

For coloured terminal output, install the optional dependency:

```bash
pip install colorama
```

---

## Usage

```bash
# Scan a full subnet using common ports
python main.py 192.168.1.0/24

# Scan a specific IP range
python main.py 192.168.1.1-50

# Scan specific ports on a single host
python main.py 192.168.1.1 --ports 22,80,443,8080

# Scan ports 1–1024 with a faster timeout, show only hosts with open ports
python main.py 192.168.1.0/24 --ports 1-1024 --timeout 0.5 --open-only

# Skip the ping check (useful when ICMP is blocked by a firewall)
python main.py 192.168.1.0/24 --skip-ping
```

### All Options

| Flag | Short | Default | Description |
|---|---|---|---|
| `--ports` | `-p` | common ports | Ports to scan: `22,80` or `1-1024` |
| `--timeout` | `-t` | `1.0` | Socket/ping timeout in seconds |
| `--workers` | `-w` | `20` | Number of hosts to scan in parallel |
| `--skip-ping` | | off | Scan all hosts, even those that don't respond to ping |
| `--open-only` | | off | Only display hosts with at least one open port |

---

## Example Output

```
Network Scanner  —  2025-03-14 11:42:01
Targets : 254 host(s)   Ports : 20   Timeout : 1.0s
───────────────────────────────────────────────────────

● 192.168.1.1  (router.local)
     80/tcp  HTTP          nginx/1.24.0
    443/tcp  HTTPS
   8080/tcp  HTTP-Alt

● 192.168.1.42  (desktop.local)
     22/tcp  SSH           SSH-2.0-OpenSSH_8.9p1
   3306/tcp  MySQL

───────────────────────────────────────────────────────
Scan complete.  2 host(s) up  |  254 scanned
```

---

## Technical Concepts Demonstrated

- **Concurrency with `ThreadPoolExecutor`** — parallel I/O-bound tasks across hosts and ports
- **TCP socket programming** — low-level `socket.create_connection()` for port probing
- **ICMP via subprocess** — cross-platform ping without requiring raw socket privileges
- **Modular design** — separation of concerns across parsing, probing, and reporting layers
- **Python type hints** — all functions annotated for clarity and IDE support
- **`ipaddress` module** — correct handling of CIDR notation and IP arithmetic
- **CLI with `argparse`** — robust argument parsing with sensible defaults

---

## Possible Extensions

- JSON or CSV output for scripting pipelines
- UDP port scanning
- OS fingerprinting via TTL analysis
- CVE lookup for detected service versions
- Web dashboard using Flask or FastAPI

---

## License

MIT — free to use, modify, and distribute.
