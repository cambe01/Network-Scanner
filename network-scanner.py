
import argparse
import ipaddress
import platform
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import colorama
    colorama.init(autoreset=True)
    GREEN  = colorama.Fore.GREEN
    RED    = colorama.Fore.RED
    YELLOW = colorama.Fore.YELLOW
    CYAN   = colorama.Fore.CYAN
    RESET  = colorama.Style.RESET_ALL
except ImportError:
    GREEN = RED = YELLOW = CYAN = RESET = ""

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443,
]

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "MS-RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
    3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}

def parse_targets(target_str: str) -> list[str]:
    """Accept CIDR, range (a.b.c.x-y), or single IP."""
    if "/" in target_str:
        return [str(h) for h in ipaddress.IPv4Network(target_str, strict=False).hosts()]
    if "-" in target_str.split(".")[-1]:
        base, rng = target_str.rsplit(".", 1)
        start, end = rng.split("-")
        return [f"{base}.{i}" for i in range(int(start), int(end) + 1)]
    return [target_str]


def parse_ports(port_str: str | None) -> list[int]:
    """Accept comma list, range, or None (common ports)."""
    if port_str is None:
        return COMMON_PORTS
    ports: list[int] = []
    for part in port_str.split(","):
        if "-" in part:
            a, b = part.split("-")
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

def ping(host: str, timeout: float = 1.0) -> bool:
    """Return True if host responds to ICMP ping."""
    flag = "-n" if platform.system().lower() == "windows" else "-c"
    cmd = ["ping", flag, "1", "-W", str(int(timeout * 1000))
           if platform.system().lower() == "linux" else str(int(timeout)), host]
    try:
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=timeout + 1)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def scan_port(host: str, port: int, timeout: float = 1.0) -> tuple[int, bool, str]:
    """Return (port, is_open, banner)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = ""
            try:
                sock.sendall(b"\r\n")
                raw = sock.recv(256)
                banner = raw.decode(errors="replace").strip().splitlines()[0][:60]
            except Exception:
                pass
            return port, True, banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return port, False, ""


def resolve_hostname(host: str) -> str:
    try:
        return socket.gethostbyaddr(host)[0]
    except socket.herror:
        return ""


def scan_host(host: str, ports: list[int], timeout: float,
              skip_ping: bool) -> dict | None:
    """Return scan result dict or None if host is down."""
    alive = skip_ping or ping(host, timeout)
    if not alive:
        return None

    hostname = resolve_hostname(host)
    open_ports: list[dict] = []

    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(scan_port, host, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            port, is_open, banner = fut.result()
            if is_open:
                open_ports.append({
                    "port": port,
                    "service": SERVICE_NAMES.get(port, "unknown"),
                    "banner": banner,
                })

    open_ports.sort(key=lambda x: x["port"])
    return {"ip": host, "hostname": hostname, "ports": open_ports}


def print_result(result: dict) -> None:
    label = f"{result['ip']}"
    if result["hostname"]:
        label += f"  ({result['hostname']})"
    print(f"\n{GREEN}● {label}{RESET}")
    if result["ports"]:
        for p in result["ports"]:
            banner_str = f"  {CYAN}{p['banner']}{RESET}" if p["banner"] else ""
            print(f"  {GREEN}{p['port']:>5}/tcp{RESET}  "
                  f"{YELLOW}{p['service']:<12}{RESET}{banner_str}")
    else:
        print(f"  {RED}No open ports found{RESET}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Python network scanner — discover hosts and open ports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("target",
                        help="IP, CIDR (192.168.1.0/24), or range (192.168.1.1-50)")
    parser.add_argument("--ports", "-p", default=None,
                        help="Ports to scan: 22,80,443 or 1-1024 (default: common ports)")
    parser.add_argument("--timeout", "-t", type=float, default=1.0,
                        help="Socket/ping timeout in seconds (default: 1.0)")
    parser.add_argument("--workers", "-w", type=int, default=20,
                        help="Parallel host workers (default: 20)")
    parser.add_argument("--skip-ping", action="store_true",
                        help="Skip ping check — scan all hosts regardless")
    parser.add_argument("--open-only", action="store_true",
                        help="Only show hosts with at least one open port")
    args = parser.parse_args()

    try:
        targets = parse_targets(args.target)
    except ValueError as e:
        print(f"{RED}Invalid target: {e}{RESET}", file=sys.stderr)
        sys.exit(1)

    ports = parse_ports(args.ports)

    print(f"\n{CYAN}Network Scanner{RESET}  —  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Targets : {len(targets)} host(s)   "
          f"Ports : {len(ports)}   "
          f"Timeout : {args.timeout}s")
    print("─" * 50)

    results: list[dict] = []
    scanned = 0

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {
            ex.submit(scan_host, h, ports, args.timeout, args.skip_ping): h
            for h in targets
        }
        for fut in as_completed(futures):
            scanned += 1
            result = fut.result()
            if result is None:
                continue
            if args.open_only and not result["ports"]:
                continue
            results.append(result)
            print_result(result)

    results.sort(key=lambda r: ipaddress.IPv4Address(r["ip"]))

    print(f"\n{'─' * 50}")
    print(f"Scan complete.  "
          f"{GREEN}{len(results)} host(s) up{RESET}  |  "
          f"{scanned} scanned  |  "
          f"Elapsed: {datetime.now().strftime('%H:%M:%S')}")


if __name__ == "__main__":
    main()
