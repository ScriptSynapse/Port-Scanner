import argparse
import socket
import concurrent.futures
import ipaddress
import sys
from typing import List, Tuple

DEFAULT_TIMEOUT = 1.0  # seconds for socket connection attempt


def resolve_target(target: str) -> str:
    return socket.gethostbyname(target)


def is_ip_allowed(ip_str: str, allow_external: bool) -> bool:
    if allow_external:
        return True
    ip = ipaddress.ip_address(ip_str)
    return ip.is_private or ip.is_loopback


def parse_ports(ports_arg: str) -> List[int]:
    ports = set()
    parts = ports_arg.split(",")
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if "-" in p:
            start, end = p.split("-", 1)
            start = int(start)
            end = int(end)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(p))
    # Keep only valid TCP port numbers
    return sorted([p for p in ports if 1 <= p <= 65535])


def scan_port(ip: str, port: int, timeout: float) -> Tuple[int, bool]:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return port, True
    except (socket.timeout, ConnectionRefusedError):
        return port, False
    except OSError:
        return port, False


def banner_grab(ip: str, port: int, timeout: float = 1.0) -> str:
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        try:
            data = s.recv(1024)
            return data.decode(errors="replace").strip()
        finally:
            s.close()
    except Exception:
        return ""


def run_scan(ip: str, ports: List[int], workers: int, timeout: float, grab_banner: bool):
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, ip, port, timeout): port for port in ports}
        for fut in concurrent.futures.as_completed(futures):
            port = futures[fut]
            try:
                p, is_open = fut.result()
            except Exception:
                continue
            if is_open:
                info = {"port": p}
                if grab_banner:
                    info["banner"] = banner_grab(ip, p, timeout)
                open_ports.append(info)

    open_ports.sort(key=lambda x: x["port"])
    return open_ports


def prompt_if_missing(value: str, prompt_text: str, default: str = "") -> str:
    if value:
        return value
    try:
        resp = input(prompt_text).strip()
    except (KeyboardInterrupt, EOFError):
        print("\nInput cancelled.")
        sys.exit(1)
    if not resp and default:
        return default
    return resp


def main():
    parser = argparse.ArgumentParser(description="Simple TCP port scanner (educational).")
    parser.add_argument("--target", "-t", required=False, help="Target hostname or IP (if omitted you'll be prompted)")
    parser.add_argument("--ports", "-p", default="", help="Ports to scan. Examples: 22,80,443   1-1000   20-22,80,443")
    parser.add_argument("--workers", "-w", type=int, default=200,
                        help="Number of concurrent worker threads (avoid setting extremely high values).")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="Socket timeout in seconds for connection attempts.")
    parser.add_argument("--allow-external", action="store_true",
                        help="Allow scanning public/external IPs (use responsibly).")
    parser.add_argument("--banner", action="store_true", help="Try to grab service banner for open ports.")
    args = parser.parse_args()

    # Interactive prompts if target / ports not provided
    target_input = prompt_if_missing(args.target, "Enter target IP or hostname: ")
    if not target_input:
        print("No target provided. Exiting.")
        sys.exit(1)

    ports_input = args.ports.strip()
    if not ports_input:
        ports_input = prompt_if_missing("", "Enter ports (e.g. 22,80,443 or 1-1024) [default 1-1024]: ", default="1-1024")

    try:
        ip = resolve_target(target_input)
    except socket.gaierror:
        print(f"ERROR: Could not resolve target {target_input}")
        sys.exit(2)

    if not is_ip_allowed(ip, args.allow_external):
        print(f"Refusing to scan external IP {ip}. Use --allow-external if you have permission.")
        sys.exit(3)

    try:
        ports = parse_ports(ports_input)
    except ValueError:
        print("ERROR: Invalid ports specification.")
        sys.exit(2)

    if not ports:
        print("No valid ports to scan.")
        sys.exit(1)

    print(f"Scanning {target_input} ({ip}) ports {ports[0]}-{ports[-1]} with {args.workers} workers...")
    open_ports = run_scan(ip, ports, args.workers, args.timeout, args.banner)

    if not open_ports:
        print("No open ports found.")
        return

    print("Open ports:")
    for entry in open_ports:
        port = entry["port"]
        banner = entry.get("banner", "")
        if banner:
            print(f"  {port}/tcp OPEN  - banner: {banner}")
        else:
            print(f"  {port}/tcp OPEN")


if __name__ == "__main__":
    main()
