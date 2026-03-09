import argparse
import socket
import concurrent.futures
import ipaddress
import sys
import time
from typing import List, Tuple
from threading import Lock

DEFAULT_TIMEOUT = 1.0
print_lock = Lock()

COMMON_PORTS = [
    21,22,23,25,53,67,68,69,80,110,119,123,137,138,139,
    143,161,162,179,194,389,443,445,465,500,514,515,
    520,587,636,989,990,993,995,1433,1521,2049,2082,
    2083,2086,2087,2095,2096,2181,2483,2484,3000,3306,
    3389,3690,4444,4567,4848,5000,5432,5601,5672,5800,
    5900,5985,5986,6379,6667,7001,7002,7070,7443,7474,
    8000,8008,8009,8080,8081,8086,8087,8088,8090,8091,
    8181,8222,8333,8443,8888,9000,9042,9090,9092,9200,
    9418,9999,10000,11211,27017
]


def resolve_target(target: str) -> str:
    return socket.gethostbyname(target)


def is_ip_allowed(ip_str: str, allow_external: bool) -> bool:
    if allow_external:
        return True
    ip = ipaddress.ip_address(ip_str)
    return ip.is_private or ip.is_loopback


def parse_ports(ports_arg: str) -> List[int]:
    ports = set()

    for part in ports_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))

    return sorted(p for p in ports if 1 <= p <= 65535)


def get_service_name(port: int) -> str:
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"


def scan_port(ip: str, port: int, timeout: float) -> Tuple[int, bool]:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return port, True
    except:
        return port, False


def banner_grab(ip: str, port: int, timeout: float = 1.0) -> str:
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)

        try:
            data = s.recv(1024)
            return data.decode(errors="ignore").strip()
        finally:
            s.close()

    except:
        return ""


def run_scan(ip: str, ports: List[int], workers: int, timeout: float, grab_banner: bool):

    open_ports = []
    scanned = 0
    total = len(ports)

    def progress():
        percent = (scanned / total) * 100
        print(f"\rProgress: {scanned}/{total} ({percent:.1f}%)", end="")

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:

        futures = {executor.submit(scan_port, ip, port, timeout): port for port in ports}

        for future in concurrent.futures.as_completed(futures):

            port = futures[future]

            try:
                p, is_open = future.result()
            except:
                continue

            scanned_nonlocal[0] += 1

            with print_lock:
                progress()

            if is_open:
                service = get_service_name(p)

                entry = {
                    "port": p,
                    "service": service
                }

                if grab_banner:
                    entry["banner"] = banner_grab(ip, p, timeout)

                open_ports.append(entry)

    print()

    return sorted(open_ports, key=lambda x: x["port"])


def print_results(results):

    if not results:
        print("\nNo open ports found.")
        return

    print("\nOpen Ports")
    print("-" * 60)
    print(f"{'PORT':<10}{'SERVICE':<15}{'INFO'}")
    print("-" * 60)

    for r in results:
        banner = r.get("banner", "")
        print(f"{r['port']:<10}{r['service']:<15}{banner}")


def prompt_if_missing(value: str, text: str, default: str = ""):

    if value:
        return value

    try:
        resp = input(text).strip()
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.")
        sys.exit(1)

    if not resp and default:
        return default

    return resp


def main():

    parser = argparse.ArgumentParser(description="Fast Python TCP Port Scanner")

    parser.add_argument("-t", "--target", help="Target hostname or IP")
    parser.add_argument("-p", "--ports", help="Ports (example: 22,80 or 1-1000)")
    parser.add_argument("--top", action="store_true", help="Scan common top ports")
    parser.add_argument("-w", "--workers", type=int, default=300)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--banner", action="store_true")
    parser.add_argument("--allow-external", action="store_true")

    args = parser.parse_args()

    target = prompt_if_missing(args.target, "Target: ")
    ports_arg = args.ports

    if args.top:
        ports = COMMON_PORTS
    else:
        ports_arg = prompt_if_missing(
            ports_arg,
            "Ports (default 1-1024): ",
            "1-1024"
        )
        ports = parse_ports(ports_arg)

    try:
        ip = resolve_target(target)
    except socket.gaierror:
        print("Could not resolve host")
        sys.exit(1)

    if not is_ip_allowed(ip, args.allow_external):
        print("External IP blocked. Use --allow-external")
        sys.exit(1)

    print(f"\nTarget : {target} ({ip})")
    print(f"Ports  : {len(ports)}")
    print(f"Workers: {args.workers}")
    print("-" * 60)

    start = time.time()

    try:
        results = run_scan(ip, ports, args.workers, args.timeout, args.banner)
    except KeyboardInterrupt:
        print("\nScan stopped.")
        sys.exit(1)

    duration = time.time() - start

    print_results(results)

    print("\nScan finished in %.2f seconds" % duration)


if __name__ == "__main__":
    scanned_nonlocal = [0]
    main()