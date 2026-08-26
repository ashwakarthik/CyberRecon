"""
ASHWA CYBERRECON
TCP Port Scanner Module

Use only against systems you own or are explicitly
authorized to assess.
"""

import socket
import time


DEFAULT_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    465,
    587,
    993,
    995,
    1433,
    1521,
    3306,
    3389,
    5432,
    5900,
    6379,
    8000,
    8080,
    8443,
    8888,
]


COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP Alt",
    8080: "HTTP Proxy/Alt",
    8443: "HTTPS Alt",
    8888: "HTTP Alt",
}


def normalize_target(target):
    """Clean and validate a hostname or IP address."""

    target = target.strip()

    if not target:
        return None

    target = target.replace("https://", "")
    target = target.replace("http://", "")

    target = target.split("/")[0]

    if ":" in target and target.count(":") == 1:
        target = target.split(":")[0]

    try:
        socket.gethostbyname(target)
        return target

    except socket.gaierror:
        return None


def resolve_target(target):
    """Resolve the target to an IPv4 address."""

    try:
        return socket.gethostbyname(target)

    except socket.gaierror:
        return None


def scan_port(target, port, timeout=1.0):
    """Attempt a TCP connection to one port."""

    start = time.perf_counter()

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    sock.settimeout(timeout)

    try:
        result = sock.connect_ex(
            (target, port)
        )

        elapsed = time.perf_counter() - start

        if result == 0:

            return {
                "port": port,
                "state": "open",
                "service": COMMON_SERVICES.get(
                    port,
                    "unknown",
                ),
                "response_time": round(
                    elapsed,
                    4,
                ),
                "error": None,
            }

        return {
            "port": port,
            "state": "closed",
            "service": COMMON_SERVICES.get(
                port,
                "unknown",
            ),
            "response_time": round(
                elapsed,
                4,
            ),
            "error": None,
        }

    except socket.timeout:

        return {
            "port": port,
            "state": "filtered",
            "service": COMMON_SERVICES.get(
                port,
                "unknown",
            ),
            "response_time": None,
            "error": "timeout",
        }

    except OSError as error:

        return {
            "port": port,
            "state": "filtered",
            "service": COMMON_SERVICES.get(
                port,
                "unknown",
            ),
            "response_time": None,
            "error": str(error),
        }

    finally:

        sock.close()


def print_result(result):
    """Display one port scan result."""

    port = result["port"]
    state = result["state"]
    service = result["service"]

    if state == "open":

        print(
            f"[+] {port:<5} OPEN      "
            f"{service}"
        )

        if result["response_time"] is not None:

            print(
                f"    Response time: "
                f"{result['response_time']}s"
            )

    elif state == "filtered":

        print(
            f"[!] {port:<5} FILTERED  "
            f"{service}"
        )

    else:

        print(
            f"[-] {port:<5} CLOSED    "
            f"{service}"
        )


def run_port_scan(
    target,
    ports=None,
    timeout=1.0,
    delay=0.05,
):
    """
    Scan a conservative list of common TCP ports.

    Returns a list containing scan results.
    """

    print()
    print("=" * 60)
    print("                 TCP PORT SCANNER")
    print("=" * 60)

    hostname = normalize_target(target)

    if not hostname:

        print()
        print("[!] Invalid or unreachable hostname/IP.")
        return []

    ip_address = resolve_target(hostname)

    if not ip_address:

        print()
        print("[!] Could not resolve target.")
        return []

    if ports is None:
        ports = DEFAULT_PORTS

    print()
    print(f"[*] Target   : {hostname}")
    print(f"[*] IP       : {ip_address}")
    print(f"[*] Ports    : {len(ports)}")
    print(f"[*] Timeout  : {timeout}s")
    print(f"[*] Delay    : {delay}s")

    print()
    print("=" * 60)
    print("                 SCAN RESULTS")
    print("=" * 60)

    results = []

    start_time = time.perf_counter()

    for port in ports:

        result = scan_port(
            ip_address,
            port,
            timeout=timeout,
        )

        results.append(result)

        print_result(result)

        time.sleep(delay)

    elapsed = time.perf_counter() - start_time

    open_ports = [
        result
        for result in results
        if result["state"] == "open"
    ]

    filtered_ports = [
        result
        for result in results
        if result["state"] == "filtered"
    ]

    closed_ports = [
        result
        for result in results
        if result["state"] == "closed"
    ]

    print()
    print("=" * 60)
    print("                 PORT SCAN SUMMARY")
    print("=" * 60)

    print()
    print(f"Target          : {hostname}")
    print(f"IP Address      : {ip_address}")
    print(f"Ports scanned   : {len(results)}")
    print(f"Open            : {len(open_ports)}")
    print(f"Closed          : {len(closed_ports)}")
    print(f"Filtered        : {len(filtered_ports)}")
    print(f"Scan time       : {round(elapsed, 2)}s")

    print()

    if open_ports:

        print("[+] Open ports:")

        for result in open_ports:

            print(
                f"    {result['port']:<5} "
                f"{result['service']}"
            )

    else:

        print("[-] No open ports found.")

    print()
    print("[+] Port scanning completed.")

    return results


def main():
    """Command-line entry point."""

    print()
    print("=" * 60)
    print("                 ASHWA CYBERRECON")
    print("                    PORT SCANNER")
    print("=" * 60)

    print()

    target = input(
        "[?] Enter target IP/hostname: "
    ).strip()

    run_port_scan(target)


if __name__ == "__main__":
    main()
