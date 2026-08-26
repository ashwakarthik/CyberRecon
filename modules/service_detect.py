"""
ASHWA CYBERRECON
Service Detection Module

Use only against systems you own or are explicitly authorized to test.
"""

import socket
import time


COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP Alt",
    8080: "HTTP Proxy/Alt",
    8443: "HTTPS Alt",
}


def detect_service(ip, port, timeout=3):
    """Attempt basic service identification on one TCP port."""

    start = time.perf_counter()

    result = {
        "ip": ip,
        "port": port,
        "service": COMMON_SERVICES.get(port, "Unknown"),
        "banner": None,
        "response_time": None,
        "error": None,
    }

    try:
        with socket.create_connection(
            (ip, port),
            timeout=timeout
        ) as sock:

            result["response_time"] = round(
                time.perf_counter() - start,
                4
            )

            sock.settimeout(timeout)

            try:
                banner = sock.recv(1024)

                if banner:
                    result["banner"] = (
                        banner.decode(
                            "utf-8",
                            errors="replace"
                        )
                        .strip()
                    )

            except socket.timeout:
                pass

    except (ConnectionRefusedError, TimeoutError, OSError) as error:

        result["error"] = str(error)

    return result


def print_result(result):
    """Display one detection result."""

    print()
    print(f"[+] Port    : {result['port']}")
    print(f"[+] Service : {result['service']}")

    if result.get("banner"):
        print(f"[+] Banner  : {result['banner']}")
    else:
        print("[-] Banner  : Not detected")

    if result.get("response_time") is not None:
        print(
            f"[+] Time    : "
            f"{result['response_time']}s"
        )

    if result.get("error"):
        print(f"[-] Error   : {result['error']}")


def run_service_detection(
    ip,
    ports=None,
    timeout=3
):
    """
    Detect services on specified TCP ports.

    Use only on authorized targets.
    """

    print()
    print("=" * 50)
    print("           SERVICE DETECTION")
    print("=" * 50)

    if ports is None:
        ports = sorted(COMMON_SERVICES.keys())

    print(f"\n[*] Target  : {ip}")
    print(f"[*] Ports   : {len(ports)}")
    print(f"[*] Timeout : {timeout}s")
    print()

    results = []

    for port in ports:

        result = detect_service(
            ip,
            port,
            timeout
        )

        if not result.get("error"):
            results.append(result)
            print_result(result)

    print()
    print("=" * 50)
    print("          SERVICE SUMMARY")
    print("=" * 50)

    print(f"\nTarget          : {ip}")
    print(f"Services found  : {len(results)}")

    if results:

        print("\n[+] Detected services:")

        for result in results:
            print(
                f"    {result['port']:<5} "
                f"{result['service']}"
            )

    else:
        print(
            "[-] No services detected."
        )

    print(
        "\n[+] Service detection completed."
    )

    return results


if __name__ == "__main__":

    target = input(
        "[?] Enter target IP: "
    ).strip()

    port_input = input(
        "[?] Enter ports "
        "(comma-separated, blank = common ports): "
    ).strip()

    if port_input:

        try:
            ports = [
                int(port.strip())
                for port in port_input.split(",")
                if port.strip()
            ]

        except ValueError:

            print(
                "[!] Invalid port list."
            )

            raise SystemExit(1)

    else:
        ports = None

    run_service_detection(
        target,
        ports=ports
    )
