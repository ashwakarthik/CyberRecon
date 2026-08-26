import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


DEFAULT_TIMEOUT = 1.0
DEFAULT_WORKERS = 50


# ============================================================
# COMMON PORTS
# ============================================================

COMMON_PORTS = {
    21: ("FTP", "File Transfer"),
    22: ("SSH", "Secure Shell"),
    23: ("Telnet", "Remote Terminal"),
    25: ("SMTP", "Mail Transfer"),
    53: ("DNS", "Domain Name System"),
    80: ("HTTP", "Web Server"),
    110: ("POP3", "Email Retrieval"),
    111: ("RPC", "Remote Procedure Call"),
    135: ("MS-RPC", "Microsoft RPC"),
    139: ("NetBIOS", "Windows Networking"),
    143: ("IMAP", "Email Retrieval"),
    443: ("HTTPS", "Secure Web Server"),
    445: ("SMB", "Windows File Sharing"),
    465: ("SMTPS", "Secure SMTP"),
    587: ("SMTP", "Mail Submission"),
    993: ("IMAPS", "Secure IMAP"),
    995: ("POP3S", "Secure POP3"),
    1433: ("MSSQL", "Microsoft SQL Server"),
    1521: ("Oracle", "Oracle Database"),
    3306: ("MySQL", "MySQL Database"),
    3389: ("RDP", "Remote Desktop"),
    5432: ("PostgreSQL", "PostgreSQL Database"),
    5900: ("VNC", "Virtual Network Computing"),
    6379: ("Redis", "Redis Database"),
    8000: ("HTTP", "Alternative Web Server"),
    8080: ("HTTP", "Alternative Web Server"),
    8443: ("HTTPS", "Alternative HTTPS"),
    8888: ("HTTP", "Alternative Web Server"),
}


# ============================================================
# SINGLE PORT SCANNER
# ============================================================

def scan_port(target, port, timeout=DEFAULT_TIMEOUT):
    """
    Scan a single TCP port.

    Returns a result dictionary when the port is open,
    otherwise returns None.
    """

    start_time = time.time()

    try:

        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as sock:

            sock.settimeout(timeout)

            result = sock.connect_ex(
                (target, port)
            )

        response_time = round(
            time.time() - start_time,
            4
        )

        # ----------------------------------------------------
        # Port is not open
        # ----------------------------------------------------

        if result != 0:
            return None

        # ----------------------------------------------------
        # Get service information from our dictionary
        # ----------------------------------------------------

        service = COMMON_PORTS.get(
            port,
            ("unknown", "Unknown Service")
        )

        # ----------------------------------------------------
        # Return scan result
        # ----------------------------------------------------

        return {
            "port": port,
            "open": True,
            "service": service[0],
            "description": service[1],
            "response_time": response_time
        }

    except (
        socket.timeout,
        socket.error,
        OSError
    ):
        return None

    except Exception:
        return None


# ============================================================
# PORT NORMALIZATION
# ============================================================

def normalize_ports(ports):
    """
    Convert different port formats into a clean list.

    Supported examples:

        [80, 443, 8080]

        ["80", "443", "8080"]

        ["80", "1000-1010", "8080"]
    """

    normalized = set()

    for item in ports:

        if isinstance(item, int):

            if 1 <= item <= 65535:
                normalized.add(item)

            continue

        item = str(item).strip()

        if not item:
            continue

        # ----------------------------------------------------
        # Port range
        # Example: 1000-1010
        # ----------------------------------------------------

        if "-" in item:

            try:

                start, end = item.split("-", 1)

                start = int(start.strip())
                end = int(end.strip())

                if start > end:
                    start, end = end, start

                start = max(start, 1)
                end = min(end, 65535)

                for port in range(start, end + 1):
                    normalized.add(port)

            except ValueError:
                continue

        # ----------------------------------------------------
        # Single port
        # ----------------------------------------------------

        else:

            try:

                port = int(item)

                if 1 <= port <= 65535:
                    normalized.add(port)

            except ValueError:
                continue

    return sorted(normalized)


# ============================================================
# MULTI-PORT SCANNER
# ============================================================

def scan_ports(
    target,
    ports,
    timeout=DEFAULT_TIMEOUT,
    workers=DEFAULT_WORKERS
):
    """
    Scan multiple TCP ports using a controlled thread pool.
    """

    ports = normalize_ports(ports)

    print(
        f"\n[*] Scanning ports on {target}..."
    )

    print(
        f"[*] Ports to scan : {len(ports)}"
    )

    print(
        f"[*] Workers       : {workers}"
    )

    if not ports:

        print(
            "[!] No valid ports supplied."
        )

        return []

    results = []

    with ThreadPoolExecutor(
        max_workers=workers
    ) as executor:

        futures = {
            executor.submit(
                scan_port,
                target,
                port,
                timeout
            ): port
            for port in ports
        }

        for future in as_completed(futures):

            port = futures[future]

            try:

                result = future.result()

            except Exception:

                result = None

            if result:

                print(
                    f"[+] {target}:"
                    f"{result['port']} OPEN "
                    f"({result['service']}) "
                    f"- {result['description']} "
                    f"[{result['response_time']}s]"
                )

                results.append(result)

    results.sort(
        key=lambda item: item["port"]
    )

    print(
        f"\n[+] Port scan completed. "
        f"{len(results)} open port(s) found."
    )

    return results


# ============================================================
# PUBLIC ENTRY POINT
# ============================================================

def run_port_scanner(
    target,
    ports,
    timeout=DEFAULT_TIMEOUT,
    workers=DEFAULT_WORKERS
):
    """
    Public scanner entry point used by CyberRecon.
    """

    return scan_ports(
        target,
        ports,
        timeout=timeout,
        workers=workers
    )
