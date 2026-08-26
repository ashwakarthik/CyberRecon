#!/usr/bin/env python3

import socket
import ssl
import re


# ============================================================
# CYBERRECON
# Service Detection Module
# ============================================================

COMMON_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    139,
    143,
    443,
    445,
    3306,
    3389,
    5432,
    8080,
    8443,
]


SERVICE_MAP = {
    21: {
        "service": "FTP",
        "technology": "FTP Server",
    },
    22: {
        "service": "SSH",
        "technology": "SSH Server",
    },
    23: {
        "service": "Telnet",
        "technology": "Telnet Server",
    },
    25: {
        "service": "SMTP",
        "technology": "Mail Server",
    },
    53: {
        "service": "DNS",
        "technology": "DNS Server",
    },
    80: {
        "service": "HTTP",
        "technology": "Web Server",
    },
    110: {
        "service": "POP3",
        "technology": "Mail Server",
    },
    139: {
        "service": "NetBIOS",
        "technology": "NetBIOS",
    },
    143: {
        "service": "IMAP",
        "technology": "Mail Server",
    },
    443: {
        "service": "HTTPS",
        "technology": "Web Server",
    },
    445: {
        "service": "SMB",
        "technology": "SMB Server",
    },
    3306: {
        "service": "MySQL",
        "technology": "Database Server",
    },
    3389: {
        "service": "RDP",
        "technology": "Remote Desktop",
    },
    5432: {
        "service": "PostgreSQL",
        "technology": "Database Server",
    },
    8080: {
        "service": "HTTP",
        "technology": "Web Server",
    },
    8443: {
        "service": "HTTPS",
        "technology": "Web Server",
    },
}


# ------------------------------------------------------------
# Basic TCP Connectivity
# ------------------------------------------------------------

def check_port(target, port, timeout=1.5):
    """
    Check whether a TCP port is actually open.

    Returns:
        True  -> TCP connection succeeded
        False -> connection failed
    """

    try:

        with socket.create_connection(
            (target, port),
            timeout=timeout
        ):

            return True

    except (
        socket.timeout,
        ConnectionRefusedError,
        ConnectionResetError,
        OSError
    ):

        return False


# ------------------------------------------------------------
# Banner Grabbing
# ------------------------------------------------------------

def grab_banner(target, port, timeout=2):
    """
    Attempt to retrieve a service banner.

    For HTTP/HTTPS ports, send a minimal HEAD request.

    For other TCP services, first attempt to receive
    a server banner without sending arbitrary data.
    """

    sock = None

    try:

        # ----------------------------------------------------
        # HTTPS
        # ----------------------------------------------------

        if port in (443, 8443):

            raw_socket = socket.create_connection(
                (target, port),
                timeout=timeout
            )

            context = ssl.create_default_context()

            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = context.wrap_socket(
                raw_socket,
                server_hostname=target
            )

        else:

            sock = socket.create_connection(
                (target, port),
                timeout=timeout
            )

        sock.settimeout(timeout)

        # ----------------------------------------------------
        # HTTP / HTTPS
        # ----------------------------------------------------

        if port in (80, 443, 8000, 8080, 8443, 8888):

            request = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"User-Agent: ASHWA-CYBERRECON/1.0\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )

            sock.sendall(
                request.encode("ascii", errors="ignore")
            )

        # ----------------------------------------------------
        # Receive response
        # ----------------------------------------------------

        data = sock.recv(8192)

        if not data:
            return ""

        return data.decode(
            "utf-8",
            errors="replace"
        ).strip()

    except (
        socket.timeout,
        ConnectionRefusedError,
        ConnectionResetError,
        ssl.SSLError,
        OSError
    ):

        return ""

    finally:

        if sock is not None:

            try:
                sock.close()

            except OSError:
                pass


# ------------------------------------------------------------
# Extract HTTP Server Information
# ------------------------------------------------------------

def extract_http_information(banner):
    """
    Extract HTTP server information.

    Example:

        Server: SimpleHTTP/0.6 Python/3.14.6

    Returns:

        technology
        version
    """

    technology = "Web Server"
    version = "unknown"

    if not banner:
        return technology, version

    for line in banner.splitlines():

        line_clean = line.strip()

        if line_clean.lower().startswith("server:"):

            server_value = line_clean.split(
                ":",
                1
            )[1].strip()

            if server_value:

                technology = server_value

                # --------------------------------------------
                # Try to extract a version number
                # --------------------------------------------

                version_match = re.search(
                    r"(?:/|\s|v)(\d+(?:\.\d+)+)",
                    server_value
                )

                if version_match:

                    version = version_match.group(1)

            break

    return technology, version


# ------------------------------------------------------------
# Detect Service
# ------------------------------------------------------------

def detect_service(target, port, timeout=2):
    """
    Detect a service on one known-open TCP port.

    Returns a result dictionary.
    """

    service_info = SERVICE_MAP.get(
        port,
        {
            "service": "Unknown",
            "technology": "Unknown",
        }
    )

    result = {
        "port": port,
        "open": False,
        "service": service_info["service"],
        "technology": service_info["technology"],
        "version": "unknown",
        "confidence": "Low",
        "banner": "",
    }

    # --------------------------------------------------------
    # First verify that the port is actually open
    # --------------------------------------------------------

    if not check_port(
        target,
        port,
        timeout=timeout
    ):

        return result

    result["open"] = True

    # --------------------------------------------------------
    # Attempt banner detection
    # --------------------------------------------------------

    banner = grab_banner(
        target,
        port,
        timeout=timeout
    )

    result["banner"] = banner

    # --------------------------------------------------------
    # HTTP detection
    # --------------------------------------------------------

    if banner.startswith("HTTP/"):

        result["service"] = (
            "HTTPS" if port in (443, 8443)
            else "HTTP"
        )

        technology, version = (
            extract_http_information(banner)
        )

        result["technology"] = technology
        result["version"] = version
        result["confidence"] = "High"

        return result

    # --------------------------------------------------------
    # SSH detection
    # --------------------------------------------------------

    if banner.startswith("SSH-"):

        result["service"] = "SSH"
        result["technology"] = "SSH Server"
        result["confidence"] = "High"

        # Example:
        #
        # SSH-2.0-OpenSSH_9.9p1
        #

        version_match = re.search(
            r"OpenSSH[_\-/]?([0-9][A-Za-z0-9._-]*)",
            banner,
            re.IGNORECASE
        )

        if version_match:

            result["version"] = (
                version_match.group(1)
            )

        return result

    # --------------------------------------------------------
    # FTP detection
    # --------------------------------------------------------

    if banner.startswith("220"):

        if "ftp" in banner.lower():

            result["service"] = "FTP"
            result["technology"] = "FTP Server"
            result["confidence"] = "High"

            return result

    # --------------------------------------------------------
    # SMTP detection
    # --------------------------------------------------------

    if banner.startswith("220"):

        if (
            "smtp" in banner.lower()
            or "mail" in banner.lower()
        ):

            result["service"] = "SMTP"
            result["technology"] = "Mail Server"
            result["confidence"] = "High"

            return result

    # --------------------------------------------------------
    # POP3 detection
    # --------------------------------------------------------

    if banner.startswith("+OK"):

        if port == 110:

            result["service"] = "POP3"
            result["technology"] = "POP3 Mail Server"
            result["confidence"] = "High"

            return result

    # --------------------------------------------------------
    # Generic responsive service
    # --------------------------------------------------------

    if banner:

        result["confidence"] = "Medium"

    else:

        result["confidence"] = "Medium"

    return result


# ------------------------------------------------------------
# Normalize Scan Results
# ------------------------------------------------------------

def extract_open_ports(scan_results):
    """
    Extract open ports from the port scanner results.

    Supports dictionaries such as:

        {
            "port": 8080,
            "open": True
        }

    Also supports integer port values.
    """

    ports = []

    if not scan_results:
        return ports

    for item in scan_results:

        # --------------------------------------------
        # Integer
        # --------------------------------------------

        if isinstance(item, int):

            if item not in ports:
                ports.append(item)

            continue

        # --------------------------------------------
        # Dictionary
        # --------------------------------------------

        if isinstance(item, dict):

            port = item.get("port")

            if port is None:
                continue

            is_open = item.get(
                "open",
                True
            )

            if is_open:

                try:
                    port = int(port)

                except (
                    TypeError,
                    ValueError
                ):
                    continue

                if port not in ports:
                    ports.append(port)

    return ports


# ------------------------------------------------------------
# Service Detection Runner
# ------------------------------------------------------------

def run_service_detection(
    target,
    scan_results=None
):
    """
    Run service detection.

    If port-scan results are supplied:
        only those open ports are checked.

    If no scan results are supplied:
        common ports are checked first for TCP connectivity.
    """

    print(
        f"\n[*] Detecting services on {target}..."
    )

    # --------------------------------------------------------
    # Use existing port scanner results when available
    # --------------------------------------------------------

    ports = extract_open_ports(
        scan_results
    )

    if ports:

        print(
            f"[*] Using {len(ports)} "
            f"open port(s) from port scan."
        )

    else:

        print(
            "[*] No port-scan results supplied."
        )

        print(
            f"[*] Checking {len(COMMON_PORTS)} "
            f"common ports for connectivity..."
        )

        ports = []

        for port in COMMON_PORTS:

            if check_port(
                target,
                port
            ):

                ports.append(port)

    # --------------------------------------------------------
    # No open ports
    # --------------------------------------------------------

    if not ports:

        print(
            "\n[-] No open TCP services detected."
        )

        return []

    # --------------------------------------------------------
    # Detect services
    # --------------------------------------------------------

    print(
        f"\n[*] Detecting services on "
        f"{len(ports)} open port(s)..."
    )

    results = []

    for port in sorted(ports):

        result = detect_service(
            target,
            port
        )

        # ----------------------------------------------------
        # Only report ports confirmed open
        # ----------------------------------------------------

        if not result["open"]:

            continue

        results.append(result)

        print(
            f"\n[+] {target}:{port}"
        )

        print(
            f"    Service    : "
            f"{result['service']}"
        )

        print(
            f"    Technology : "
            f"{result['technology']}"
        )

        print(
            f"    Version    : "
            f"{result['version']}"
        )

        print(
            f"    Confidence : "
            f"{result['confidence']}"
        )

        if result["banner"]:

            # Keep terminal output readable
            banner_display = (
                result["banner"]
                .replace("\r", " ")
                .replace("\n", " ")
            )

            if len(banner_display) > 300:

                banner_display = (
                    banner_display[:300]
                    + "..."
                )

            print(
                f"    Banner     : "
                f"{banner_display}"
            )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print(
        "\n[+] Service detection completed."
    )

    print(
        f"[+] Services identified: "
        f"{len(results)}"
    )

    return results
