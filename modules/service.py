import socket

from cyberrecon.modules.fingerprint import fingerprint_service


# ============================================================
# SERVICE IDENTIFICATION
# ============================================================

def identify_service(target, port):
    """
    Identify the service running on a TCP port.

    Returns:
        {
            "port": int,
            "service": str,
            "banner": str,
            "fingerprint": dict
        }
    """

    banner = ""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)

    try:
        sock.connect((target, port))

        # Try to receive an initial banner
        try:
            data = sock.recv(4096)
            banner = data.decode("utf-8", errors="replace").strip()
        except socket.timeout:
            banner = ""

    except (socket.timeout, socket.error):
        banner = ""

    finally:
        sock.close()

    # --------------------------------------------------------
    # Basic service identification
    # --------------------------------------------------------

    service = "unknown"

    banner_lower = banner.lower()

    if port == 21:
        service = "FTP"

    elif port == 22:
        service = "SSH"

    elif port in (23,):
        service = "Telnet"

    elif port in (25, 465, 587):
        service = "SMTP"

    elif port in (53,):
        service = "DNS"

    elif port in (80, 8080, 8000, 8008, 8888):
        service = "HTTP"

    elif port in (110, 995):
        service = "POP3"

    elif port in (143, 993):
        service = "IMAP"

    elif port == 443:
        service = "HTTPS"

    elif port == 3306:
        service = "MySQL"

    elif port == 5432:
        service = "PostgreSQL"

    elif port == 6379:
        service = "Redis"

    elif port == 27017:
        service = "MongoDB"

    # --------------------------------------------------------
    # Banner-based identification
    # --------------------------------------------------------

    if "ssh" in banner_lower:
        service = "SSH"

    elif "ftp" in banner_lower:
        service = "FTP"

    elif "smtp" in banner_lower:
        service = "SMTP"

    elif "http/" in banner_lower:
        service = "HTTP"

    elif "mysql" in banner_lower:
        service = "MySQL"

    elif "postgres" in banner_lower:
        service = "PostgreSQL"

    elif "redis" in banner_lower:
        service = "Redis"

    # --------------------------------------------------------
    # Fingerprinting
    # --------------------------------------------------------

    fingerprint = {}

    try:
        fingerprint = fingerprint_service(target, port)
    except Exception as error:
        fingerprint = {
            "error": str(error)
        }

    return {
        "port": port,
        "service": service,
        "banner": banner,
        "fingerprint": fingerprint
    }


# ============================================================
# SERVICE DETECTION
# ============================================================

def identify_services(target, open_ports):
    """
    Identify services running on previously discovered ports.

    Parameters:
        target:
            IP address or hostname

        open_ports:
            List of open TCP ports

    Returns:
        List of dictionaries containing:
            port
            service
            banner
            fingerprint
    """

    results = []

    print("\n[*] Detecting services ...")

    if not open_ports:
        print("[!] No open ports to analyze.")
        return results

    for port in sorted(open_ports):

        print(f"[>] Checking {target}:{port}")

        try:
            result = identify_service(target, port)

            results.append(result)

            print(
                f"[+] {target}:{port} -> "
                f"{result['service']}"
            )

            if result.get("fingerprint"):

                fp = result["fingerprint"]

                if isinstance(fp, dict):

                    technology = fp.get("technology")
                    version = fp.get("version")
                    confidence = fp.get("confidence")

                    if technology:
                        print(
                            f"    Technology : {technology}"
                        )

                    if version:
                        print(
                            f"    Version    : {version}"
                        )

                    if confidence:
                        print(
                            f"    Confidence : {confidence}"
                        )

        except Exception as error:

            print(
                f"[!] Error detecting "
                f"{target}:{port}: {error}"
            )

            results.append({
                "port": port,
                "service": "unknown",
                "banner": "",
                "fingerprint": {
                    "error": str(error)
                }
            })

    print("\n[+] Service detection completed.")

    return results
