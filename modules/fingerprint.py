import re


def fingerprint_port(target, port, service="unknown", service_result=None):
    """
    Fingerprint a single open port using service-detection results.
    """

    result = {
        "target": target,
        "port": port,
        "service": service,
        "technology": "Unknown",
        "version": "Unknown",
        "confidence": "Low"
    }

    # Use information already discovered by service detection
    if service_result:

        detected_service = service_result.get("service", "unknown")
        technology = service_result.get("technology", "unknown")
        banner = service_result.get("banner", "")

        result["service"] = detected_service

        if technology and technology.lower() != "unknown":
            result["technology"] = technology

        # Try to extract a version from common technology strings
        version_match = re.search(
            r"(?:Python|Apache|nginx|OpenSSH|vsftpd|Postfix|Microsoft-IIS)[/\s-]?(\d+(?:\.\d+)+)",
            technology,
            re.IGNORECASE
        )

        if version_match:
            result["version"] = version_match.group(1)

        # If we have a banner but couldn't extract a version,
        # keep a short banner as supporting fingerprint data.
        elif banner:
            first_line = banner.splitlines()[0].strip()

            if first_line:
                result["version"] = first_line[:100]

        if service_result.get("confidence") == "High":
            result["confidence"] = "High"

        elif service_result.get("confidence") == "Medium":
            result["confidence"] = "Medium"

        return result

    # Fallback when service detection data is unavailable
    if port in (80, 8080, 8000, 8888):
        result["service"] = "HTTP"
        result["technology"] = "HTTP"
        result["confidence"] = "Medium"

    elif port == 443:
        result["service"] = "HTTPS"
        result["technology"] = "HTTPS"
        result["confidence"] = "Medium"

    elif port == 22:
        result["service"] = "SSH"
        result["technology"] = "SSH"
        result["confidence"] = "Medium"

    elif port == 21:
        result["service"] = "FTP"
        result["technology"] = "FTP"
        result["confidence"] = "Medium"

    elif port == 25:
        result["service"] = "SMTP"
        result["technology"] = "SMTP"
        result["confidence"] = "Medium"

    return result


def run_fingerprinting(target, scan_results, service_results=None):
    """
    Fingerprint discovered services using service-detection results.
    """

    print(f"\n[*] Fingerprinting {target}")

    results = []

    if not scan_results:
        print(
            "[+] Fingerprinting completed. "
            "0 target(s) processed."
        )
        return results

    # Convert service results into a lookup table by port
    services_by_port = {}

    if service_results:
        for service_result in service_results:

            port = service_result.get("port")

            if port is not None:
                services_by_port[port] = service_result

    for item in scan_results:

        port = item.get("port")

        if port is None:
            continue

        service_result = services_by_port.get(port)

        service = "unknown"

        if service_result:
            service = service_result.get(
                "service",
                "unknown"
            )

        result = fingerprint_port(
            target,
            port,
            service,
            service_result
        )

        results.append(result)

        print(f"\n[+] Port        : {result['port']}")
        print(f"[+] Service     : {result['service']}")
        print(f"[+] Technology  : {result['technology']}")
        print(f"[+] Version     : {result['version']}")
        print(f"[+] Confidence  : {result['confidence']}")

    print(
        f"\n[+] Fingerprinting completed. "
        f"{len(results)} target(s) processed."
    )

    return results
