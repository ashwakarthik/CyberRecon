# ============================================================
# ASHWA CYBERRECON
# Report Generator
# ============================================================

import json
import os
from datetime import datetime


def save_report(
    target,
    scan_results,
    service_results,
    fingerprint_results,
    http_results,
    dns_results=None,
    subdomain_results=None,
    endpoint_results=None,
    vulnerability_results=None
):
    """
    Generate complete ASHWA CYBERRECON TXT and JSON reports.
    """

    # --------------------------------------------------------
    # REPORT DIRECTORY
    # --------------------------------------------------------

    os.makedirs(
        "reports",
        exist_ok=True
    )

    timestamp = datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S"
    )

    txt_path = (
        f"reports/recon_{timestamp}.txt"
    )

    json_path = (
        f"reports/recon_{timestamp}.json"
    )

    # --------------------------------------------------------
    # NORMALIZE DATA
    # --------------------------------------------------------

    if scan_results is None:
        scan_results = []

    if service_results is None:
        service_results = []

    if fingerprint_results is None:
        fingerprint_results = []

    if http_results is None:
        http_results = []

    if dns_results is None:
        dns_results = {}

    if subdomain_results is None:
        subdomain_results = []

    if endpoint_results is None:
        endpoint_results = []

    if vulnerability_results is None:
        vulnerability_results = []

    # --------------------------------------------------------
    # JSON REPORT
    # --------------------------------------------------------

    report_data = {

        "tool": "ASHWA CYBERRECON",

        "target": target,

        "timestamp": datetime.now().isoformat(),

        "port_scan": scan_results,

        "service_detection": service_results,

        "fingerprinting": fingerprint_results,

        "http_recon": http_results,

        "dns_recon": dns_results,

        "subdomains": subdomain_results,

        "endpoints": endpoint_results,

        "vulnerabilities": vulnerability_results,

        "summary": {

            "open_ports": len(
                scan_results
            ),

            "services_detected": len(
                service_results
            ),

            "fingerprints": len(
                fingerprint_results
            ),

            "http_targets": len(
                http_results
            ),

            "subdomains": len(
                subdomain_results
            ),

            "endpoints": len(
                endpoint_results
            ),

            "vulnerabilities": len(
                vulnerability_results
            )
        }
    }

    # --------------------------------------------------------
    # WRITE JSON
    # --------------------------------------------------------

    with open(
        json_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report_data,
            file,
            indent=4,
            default=str
        )

    # --------------------------------------------------------
    # WRITE TXT
    # --------------------------------------------------------

    with open(
        txt_path,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "=" * 70 + "\n"
        )

        file.write(
            "                    ASHWA CYBERRECON\n"
        )

        file.write(
            "                       RECON REPORT\n"
        )

        file.write(
            "=" * 70 + "\n\n"
        )

        file.write(
            f"Target    : {target}\n"
        )

        file.write(
            f"Timestamp : "
            f"{datetime.now().isoformat()}\n\n"
        )

        # ====================================================
        # PORT SCANNER
        # ====================================================

        file.write(
            "=" * 70 + "\n"
        )

        file.write(
            "                         PORT SCANNER\n"
        )

        file.write(
            "=" * 70 + "\n\n"
        )

        if scan_results:

            for result in scan_results:

                if isinstance(
                    result,
                    dict
                ):

                    file.write(
                        f"Port       : "
                        f"{result.get('port')}\n"
                    )

                    file.write(
                        f"Status     : "
                        f"{result.get('status')}\n"
                    )

                    file.write(
                        f"Service    : "
                        f"{result.get('service')}\n"
                    )

                    file.write(
                        f"Response   : "
                        f"{result.get('response_time')}\n\n"
                    )

                else:

                    file.write(
                        f"{result}\n\n"
                    )

        else:

            file.write(
                "No open ports detected.\n\n"
            )

        # ====================================================
        # SERVICE DETECTION
        # ====================================================

        file.write(
            "=" * 70 + "\n"
        )

        file.write(
            "                      SERVICE DETECTION\n"
        )

        file.write(
            "=" * 70 + "\n\n"
        )

        if service_results:

            for result in service_results:

                if isinstance(
                    result,
                    dict
                ):

                    file.write(
                        f"Port       : "
                        f"{result.get('port')}\n"
                    )

                    file.write(
                        f"Service    : "
                        f"{result.get('service')}\n"
                    )

                    file.write(
                        f"Technology : "
                        f"{result.get('technology')}\n"
                    )

                    file.write(
                        f"Version    : "
                        f"{result.get('version')}\n"
                    )

                    file.write(
                        f"Confidence : "
                        f"{result.get('confidence')}\n\n"
                    )

                else:

                    file.write(
                        f"{result}\n\n"
                    )

        else:

            file.write(
                "No services detected.\n\n"
            )

        # ====================================================
        # FINGERPRINTING
        # ====================================================

        file.write(
            "=" * 70 + "\n"
        )

        file.write(
            "                       FINGERPRINTING\n"
        )

        file.write(
            "=" * 70 + "\n\n"
        )

        if fingerprint_results:

            for result in fingerprint_results:

                if isinstance(
                    result,
                    dict
                ):

                    file.write(
                        f"Port        : "
                        f"{result.get('port')}\n"
                    )

                    file.write(
                        f"Service     : "
                        f"{result.get('service')}\n"
                    )

                    file.write(
                        f"Technology  : "
                        f"{result.get('technology')}\n"
                    )

                    file.write(
                        f"Version     : "
                        f"{result.get('version')}\n"
                    )

                    file.write(
                        f"Confidence  : "
                        f"{result.get('confidence')}\n\n"
                    )

                else:

                    file.write(
                        f"{result}\n\n"
                    )

        else:

            file.write(
                "No fingerprints detected.\n\n"
            )

        # ====================================================
        # HTTP RECON
        # ====================================================

        file.write(
            "=" * 70 + "\n"
        )

        file.write(
            "                         HTTP RECON\n"
        )

        file.write(
            "=" * 70 + "\n\n"
        )

        if http_results:

            for result in http_results:

                if isinstance(
                    result,
                    dict
                ):

                    file.write(
                        f"URL            : "
                        f"{result.get('url')}\n"
                    )

                    file.write(
                        f"Final URL      : "
                        f"{result.get('final_url')}\n"
                    )

                    file.write(
                        f"Status         : "
                        f"{result.get('status')}\n"
                    )

                    file.write(
                        f"Title          : "
                        f"{result.get('title')}\n"
                    )

                    file.write(
                        f"Server         : "
                        f"{result.get('server')}\n"
                    )

                    file.write(
                        f"Content-Type   : "
                        f"{result.get('content_type')}\n"
                    )

                    file.write(
                        f"Content-Length : "
                        f"{result.get('content_length')}\n"
                    )

                    file.write(
                        f"Response Time  : "
                        f"{result.get('response_time')}\n"
                    )

                    if result.get("error"):

                        file.write(
                            f"Error          : "
                            f"{result.get('error')}\n"
                        )

                    file.write("\n")

                else:

                    file.write(
                        f"{result}\n\n"
                    )

        else:

            file.write(
                "No HTTP targets detected.\n\n"
            )

        # ====================================================
        # DNS RECON
        # ====================================================

        file.write(
            "=" * 70 + "\n"
        )

        file.write(
            "                          DNS RECON\n"
        )

        file.write(
            "=" * 70 + "\n\n"
        )

        if dns_results:

            if isinstance(
                dns_results,
                dict
            ):

                records = dns_results.get(
                    "records",
                    []
                )

                if records:

                    for record in records:

                        if not isinstance(
                            record,
                            dict
                        ):

                            file.write(
                                f"{record}\n\n"
                            )

                            continue

                        record_type = record.get(
                            "type",
                            "UNKNOWN"
                        )

                        values = record.get(
                            "records",
                            []
                        )

                        file.write(
                            f"{record_type} RECORDS\n"
                        )

                        if values:

                            for value in values:

                                file.write(
                                    f"  - {value}\n"
                                )

                        else:

                            file.write(
                                "  - No record found\n"
                            )

                        file.write("\n")

                else:

                    file.write(
                        "No DNS records found.\n\n"
                    )

                reverse_dns = dns_results.get(
                    "reverse_dns"
                )

                if reverse_dns:

                    file.write(
                        "REVERSE DNS\n"
                    )

                    if isinstance(
                        reverse_dns,
                        dict
                    ):

                        file.write(
                            f"  Target   : "
                            f"{reverse_dns.get('target')}\n"
                        )

                        file.write(
                            f"  Hostname : "
                            f"{reverse_dns.get('hostname')}\n\n"
                        )

                    else:

                        file.write(
                            f"  {reverse_dns}\n\n"
                        )

            else:

                file.write(
                    f"{dns_results}\n\n"
                )

        else:

            file.write(
                "DNS reconnaissance returned no data.\n\n"
            )

        # ====================================================
        # SUBDOMAINS
        # ====================================================

        file.write(
            "=" * 70 + "\n"
        )

        file.write(
            "                    SUBDOMAIN ENUMERATION\n"
        )

        file.write(
            "=" * 70 + "\n\n"
        )

        if subdomain_results:

            for subdomain in subdomain_results:

                if isinstance(
                    subdomain,
                    dict
                ):

                    file.write(
                        json.dumps(
                            subdomain,
                            default=str
                        )
                        + "\n"
                    )

                else:

                    file.write(
                        f"{subdomain}\n"
                    )

        else:

            file.write(
                "No subdomains discovered.\n"
            )

        file.write("\n")

        # ====================================================
        # ENDPOINTS
        # ====================================================

        file.write(
            "=" * 70 + "\n"
        )

        file.write(
            "                     ENDPOINT ENUMERATION\n"
        )

        file.write(
            "=" * 70 + "\n\n"
        )

        if endpoint_results:

            for endpoint in endpoint_results:

                if isinstance(
                    endpoint,
                    dict
                ):

                    file.write(
                        json.dumps(
                            endpoint,
                            default=str
                        )
                        + "\n"
                    )

                else:

                    file.write(
                        f"{endpoint}\n"
                    )

        else:

            file.write(
                "No endpoints discovered.\n"
            )

        file.write("\n")

        # ====================================================
        # VULNERABILITIES
        # ====================================================

        file.write(
            "=" * 70 + "\n"
        )

        file.write(
            "                     VULNERABILITY ASSESSMENT\n"
        )

        file.write(
            "=" * 70 + "\n\n"
        )

        if vulnerability_results:

            for finding in vulnerability_results:

                if isinstance(
                    finding,
                    dict
                ):

                    file.write(
                        json.dumps(
                            finding,
                            indent=2,
                            default=str
                        )
                    )

                    file.write("\n\n")

                else:

                    file.write(
                        f"{finding}\n\n"
                    )

        else:

            file.write(
                "No vulnerabilities reported.\n\n"
            )

        # ====================================================
        # SUMMARY
        # ====================================================

        file.write(
            "=" * 70 + "\n"
        )

        file.write(
            "                           SUMMARY\n"
        )

        file.write(
            "=" * 70 + "\n\n"
        )

        file.write(
            f"Open Ports        : "
            f"{len(scan_results)}\n"
        )

        file.write(
            f"Services Detected : "
            f"{len(service_results)}\n"
        )

        file.write(
            f"Fingerprints      : "
            f"{len(fingerprint_results)}\n"
        )

        file.write(
            f"HTTP Targets      : "
            f"{len(http_results)}\n"
        )

        file.write(
            f"Subdomains        : "
            f"{len(subdomain_results)}\n"
        )

        file.write(
            f"Endpoints         : "
            f"{len(endpoint_results)}\n"
        )

        file.write(
            f"Vulnerabilities   : "
            f"{len(vulnerability_results)}\n"
        )

        # DNS COUNT

        dns_count = 0

        if isinstance(
            dns_results,
            dict
        ):

            for record in dns_results.get(
                "records",
                []
            ):

                if isinstance(
                    record,
                    dict
                ):

                    dns_count += len(
                        record.get(
                            "records",
                            []
                        )
                    )

        file.write(
            f"DNS Records       : "
            f"{dns_count}\n"
        )

        file.write("\n")

        file.write(
            "=" * 70 + "\n"
        )

        file.write(
            "                    END OF REPORT\n"
        )

        file.write(
            "=" * 70 + "\n"
        )

    # --------------------------------------------------------
    # OUTPUT
    # --------------------------------------------------------

    print("\n[+] Reports generated:")

    print(
        f"[+] TXT  : {txt_path}"
    )

    print(
        f"[+] JSON : {json_path}"
    )

    return {
        "txt": txt_path,
        "json": json_path
    }
