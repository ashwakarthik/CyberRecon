#!/usr/bin/env python3

import os
import sys
import importlib


# ============================================================
# CYBERRECON
# Reconnaissance Framework
# ============================================================

# ------------------------------------------------------------
# IMPORTANT PACKAGE PATH FIX
# ------------------------------------------------------------
#
# If main.py is launched like:
#
#     python3 cyberrecon/main.py
#
# Python may put the cyberrecon directory itself on sys.path
# instead of the project root.
#
# That makes imports such as:
#
#     modules.tech_fingerprint
#
# fail with:
#
#     No module named 'cyberrecon'
#
# Add the project root explicitly.
# ------------------------------------------------------------

CURRENT_FILE = os.path.abspath(__file__)
CYBERRECON_DIR = os.path.dirname(CURRENT_FILE)
PROJECT_ROOT = os.path.dirname(CYBERRECON_DIR)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


BANNER = r"""
============================================================
              CYBERRECON
          Reconnaissance Framework
============================================================
"""


# ============================================================
# CONSTANTS
# ============================================================

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


# ============================================================
# UTILITY
# ============================================================

def clear_screen():
    os.system("clear" if os.name != "nt" else "cls")


def pause():
    input("\n[ENTER] Return to menu...")


def load_module(module_name):
    """
    Import a CyberRecon module safely.

    Returns:
        module object
        None if import fails
    """

    try:
        return importlib.import_module(module_name)

    except Exception as exc:
        print(f"\n[!] Could not import {module_name}")
        print(f"[!] {exc}")

        return None


def load_function(module_name, function_names):
    """
    Load the first compatible function from a module.

    This keeps the framework compatible with slightly different
    function names while still showing the actual import error.
    """

    module = load_module(module_name)

    if module is None:
        return None

    for function_name in function_names:

        function = getattr(
            module,
            function_name,
            None
        )

        if callable(function):
            return function

    print(
        f"\n[!] No compatible function found in "
        f"{module_name}"
    )

    print(
        f"[!] Tried: {', '.join(function_names)}"
    )

    return None


# ============================================================
# PORT SCANNER
# ============================================================

def port_scanner():

    print("\n" + "=" * 60)
    print("                    PORT SCANNER")
    print("=" * 60)

    target = input("[?] Enter target: ").strip()

    if not target:
        print("[!] Target cannot be empty.")
        return

    print(f"\n[+] Target: {target}")
    print("[+] Starting port scan...\n")

    function = load_function(
        "modules.scanner",
        [
            "run_port_scanner",
            "scan_ports",
        ],
    )

    if function is None:
        return

    try:

        results = function(
            target,
            DEFAULT_PORTS,
        )

        if results is None:
            results = []

        print("\n[+] Port scan completed.")
        print(f"[+] Results: {len(results)}")

        if results:

            print("\nOpen/Detected Ports:")
            print("-" * 40)

            for result in results:
                print(result)

    except Exception as exc:

        print("\n[!] Scanner error:")
        print(f"[!] {exc}")


# ============================================================
# SERVICE DETECTION
# ============================================================

def service_detection():

    print("\n" + "=" * 60)
    print("                 SERVICE DETECTION")
    print("=" * 60)

    target = input("[?] Enter target: ").strip()

    if not target:
        print("[!] Target cannot be empty.")
        return

    function = load_function(
        "modules.service_detection",
        [
            "run_service_detection",
            "detect_services",
            "service_detection",
        ],
    )

    if function is None:
        return

    try:

        # ----------------------------------------------------
        # Service detection expects:
        #
        # run_service_detection(target, scan_results)
        #
        # We first try to obtain actual port-scan results.
        # ----------------------------------------------------

        scanner_function = load_function(
            "modules.scanner",
            [
                "run_port_scanner",
                "scan_ports",
            ],
        )

        scan_results = []

        if scanner_function is not None:

            print(
                "\n[*] Running port scanner first "
                "to obtain open ports..."
            )

            try:

                scan_results = scanner_function(
                    target,
                    DEFAULT_PORTS,
                )

                if scan_results is None:
                    scan_results = []

            except Exception as exc:

                print(
                    f"[!] Port scanner could not provide "
                    f"results: {exc}"
                )

                scan_results = []

        # ----------------------------------------------------
        # If no scan results are available, the service module
        # can perform its own connectivity checks.
        # ----------------------------------------------------

        results = function(
            target,
            scan_results,
        )

        print("\n[+] Service detection completed.")

        if results is not None:

            print(
                f"[+] Services identified: "
                f"{len(results)}"
            )

            print()

            for result in results:

                print(
                    f"[+] {target}:{result.get('port', '?')}"
                )

                print(
                    f"    Service    : "
                    f"{result.get('service', 'unknown')}"
                )

                print(
                    f"    Technology : "
                    f"{result.get('technology', 'unknown')}"
                )

                print(
                    f"    Version    : "
                    f"{result.get('version', 'unknown')}"
                )

                print(
                    f"    Confidence : "
                    f"{result.get('confidence', 'unknown')}"
                )

                banner = result.get("banner", "")

                if banner:
                    print(
                        f"    Banner     : "
                        f"{banner[:300]}"
                    )

                print()

    except Exception as exc:

        print(
            f"\n[!] Service detection error: {exc}"
        )


# ============================================================
# TECHNOLOGY FINGERPRINTING
# ============================================================

def technology_fingerprinting():

    print("\n" + "=" * 60)
    print("             TECHNOLOGY FINGERPRINTING")
    print("=" * 60)

    target = input(
        "[?] Enter target: "
    ).strip()

    if not target:
        print("[!] Target cannot be empty.")
        return

    # --------------------------------------------------------
    # 1. Run port scanner
    # --------------------------------------------------------

    scanner_function = load_function(
        "modules.scanner",
        [
            "run_port_scanner",
            "scan_ports",
        ],
    )

    if scanner_function is None:
        return

    try:

        print(
            "\n[*] Running port scanner "
            "to discover open ports..."
        )

        scan_results = scanner_function(
            target,
            DEFAULT_PORTS,
        )

        if scan_results is None:
            scan_results = []

    except Exception as exc:

        print(
            f"\n[!] Port scanning failed: {exc}"
        )
        return

    if not scan_results:

        print(
            "\n[-] No open ports discovered."
        )
        print(
            "[+] Technology fingerprinting "
            "cannot continue."
        )
        return

    # --------------------------------------------------------
    # 2. Run service detection
    # --------------------------------------------------------

    service_function = load_function(
        "modules.service_detection",
        [
            "run_service_detection",
            "detect_services",
            "service_detection",
        ],
    )

    if service_function is None:
        return

    try:

        print(
            "\n[*] Running service detection..."
        )

        service_results = service_function(
            target,
            scan_results,
        )

        if service_results is None:
            service_results = []

    except Exception as exc:

        print(
            f"\n[!] Service detection failed: {exc}"
        )

        service_results = []

    # --------------------------------------------------------
    # 3. Run technology fingerprinting
    # --------------------------------------------------------

    fingerprint_function = load_function(
        "modules.fingerprint",
        [
            "run_fingerprinting",
        ],
    )

    if fingerprint_function is None:
        return

    try:

        print(
            "\n[*] Running technology fingerprinting..."
        )

        results = fingerprint_function(
            target,
            scan_results,
            service_results,
        )

        print(
            "\n[+] Technology fingerprinting completed."
        )

        if results:

            print(
                f"[+] Fingerprints found: {len(results)}"
            )

        else:

            print(
                "[-] No technology fingerprints "
                "were identified."
            )

    except Exception as exc:

        print(
            f"\n[!] Fingerprinting error: {exc}"
        )


# ============================================================
# HTTP RECON
# ============================================================

def http_recon():

    print("\n" + "=" * 60)
    print("                    HTTP RECON")
    print("=" * 60)

    target = input(
        "[?] Enter target URL: "
    ).strip()

    if not target:
        print("[!] Target cannot be empty.")
        return

    function = load_function(
        "modules.http_recon",
        [
            "run_http_recon",
            "http_recon",
        ],
    )

    if function is None:
        return

    try:

        results = function(target)

        print(
            "\n[+] HTTP reconnaissance completed."
        )

        if results is not None:
            print(results)

    except Exception as exc:

        print(
            f"\n[!] HTTP recon error: {exc}"
        )


# ============================================================
# DNS RECON
# ============================================================

def dns_recon():

    print("\n" + "=" * 60)
    print("                     DNS RECON")
    print("=" * 60)

    target = input(
        "[?] Enter domain: "
    ).strip()

    if not target:
        print("[!] Target cannot be empty.")
        return

    function = load_function(
        "modules.dns_recon",
        [
            "run_dns_recon",
            "dns_recon",
        ],
    )

    if function is None:
        return

    try:

        results = function(target)

        print(
            "\n[+] DNS reconnaissance completed."
        )

        if results is not None:
            print(results)

    except Exception as exc:

        print(
            f"\n[!] DNS recon error: {exc}"
        )


# ============================================================
# SUBDOMAIN ENUMERATION
# ============================================================

def subdomain_enumeration():

    print("\n" + "=" * 60)
    print("                SUBDOMAIN ENUMERATION")
    print("=" * 60)

    target = input(
        "[?] Enter domain: "
    ).strip()

    if not target:
        print("[!] Target cannot be empty.")
        return

    function = load_function(
        "modules.subdomain_enum",
        [
            "run_subdomain_enumeration",
            "enumerate_subdomains",
            "subdomain_enumeration",
        ],
    )

    if function is None:
        return

    try:

        results = function(target)

        print(
            "\n[+] Subdomain enumeration completed."
        )

        if results is not None:
            print(results)

    except Exception as exc:

        print(
            f"\n[!] Subdomain error: {exc}"
        )


# ============================================================
# ENDPOINT ENUMERATION
# ============================================================

def endpoint_enumeration():

    print("\n" + "=" * 60)
    print("                ENDPOINT ENUMERATION")
    print("=" * 60)

    target = input(
        "[?] Enter target URL: "
    ).strip()

    if not target:
        print("[!] Target cannot be empty.")
        return

    function = load_function(
        "modules.endpoint",
        [
            "run_endpoint_enumeration",
            "enumerate_endpoints",
            "endpoint_enumeration",
        ],
    )

    if function is None:
        return

    try:

        results = function(target)

        print(
            "\n[+] Endpoint enumeration completed."
        )

        if results is not None:
            print(results)

    except Exception as exc:

        print(
            f"\n[!] Endpoint enumeration error: {exc}"
        )


# ============================================================
# FULL RECON
# ============================================================

def full_recon():

    print("\n" + "=" * 60)
    print("                     FULL RECON")
    print("=" * 60)

    target = input(
        "[?] Enter target: "
    ).strip()

    if not target:
        print("[!] Target cannot be empty.")
        return

    print("\n[+] Starting full reconnaissance...")
    print(f"[+] Target: {target}")

    results = {}

    # --------------------------------------------------------
    # 1. PORT SCANNER
    # --------------------------------------------------------

    print("\n" + "-" * 60)
    print("[+] Running: Port Scanner")
    print("-" * 60)

    scanner_function = load_function(
        "modules.scanner",
        [
            "run_port_scanner",
            "scan_ports",
        ],
    )

    scan_results = []

    if scanner_function is not None:

        try:

            scan_results = scanner_function(
                target,
                DEFAULT_PORTS,
            )

            if scan_results is None:
                scan_results = []

            results["Port Scanner"] = scan_results

            print("[+] Port Scanner completed.")

        except Exception as exc:

            results["Port Scanner"] = None

            print(
                f"[!] Port Scanner failed: {exc}"
            )

    else:

        results["Port Scanner"] = None

    # --------------------------------------------------------
    # 2. SERVICE DETECTION
    # --------------------------------------------------------

    print("\n" + "-" * 60)
    print("[+] Running: Service Detection")
    print("-" * 60)

    service_function = load_function(
        "modules.service_detection",
        [
            "run_service_detection",
            "detect_services",
            "service_detection",
        ],
    )

    if service_function is not None:

        try:

            service_results = service_function(
                target,
                scan_results,
            )

            results["Service Detection"] = (
                service_results
            )

            print(
                "[+] Service Detection completed."
            )

        except Exception as exc:

            results["Service Detection"] = None

            print(
                f"[!] Service Detection failed: "
                f"{exc}"
            )

    else:

        results["Service Detection"] = None

    # --------------------------------------------------------
    # 3. TECHNOLOGY FINGERPRINTING
    # --------------------------------------------------------

    print("\n" + "-" * 60)
    print("[+] Running: Technology Fingerprinting")
    print("-" * 60)

    fingerprint_function = load_function(
        "modules.tech_fingerprint",
        [
            "run_technology_fingerprinting",
            "run_tech_fingerprinting",
        ],
    )

    if fingerprint_function is not None:

        try:

            fingerprint_results = (
                fingerprint_function(target)
            )

            results["Technology Fingerprinting"] = (
                fingerprint_results
            )

            print(
                "[+] Technology Fingerprinting completed."
            )

        except Exception as exc:

            results["Technology Fingerprinting"] = None

            print(
                "[!] Technology Fingerprinting failed: "
                f"{exc}"
            )

    else:

        results["Technology Fingerprinting"] = None

    # --------------------------------------------------------
    # 4. HTTP RECON
    # --------------------------------------------------------

    print("\n" + "-" * 60)
    print("[+] Running: HTTP Recon")
    print("-" * 60)

    http_function = load_function(
        "modules.http_recon",
        [
            "run_http_recon",
            "http_recon",
        ],
    )

    if http_function is not None:

        try:

            http_results = http_function(target)

            results["HTTP Recon"] = http_results

            print(
                "[+] HTTP Recon completed."
            )

        except Exception as exc:

            results["HTTP Recon"] = None

            print(
                f"[!] HTTP Recon failed: {exc}"
            )

    else:

        results["HTTP Recon"] = None

    # --------------------------------------------------------
    # 5. DNS RECON
    # --------------------------------------------------------

    print("\n" + "-" * 60)
    print("[+] Running: DNS Recon")
    print("-" * 60)

    dns_function = load_function(
        "modules.dns_recon",
        [
            "run_dns_recon",
            "dns_recon",
        ],
    )

    if dns_function is not None:

        try:

            dns_results = dns_function(target)

            results["DNS Recon"] = dns_results

            print(
                "[+] DNS Recon completed."
            )

        except Exception as exc:

            results["DNS Recon"] = None

            print(
                f"[!] DNS Recon failed: {exc}"
            )

    else:

        results["DNS Recon"] = None

    # --------------------------------------------------------
    # 6. SUBDOMAIN ENUMERATION
    # --------------------------------------------------------

    print("\n" + "-" * 60)
    print("[+] Running: Subdomain Enumeration")
    print("-" * 60)

    subdomain_function = load_function(
        "modules.subdomain_enum",
        [
            "run_subdomain_enumeration",
            "enumerate_subdomains",
            "subdomain_enumeration",
        ],
    )

    if subdomain_function is not None:

        try:

            subdomain_results = (
                subdomain_function(target)
            )

            results["Subdomain Enumeration"] = (
                subdomain_results
            )

            print(
                "[+] Subdomain Enumeration completed."
            )

        except Exception as exc:

            results["Subdomain Enumeration"] = None

            print(
                "[!] Subdomain Enumeration failed: "
                f"{exc}"
            )

    else:

        results["Subdomain Enumeration"] = None

    # --------------------------------------------------------
    # 7. ENDPOINT ENUMERATION
    # --------------------------------------------------------

    print("\n" + "-" * 60)
    print("[+] Running: Endpoint Enumeration")
    print("-" * 60)

    endpoint_function = load_function(
        "modules.endpoint",
        [
            "run_endpoint_enumeration",
            "enumerate_endpoints",
            "endpoint_enumeration",
        ],
    )

    if endpoint_function is not None:

        try:

            endpoint_results = (
                endpoint_function(target)
            )

            results["Endpoint Enumeration"] = (
                endpoint_results
            )

            print(
                "[+] Endpoint Enumeration completed."
            )

        except Exception as exc:

            results["Endpoint Enumeration"] = None

            print(
                "[!] Endpoint Enumeration failed: "
                f"{exc}"
            )

    else:

        results["Endpoint Enumeration"] = None

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    print("\n" + "=" * 60)
    print("                 FULL RECON COMPLETE")
    print("=" * 60)

    print(
        f"\n[+] Target: {target}"
    )

    print(
        f"[+] Modules executed: {len(results)}"
    )

    return results


# ============================================================
# VULNERABILITY SCANNER
# ============================================================

def vulnerability_scanner():

    print("\n" + "=" * 60)
    print("                VULNERABILITY SCANNER")
    print("=" * 60)

    target = input(
        "[?] Enter target: "
    ).strip()

    if not target:
        print("[!] Target cannot be empty.")
        return

    function = load_function(
        "modules.vulnerability",
        [
            "run_vulnerability_scan",
            "run_vuln_scanner",
            "vulnerability_scan",
        ],
    )

    if function is None:
        return

    try:

        results = function(target)

        print(
            "\n[+] Vulnerability scan completed."
        )

        if results is not None:
            print(results)

    except Exception as exc:

        print(
            f"\n[!] Vulnerability scanner error: "
            f"{exc}"
        )


# ============================================================
# SAVE REPORT
# ============================================================

def save_report():

    print("\n" + "=" * 60)
    print("                    SAVE REPORT")
    print("=" * 60)

    function = load_function(
        "modules.report",
        [
            "save_report",
            "run_save_report",
            "generate_report",
        ],
    )

    if function is None:

        print(
            "\n[!] Report module is not available."
        )

        return

    try:

        function()

        print(
            "\n[+] Report operation completed."
        )

    except Exception as exc:

        print(
            f"\n[!] Report error: {exc}"
        )


# ============================================================
# MENU
# ============================================================

def show_menu():

    print("\n")
    print("=" * 50)
    print("           ASHWA CYBERRECON")
    print("         Reconnaissance Framework")
    print("=" * 50)

    print()

    print("1. Port Scanner")
    print("2. Service Detection")
    print("3. Fingerprinting")
    print("4. HTTP Recon")
    print("5. DNS Recon")
    print("6. Subdomain Enumeration")
    print("7. Endpoint Enumeration")
    print("8. Full Recon")
    print("9. Vulnerability Scanner")
    print("10. Save Report")
    print("0. Exit")

    print()
    print("=" * 50)


# ============================================================
# MAIN
# ============================================================

def main():

    clear_screen()

    print(BANNER)

    # --------------------------------------------------------
    # Show import environment once.
    # This makes future module problems much easier to diagnose.
    # --------------------------------------------------------

    print(
        f"[+] Project root: {PROJECT_ROOT}"
    )

    while True:

        show_menu()

        choice = input(
            "[>] Select an option: "
        ).strip()

        if choice == "1":

            port_scanner()
            pause()

        elif choice == "2":

            service_detection()
            pause()

        elif choice == "3":

            technology_fingerprinting()
            pause()

        elif choice == "4":

            http_recon()
            pause()

        elif choice == "5":

            dns_recon()
            pause()

        elif choice == "6":

            subdomain_enumeration()
            pause()

        elif choice == "7":

            endpoint_enumeration()
            pause()

        elif choice == "8":

            full_recon()
            pause()

        elif choice == "9":

            vulnerability_scanner()
            pause()

        elif choice == "10":

            save_report()
            pause()

        elif choice == "0":

            print(
                "\n[+] Exiting ASHWA CYBERRECON..."
            )

            print(
                "[+] Goodbye! 👋"
            )

            break

        else:

            print(
                "\n[!] Invalid option."
            )

            print(
                "[!] Choose a number from 0-10."
            )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
