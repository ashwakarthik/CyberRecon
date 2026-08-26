"""
ASHWA CYBERRECON
DNS Reconnaissance Module

Use only against systems you own or are explicitly authorized to test.
"""

import socket
import subprocess
import re
from urllib.parse import urlparse


def normalize_domain(target):
    """Convert a target into a clean domain name."""

    target = target.strip()

    if not target:
        return None

    if "://" in target:
        parsed = urlparse(target)
        domain = parsed.hostname
    else:
        domain = target.split("/")[0]

    if not domain:
        return None

    domain = domain.strip().lower()

    # Remove accidental port
    if ":" in domain:
        domain = domain.split(":")[0]

    return domain


def resolve_ipv4(domain):
    """Resolve IPv4 addresses for a domain."""

    try:
        addresses = socket.getaddrinfo(
            domain,
            None,
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        ips = sorted(
            set(
                result[4][0]
                for result in addresses
            )
        )

        return ips

    except socket.gaierror:
        return []


def resolve_ipv6(domain):
    """Resolve IPv6 addresses for a domain."""

    try:
        addresses = socket.getaddrinfo(
            domain,
            None,
            socket.AF_INET6,
            socket.SOCK_STREAM
        )

        ips = sorted(
            set(
                result[4][0]
                for result in addresses
            )
        )

        return ips

    except socket.gaierror:
        return []


def reverse_dns(ip):
    """Perform reverse DNS lookup."""

    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip)

        return {
            "hostname": hostname,
            "aliases": aliases,
            "addresses": addresses,
        }

    except (socket.herror, socket.gaierror):
        return None


def run_dig(domain, record_type):
    """Query DNS records using the dig command."""

    try:
        result = subprocess.run(
            [
                "dig",
                "+short",
                domain,
                record_type
            ],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return []

        records = []

        for line in result.stdout.splitlines():

            line = line.strip()

            if line:
                records.append(line)

        return records

    except (
        FileNotFoundError,
        subprocess.TimeoutExpired,
        OSError
    ):
        return []


def print_section(title):
    """Print a formatted section header."""

    print()
    print("=" * 55)
    print(f"          {title}")
    print("=" * 55)


def run_dns_recon(target):
    """Run DNS reconnaissance against a target."""

    print_section("DNS RECONNAISSANCE")

    domain = normalize_domain(target)

    if not domain:

        print("[!] Invalid domain.")

        return {}

    print(f"\n[*] Target : {domain}")
    print("[*] Starting DNS reconnaissance...")

    results = {
        "domain": domain,
        "ipv4": [],
        "ipv6": [],
        "reverse_dns": {},
        "records": {
            "NS": [],
            "MX": [],
            "TXT": [],
            "CNAME": [],
        },
    }

    # -------------------------------------------------
    # IPv4
    # -------------------------------------------------

    print_section("IPv4 ADDRESSES")

    ipv4_addresses = resolve_ipv4(domain)

    results["ipv4"] = ipv4_addresses

    if ipv4_addresses:

        for ip in ipv4_addresses:
            print(f"[+] {ip}")

    else:

        print("[-] No IPv4 addresses found.")

    # -------------------------------------------------
    # IPv6
    # -------------------------------------------------

    print_section("IPv6 ADDRESSES")

    ipv6_addresses = resolve_ipv6(domain)

    results["ipv6"] = ipv6_addresses

    if ipv6_addresses:

        for ip in ipv6_addresses:
            print(f"[+] {ip}")

    else:

        print("[-] No IPv6 addresses found.")

    # -------------------------------------------------
    # Reverse DNS
    # -------------------------------------------------

    print_section("REVERSE DNS")

    all_ips = ipv4_addresses + ipv6_addresses

    if not all_ips:

        print("[-] No addresses available for reverse lookup.")

    else:

        for ip in all_ips:

            reverse = reverse_dns(ip)

            if reverse:

                results["reverse_dns"][ip] = reverse

                print(f"[+] {ip}")
                print(
                    f"    Hostname: "
                    f"{reverse['hostname']}"
                )

                if reverse["aliases"]:

                    print(
                        f"    Aliases : "
                        f"{', '.join(reverse['aliases'])}"
                    )

            else:

                print(
                    f"[-] {ip} -> "
                    "No reverse DNS record"
                )

    # -------------------------------------------------
    # DNS RECORDS
    # -------------------------------------------------

    record_types = [
        "NS",
        "MX",
        "TXT",
        "CNAME",
    ]

    for record_type in record_types:

        print_section(f"{record_type} RECORDS")

        records = run_dig(
            domain,
            record_type
        )

        results["records"][record_type] = records

        if records:

            for record in records:
                print(f"[+] {record}")

        else:

            print(
                f"[-] No {record_type} records found."
            )

    # -------------------------------------------------
    # SUMMARY
    # -------------------------------------------------

    print_section("DNS RECON SUMMARY")

    print(f"Domain        : {domain}")
    print(
        f"IPv4 addresses: "
        f"{len(results['ipv4'])}"
    )
    print(
        f"IPv6 addresses: "
        f"{len(results['ipv6'])}"
    )

    print(
        f"NS records    : "
        f"{len(results['records']['NS'])}"
    )

    print(
        f"MX records    : "
        f"{len(results['records']['MX'])}"
    )

    print(
        f"TXT records   : "
        f"{len(results['records']['TXT'])}"
    )

    print(
        f"CNAME records : "
        f"{len(results['records']['CNAME'])}"
    )

    print()
    print("[+] DNS reconnaissance completed.")

    return results


if __name__ == "__main__":

    target = input(
        "[?] Enter domain: "
    ).strip()

    run_dns_recon(target)
