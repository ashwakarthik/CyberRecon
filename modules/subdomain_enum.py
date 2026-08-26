"""
ASHWA CYBERRECON
Subdomain Enumeration Module

Use only against domains you own or are explicitly authorized to test.

Performs lightweight passive DNS-style enumeration using common
subdomain names and DNS resolution.
"""

import socket


DEFAULT_SUBDOMAINS = [
    "www",
    "mail",
    "api",
    "dev",
    "test",
    "staging",
    "admin",
    "portal",
    "app",
    "blog",
    "shop",
    "vpn",
    "remote",
    "cdn",
    "static",
    "docs",
    "support",
]


def normalize_domain(target):
    """Normalize a domain name."""

    if not target:
        return None

    target = target.strip().lower()

    target = target.replace(
        "https://",
        ""
    ).replace(
        "http://",
        ""
    )

    target = target.split("/")[0]
    target = target.split(":")[0]

    if not target:
        return None

    return target


def resolve_hostname(hostname, timeout=2):
    """Resolve a hostname to an IP address."""

    old_timeout = socket.getdefaulttimeout()

    try:

        socket.setdefaulttimeout(timeout)

        return socket.gethostbyname(hostname)

    except (
        socket.gaierror,
        socket.timeout,
        OSError,
    ):

        return None

    finally:

        socket.setdefaulttimeout(
            old_timeout
        )


def subdomain_enumeration(
    target,
    wordlist=None,
    timeout=2,
):
    """
    Enumerate common subdomains.

    Returns a structured dictionary.
    """

    domain = normalize_domain(target)

    if not domain:

        return {
            "target": target,
            "domain": None,
            "found": [],
            "error": "Invalid domain",
        }

    names = (
        wordlist
        if wordlist is not None
        else DEFAULT_SUBDOMAINS
    )

    found = []

    print()
    print("=" * 55)
    print("             SUBDOMAIN ENUMERATION")
    print("=" * 55)

    print()
    print(f"[*] Domain : {domain}")
    print(f"[*] Candidates : {len(names)}")
    print()

    for name in names:

        name = str(name).strip().lower()

        if not name:
            continue

        if "." in name:
            hostname = name
        else:
            hostname = f"{name}.{domain}"

        print(
            f"[*] Checking {hostname}...",
            end=" "
        )

        ip = resolve_hostname(
            hostname,
            timeout=timeout
        )

        if ip:

            print(f"FOUND → {ip}")

            found.append({
                "subdomain": hostname,
                "ip": ip,
            })

        else:

            print("not found")

    print()
    print(
        f"[+] Found {len(found)} "
        f"resolvable subdomain(s)."
    )

    print("=" * 55)

    return {
        "target": target,
        "domain": domain,
        "found": found,
        "count": len(found),
        "error": None,
    }


# Compatibility alias for possible older code.
run_subdomain_enumeration = subdomain_enumeration


if __name__ == "__main__":

    import sys

    if len(sys.argv) < 2:

        print(
            "Usage:"
        )

        print(
            "python3 -m "
            "cyberrecon.modules.subdomain_enum "
            "<domain>"
        )

        sys.exit(1)

    target = sys.argv[1]

    subdomain_enumeration(target)
