import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


# Common subdomains for authorized reconnaissance
COMMON_SUBDOMAINS = [
    "www",
    "mail",
    "webmail",
    "api",
    "app",
    "dev",
    "test",
    "staging",
    "stage",
    "beta",
    "demo",
    "admin",
    "portal",
    "login",
    "dashboard",
    "blog",
    "shop",
    "store",
    "support",
    "docs",
    "cdn",
    "static",
    "assets",
    "media",
    "images",
    "files",
    "ftp",
    "git",
    "gitlab",
    "github",
    "vpn",
    "remote",
    "m",
    "mobile",
]


def resolve_subdomain(subdomain, domain):
    """
    Resolve a single subdomain.

    Returns a dictionary containing the hostname,
    resolved IP addresses, and status.
    """

    hostname = f"{subdomain}.{domain}"

    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM
        )

        ips = sorted(
            {
                result[4][0]
                for result in addresses
                if result[4]
            }
        )

        if ips:
            return {
                "subdomain": hostname,
                "ips": ips,
                "status": "FOUND"
            }

    except socket.gaierror:
        pass

    except socket.timeout:
        pass

    except OSError:
        pass

    except Exception:
        pass

    return {
        "subdomain": hostname,
        "ips": [],
        "status": "NOT_FOUND"
    }


def run_subdomain_recon(domain):
    """
    Enumerate common subdomains for a domain.

    This performs DNS resolution only.
    """

    domain = domain.strip().lower()

    # Remove accidental protocol/path input
    domain = domain.replace("https://", "")
    domain = domain.replace("http://", "")
    domain = domain.split("/")[0]

    if not domain:
        print("[!] Domain cannot be empty.")
        return []

    print()
    print("=" * 50)
    print("          SUBDOMAIN ENUMERATION")
    print("=" * 50)

    print(f"\n[*] Target : {domain}")
    print(f"[*] Wordlist entries : {len(COMMON_SUBDOMAINS)}")
    print("[*] Workers : 20")
    print("[*] Performing DNS resolution...\n")

    results = []

    with ThreadPoolExecutor(max_workers=20) as executor:

        futures = {
            executor.submit(
                resolve_subdomain,
                subdomain,
                domain
            ): subdomain
            for subdomain in COMMON_SUBDOMAINS
        }

        for future in as_completed(futures):

            try:
                result = future.result()

            except Exception:
                continue

            if result["status"] == "FOUND":

                results.append(result)

                ip_string = ", ".join(result["ips"])

                print(
                    f"[+] {result['subdomain']:<30} -> {ip_string}"
                )

    # Sort alphabetically for clean reports
    results.sort(
        key=lambda item: item["subdomain"]
    )

    print()
    print("-" * 50)

    if results:

        print(
            f"[+] Subdomains discovered : {len(results)}"
        )

    else:

        print(
            "[-] No common subdomains discovered."
        )

    print("[+] Subdomain enumeration completed.")

    return results


def print_subdomain_results(results):
    """
    Print already collected subdomain results.
    """

    print()
    print("=" * 50)
    print("          DISCOVERED SUBDOMAINS")
    print("=" * 50)

    if not results:
        print("\n[-] No subdomains found.")
        return

    for result in results:

        hostname = result.get(
            "subdomain",
            "unknown"
        )

        ips = result.get(
            "ips",
            []
        )

        print(
            f"[+] {hostname:<30} -> "
            f"{', '.join(ips)}"
        )

    print(
        f"\n[+] Total : {len(results)}"
    )
