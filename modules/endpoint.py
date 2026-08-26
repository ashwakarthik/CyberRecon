"""
ASHWA CYBERRECON
Endpoint Enumeration Module

Use only against systems you own or are explicitly authorized to test.

Performs lightweight HTTP endpoint discovery using a small,
non-invasive list of common public paths.
"""

import time
from urllib.parse import urljoin
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


DEFAULT_TIMEOUT = 5

DEFAULT_ENDPOINTS = [
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/favicon.ico",
    "/login",
    "/signin",
    "/admin",
    "/dashboard",
    "/api",
    "/api/",
    "/docs",
    "/documentation",
    "/swagger",
    "/swagger/",
    "/openapi.json",
    "/health",
    "/status",
]


USER_AGENT = "AshwaCyberRecon/2.0"


def normalize_url(target):
    """Normalize an HTTP target."""

    if not target:
        return None

    target = target.strip()

    if not target:
        return None

    if not target.startswith(
        ("http://", "https://")
    ):
        target = "http://" + target

    return target.rstrip("/") + "/"


def check_endpoint(
    base_url,
    endpoint,
    timeout=DEFAULT_TIMEOUT,
):
    """Check one HTTP endpoint."""

    url = urljoin(
        base_url,
        endpoint.lstrip("/")
    )

    start = time.perf_counter()

    request = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
        },
        method="GET",
    )

    try:

        with urlopen(
            request,
            timeout=timeout
        ) as response:

            elapsed = (
                time.perf_counter() - start
            )

            return {
                "path": endpoint,
                "url": url,
                "status": response.status,
                "content_type": (
                    response.headers.get(
                        "Content-Type"
                    )
                ),
                "response_time": round(
                    elapsed,
                    4
                ),
                "error": None,
            }

    except HTTPError as error:

        elapsed = (
            time.perf_counter() - start
        )

        return {
            "path": endpoint,
            "url": url,
            "status": error.code,
            "content_type": (
                error.headers.get(
                    "Content-Type"
                )
                if error.headers
                else None
            ),
            "response_time": round(
                elapsed,
                4
            ),
            "error": f"HTTP {error.code}",
        }

    except (
        URLError,
        TimeoutError,
        OSError,
    ) as error:

        return {
            "path": endpoint,
            "url": url,
            "status": None,
            "content_type": None,
            "response_time": None,
            "error": str(error),
        }

    except Exception as error:

        return {
            "path": endpoint,
            "url": url,
            "status": None,
            "content_type": None,
            "response_time": None,
            "error": str(error),
        }


def endpoint_enumeration(
    target,
    endpoints=None,
    timeout=DEFAULT_TIMEOUT,
):
    """
    Enumerate a small set of common HTTP endpoints.

    Returns structured results.
    """

    base_url = normalize_url(target)

    if not base_url:

        return {
            "target": target,
            "base_url": None,
            "results": [],
            "found": [],
            "error": "Invalid target",
        }

    paths = (
        endpoints
        if endpoints is not None
        else DEFAULT_ENDPOINTS
    )

    print()
    print("=" * 55)
    print("              ENDPOINT ENUMERATION")
    print("=" * 55)

    print()
    print(f"[*] Target : {base_url}")
    print(f"[*] Paths  : {len(paths)}")
    print()

    results = []
    found = []

    for endpoint in paths:

        endpoint = str(endpoint).strip()

        if not endpoint:
            continue

        result = check_endpoint(
            base_url,
            endpoint,
            timeout=timeout,
        )

        results.append(result)

        status = result.get("status")

        if status is not None:

            if 200 <= status < 400:

                print(
                    f"[+] {endpoint:<20} "
                    f"HTTP {status}"
                )

                found.append(result)

            elif status in (
                401,
                403,
            ):

                print(
                    f"[!] {endpoint:<20} "
                    f"HTTP {status}"
                )

                found.append(result)

            else:

                print(
                    f"[-] {endpoint:<20} "
                    f"HTTP {status}"
                )

        else:

            print(
                f"[?] {endpoint:<20} "
                f"unreachable"
            )

    print()
    print(
        f"[+] Interesting endpoints: "
        f"{len(found)}"
    )

    print("=" * 55)

    return {
        "target": target,
        "base_url": base_url,
        "results": results,
        "found": found,
        "count": len(found),
        "error": None,
    }


# Compatibility aliases.
run_endpoint_enumeration = endpoint_enumeration
endpoint_enum = endpoint_enumeration


if __name__ == "__main__":

    import sys

    if len(sys.argv) < 2:

        print()
        print("Usage:")
        print(
            "python3 -m "
            "cyberrecon.modules.endpoint "
            "<target>"
        )

        sys.exit(1)

    target = sys.argv[1]

    endpoint_enumeration(target)
