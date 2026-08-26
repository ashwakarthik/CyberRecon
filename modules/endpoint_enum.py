"""
ASHWA CYBERRECON
Endpoint Enumeration Module v2

Use only against systems you own or are explicitly
authorized to test.

Adds baseline comparison to reduce false-positive
HTTP 200 responses from generic fallback pages.
"""

import hashlib
import time
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


# ============================================================
# DEFAULT ENDPOINTS
# ============================================================

DEFAULT_PATHS = [
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/favicon.ico",

    "/login",
    "/signin",
    "/register",
    "/signup",
    "/logout",

    "/admin",
    "/admin/",
    "/dashboard",
    "/panel",

    "/api",
    "/api/",
    "/api/v1",
    "/api/v2",

    "/docs",
    "/documentation",
    "/swagger",
    "/swagger/",
    "/openapi.json",

    "/uploads",
    "/upload",
    "/images",
    "/static",
    "/assets",
    "/css",
    "/js",
]


BASELINE_PATH = (
    "/__ashwa_cyberrecon_baseline_"
    "9f31c7a4__"
)


# ============================================================
# URL NORMALIZATION
# ============================================================

def normalize_url(target):
    """Convert target into a clean HTTP/HTTPS URL."""

    if not target:
        return None

    target = target.strip()

    if not target:
        return None

    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    parsed = urlparse(target)

    if not parsed.netloc:
        return None

    if not parsed.hostname:
        return None

    return target.rstrip("/") + "/"


# ============================================================
# HTTP REQUEST
# ============================================================

def check_endpoint(url, timeout=5):
    """
    Request one endpoint and return structured information.

    The response body is intentionally not returned in full.
    A short body fingerprint is used for comparison.
    """

    start = time.perf_counter()

    request = Request(
        url,
        headers={
            "User-Agent": "AshwaCyberRecon/2.0"
        },
        method="GET",
    )

    try:

        with urlopen(
            request,
            timeout=timeout
        ) as response:

            body = response.read(65536)

            elapsed = (
                time.perf_counter() - start
            )

            content_type = response.headers.get(
                "Content-Type",
                "unknown"
            )

            return {
                "url": url,
                "final_url": response.geturl(),
                "status": response.status,
                "content_type": content_type,
                "content_length": response.headers.get(
                    "Content-Length",
                    str(len(body))
                ),
                "body_length": len(body),
                "body_hash": hashlib.sha256(
                    body
                ).hexdigest(),
                "server": response.headers.get(
                    "Server",
                    "unknown"
                ),
                "response_time": round(
                    elapsed,
                    4
                ),
                "redirected": (
                    response.geturl() != url
                ),
                "error": None,
            }

    except HTTPError as error:

        elapsed = (
            time.perf_counter() - start
        )

        try:
            body = error.read(65536)
        except Exception:
            body = b""

        return {
            "url": url,
            "final_url": error.geturl()
            if hasattr(error, "geturl")
            else url,
            "status": error.code,
            "content_type": error.headers.get(
                "Content-Type",
                "unknown"
            ),
            "content_length": error.headers.get(
                "Content-Length",
                str(len(body))
            ),
            "body_length": len(body),
            "body_hash": hashlib.sha256(
                body
            ).hexdigest(),
            "server": error.headers.get(
                "Server",
                "unknown"
            ),
            "response_time": round(
                elapsed,
                4
            ),
            "redirected": False,
            "error": None,
        }

    except (
        URLError,
        TimeoutError,
        OSError,
    ) as error:

        return {
            "url": url,
            "final_url": url,
            "status": None,
            "content_type": None,
            "content_length": None,
            "body_length": 0,
            "body_hash": None,
            "server": None,
            "response_time": None,
            "redirected": False,
            "error": str(error),
        }

    except Exception as error:

        return {
            "url": url,
            "final_url": url,
            "status": None,
            "content_type": None,
            "content_length": None,
            "body_length": 0,
            "body_hash": None,
            "server": None,
            "response_time": None,
            "redirected": False,
            "error": str(error),
        }


# ============================================================
# BASELINE COMPARISON
# ============================================================

def compare_with_baseline(
    result,
    baseline
):
    """
    Detect likely generic fallback responses.

    A response is marked as a likely fallback when its
    status, content type and body characteristics closely
    match the random baseline response.
    """

    result["baseline_match"] = False
    result["classification"] = None

    if not baseline:
        return result

    if result.get("status") is None:
        return result

    if baseline.get("status") != result.get("status"):
        return result

    if (
        baseline.get("content_type")
        != result.get("content_type")
    ):
        return result

    baseline_length = baseline.get(
        "body_length",
        0
    )

    result_length = result.get(
        "body_length",
        0
    )

    # Exact body hash is strong evidence that the server
    # returned the same generic page.
    if (
        baseline.get("body_hash")
        and baseline.get("body_hash")
        == result.get("body_hash")
    ):

        result["baseline_match"] = True
        result["classification"] = (
            "GENERIC FALLBACK"
        )

        return result

    # Some servers inject small dynamic values into their
    # fallback page. Allow a small size difference.
    if baseline_length > 0:

        difference = abs(
            baseline_length
            - result_length
        )

        ratio = (
            difference
            / baseline_length
        )

        if ratio <= 0.02:

            result["baseline_match"] = True
            result["classification"] = (
                "LIKELY FALLBACK"
            )

    return result


# ============================================================
# RESULT CLASSIFICATION
# ============================================================

def classify_status(result):
    """Return display symbol and classification."""

    status = result.get("status")

    if status is None:
        return "[!]", "ERROR"

    if result.get("baseline_match"):
        return "[~]", result.get(
            "classification",
            "FALLBACK"
        )

    if status in (200, 201, 202, 204):
        return "[+]", "ACCESSIBLE"

    if status in (
        301,
        302,
        303,
        307,
        308,
    ):
        return "[>]", "REDIRECT"

    if status in (401, 403):
        return "[!]", "RESTRICTED"

    if status == 404:
        return "[-]", "NOT FOUND"

    if 400 <= status < 500:
        return "[*]", "CLIENT ERROR"

    if 500 <= status < 600:
        return "[*]", "SERVER ERROR"

    return "[*]", "OTHER"


# ============================================================
# PRINT RESULT
# ============================================================

def print_result(result):
    """Print one endpoint result."""

    status = result.get("status")

    if status is None:

        print(
            f"[!] ERROR "
            f"{result['url']}"
        )

        if result.get("error"):
            print(
                f"    Reason      : "
                f"{result['error']}"
            )

        return

    symbol, classification = classify_status(
        result
    )

    print(
        f"{symbol} {status:<3} "
        f"{classification:<18} "
        f"{result['url']}"
    )

    if result.get("server"):
        print(
            f"    Server      : "
            f"{result['server']}"
        )

    if result.get("content_type"):
        print(
            f"    Content-Type: "
            f"{result['content_type']}"
        )

    if result.get("body_length") is not None:
        print(
            f"    Body Size   : "
            f"{result['body_length']}"
        )

    if result.get("response_time") is not None:
        print(
            f"    Time        : "
            f"{result['response_time']}s"
        )

    if result.get("redirected"):
        print(
            "    Redirect    : Yes"
        )


# ============================================================
# ENDPOINT ENUMERATION
# ============================================================

def run_endpoint_enum(
    target,
    paths=None,
    delay=0.15,
    timeout=5
):
    """
    Enumerate common web endpoints.

    Returns:
        list[dict]
    """

    print()
    print("=" * 60)
    print("          ENDPOINT ENUMERATION v2")
    print("=" * 60)

    base_url = normalize_url(target)

    if not base_url:

        print(
            "\n[!] Invalid target."
        )

        return []

    if paths is None:
        paths = DEFAULT_PATHS

    print(
        f"\n[*] Base URL : {base_url}"
    )

    print(
        f"[*] Paths    : {len(paths)}"
    )

    print(
        f"[*] Delay    : {delay}s"
    )

    print(
        f"[*] Timeout  : {timeout}s"
    )

    # --------------------------------------------------------
    # BASELINE
    # --------------------------------------------------------

    baseline_url = urljoin(
        base_url,
        BASELINE_PATH.lstrip("/")
    )

    print()
    print(
        "[*] Establishing random-path baseline..."
    )

    baseline = check_endpoint(
        baseline_url,
        timeout=timeout
    )

    print(
        f"[*] Baseline status : "
        f"{baseline.get('status')}"
    )

    print(
        f"[*] Baseline size   : "
        f"{baseline.get('body_length')}"
    )

    print(
        f"[*] Baseline type   : "
        f"{baseline.get('content_type')}"
    )

    # --------------------------------------------------------
    # SCAN
    # --------------------------------------------------------

    results = []

    print()
    print("[*] Scanning endpoints...")
    print()

    for path in paths:

        if not path:
            continue

        if not path.startswith("/"):
            path = "/" + path

        endpoint = urljoin(
            base_url,
            path.lstrip("/")
        )

        result = check_endpoint(
            endpoint,
            timeout=timeout
        )

        result = compare_with_baseline(
            result,
            baseline
        )

        results.append(result)

        print_result(result)

        time.sleep(delay)

    # --------------------------------------------------------
    # CATEGORIES
    # --------------------------------------------------------

    accessible = [
        result
        for result in results
        if (
            result.get("status")
            in (200, 201, 202, 204)
            and not result.get(
                "baseline_match"
            )
        )
    ]

    restricted = [
        result
        for result in results
        if result.get("status")
        in (401, 403)
    ]

    redirects = [
        result
        for result in results
        if result.get("status")
        in (
            301,
            302,
            303,
            307,
            308,
        )
    ]

    fallback = [
        result
        for result in results
        if result.get("baseline_match")
    ]

    errors = [
        result
        for result in results
        if result.get("status") is None
    ]

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("          ENDPOINT SUMMARY")
    print("=" * 60)

    print(
        f"\nTarget              : "
        f"{base_url}"
    )

    print(
        f"Endpoints checked   : "
        f"{len(results)}"
    )

    print(
        f"Accessible          : "
        f"{len(accessible)}"
    )

    print(
        f"Restricted          : "
        f"{len(restricted)}"
    )

    print(
        f"Redirects           : "
        f"{len(redirects)}"
    )

    print(
        f"Generic/Fallback    : "
        f"{len(fallback)}"
    )

    print(
        f"Errors              : "
        f"{len(errors)}"
    )

    # --------------------------------------------------------
    # ACCESSIBLE
    # --------------------------------------------------------

    if accessible:

        print()
        print(
            "[+] Confirmed/likely accessible:"
        )

        for result in accessible:

            print(
                f"    {result['status']} "
                f"{result['url']}"
            )

    # --------------------------------------------------------
    # RESTRICTED
    # --------------------------------------------------------

    if restricted:

        print()
        print(
            "[!] Restricted endpoints:"
        )

        for result in restricted:

            print(
                f"    {result['status']} "
                f"{result['url']}"
            )

    # --------------------------------------------------------
    # REDIRECTS
    # --------------------------------------------------------

    if redirects:

        print()
        print(
            "[>] Redirect endpoints:"
        )

        for result in redirects:

            print(
                f"    {result['status']} "
                f"{result['url']}"
            )

    # --------------------------------------------------------
    # FALLBACK
    # --------------------------------------------------------

    if fallback:

        print()
        print(
            "[~] Likely generic/fallback responses:"
        )

        for result in fallback:

            print(
                f"    {result['status']} "
                f"{result['url']}"
            )

    # --------------------------------------------------------
    # FINAL
    # --------------------------------------------------------

    interesting_count = (
        len(accessible)
        + len(restricted)
        + len(redirects)
    )

    print()

    print(
        f"[+] Interesting endpoints "
        f"discovered: {interesting_count}"
    )

    print(
        "[+] Endpoint enumeration "
        "completed."
    )

    return results


# ============================================================
# COMPATIBILITY ALIASES
# ============================================================

endpoint_enumeration = run_endpoint_enum
enumerate_endpoints = run_endpoint_enum


# ============================================================
# COMMAND LINE
# ============================================================

if __name__ == "__main__":

    import sys

    if len(sys.argv) < 2:

        print(
            "Usage:"
        )

        print(
            "python3 -m "
            "cyberrecon.modules.endpoint_enum "
            "<target>"
        )

        sys.exit(1)

    run_endpoint_enum(
        sys.argv[1]
    )
