"""
ASHWA CYBERRECON
HTTP Reconnaissance Module

Use only against systems you own or are explicitly authorized to test.
"""

import re
import time
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


USER_AGENT = "AshwaCyberRecon/1.0"


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]


def normalize_url(target):
    """Convert a target into a clean HTTP URL."""

    target = target.strip()

    if not target:
        return None

    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    parsed = urlparse(target)

    if not parsed.netloc:
        return None

    return target.rstrip("/") + "/"


def extract_title(body):
    """Extract the HTML title if present."""

    if not body:
        return None

    match = re.search(
        r"<title[^>]*>(.*?)</title>",
        body,
        re.IGNORECASE | re.DOTALL,
    )

    if not match:
        return None

    title = re.sub(r"\s+", " ", match.group(1))

    return title.strip()


def perform_request(url, timeout=5):
    """Perform a GET request and collect HTTP information."""

    start = time.perf_counter()

    request = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
        },
        method="GET",
    )

    try:

        with urlopen(request, timeout=timeout) as response:

            elapsed = time.perf_counter() - start

            content_type = response.headers.get(
                "Content-Type",
                "unknown",
            )

            content_length = response.headers.get(
                "Content-Length",
                "unknown",
            )

            server = response.headers.get(
                "Server",
                "unknown",
            )

            cookies = response.headers.get_all(
                "Set-Cookie"
            )

            headers = {
                name: response.headers.get(name)
                for name in SECURITY_HEADERS
                if response.headers.get(name)
            }

            body = b""

            try:
                body = response.read(500000)

            except Exception:
                body = b""

            try:
                decoded_body = body.decode(
                    "utf-8",
                    errors="ignore",
                )

            except Exception:
                decoded_body = ""

            return {
                "url": url,
                "final_url": response.geturl(),
                "status": response.status,
                "reason": response.reason,
                "server": server,
                "content_type": content_type,
                "content_length": content_length,
                "response_time": round(elapsed, 4),
                "redirected": response.geturl() != url,
                "cookies": cookies or [],
                "security_headers": headers,
                "title": extract_title(decoded_body),
                "error": None,
            }

    except HTTPError as error:

        elapsed = time.perf_counter() - start

        cookies = []

        if error.headers:
            cookies = error.headers.get_all(
                "Set-Cookie"
            ) or []

        headers = {}

        if error.headers:
            for name in SECURITY_HEADERS:
                value = error.headers.get(name)

                if value:
                    headers[name] = value

        return {
            "url": url,
            "final_url": error.geturl(),
            "status": error.code,
            "reason": error.reason,
            "server": (
                error.headers.get("Server", "unknown")
                if error.headers
                else "unknown"
            ),
            "content_type": (
                error.headers.get(
                    "Content-Type",
                    "unknown",
                )
                if error.headers
                else "unknown"
            ),
            "content_length": (
                error.headers.get(
                    "Content-Length",
                    "unknown",
                )
                if error.headers
                else "unknown"
            ),
            "response_time": round(elapsed, 4),
            "redirected": False,
            "cookies": cookies,
            "security_headers": headers,
            "title": None,
            "error": None,
        }

    except (URLError, TimeoutError, OSError) as error:

        return {
            "url": url,
            "final_url": None,
            "status": None,
            "reason": None,
            "server": None,
            "content_type": None,
            "content_length": None,
            "response_time": None,
            "redirected": False,
            "cookies": [],
            "security_headers": {},
            "title": None,
            "error": str(error),
        }

    except Exception as error:

        return {
            "url": url,
            "final_url": None,
            "status": None,
            "reason": None,
            "server": None,
            "content_type": None,
            "content_length": None,
            "response_time": None,
            "redirected": False,
            "cookies": [],
            "security_headers": {},
            "title": None,
            "error": str(error),
        }


def print_header(title):
    """Print a section header."""

    print()
    print("=" * 55)
    print(f"          {title}")
    print("=" * 55)


def print_result(result):
    """Display HTTP reconnaissance results."""

    if result["status"] is None:

        print(
            f"[-] Request failed: "
            f"{result.get('error', 'unknown error')}"
        )

        return

    print(
        f"[+] Status        : "
        f"{result['status']} {result.get('reason', '')}"
    )

    print(
        f"[+] URL           : "
        f"{result['url']}"
    )

    if result.get("final_url"):
        print(
            f"[+] Final URL     : "
            f"{result['final_url']}"
        )

    print(
        f"[+] Server        : "
        f"{result.get('server', 'unknown')}"
    )

    print(
        f"[+] Content-Type  : "
        f"{result.get('content_type', 'unknown')}"
    )

    print(
        f"[+] Content-Length: "
        f"{result.get('content_length', 'unknown')}"
    )

    if result.get("response_time") is not None:
        print(
            f"[+] Response Time : "
            f"{result['response_time']}s"
        )

    print(
        f"[+] Redirected    : "
        f"{'Yes' if result.get('redirected') else 'No'}"
    )

    print(
        f"[+] Page Title    : "
        f"{result.get('title') or 'Not detected'}"
    )


def print_cookies(result):
    """Display detected cookies."""

    print_header("COOKIE INFORMATION")

    cookies = result.get("cookies", [])

    if not cookies:

        print("[-] No Set-Cookie headers detected.")

        return

    print(
        f"[+] Cookies detected: {len(cookies)}"
    )

    for cookie in cookies:

        cookie_name = cookie.split("=", 1)[0]

        print(
            f"    - {cookie_name}"
        )


def print_security_headers(result):
    """Display security header analysis."""

    print_header("SECURITY HEADERS")

    headers = result.get(
        "security_headers",
        {},
    )

    detected = 0

    for header in SECURITY_HEADERS:

        if header in headers:

            print(
                f"[+] {header}: "
                f"{headers[header]}"
            )

            detected += 1

        else:

            print(
                f"[-] {header}: Missing"
            )

    print()
    print(
        f"[*] Security headers detected: "
        f"{detected}/{len(SECURITY_HEADERS)}"
    )


def run_http_recon(target, timeout=5):
    """
    Run HTTP reconnaissance against an authorized target.
    """

    print_header("HTTP RECONNAISSANCE")

    base_url = normalize_url(target)

    if not base_url:

        print("[!] Invalid target.")

        return None

    print(
        f"[*] Target  : {base_url}"
    )

    print(
        f"[*] Timeout : {timeout}s"
    )

    print(
        f"[*] Fetching HTTP response..."
    )

    result = perform_request(
        base_url,
        timeout=timeout,
    )

    print_header("HTTP RESPONSE")

    print_result(result)

    if result["status"] is None:

        print()
        print(
            "[-] HTTP reconnaissance failed."
        )

        return result

    print_cookies(result)

    print_security_headers(result)

    print_header("HTTP RECON SUMMARY")

    print(
        f"Target           : {base_url}"
    )

    print(
        f"Status           : {result['status']}"
    )

    print(
        f"Server           : "
        f"{result.get('server', 'unknown')}"
    )

    print(
        f"Content-Type     : "
        f"{result.get('content_type', 'unknown')}"
    )

    print(
        f"Page Title       : "
        f"{result.get('title') or 'Not detected'}"
    )

    print(
        f"Cookies          : "
        f"{len(result.get('cookies', []))}"
    )

    print(
        f"Security Headers : "
        f"{len(result.get('security_headers', {}))}/"
        f"{len(SECURITY_HEADERS)}"
    )

    print()

    print(
        "[+] HTTP reconnaissance completed."
    )

    return result


if __name__ == "__main__":

    import sys

    if len(sys.argv) < 2:

        print(
            "Usage:"
        )

        print(
            "python3 -m "
            "cyberrecon.modules.http_recon "
            "<target>"
        )

        sys.exit(1)

    target = sys.argv[1]

    run_http_recon(target)
