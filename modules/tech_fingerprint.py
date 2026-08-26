#!/usr/bin/env python3

import re
import ssl
import urllib.request
import urllib.error
from urllib.parse import urlparse


# ============================================================
# CYBERRECON
# Technology Fingerprinting Module
# ============================================================


USER_AGENT = (
    "Mozilla/5.0 "
    "(X11; Linux x86_64) "
    "AppleWebKit/537.36 "
    "(KHTML, like Gecko) "
    "Chrome/120 Safari/537.36"
)


# ------------------------------------------------------------
# URL Normalization
# ------------------------------------------------------------

def normalize_url(target):
    """
    Make sure the target has a usable HTTP/HTTPS scheme.
    """

    target = target.strip()

    if not target:
        return ""

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    return target


# ------------------------------------------------------------
# HTTP Request
# ------------------------------------------------------------

def fetch_target(url, timeout=8):
    """
    Fetch target headers and HTML using Python's standard
    library only.
    """

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": (
                "text/html,application/xhtml+xml,"
                "application/xml;q=0.9,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.5",
        },
        method="GET",
    )

    ssl_context = ssl.create_default_context()

    try:

        with urllib.request.urlopen(
            request,
            timeout=timeout,
            context=ssl_context
        ) as response:

            body = response.read(200000).decode(
                "utf-8",
                errors="replace"
            )

            headers = {
                key.lower(): value
                for key, value in response.headers.items()
            }

            return {
                "url": response.geturl(),
                "status": response.status,
                "headers": headers,
                "body": body,
            }

    except urllib.error.HTTPError as exc:

        try:
            body = exc.read(200000).decode(
                "utf-8",
                errors="replace"
            )
        except Exception:
            body = ""

        headers = {
            key.lower(): value
            for key, value in exc.headers.items()
        }

        return {
            "url": exc.geturl(),
            "status": exc.code,
            "headers": headers,
            "body": body,
        }

    except (
        urllib.error.URLError,
        TimeoutError,
        OSError
    ):

        # HTTPS may fail because of certificate validation.
        # Retry with certificate verification disabled,
        # useful for authorized lab/test environments.
        try:

            insecure_context = ssl._create_unverified_context()

            with urllib.request.urlopen(
                request,
                timeout=timeout,
                context=insecure_context
            ) as response:

                body = response.read(200000).decode(
                    "utf-8",
                    errors="replace"
                )

                headers = {
                    key.lower(): value
                    for key, value in response.headers.items()
                }

                return {
                    "url": response.geturl(),
                    "status": response.status,
                    "headers": headers,
                    "body": body,
                }

        except Exception:
            return None

    except Exception:
        return None


# ------------------------------------------------------------
# Technology Detection
# ------------------------------------------------------------

def detect_technologies(data):
    """
    Analyze HTTP headers and page content for common
    technology indicators.
    """

    technologies = []
    evidence = []

    if not data:
        return technologies, evidence

    headers = data.get("headers", {})
    body = data.get("body", "")

    body_lower = body.lower()

    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    generator = headers.get("x-generator", "")

    # --------------------------------------------------------
    # Server header
    # --------------------------------------------------------

    if server:

        technologies.append(server)
        evidence.append(
            f"Server header: {server}"
        )

    # --------------------------------------------------------
    # X-Powered-By
    # --------------------------------------------------------

    if powered_by:

        technologies.append(powered_by)
        evidence.append(
            f"X-Powered-By: {powered_by}"
        )

    # --------------------------------------------------------
    # X-Generator
    # --------------------------------------------------------

    if generator:

        technologies.append(generator)
        evidence.append(
            f"X-Generator: {generator}"
        )

    # --------------------------------------------------------
    # WordPress
    # --------------------------------------------------------

    if (
        "wp-content/" in body_lower
        or "wp-includes/" in body_lower
        or "wordpress" in body_lower
    ):

        technologies.append("WordPress")

        evidence.append(
            "WordPress indicators detected in page"
        )

        match = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            body,
            re.IGNORECASE
        )

        if match:
            generator_value = match.group(1)

            if "wordpress" in generator_value.lower():
                technologies.append(generator_value)

                evidence.append(
                    f"Generator meta tag: {generator_value}"
                )

    # --------------------------------------------------------
    # React
    # --------------------------------------------------------

    if (
        "react" in body_lower
        or "react-dom" in body_lower
        or "__next_data__" in body_lower
    ):

        technologies.append("React")

        evidence.append(
            "React-related page indicators detected"
        )

    # --------------------------------------------------------
    # Next.js
    # --------------------------------------------------------

    if (
        "__next_data__" in body_lower
        or "/_next/" in body_lower
        or "next.js" in body_lower
    ):

        technologies.append("Next.js")

        evidence.append(
            "Next.js indicators detected"
        )

    # --------------------------------------------------------
    # Vue.js
    # --------------------------------------------------------

    if (
        "vue.js" in body_lower
        or "vue.min.js" in body_lower
        or "vue@" in body_lower
    ):

        technologies.append("Vue.js")

        evidence.append(
            "Vue.js indicators detected"
        )

    # --------------------------------------------------------
    # Angular
    # --------------------------------------------------------

    if (
        "ng-version" in body_lower
        or "angular" in body_lower
    ):

        technologies.append("Angular")

        evidence.append(
            "Angular indicators detected"
        )

    # --------------------------------------------------------
    # jQuery
    # --------------------------------------------------------

    if (
        "jquery" in body_lower
        or "jquery.min.js" in body_lower
    ):

        technologies.append("jQuery")

        evidence.append(
            "jQuery indicators detected"
        )

    # --------------------------------------------------------
    # Bootstrap
    # --------------------------------------------------------

    if (
        "bootstrap" in body_lower
        or "bootstrap.min.css" in body_lower
        or "bootstrap.min.js" in body_lower
    ):

        technologies.append("Bootstrap")

        evidence.append(
            "Bootstrap indicators detected"
        )

    # --------------------------------------------------------
    # Tailwind CSS
    # --------------------------------------------------------

    if (
        "tailwindcss" in body_lower
        or "tailwind.min.css" in body_lower
    ):

        technologies.append("Tailwind CSS")

        evidence.append(
            "Tailwind CSS indicators detected"
        )

    # --------------------------------------------------------
    # PHP
    # --------------------------------------------------------

    if (
        ".php" in body_lower
        or "php" in powered_by.lower()
        or "php" in server.lower()
    ):

        technologies.append("PHP")

        evidence.append(
            "PHP indicators detected"
        )

    # --------------------------------------------------------
    # ASP.NET
    # --------------------------------------------------------

    if (
        "asp.net" in body_lower
        or "aspnet" in powered_by.lower()
        or "x-aspnet" in " ".join(headers.keys()).lower()
    ):

        technologies.append("ASP.NET")

        evidence.append(
            "ASP.NET indicators detected"
        )

    # --------------------------------------------------------
    # Nginx
    # --------------------------------------------------------

    if "nginx" in server.lower():

        technologies.append("Nginx")

        evidence.append(
            f"Nginx identified from Server header: {server}"
        )

    # --------------------------------------------------------
    # Apache
    # --------------------------------------------------------

    if "apache" in server.lower():

        technologies.append("Apache")

        evidence.append(
            f"Apache identified from Server header: {server}"
        )

    # --------------------------------------------------------
    # Python
    # --------------------------------------------------------

    if (
        "python" in server.lower()
        or "python" in powered_by.lower()
    ):

        technologies.append("Python")

        evidence.append(
            "Python identified from HTTP headers"
        )

    # --------------------------------------------------------
    # Django
    # --------------------------------------------------------

    if (
        "django" in body_lower
        or "csrftoken" in body_lower
        or "django" in powered_by.lower()
    ):

        technologies.append("Django")

        evidence.append(
            "Django indicators detected"
        )

    # --------------------------------------------------------
    # Laravel
    # --------------------------------------------------------

    if (
        "laravel" in body_lower
        or "laravel_session" in body_lower
    ):

        technologies.append("Laravel")

        evidence.append(
            "Laravel indicators detected"
        )

    # --------------------------------------------------------
    # Node.js / Express
    # --------------------------------------------------------

    if (
        "express" in server.lower()
        or "node.js" in server.lower()
        or "nodejs" in server.lower()
    ):

        technologies.append("Node.js / Express")

        evidence.append(
            f"Node.js/Express indicator: {server}"
        )

    # --------------------------------------------------------
    # Cloudflare
    # --------------------------------------------------------

    if (
        "cloudflare" in server.lower()
        or "cf-ray" in headers
    ):

        technologies.append("Cloudflare")

        evidence.append(
            "Cloudflare indicators detected"
        )

    # --------------------------------------------------------
    # Remove duplicates
    # --------------------------------------------------------

    unique_technologies = []

    for technology in technologies:

        if technology not in unique_technologies:
            unique_technologies.append(technology)

    return unique_technologies, evidence


# ------------------------------------------------------------
# Meta Information
# ------------------------------------------------------------

def extract_metadata(body):
    """
    Extract useful page metadata.
    """

    metadata = {
        "title": "",
        "description": "",
        "generator": "",
    }

    if not body:
        return metadata

    title_match = re.search(
        r"<title[^>]*>(.*?)</title>",
        body,
        re.IGNORECASE | re.DOTALL
    )

    if title_match:
        metadata["title"] = re.sub(
            r"\s+",
            " ",
            title_match.group(1)
        ).strip()

    description_match = re.search(
        r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']*)["\']',
        body,
        re.IGNORECASE
    )

    if description_match:
        metadata["description"] = (
            description_match.group(1).strip()
        )

    generator_match = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']*)["\']',
        body,
        re.IGNORECASE
    )

    if generator_match:
        metadata["generator"] = (
            generator_match.group(1).strip()
        )

    return metadata


# ------------------------------------------------------------
# Main Fingerprinting Function
# ------------------------------------------------------------

def run_technology_fingerprinting(target):
    """
    Main entry point used by CYBERRECON.
    """

    print(
        f"\n[*] Fingerprinting target: {target}"
    )

    url = normalize_url(target)

    if not url:

        print("[!] Invalid target.")
        return None

    print(f"[*] Target URL: {url}")
    print("[*] Fetching HTTP response...")

    data = fetch_target(url)

    if data is None:

        print("[!] Could not retrieve target.")
        print(
            "[!] Check the URL, network connection, "
            "or whether the target is reachable."
        )

        return None

    technologies, evidence = detect_technologies(
        data
    )

    metadata = extract_metadata(
        data.get("body", "")
    )

    parsed = urlparse(
        data.get("url", url)
    )

    result = {
        "target": data.get("url", url),
        "scheme": parsed.scheme,
        "host": parsed.netloc,
        "status_code": data.get("status"),
        "server": data.get(
            "headers",
            {}
        ).get(
            "server",
            "unknown"
        ),
        "powered_by": data.get(
            "headers",
            {}
        ).get(
            "x-powered-by",
            "unknown"
        ),
        "technologies": technologies,
        "evidence": evidence,
        "metadata": metadata,
        "headers": data.get(
            "headers",
            {}
        ),
    }

    # --------------------------------------------------------
    # Display results
    # --------------------------------------------------------

    print(
        "\n[+] Technology fingerprinting completed."
    )

    print(
        "\n" + "=" * 60
    )

    print(
        "                 FINGERPRINT RESULTS"
    )

    print(
        "=" * 60
    )

    print(
        f"Target       : {result['target']}"
    )

    print(
        f"Status Code  : {result['status_code']}"
    )

    print(
        f"Server       : {result['server']}"
    )

    print(
        f"Powered By   : {result['powered_by']}"
    )

    print(
        f"Page Title   : "
        f"{metadata['title'] or 'unknown'}"
    )

    print(
        f"Generator    : "
        f"{metadata['generator'] or 'unknown'}"
    )

    print("\nTechnologies:")

    if technologies:

        for technology in technologies:

            print(
                f"  [+] {technology}"
            )

    else:

        print(
            "  [-] No specific technology identified."
        )

    if evidence:

        print("\nEvidence:")

        for item in evidence:

            print(
                f"  [*] {item}"
            )

    print(
        "\n" + "=" * 60
    )

    return result


# ------------------------------------------------------------
# Compatibility Alias
# ------------------------------------------------------------

def run_tech_fingerprinting(target):
    """
    Compatibility wrapper for older CYBERRECON code.
    """

    return run_technology_fingerprinting(
        target
    )


# ------------------------------------------------------------
# Direct Execution
# ------------------------------------------------------------

if __name__ == "__main__":

    target = input(
        "Enter target URL: "
    ).strip()

    run_technology_fingerprinting(
        target
    )
