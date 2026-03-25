import httpx
from dataclasses import dataclass

REQUIRED_HEADERS = {
    "strict-transport-security": {
        "severity": "medium",
        "title": "Missing Strict-Transport-Security (HSTS)",
        "description": "HSTS is not set. The site may be vulnerable to protocol downgrade attacks.",
    },
    "x-content-type-options": {
        "severity": "low",
        "title": "Missing X-Content-Type-Options",
        "description": "X-Content-Type-Options is not set. Browsers may MIME-sniff responses.",
    },
    "x-frame-options": {
        "severity": "medium",
        "title": "Missing X-Frame-Options",
        "description": "X-Frame-Options is not set. The site may be vulnerable to clickjacking.",
    },
    "content-security-policy": {
        "severity": "medium",
        "title": "Missing Content-Security-Policy",
        "description": "CSP header is not set. This helps prevent XSS and data injection attacks.",
    },
    "x-xss-protection": {
        "severity": "low",
        "title": "Missing X-XSS-Protection",
        "description": "X-XSS-Protection is not set. While deprecated, it provides defense-in-depth for older browsers.",
    },
    "referrer-policy": {
        "severity": "low",
        "title": "Missing Referrer-Policy",
        "description": "Referrer-Policy is not set. Sensitive URLs may leak via the Referer header.",
    },
    "permissions-policy": {
        "severity": "low",
        "title": "Missing Permissions-Policy",
        "description": "Permissions-Policy (formerly Feature-Policy) is not set.",
    },
}

DANGEROUS_HEADERS = {
    "server": {
        "severity": "info",
        "title": "Server Version Disclosure",
        "description": "The Server header discloses server software information.",
    },
    "x-powered-by": {
        "severity": "info",
        "title": "X-Powered-By Disclosure",
        "description": "The X-Powered-By header discloses technology stack information.",
    },
    "x-aspnet-version": {
        "severity": "info",
        "title": "ASP.NET Version Disclosure",
        "description": "The X-AspNet-Version header discloses the ASP.NET version.",
    },
}


@dataclass
class HeaderResult:
    endpoint_url: str
    severity: str
    title: str
    description: str
    evidence: str


def run(endpoints: list[dict], client: httpx.Client) -> list[HeaderResult]:
    """Check endpoints for missing or insecure security headers.

    Produces ONE finding per header issue with all affected endpoints listed,
    instead of one finding per endpoint per header.
    """
    # Collect: { title -> [affected_urls] }
    missing_map = {}   # title -> { info, urls }
    disclosure_map = {}  # title -> { info, urls, values }
    checked_base = set()

    # Sample up to 30 unique endpoints for header checks
    sampled = 0
    for ep in endpoints:
        url = ep["url"]
        base = url.split("?")[0]
        if base in checked_base:
            continue
        checked_base.add(base)
        sampled += 1
        if sampled > 30:
            break

        try:
            resp = client.get(url)
        except Exception:
            continue

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for header_name, info in REQUIRED_HEADERS.items():
            if header_name not in headers_lower:
                key = info["title"]
                if key not in missing_map:
                    missing_map[key] = {"info": info, "header": header_name, "urls": []}
                missing_map[key]["urls"].append(url)

        for header_name, info in DANGEROUS_HEADERS.items():
            if header_name in headers_lower:
                key = info["title"]
                if key not in disclosure_map:
                    disclosure_map[key] = {"info": info, "header": header_name, "urls": [], "value": headers_lower[header_name]}
                disclosure_map[key]["urls"].append(url)

    # Produce consolidated findings
    results = []

    for title, data in missing_map.items():
        urls = data["urls"]
        info = data["info"]
        sample = urls[:10]
        results.append(HeaderResult(
            endpoint_url=urls[0],
            severity=info["severity"],
            title=f"{info['title']} ({len(urls)} endpoints)",
            description=info["description"],
            evidence=(
                f"Header '{data['header']}' missing on {len(urls)} endpoints:\n"
                + "\n".join(f"  • {u}" for u in sample)
                + (f"\n  ... and {len(urls) - 10} more" if len(urls) > 10 else "")
            ),
        ))

    for title, data in disclosure_map.items():
        urls = data["urls"]
        info = data["info"]
        sample = urls[:10]
        results.append(HeaderResult(
            endpoint_url=urls[0],
            severity=info["severity"],
            title=f"{info['title']} ({len(urls)} endpoints)",
            description=f"{info['description']} Value: {data['value']}",
            evidence=(
                f"{data['header']}: {data['value']}\n"
                f"Found on {len(urls)} endpoints:\n"
                + "\n".join(f"  • {u}" for u in sample)
                + (f"\n  ... and {len(urls) - 10} more" if len(urls) > 10 else "")
            ),
        ))

    return results
