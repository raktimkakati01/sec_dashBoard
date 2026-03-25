import httpx
from dataclasses import dataclass

MAX_ENDPOINTS = 50  # limit for speed

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    "{{constructor.constructor('return this')()}}",
]

# Unique markers to detect reflection
REFLECTION_MARKERS = [
    ("SEC_XSS_TEST_12345", "SEC_XSS_TEST_12345"),
    ('<script>alert("SEC_XSS")</script>', 'alert("SEC_XSS")'),
]


@dataclass
class XSSResult:
    endpoint_url: str
    severity: str
    title: str
    description: str
    evidence: str


def run(endpoints: list[dict], client: httpx.Client) -> list[XSSResult]:
    """Test endpoints for Cross-Site Scripting vulnerabilities."""
    results = []
    tested = set()

    live_eps = [ep for ep in endpoints
                if ep.get("status_code") and 200 <= ep["status_code"] < 400]

    for ep in live_eps[:MAX_ENDPOINTS]:
        url = ep["url"]
        method = ep.get("method", "GET")
        base = url.split("?")[0]
        if base in tested:
            continue
        tested.add(base)
        found_for_endpoint = False

        # First check if input is reflected at all
        for marker, check in REFLECTION_MARKERS:
            try:
                if method == "GET":
                    test_url = f"{url}?q={marker}&search={marker}&input={marker}"
                    resp = client.get(test_url)
                else:
                    resp = client.request(method, url, data={
                        "q": marker, "search": marker, "input": marker,
                        "name": marker, "comment": marker,
                    })

                if check in resp.text:
                    ct = resp.headers.get("content-type", "")
                    # Check if content-type header is missing or allows HTML
                    is_html = "html" in ct or "text/plain" in ct or not ct

                    if is_html:
                        results.append(XSSResult(
                            endpoint_url=url,
                            severity="high",
                            title=f"Reflected XSS ({method})",
                            description=(
                                f"Input is reflected in the response without sanitization at {url}. "
                                f"Content-Type: {ct or 'not set'}"
                            ),
                            evidence=f"Marker: {marker}\nReflected in response: yes\nContent-Type: {ct}",
                        ))
                        found_for_endpoint = True
                        break
            except Exception:
                continue

        if found_for_endpoint:
            continue

        # Try actual XSS payloads
        for payload in XSS_PAYLOADS:
            try:
                if method == "GET":
                    test_url = f"{url}?q={payload}&search={payload}"
                    resp = client.get(test_url)
                else:
                    resp = client.request(method, url, data={
                        "q": payload, "input": payload, "comment": payload,
                    })

                if payload in resp.text:
                    results.append(XSSResult(
                        endpoint_url=url,
                        severity="high",
                        title=f"XSS - Payload Reflected ({method})",
                        description=(
                            f"XSS payload was reflected unescaped in the response body at {url}."
                        ),
                        evidence=f"Payload: {payload}\nStatus: {resp.status_code}",
                    ))
                    break
            except Exception:
                continue

    return results
