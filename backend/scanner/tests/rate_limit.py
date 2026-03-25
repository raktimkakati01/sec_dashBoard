import time
import httpx
from dataclasses import dataclass

BURST_COUNT = 15  # Number of rapid requests to send
BURST_DELAY = 0.01  # Minimal delay between requests
MAX_ENDPOINTS = 10  # only test a few endpoints


@dataclass
class RateLimitResult:
    endpoint_url: str
    severity: str
    title: str
    description: str
    evidence: str


def run(endpoints: list[dict], client: httpx.Client) -> list[RateLimitResult]:
    """Test endpoints for rate limiting enforcement."""
    results = []
    checked = set()
    found_count = 0

    sensitive_keywords = ["login", "auth", "token", "register", "signup", "password", "reset"]

    for ep in endpoints:
        url = ep["url"]
        method = ep.get("method", "GET")
        base = url.split("?")[0]

        if base in checked:
            continue
        checked.add(base)

        is_sensitive = any(kw in url.lower() for kw in sensitive_keywords)
        if not is_sensitive:
            continue
        if found_count >= MAX_ENDPOINTS:
            break

        try:
            status_codes = []
            rate_limited = False

            for i in range(BURST_COUNT):
                resp = client.request(method, url)
                status_codes.append(resp.status_code)
                if resp.status_code == 429:
                    rate_limited = True
                    break
                time.sleep(BURST_DELAY)

            if not rate_limited:
                # All requests succeeded - no rate limiting
                success_count = sum(1 for s in status_codes if 200 <= s < 400)
                results.append(RateLimitResult(
                    endpoint_url=url,
                    severity="medium",
                    title="No Rate Limiting Detected",
                    description=(
                        f"Sent {BURST_COUNT} rapid requests to {url} without being rate limited. "
                        f"This endpoint may be vulnerable to brute-force or abuse."
                    ),
                    evidence=(
                        f"Requests sent: {len(status_codes)}\n"
                        f"Successful (2xx/3xx): {success_count}\n"
                        f"429 responses: 0\n"
                        f"Status codes: {status_codes[:10]}..."
                    ),
                ))
            else:
                # Rate limiting is in place - informational
                trigger_index = status_codes.index(429) + 1
                results.append(RateLimitResult(
                    endpoint_url=url,
                    severity="info",
                    title="Rate Limiting Active",
                    description=(
                        f"Rate limiting triggered after {trigger_index} requests to {url}."
                    ),
                    evidence=f"429 received after {trigger_index} requests",
                ))

        except Exception:
            continue

    return results
