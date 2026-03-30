import httpx
from dataclasses import dataclass
from scanner.tests.request_utils import build_request_kwargs

MAX_ENDPOINTS = 80  # limit for speed


@dataclass
class AuthResult:
    endpoint_url: str
    severity: str
    title: str
    description: str
    evidence: str


def run(endpoints: list[dict], auth_client: httpx.Client,
        noauth_client: httpx.Client) -> list[AuthResult]:
    """Test endpoints for authentication and authorization issues.

    auth_client: has cookies/headers set (authenticated)
    noauth_client: bare client with NO auth (for bypass testing)
    """
    results = []
    tested = set()

    # Focus on endpoints that returned 200 with auth
    live_eps = [ep for ep in endpoints
                if ep.get("status_code") and 200 <= ep["status_code"] < 400]

    for ep in live_eps[:MAX_ENDPOINTS]:
        url = ep["url"]
        method = ep.get("method", "GET")
        base = url.split("?")[0]
        if base in tested:
            continue
        tested.add(base)

        # Test 1: Auth bypass — access endpoint WITHOUT cookies
        try:
            request_kwargs = build_request_kwargs(ep)
            resp_noauth = noauth_client.request(method, url, **request_kwargs)
            resp_auth = auth_client.request(method, url, **request_kwargs)

            if (200 <= resp_noauth.status_code < 300 and
                    200 <= resp_auth.status_code < 300):
                # Both succeed — endpoint is public or auth is not enforced
                # Check if responses are similar (same content = no auth check)
                if abs(len(resp_noauth.text) - len(resp_auth.text)) < 200:
                    results.append(AuthResult(
                        endpoint_url=url,
                        severity="high",
                        title="No Authentication Required",
                        description=(
                            f"Endpoint {url} returns the same response with and without "
                            f"authentication cookies. No auth enforcement detected."
                        ),
                        evidence=(
                            f"With auth: {resp_auth.status_code} ({len(resp_auth.text)} bytes)\n"
                            f"Without auth: {resp_noauth.status_code} ({len(resp_noauth.text)} bytes)"
                        ),
                    ))
            elif (resp_auth.status_code < 300 and
                  resp_noauth.status_code in (401, 403)):
                # Good: auth is enforced (informational)
                pass
            elif (200 <= resp_noauth.status_code < 300 and
                  resp_noauth.status_code != resp_auth.status_code):
                results.append(AuthResult(
                    endpoint_url=url,
                    severity="medium",
                    title="Partial Auth Bypass",
                    description=(
                        f"Endpoint {url} returns different status codes with/without auth "
                        f"but still responds to unauthenticated requests."
                    ),
                    evidence=(
                        f"With auth: {resp_auth.status_code}\n"
                        f"Without auth: {resp_noauth.status_code}"
                    ),
                ))
        except Exception:
            pass

        # Test 2: IDOR — swap numeric IDs
        if any(seg.isdigit() for seg in url.rstrip("/").split("/")):
            try:
                parts = url.rstrip("/").split("/")
                for i, part in enumerate(parts):
                    if part.isdigit():
                        original_id = part
                        parts[i] = str(int(part) + 1)
                        test_url = "/".join(parts)
                        resp = auth_client.request(method, test_url, **build_request_kwargs(ep))
                        if 200 <= resp.status_code < 300:
                            results.append(AuthResult(
                                endpoint_url=url,
                                severity="medium",
                                title="Potential IDOR Vulnerability",
                                description=(
                                    f"Changing ID from {original_id} to {parts[i]} "
                                    f"at {url} returned {resp.status_code}."
                                ),
                                evidence=f"Original: {url}\nModified: {test_url}\nStatus: {resp.status_code}",
                            ))
                        parts[i] = original_id
                        break
            except Exception:
                pass

    return results
