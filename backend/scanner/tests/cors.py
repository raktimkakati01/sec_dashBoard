import httpx
from dataclasses import dataclass

EVIL_ORIGINS = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
]


@dataclass
class CORSResult:
    endpoint_url: str
    severity: str
    title: str
    description: str
    evidence: str


def run(endpoints: list[dict], client: httpx.Client) -> list[CORSResult]:
    """Test endpoints for CORS misconfiguration."""
    results = []

    for ep in endpoints:
        url = ep["url"]

        for origin in EVIL_ORIGINS:
            try:
                resp = client.get(url, headers={"Origin": origin})
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")

                # Wildcard with credentials
                if acao == "*" and acac.lower() == "true":
                    results.append(CORSResult(
                        endpoint_url=url,
                        severity="critical",
                        title="CORS: Wildcard Origin with Credentials",
                        description=(
                            f"The endpoint {url} returns Access-Control-Allow-Origin: * "
                            f"along with Access-Control-Allow-Credentials: true. "
                            f"This is a dangerous misconfiguration."
                        ),
                        evidence=f"Origin sent: {origin}\nACAO: {acao}\nACAC: {acac}",
                    ))
                    break

                # Reflects arbitrary origin
                if acao == origin and origin != "null":
                    severity = "high" if acac.lower() == "true" else "medium"
                    results.append(CORSResult(
                        endpoint_url=url,
                        severity=severity,
                        title="CORS: Origin Reflection",
                        description=(
                            f"The endpoint {url} reflects the attacker's origin ({origin}) "
                            f"in the Access-Control-Allow-Origin header."
                        ),
                        evidence=f"Origin sent: {origin}\nACAO: {acao}\nACAC: {acac}",
                    ))
                    break

                # Accepts null origin
                if acao == "null":
                    results.append(CORSResult(
                        endpoint_url=url,
                        severity="medium",
                        title="CORS: Null Origin Accepted",
                        description=(
                            f"The endpoint {url} accepts a null Origin, which can be "
                            f"exploited via sandboxed iframes."
                        ),
                        evidence=f"Origin sent: null\nACAO: {acao}",
                    ))
                    break

                # Wildcard (without credentials - lower severity)
                if acao == "*":
                    results.append(CORSResult(
                        endpoint_url=url,
                        severity="low",
                        title="CORS: Wildcard Origin",
                        description=(
                            f"The endpoint {url} uses Access-Control-Allow-Origin: *. "
                            f"While not inherently dangerous without credentials, "
                            f"it may expose data to any origin."
                        ),
                        evidence=f"ACAO: {acao}",
                    ))
                    break

            except Exception:
                continue

    return results
