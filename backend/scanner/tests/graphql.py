import json
import httpx
from dataclasses import dataclass

from scanner.tests.request_utils import build_request_kwargs

MAX_ENDPOINTS = 15
INTROSPECTION_QUERY = {
    "query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name } } }"
}


@dataclass
class GraphQLResult:
    endpoint_url: str
    severity: str
    title: str
    description: str
    evidence: str


def run(endpoints: list[dict], client: httpx.Client) -> list[GraphQLResult]:
    results = []
    seen = set()

    candidates = []
    for endpoint in endpoints:
      url = endpoint["url"]
      if "/graphql" in url.lower() or endpoint.get("request_content_type", "").lower().find("graphql") >= 0:
          candidates.append(endpoint)

    for endpoint in candidates[:MAX_ENDPOINTS]:
        url = endpoint["url"]
        if url in seen:
            continue
        seen.add(url)

        method = endpoint.get("method", "POST").upper()
        if method not in {"GET", "POST"}:
            method = "POST"

        try:
            kwargs = build_request_kwargs(
                {
                    **endpoint,
                    "request_content_type": "application/json",
                    "request_example": json.dumps(INTROSPECTION_QUERY),
                }
            )
            resp = client.request(method, url, **kwargs)
            body = resp.text
        except Exception:
            continue

        if resp.status_code < 400 and "__schema" in body:
            results.append(GraphQLResult(
                endpoint_url=url,
                severity="medium",
                title="GraphQL Introspection Enabled",
                description=f"GraphQL introspection is enabled on {url}.",
                evidence=body[:1200],
            ))

        if "GraphiQL" in body or "Apollo Sandbox" in body or "graphql-playground" in body.lower():
            results.append(GraphQLResult(
                endpoint_url=url,
                severity="low",
                title="Interactive GraphQL Console Exposed",
                description=f"An interactive GraphQL UI appears to be exposed at {url}.",
                evidence=body[:1200],
            ))

    return results
