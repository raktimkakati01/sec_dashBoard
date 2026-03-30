import httpx
from dataclasses import dataclass
from scanner.tests.request_utils import build_request_kwargs, inject_query_payload, parse_request_params

MAX_ENDPOINTS = 50  # limit for speed

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "1 UNION SELECT NULL--",
    "admin'--",
    "' OR 1=1#",
]

SQL_ERROR_PATTERNS = [
    "sql syntax",
    "mysql_fetch",
    "sqlite3.operationalerror",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query",
    "psycopg2",
    "orm exception",
    "sqlstate",
    "microsoft ole db",
    "odbc sql server driver",
    "syntax error",
    "unexpected end of sql",
    "database error",
    "sql error",
    "warning: mysql",
    "valid mysql result",
    "mysqlclient",
    "postgresql",
    "oracle error",
    "ora-",
]


@dataclass
class SQLiResult:
    endpoint_url: str
    severity: str
    title: str
    description: str
    evidence: str


def run(endpoints: list[dict], client: httpx.Client) -> list[SQLiResult]:
    """Test endpoints for SQL injection vulnerabilities."""
    results = []
    tested = set()

    live_eps = [ep for ep in endpoints
                if ep.get("status_code") and 200 <= ep["status_code"] < 400]

    for ep in live_eps[:MAX_ENDPOINTS]:
        url = ep["url"]
        method = ep.get("method", "GET")
        request_params = parse_request_params(ep.get("request_params"))
        base = url.split("?")[0]
        if base in tested:
            continue
        tested.add(base)
        found = False

        for payload in SQLI_PAYLOADS:
            if found:
                break
            try:
                if method == "GET":
                    test_url = inject_query_payload(url, request_params, payload)
                    resp = client.get(test_url)
                else:
                    resp = client.request(method, url, **build_request_kwargs(ep, payload))

                body = resp.text.lower()

                for pattern in SQL_ERROR_PATTERNS:
                    if pattern in body:
                        results.append(SQLiResult(
                            endpoint_url=url,
                            severity="critical",
                            title=f"SQL Injection - Error Based ({method})",
                            description=(
                                f"SQL error pattern '{pattern}' detected at {url} "
                                f"with payload: {payload}"
                            ),
                            evidence=f"Payload: {payload}\nPattern: {pattern}\nStatus: {resp.status_code}",
                        ))
                        found = True
                        break

                # Boolean-based check on first payload only
                if not found and payload == SQLI_PAYLOADS[0]:
                    try:
                        baseline = client.request(method, url, **build_request_kwargs(ep))
                        if abs(len(resp.text) - len(baseline.text)) > 500:
                            results.append(SQLiResult(
                                endpoint_url=url,
                                severity="high",
                                title=f"SQL Injection - Boolean Based ({method})",
                                description=f"Significant response difference at {url} with SQLi payload.",
                                evidence=f"Payload: {payload}\nBaseline: {len(baseline.text)}B\nInjected: {len(resp.text)}B",
                            ))
                            found = True
                    except Exception:
                        pass
            except Exception:
                continue

    return results
