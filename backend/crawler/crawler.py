from __future__ import annotations

import time
import re
import httpx
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from dataclasses import dataclass, field

# Common API paths to brute-force
COMMON_PATHS = [
    "/", "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/health", "/api/status", "/api/info", "/api/version",
    "/api/users", "/api/user", "/api/auth", "/api/login", "/api/logout",
    "/api/register", "/api/signup", "/api/token", "/api/refresh",
    "/api/me", "/api/profile", "/api/account", "/api/settings",
    "/api/admin", "/api/dashboard", "/api/config", "/api/env",
    "/api/search", "/api/upload", "/api/download", "/api/export",
    "/api/products", "/api/items", "/api/orders", "/api/payments",
    "/api/posts", "/api/comments", "/api/messages", "/api/notifications",
    "/api/files", "/api/images", "/api/docs", "/api/reports",
    "/health", "/healthz", "/ready", "/readyz", "/status", "/info",
    "/metrics", "/debug", "/debug/vars", "/debug/pprof",
    "/graphql", "/graphiql", "/playground",
    "/admin", "/admin/login", "/console", "/dashboard",
    "/login", "/logout", "/register", "/signup",
    "/robots.txt", "/sitemap.xml", "/.env", "/.git/config",
    "/swagger.json", "/swagger.yaml", "/swagger-ui", "/swagger-ui.html",
    "/openapi.json", "/openapi.yaml",
    "/api-docs", "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/docs", "/redoc",
    "/wp-json", "/wp-json/wp/v2/posts",
    "/actuator", "/actuator/health", "/actuator/info", "/actuator/env",
    "/.well-known/openid-configuration",
]

SWAGGER_PATHS = [
    "/openapi.json", "/swagger.json", "/swagger.yaml",
    "/api-docs", "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/docs", "/openapi.yaml",
]

HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]


@dataclass
class DiscoveredEndpoint:
    url: str
    method: str = "GET"
    status_code: int | None = None
    content_type: str | None = None
    response_time: float | None = None
    source: str = "brute_force"


@dataclass
class CrawlResult:
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def build_auth_headers(cookies: str | None = None,
                       headers_json: str | None = None) -> dict:
    """Build HTTP headers dict from cookies string and extra headers JSON."""
    import json
    result = {}
    if cookies and cookies.strip():
        result["Cookie"] = cookies.strip()
    if headers_json and headers_json.strip():
        try:
            extra = json.loads(headers_json)
            if isinstance(extra, dict):
                result.update(extra)
        except json.JSONDecodeError:
            # Try parsing as "Name: Value" lines
            for line in headers_json.strip().splitlines():
                if ":" in line:
                    name, _, val = line.partition(":")
                    result[name.strip()] = val.strip()
    return result


class APICrawler:
    def __init__(self, base_url: str, timeout: float = 5.0,
                 cookies: str | None = None, headers_json: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.seen_urls: set[str] = set()
        self.result = CrawlResult()
        auth_headers = build_auth_headers(cookies, headers_json)
        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            verify=False,  # allow self-signed certs for testing
            headers={"User-Agent": "SecDashboard-Scanner/1.0", **auth_headers},
        )

    def crawl(self) -> CrawlResult:
        """Run all discovery strategies."""
        self._discover_openapi()
        self._brute_force_paths()
        self._crawl_html_links()
        self.client.close()
        return self.result

    def _add_endpoint(self, endpoint: DiscoveredEndpoint):
        key = f"{endpoint.method}:{endpoint.url}"
        if key not in self.seen_urls:
            self.seen_urls.add(key)
            self.result.endpoints.append(endpoint)

    def _probe_url(self, url: str, method: str = "GET", source: str = "brute_force") -> DiscoveredEndpoint | None:
        """Send a request and record the endpoint if it responds."""
        try:
            start = time.time()
            resp = self.client.request(method, url)
            elapsed = round(time.time() - start, 3)
            ct = resp.headers.get("content-type", "")
            ep = DiscoveredEndpoint(
                url=url,
                method=method,
                status_code=resp.status_code,
                content_type=ct,
                response_time=elapsed,
                source=source,
            )
            self._add_endpoint(ep)
            # Check for additional endpoints in headers
            self._extract_header_links(resp, source="header_analysis")
            return ep
        except httpx.RequestError as e:
            self.result.errors.append(f"{method} {url}: {str(e)}")
            return None

    # --- Strategy 1: OpenAPI / Swagger detection ---
    def _discover_openapi(self):
        """Check for OpenAPI/Swagger specs and parse endpoints from them."""
        for path in SWAGGER_PATHS:
            url = urljoin(self.base_url + "/", path.lstrip("/"))
            try:
                resp = self.client.get(url)
                if resp.status_code == 200:
                    ct = resp.headers.get("content-type", "")
                    if "json" in ct or url.endswith(".json"):
                        self._parse_openapi_json(resp.json())
                    elif "yaml" in ct or "yml" in ct or url.endswith((".yaml", ".yml")):
                        # Record as found but skip YAML parsing to keep deps minimal
                        self._add_endpoint(DiscoveredEndpoint(
                            url=url, method="GET", status_code=200,
                            content_type=ct, source="openapi_spec"
                        ))
            except Exception:
                continue

    def _parse_openapi_json(self, spec: dict):
        """Extract endpoint paths from an OpenAPI JSON spec."""
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            full_url = urljoin(self.base_url + "/", path.lstrip("/"))
            for method in methods:
                if method.upper() in HTTP_METHODS:
                    self._add_endpoint(DiscoveredEndpoint(
                        url=full_url,
                        method=method.upper(),
                        source="openapi_spec",
                    ))

    # --- Strategy 2: Common path brute-force ---
    def _brute_force_paths(self):
        """Try common API paths and record those that respond."""
        for path in COMMON_PATHS:
            url = urljoin(self.base_url + "/", path.lstrip("/"))
            self._probe_url(url, method="GET", source="brute_force")

    # --- Strategy 3: HTML link extraction ---
    def _crawl_html_links(self):
        """Crawl the base URL for HTML links and JS references to API routes."""
        try:
            resp = self.client.get(self.base_url)
            if "html" not in resp.headers.get("content-type", ""):
                return
            soup = BeautifulSoup(resp.text, "html.parser")
            # Extract <a> hrefs
            for tag in soup.find_all("a", href=True):
                href = tag["href"]
                if href.startswith(("http://", "https://")):
                    full = href
                elif href.startswith("/"):
                    full = urljoin(self.base_url, href)
                else:
                    continue
                parsed = urlparse(full)
                base_parsed = urlparse(self.base_url)
                if parsed.netloc == base_parsed.netloc:
                    self._probe_url(full, source="html_link")

            # Extract API-like URLs from inline/linked scripts
            for script in soup.find_all("script", src=True):
                script_url = urljoin(self.base_url, script["src"])
                try:
                    js_resp = self.client.get(script_url)
                    self._extract_api_urls_from_js(js_resp.text)
                except Exception:
                    continue

            # Inline scripts
            for script in soup.find_all("script", src=False):
                if script.string:
                    self._extract_api_urls_from_js(script.string)

        except Exception as e:
            self.result.errors.append(f"HTML crawl error: {str(e)}")

    def _extract_api_urls_from_js(self, js_text: str):
        """Find API-like paths in JavaScript code."""
        patterns = [
            r'["\'](/api/[a-zA-Z0-9_/\-]+)["\']',
            r'["\'](/v[0-9]+/[a-zA-Z0-9_/\-]+)["\']',
            r'fetch\(["\']([/a-zA-Z0-9_\-]+)["\']',
            r'axios\.[a-z]+\(["\']([/a-zA-Z0-9_\-]+)["\']',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, js_text):
                path = match.group(1)
                if path.startswith("/"):
                    url = urljoin(self.base_url, path)
                    self._probe_url(url, source="js_extraction")

    # --- Strategy 4: Response header analysis ---
    def _extract_header_links(self, resp: httpx.Response, source: str = "header_analysis"):
        """Extract additional URLs from response headers."""
        # Link header
        link_header = resp.headers.get("link", "")
        for match in re.finditer(r'<([^>]+)>', link_header):
            url = match.group(1)
            if not url.startswith("http"):
                url = urljoin(self.base_url, url)
            self._add_endpoint(DiscoveredEndpoint(url=url, source=source))

        # Location header (redirects)
        location = resp.headers.get("location", "")
        if location:
            if not location.startswith("http"):
                location = urljoin(self.base_url, location)
            self._add_endpoint(DiscoveredEndpoint(url=location, source=source))
