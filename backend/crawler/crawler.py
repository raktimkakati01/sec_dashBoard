from __future__ import annotations

import json
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
    request_content_type: str | None = None
    request_params: str | None = None
    request_example: str | None = None
    response_body_sample: str | None = None


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
            return

        # Merge richer request/response context into the existing endpoint record.
        for current in self.result.endpoints:
            if current.method == endpoint.method and current.url == endpoint.url:
                if endpoint.request_content_type and not current.request_content_type:
                    current.request_content_type = endpoint.request_content_type
                if endpoint.request_params and not current.request_params:
                    current.request_params = endpoint.request_params
                if endpoint.request_example and not current.request_example:
                    current.request_example = endpoint.request_example
                if endpoint.response_body_sample and not current.response_body_sample:
                    current.response_body_sample = endpoint.response_body_sample
                if endpoint.content_type and not current.content_type:
                    current.content_type = endpoint.content_type
                if endpoint.status_code is not None and current.status_code is None:
                    current.status_code = endpoint.status_code
                if endpoint.response_time is not None and current.response_time is None:
                    current.response_time = endpoint.response_time
                break

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
                response_body_sample=self._sample_response_body(resp),
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
            for method, operation in methods.items():
                if method.upper() in HTTP_METHODS:
                    request_content_type, request_example = self._extract_request_body_from_operation(operation or {})
                    request_params = self._extract_params_from_operation(operation or {})
                    self._add_endpoint(DiscoveredEndpoint(
                        url=full_url,
                        method=method.upper(),
                        source="openapi_spec",
                        request_content_type=request_content_type,
                        request_example=request_example,
                        request_params=request_params,
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

            for form in soup.find_all("form"):
                self._extract_form_endpoint(form)

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

    def _extract_form_endpoint(self, form):
        action = form.get("action") or self.base_url
        method = (form.get("method") or "GET").upper()
        if method not in HTTP_METHODS:
            return

        target_url = urljoin(self.base_url + "/", action.lstrip("/")) if action.startswith("/") else urljoin(self.base_url + "/", action)
        fields = {}
        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name")
            if not name:
                continue
            field_type = field.get("type", "text")
            fields[name] = f"<{field_type}>"

        if not fields:
            return

        self._add_endpoint(DiscoveredEndpoint(
            url=target_url,
            method=method,
            source="html_form",
            request_content_type="application/x-www-form-urlencoded",
            request_params=json.dumps(sorted(fields.keys())),
            request_example=json.dumps(fields),
        ))

    def _extract_params_from_operation(self, operation: dict) -> str | None:
        names = []
        for param in operation.get("parameters", []):
            name = param.get("name")
            location = param.get("in")
            if name:
                names.append(f"{location}:{name}" if location else name)
        return json.dumps(names) if names else None

    def _extract_request_body_from_operation(self, operation: dict) -> tuple[str | None, str | None]:
        request_body = operation.get("requestBody") or {}
        content = request_body.get("content") or {}
        for content_type, spec in content.items():
            schema = spec.get("schema") or {}
            example = spec.get("example")
            if example is None:
                examples = spec.get("examples") or {}
                if isinstance(examples, dict):
                    for item in examples.values():
                        if isinstance(item, dict) and "value" in item:
                            example = item["value"]
                            break
            if example is None:
                example = self._schema_to_example(schema)
            return content_type, json.dumps(example) if example is not None else None
        return None, None

    def _schema_to_example(self, schema: dict):
        if not schema:
            return None
        schema_type = schema.get("type")
        if schema_type == "object":
            properties = schema.get("properties") or {}
            return {name: self._schema_to_example(value) for name, value in properties.items()}
        if schema_type == "array":
            item_schema = schema.get("items") or {}
            item_value = self._schema_to_example(item_schema)
            return [item_value] if item_value is not None else []
        if "example" in schema:
            return schema["example"]
        if "default" in schema:
            return schema["default"]
        if schema_type in {"integer", "number"}:
            return 0
        if schema_type == "boolean":
            return False
        return "<value>"

    def _sample_response_body(self, resp: httpx.Response) -> str | None:
        content_type = (resp.headers.get("content-type") or "").lower()
        if not any(kind in content_type for kind in ("json", "text", "xml", "html", "javascript")):
            return None
        text_body = resp.text.strip()
        if not text_body:
            return None
        return text_body[:2000]
