import re
import httpx
from dataclasses import dataclass

MAX_ENDPOINTS = 100


@dataclass
class InfoResult:
    endpoint_url: str
    severity: str
    title: str
    description: str
    evidence: str


# Patterns that indicate information disclosure
STACK_TRACE_PATTERNS = [
    (r"Traceback \(most recent call last\)", "Python stack trace"),
    (r"at [\w\.$]+\([\w]+\.java:\d+\)", "Java stack trace"),
    (r"at [\w\.]+\s+in [\w/\\]+\.cs:line \d+", ".NET stack trace"),
    (r"Fatal error:.*on line \d+", "PHP fatal error"),
    (r"Warning:.*on line \d+", "PHP warning"),
    (r"Parse error:.*on line \d+", "PHP parse error"),
    (r"<b>Warning</b>:.*on line <b>\d+</b>", "PHP warning (HTML)"),
    (r"Error \d+:.*line \d+", "Generic error with line number"),
    (r"node_modules/", "Node.js stack trace"),
    (r"ReferenceError:|TypeError:|SyntaxError:", "JavaScript error"),
]

SENSITIVE_PATTERNS = [
    (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "Internal IP Address", "medium",
     lambda m: _is_internal_ip(m.group())),
    (r"(?i)(password|passwd|pwd|secret|api.?key|access.?token|private.?key)\s*[:=]\s*['\"]?[\w\-\.]+",
     "Credentials/Secrets in Response", "high", None),
    (r"(?i)mongodb://|postgres://|mysql://|redis://|amqp://",
     "Database Connection String", "critical", None),
    (r"(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]",
     "AWS Credentials", "critical", None),
    (r"(?i)-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
     "Private Key Exposed", "critical", None),
]

VERSION_PATTERNS = [
    (r"(?i)(apache|nginx|iis|tomcat|express|django|flask|rails|spring|laravel)[/\s][\d\.]+",
     "Server/Framework Version Disclosure"),
    (r"(?i)(php|python|java|node|ruby|perl|asp\.net)[/\s][\d\.]+",
     "Language Version Disclosure"),
    (r"(?i)x-debug-token", "Debug Mode Enabled"),
]

DEBUG_ENDPOINTS = [
    "/.env", "/debug", "/debug/vars", "/phpinfo.php", "/server-info",
    "/server-status", "/.git/config", "/.svn/entries", "/wp-config.php.bak",
    "/.DS_Store", "/config.yml", "/config.json",
]


def _is_internal_ip(ip):
    """Check if an IP is a private/internal address."""
    parts = ip.split(".")
    try:
        a, b = int(parts[0]), int(parts[1])
        return (a == 10 or (a == 172 and 16 <= b <= 31) or
                (a == 192 and b == 168) or a == 127)
    except (ValueError, IndexError):
        return False


def run(endpoints: list[dict], client: httpx.Client) -> list[InfoResult]:
    """Check response bodies for information disclosure."""
    results = []
    checked = set()

    live_eps = [ep for ep in endpoints
                if ep.get("status_code") and 200 <= ep["status_code"] < 400]

    for ep in live_eps[:MAX_ENDPOINTS]:
        url = ep["url"]
        base = url.split("?")[0]
        if base in checked:
            continue
        checked.add(base)

        try:
            resp = client.get(url)
            body = resp.text
            if not body or len(body) < 10:
                continue
        except Exception:
            continue

        # Check for stack traces
        for pattern, name in STACK_TRACE_PATTERNS:
            match = re.search(pattern, body)
            if match:
                snippet = body[max(0, match.start()-50):match.end()+100][:300]
                results.append(InfoResult(
                    endpoint_url=url,
                    severity="medium",
                    title=f"Stack Trace Detected: {name}",
                    description=f"A {name} was found in the response from {url}.",
                    evidence=f"Match: {snippet}",
                ))
                break  # one stack trace per endpoint is enough

        # Check for sensitive data patterns
        for pattern, name, severity, validator in SENSITIVE_PATTERNS:
            matches = list(re.finditer(pattern, body))
            for match in matches[:3]:  # limit matches
                if validator and not validator(match):
                    continue
                snippet = body[max(0, match.start()-20):match.end()+20][:200]
                results.append(InfoResult(
                    endpoint_url=url,
                    severity=severity,
                    title=f"Information Disclosure: {name}",
                    description=f"{name} found in response from {url}.",
                    evidence=f"Pattern: {snippet}",
                ))
                break  # one match per pattern per endpoint

        # Check for version info in response body
        for pattern, name in VERSION_PATTERNS:
            match = re.search(pattern, body)
            if match:
                results.append(InfoResult(
                    endpoint_url=url,
                    severity="info",
                    title=name,
                    description=f"{name} at {url}: {match.group()}",
                    evidence=f"Found: {match.group()}",
                ))
                break

        # Check for verbose error responses
        ct = resp.headers.get("content-type", "")
        if resp.status_code >= 400 and "json" in ct:
            try:
                data = resp.json()
                # Check for detailed error messages
                for key in ("exception", "stackTrace", "stack", "trace",
                            "debug", "error_description", "detail"):
                    if isinstance(data, dict) and key in data:
                        results.append(InfoResult(
                            endpoint_url=url,
                            severity="low",
                            title="Verbose Error Response",
                            description=f"API at {url} returns detailed error info in '{key}' field.",
                            evidence=f"Key: {key}\nValue: {str(data[key])[:300]}",
                        ))
                        break
            except Exception:
                pass

    return results
