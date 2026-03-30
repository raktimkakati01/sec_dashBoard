from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass


NUCLEI_BINARY = os.getenv("NUCLEI_BINARY", "nuclei")
# When PATH is minimal (LaunchAgent, some IDEs, systemd), `nuclei` on PATH may be missing
# even if Homebrew installed it. These fallbacks fix “Nuclei not installed” false negatives.
_NUCLEI_FALLBACK_PATHS = (
    "/opt/homebrew/bin/nuclei",  # macOS Apple Silicon (Homebrew)
    "/usr/local/bin/nuclei",  # macOS Intel / Linux Homebrew default
    str(os.path.expanduser("~/.local/bin/nuclei")),
    str(os.path.expanduser("~/go/bin/nuclei")),
)
NUCLEI_DEFAULT_TAGS = os.getenv(
    "NUCLEI_DEFAULT_TAGS",
    "exposure,misconfig,takeover,token-spray,tech,cve",
)
NUCLEI_TIMEOUT_SECONDS = int(os.getenv("NUCLEI_TIMEOUT_SECONDS", "180"))


@dataclass
class NucleiResult:
    endpoint_url: str
    severity: str
    title: str
    description: str
    evidence: str


def _resolve_nuclei_binary() -> str | None:
    """Return absolute path to nuclei, or None if not present."""
    name = NUCLEI_BINARY.strip() or "nuclei"
    if os.path.isabs(name) and os.path.isfile(name) and os.access(name, os.X_OK):
        return name
    found = shutil.which(name)
    if found and os.path.isfile(found) and os.access(found, os.X_OK):
        return found
    for path in _NUCLEI_FALLBACK_PATHS:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def run(endpoints: list[dict], headers: dict | None = None, tags: str | None = None) -> list[NucleiResult]:
    if not endpoints:
        return []

    binary = _resolve_nuclei_binary()
    if not binary:
        return [
            NucleiResult(
                endpoint_url=endpoints[0]["url"],
                severity="info",
                title="Nuclei not installed",
                description="Nuclei phase was requested but the nuclei binary is not available on this machine.",
                evidence=(
                    f"Looked for: {NUCLEI_BINARY} on PATH plus common paths "
                    f"{_NUCLEI_FALLBACK_PATHS}. "
                    "Install: brew install nuclei (macOS) or see "
                    "https://github.com/projectdiscovery/nuclei — or set NUCLEI_BINARY to the full path."
                ),
            )
        ]

    unique_urls = []
    seen = set()
    for endpoint in endpoints:
        url = endpoint["url"]
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)

    selected_tags = (tags or NUCLEI_DEFAULT_TAGS).strip()

    with tempfile.TemporaryDirectory(prefix="nuclei-scan-") as temp_dir:
        targets_file = os.path.join(temp_dir, "targets.txt")
        with open(targets_file, "w", encoding="utf-8") as handle:
            handle.write("\n".join(unique_urls))

        cmd = [
            binary,
            "-l", targets_file,
            "-jsonl",
            "-silent",
            "-duc",
            "-tags", selected_tags,
        ]

        if headers:
            for name, value in headers.items():
                cmd.extend(["-H", f"{name}: {value}"])

        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=NUCLEI_TIMEOUT_SECONDS,
            check=False,
        )

        results = []
        if completed.stdout.strip():
            for line in completed.stdout.splitlines():
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                info = item.get("info", {})
                severity = (info.get("severity") or "info").lower()
                if severity not in {"critical", "high", "medium", "low", "info"}:
                    severity = "info"
                results.append(
                    NucleiResult(
                        endpoint_url=item.get("matched-at") or item.get("host") or unique_urls[0],
                        severity=severity,
                        title=info.get("name") or item.get("template-id") or "Nuclei finding",
                        description=info.get("description") or f"Nuclei template {item.get('template-id', 'unknown')} matched.",
                        evidence=json.dumps(
                            {
                                "template_id": item.get("template-id"),
                                "matcher_name": item.get("matcher-name"),
                                "type": item.get("type"),
                                "matched_at": item.get("matched-at"),
                                "curl_command": item.get("curl-command"),
                                "tags": info.get("tags"),
                            },
                            ensure_ascii=True,
                        ),
                    )
                )

        if completed.returncode not in (0, 1):
            results.append(
                NucleiResult(
                    endpoint_url=unique_urls[0],
                    severity="info",
                    title="Nuclei execution error",
                    description="Nuclei exited with a non-standard error code.",
                    evidence=(completed.stderr or completed.stdout or f"Exit code: {completed.returncode}")[:2000],
                )
            )

        return results
