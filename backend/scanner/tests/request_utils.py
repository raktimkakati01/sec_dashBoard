from __future__ import annotations

import json
from copy import deepcopy
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit


def parse_request_params(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    names = []
    for item in parsed:
        if not isinstance(item, str):
            continue
        names.append(item.split(":", 1)[-1])
    return names


def parse_request_example(value: str | None):
    if not value:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None


def build_request_kwargs(endpoint: dict, payload: str | None = None) -> dict:
    method = endpoint.get("method", "GET").upper()
    content_type = (endpoint.get("request_content_type") or "").lower()
    request_example = parse_request_example(endpoint.get("request_example"))
    request_params = parse_request_params(endpoint.get("request_params"))
    kwargs = {}

    if method == "GET":
        return kwargs

    if "json" in content_type:
        kwargs["json"] = inject_payload(request_example, payload) if payload is not None else request_example
        if kwargs["json"] is None and payload is not None:
            kwargs["json"] = {"q": payload, "input": payload}
        return kwargs

    if "x-www-form-urlencoded" in content_type or "form-data" in content_type:
        form_data = request_example if isinstance(request_example, dict) else {name: "<value>" for name in request_params}
        kwargs["data"] = inject_payload(form_data, payload) if payload is not None else form_data
        if not kwargs["data"] and payload is not None:
            kwargs["data"] = {"q": payload, "input": payload}
        return kwargs

    if payload is not None and request_params:
        kwargs["data"] = {name: payload for name in request_params}
        return kwargs

    return kwargs


def inject_payload(obj, payload: str | None):
    if payload is None:
        return deepcopy(obj)
    if obj is None:
        return payload
    if isinstance(obj, dict):
        return {key: inject_payload(value, payload) for key, value in obj.items()}
    if isinstance(obj, list):
        return [inject_payload(value, payload) for value in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return payload
    return payload


def inject_query_payload(url: str, params: list[str], payload: str) -> str:
    split = urlsplit(url)
    query = parse_qs(split.query, keep_blank_values=True)
    if not query and params:
        query = {name: [payload] for name in params}
    else:
        for name in list(query.keys()) or params:
            query[name] = [payload]
        if not query:
            query = {"q": [payload], "id": [payload]}
    encoded = urlencode(query, doseq=True)
    return urlunsplit((split.scheme, split.netloc, split.path, encoded, split.fragment))
