"""Bounded, same-origin navigation links from explicit JSON link fields."""

from __future__ import annotations

import json
from collections.abc import Mapping
from urllib.parse import urljoin, urlsplit

_MAX_BYTES = 1024 * 1024
_MAX_NODES = 300
_MAX_LINKS = 32
_LINK_KEYS = frozenset({"href", "url", "path", "route", "link", "endpoint"})
_LINK_LIST_KEYS = frozenset({"links", "navigation", "routes"})


def json_links_from_observation(observation: Mapping[str, object],
                                base_url: str) -> tuple[str, ...]:
    """Use link-shaped keys only; never treat arbitrary response strings as URLs."""

    media = observation.get("content_type")
    body = observation.get("body")
    if (
        not isinstance(media, str)
        or media.split(";", 1)[0].strip().casefold()
        not in {"application/json", "application/hal+json"}
        or not isinstance(body, str) or len(body) > _MAX_BYTES
        or observation.get("truncated")
    ):
        return ()
    try:
        document = json.loads(body)
    except (ValueError, TypeError):
        return ()
    if isinstance(document, dict) and ("openapi" in document or "swagger" in document):
        return ()

    origin = urlsplit(base_url)
    links: list[str] = []
    seen: set[str] = set()
    pending: list[tuple[object, int, bool]] = [(document, 0, False)]
    visited_nodes = 0
    while pending and visited_nodes < _MAX_NODES and len(links) < _MAX_LINKS:
        value, depth, link_list = pending.pop()
        visited_nodes += 1
        if depth > 5:
            continue
        if isinstance(value, str):
            if (
                not link_list or len(value) > 2048
                or not value.startswith(("/", "http://", "https://"))
                or value.startswith("//")
            ):
                continue
            candidate = urljoin(base_url, value)
            parsed = urlsplit(candidate)
            if (parsed.scheme in {"http", "https"} and parsed.netloc == origin.netloc
                    and candidate not in seen):
                seen.add(candidate)
                links.append(candidate)
        elif isinstance(value, dict):
            for key, item in reversed(tuple(value.items())[:100]):
                if not isinstance(key, str):
                    continue
                normalized = key.casefold()
                if normalized in _LINK_KEYS or normalized in _LINK_LIST_KEYS:
                    pending.append((item, depth + 1, True))
                elif isinstance(item, (dict, list)):
                    pending.append((item, depth + 1, False))
        elif isinstance(value, list):
            for item in reversed(value[:100]):
                pending.append((item, depth + 1, link_list))
    return tuple(links)
