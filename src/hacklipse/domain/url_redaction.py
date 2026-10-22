"""Infrastructure-free URL path redaction shared across core boundaries."""

from __future__ import annotations

import math
import ipaddress
import re
from urllib.parse import urlsplit


_JWT_PATH_SEGMENT = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."
    r"[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
)
_SENSITIVE_PATH_KEY = re.compile(
    r"(?:^|[-_.])(?:token|secret|key|password|credential|auth)(?:$|[-_.])",
    re.IGNORECASE,
)
_SAFE_PATH_SEGMENT = re.compile(r"[a-z][a-z0-9._-]{0,31}\Z")
_UUID_PATH_SEGMENT = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z",
    re.IGNORECASE,
)
_TOKEN_PATH_SEGMENT = re.compile(r"[A-Za-z0-9_-]{20,}={0,2}\Z")
_MAX_PATH_HINT_LENGTH = 160


def _redacted_destination_host(hostname: str) -> str:
    """Mask secret-shaped DNS labels while preserving a useful host shape."""

    try:
        return ipaddress.ip_address(hostname).compressed
    except ValueError:
        pass
    result: list[str] = []
    hide_next = False
    for label in hostname.split("."):
        secret_like = (
            hide_next
            or "%" in label
            or _UUID_PATH_SEGMENT.fullmatch(label) is not None
            or _TOKEN_PATH_SEGMENT.fullmatch(label) is not None
            or (len(label) >= 16 and _segment_entropy(label) >= 3.75)
        )
        result.append("redacted" if secret_like else label)
        hide_next = _SENSITIVE_PATH_KEY.search(label) is not None
    return ".".join(result)


def ssrf_destination_reference_parts(
    raw_url: str,
) -> tuple[str, str, bytes] | None:
    """Return persistence-safe URL metadata and private fingerprint material.

    The returned bytes contain the normalized origin and the unredacted path and
    must only be passed to a Run-scoped HMAC.  They must never be persisted,
    logged, reported, or sent to an LLM.
    """

    if not isinstance(raw_url, str) or not raw_url:
        return None
    try:
        parsed = urlsplit(raw_url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.casefold()
    if scheme not in {"http", "https"} or hostname is None:
        return None

    normalized_host = hostname.casefold().rstrip(".")
    try:
        normalized_host = ipaddress.ip_address(normalized_host).compressed
    except ValueError:
        pass
    fingerprint_host = (
        f"[{normalized_host}]" if ":" in normalized_host else normalized_host
    )
    redacted_host = _redacted_destination_host(normalized_host)
    rendered_host = f"[{redacted_host}]" if ":" in redacted_host else redacted_host
    if (scheme, port) in {("http", 80), ("https", 443)}:
        port = None
    authority = rendered_host + (f":{port}" if port is not None else "")
    origin = f"{scheme}://{authority}"
    fingerprint_authority = fingerprint_host + (
        f":{port}" if port is not None else ""
    )
    fingerprint_origin = f"{scheme}://{fingerprint_authority}"
    raw_path = parsed.path or "/"
    fingerprint_material = (
        "ssrf-destination-v1\0" + fingerprint_origin + raw_path
    ).encode("utf-8")
    if len(fingerprint_material) > 672:
        return None
    return origin, redacted_internal_url_path(raw_path), fingerprint_material


def _segment_entropy(segment: str) -> float:
    if not segment:
        return 0.0
    return -sum(
        (count / len(segment)) * math.log2(count / len(segment))
        for count in (segment.count(char) for char in set(segment))
    )


def redacted_internal_url_path(path: str) -> str:
    """Keep a bounded route shape while removing credential-like path values."""

    result: list[str] = []
    hide_next = False
    for segment in path.split("/"):
        if not segment:
            continue
        sensitive_key = _SENSITIVE_PATH_KEY.search(segment) is not None
        secret_like = (
            hide_next
            or segment == "redacted"
            or "%" in segment
            or _UUID_PATH_SEGMENT.fullmatch(segment) is not None
            or _JWT_PATH_SEGMENT.fullmatch(segment) is not None
            or _TOKEN_PATH_SEGMENT.fullmatch(segment) is not None
            or (len(segment) >= 16 and _segment_entropy(segment) >= 3.75)
        )
        safe = not secret_like and _SAFE_PATH_SEGMENT.fullmatch(segment) is not None
        result.append(segment if safe else "{redacted}")
        hide_next = sensitive_key
        if len("/" + "/".join(result)) > _MAX_PATH_HINT_LENGTH:
            result.pop()
            while (
                result
                and len("/" + "/".join((*result, "{redacted}")))
                > _MAX_PATH_HINT_LENGTH
            ):
                result.pop()
            result.append("{redacted}")
            break
    return "/" + "/".join(result)
