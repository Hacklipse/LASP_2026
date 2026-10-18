"""Bounded postMessage HTML-sink plans inferred from delivered client scripts.

These are candidate inputs only. A foreign-origin browser probe and an independent
validation are required before a finding can be created.
"""

from __future__ import annotations

import re

POSTMESSAGE_PLAN = "postmessage_html_plan"
POSTMESSAGE_ANALYZER = "postmessage_xss_analyzer"
POSTMESSAGE_CAPABILITY = "xss.browser.postmessage"

_LISTENER = re.compile(r"(?:addEventListener\s*\(\s*|onmessage\s*=\s*)['\"]?message['\"]?", re.I)
_HTML_SOURCE = re.compile(r"\b[A-Za-z_$][\w$]*\.(html|markup|content)\b")
_HTML_SINK = re.compile(r"\b(?:innerHTML|dangerouslySetInnerHTML)\b")
_TYPE_TEST = re.compile(
    r"\b[A-Za-z_$][\w$]*\.type\s*(?:===|==|!==|!=)\s*['\"]([^'\"\s]{1,48})['\"]"
    r"|['\"]([^'\"\s]{1,48})['\"]\s*(?:===|==|!==|!=)\s*[A-Za-z_$][\w$]*\.type"
)
_EVENT_TYPE = re.compile(r"^[a-z][a-z0-9_-]{0,19}(?::[a-z][a-z0-9_-]{0,19}){0,2}$")


def postmessage_html_plans(script: str) -> tuple[tuple[str, str], ...]:
    """Return only short event names and content fields, never script or key values.

    Broad static matching is intentional: the browser probe proves whether a
    message from a foreign origin reaches an HTML sink. The parser never treats
    a source-code comment or a matching literal as proof of a vulnerability.
    """

    if (
        not script or len(script) > 4 * 1024 * 1024
        or _LISTENER.search(script) is None
        or _HTML_SINK.search(script) is None
    ):
        return ()
    fields = tuple(sorted(
        set(_HTML_SOURCE.findall(script)),
        key=lambda field: ("html", "markup", "content").index(field),
    ))
    if not fields:
        return ()
    plans: list[tuple[str, str]] = []
    for match in _TYPE_TEST.finditer(script):
        event_type = match.group(1) or match.group(2)
        if _EVENT_TYPE.fullmatch(event_type) is None:
            continue
        for field in fields[:2]:
            plan = (event_type, field)
            if plan not in plans:
                plans.append(plan)
            if len(plans) >= 4:
                return tuple(plans)
    return tuple(plans)
