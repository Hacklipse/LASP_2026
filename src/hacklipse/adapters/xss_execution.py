"""브라우저 XSS 검증에 사용하는 고정된 안전 probe 계약."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from hacklipse.domain import ExecutionRequest, HttpRequestKind

BROWSER_XSS_TOOL = "browser_xss"
XSS_EXECUTION_MARKER_PREFIX = "hacklipsexecution"
_WINDOW_SLOT = "__hacklipse_xss_probe__"
_MARKER = re.compile(rf"^{XSS_EXECUTION_MARKER_PREFIX}[A-Za-z0-9_-]+$")


def validate_browser_xss_request(request: ExecutionRequest) -> None:
    """브라우저 도구가 고정 GET control/probe 계약 밖 요청을 받지 않게 한다."""

    if request.tool != BROWSER_XSS_TOOL:
        raise ValueError("request is not assigned to the browser XSS tool")
    if request.method.upper() != "GET" or request.body is not None or request.headers:
        raise ValueError("browser XSS execution supports headerless GET requests only")

    markers = _execution_markers(request)
    if request.request_kind is HttpRequestKind.CONTROL:
        if markers:
            raise ValueError("browser XSS control request cannot contain an execution marker")
        return
    if request.request_kind is not HttpRequestKind.PROBE or len(markers) != 1:
        raise ValueError("browser XSS probe requires exactly one execution marker")


def browser_navigation_url(request: ExecutionRequest) -> tuple[str, str | None]:
    """검증된 marker 하나만 고정 스크립트로 바꾼 실제 브라우저 URL을 만든다.

    Agent나 LLM은 marker만 선택할 수 있다. 실행되는 JavaScript의 형태는 이 모듈에
    고정되어 있어 외부 전송, DOM 변경, 임의 코드 실행을 요청 명세로 주입할 수 없다.
    """

    validate_browser_xss_request(request)
    if request.request_kind is HttpRequestKind.CONTROL:
        return request.resolved_url, None

    marker = _execution_markers(request)[0]
    payload = f"<script>window.{_WINDOW_SLOT}='{marker}'</script>"
    parsed = urlsplit(request.resolved_url)
    parameters = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    encoded: list[tuple[str, str]] = []
    for name, value in parameters:
        if not replaced and value == marker:
            encoded.append((name, payload))
            replaced = True
        else:
            encoded.append((name, value))
    if not replaced:  # validate 이후에는 도달하지 않는 방어선.
        raise ValueError("browser XSS marker was not present in the resolved URL")
    return (
        urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                urlencode(encoded),
                "",
            )
        ),
        marker,
    )


def execution_marker_script() -> str:
    """페이지가 기록한 실행 marker만 읽는 고정 JavaScript를 반환한다."""

    return f"() => window.{_WINDOW_SLOT} ?? null"


def _execution_markers(request: ExecutionRequest) -> tuple[str, ...]:
    return tuple(
        value
        for _, value in request.query_parameters
        if _MARKER.fullmatch(value) is not None
    )
