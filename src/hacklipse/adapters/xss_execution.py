"""브라우저 XSS 검증에 사용하는 고정된 안전 probe 계약."""

from __future__ import annotations

from html import escape
import json
import re
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from hacklipse.domain import ExecutionRequest, HttpRequestKind
from .probing import probe_marker

BROWSER_XSS_TOOL = "browser_xss"
XSS_EXECUTION_MARKER_PREFIX = "hacklipsexecution"
# Analysis 가 쓰는 무해한 반사 marker. 값이 DOM 에 도달하는지만 본다. 실행 가능한
# 문자가 없으므로 이 marker 로는 스크립트가 실행되지 않는다 — 실행 증명은 Validation
# 만이 만들 수 있어야 하기 때문이다.
XSS_REFLECTION_MARKER_PREFIX = "hacklipsreflection"
RAW_HASH_CANARY = "hacklipsehashcontrol"
RAW_HASH_PARAMETER = "fragment"
_WINDOW_SLOT = "__hacklipse_xss_probe__"
_MARKER = re.compile(rf"^{XSS_EXECUTION_MARKER_PREFIX}[A-Za-z0-9_-]+$")
_ATTRIBUTE_MARKER = re.compile(
    rf"^{XSS_EXECUTION_MARKER_PREFIX}attr_(data-[A-Za-z][A-Za-z0-9-]{{0,30}})_[A-Za-z0-9z]+$"
)
_ATTRIBUTE_NAME = re.compile(r"^data-[a-z][a-z0-9-]{0,30}$")
_REFLECTION_MARKER = re.compile(rf"^{XSS_REFLECTION_MARKER_PREFIX}[A-Za-z0-9_-]+$")
_MESSAGE_TYPE = re.compile(r"^[a-z][a-z0-9_-]{0,19}(?::[a-z][a-z0-9_-]{0,19}){0,2}$")
_MESSAGE_FIELDS = frozenset({"html", "markup", "content"})
_POSTMESSAGE_KINDS = frozenset({
    HttpRequestKind.POSTMESSAGE_CONTROL,
    HttpRequestKind.POSTMESSAGE_REFLECTION,
    HttpRequestKind.POSTMESSAGE_EXECUTION,
})


def postmessage_payload(request: ExecutionRequest) -> tuple[str, str, str] | None:
    """Decode a tightly bounded message plan. Browser runtime owns the markup."""

    if request.request_kind not in _POSTMESSAGE_KINDS:
        raise ValueError("request is not a postMessage browser probe")
    if request.query_parameters or request.headers:
        raise ValueError("postMessage browser probe cannot change URL or headers")
    if request.request_kind is HttpRequestKind.POSTMESSAGE_CONTROL:
        if request.body is not None:
            raise ValueError("postMessage control must not send a message")
        return None
    if request.body is None or len(request.body) > 240:
        raise ValueError("postMessage probe requires a bounded plan")
    try:
        plan = json.loads(request.body)
    except (ValueError, TypeError) as error:
        raise ValueError("postMessage plan is not valid JSON") from error
    if not isinstance(plan, dict) or set(plan) != {"type", "field", "marker"}:
        raise ValueError("postMessage plan has invalid fields")
    event_type, field, marker = (plan[key] for key in ("type", "field", "marker"))
    if not isinstance(event_type, str) or _MESSAGE_TYPE.fullmatch(event_type) is None:
        raise ValueError("postMessage type is not a bounded event name")
    if not isinstance(field, str) or field not in _MESSAGE_FIELDS:
        raise ValueError("postMessage field is not an approved HTML field")
    expected = (
        _REFLECTION_MARKER if request.request_kind is HttpRequestKind.POSTMESSAGE_REFLECTION
        else _MARKER
    )
    if not isinstance(marker, str) or expected.fullmatch(marker) is None:
        raise ValueError("postMessage marker does not match its request kind")
    return event_type, field, marker


def validate_browser_xss_request(request: ExecutionRequest) -> None:
    """브라우저 도구가 고정 GET control/probe 계약 밖 요청을 받지 않게 한다."""

    if request.tool != BROWSER_XSS_TOOL:
        raise ValueError("request is not assigned to the browser XSS tool")
    if request.method.upper() != "GET" or request.headers:
        raise ValueError("browser XSS execution supports headerless GET requests only")
    if request.request_kind in _POSTMESSAGE_KINDS:
        postmessage_payload(request)
        return
    if request.body is not None:
        raise ValueError("ordinary browser XSS execution cannot send a request body")
    if urlsplit(request.target_url).fragment == RAW_HASH_CANARY and (
        len(request.query_parameters) != 1
        or request.query_parameters[0][0] != RAW_HASH_PARAMETER
    ):
        raise ValueError("raw hash probe must change only the observed fragment")

    markers = _execution_markers(request)
    reflections = _reflection_markers(request)
    if request.request_kind is HttpRequestKind.CONTROL:
        if markers or reflections:
            raise ValueError("browser XSS control request cannot contain a probe marker")
        return
    if request.request_kind is not HttpRequestKind.PROBE:
        raise ValueError("browser XSS probe requires the probe request kind")
    # 실행 탐침과 반사 탐침은 서로 배타적이다. 둘을 한 요청에 섞으면 어느 쪽이
    # 관측을 만들었는지 증명에서 구분할 수 없다.
    if len(markers) + len(reflections) != 1:
        raise ValueError(
            "browser XSS probe requires exactly one execution or reflection marker"
        )


def browser_navigation_url(request: ExecutionRequest) -> tuple[str, str | None]:
    """검증된 marker 하나만 고정 스크립트로 바꾼 실제 브라우저 URL을 만든다.

    Agent나 LLM은 marker만 선택할 수 있다. 실행되는 JavaScript의 형태는 이 모듈에
    고정되어 있어 외부 전송, DOM 변경, 임의 코드 실행을 요청 명세로 주입할 수 없다.
    """

    validate_browser_xss_request(request)
    if request.request_kind in _POSTMESSAGE_KINDS:
        plan = postmessage_payload(request)
        return _browser_url(request, {}), plan[2] if plan else None
    if request.request_kind is HttpRequestKind.CONTROL:
        return _browser_url(request, {}), None

    reflections = _reflection_markers(request)
    if reflections:
        # 반사 탐침은 marker 를 그대로 싣는다. 치환할 payload 가 없다.
        return _browser_url(request, {}), None

    marker = _execution_markers(request)[0]
    return _browser_url(request, {marker: _execution_payload(marker)}), marker


def reflection_marker(request: ExecutionRequest) -> str | None:
    """반사 탐침이 실은 marker. 실행 탐침과 control 에서는 None 이다."""

    validate_browser_xss_request(request)
    if request.request_kind is HttpRequestKind.POSTMESSAGE_REFLECTION:
        plan = postmessage_payload(request)
        return plan[2] if plan else None
    reflections = _reflection_markers(request)
    return reflections[0] if reflections else None


def attribute_execution_marker(raw: str, attribute: str) -> str:
    """Bind a fixed double-parsing probe to a validated observed attribute."""

    if _ATTRIBUTE_NAME.fullmatch(attribute) is None:
        raise ValueError("secondary XSS attribute must be a bounded data-* name")
    return probe_marker(raw, prefix=f"{XSS_EXECUTION_MARKER_PREFIX}attr_{attribute}_")


def _execution_payload(marker: str) -> str:
    """DOM 에 삽입되었을 때 실행되는 고정 payload.

    innerHTML 로 삽입된 `<script>` 는 브라우저가 실행하지 않는다. SPA 의 DOM sink 를
    검증하려면 삽입만으로 이벤트가 발생하는 형태여야 한다. 형태는 여기에 고정되어
    있고 marker 만 바뀌므로 Agent 나 LLM 이 임의 코드를 주입할 수 없다.
    """

    # The marker is restricted to safe identifier characters. A template
    # literal avoids the apostrophe that can break a surrounding SQL string
    # before an otherwise exploitable reflected HTML response is rendered.
    script = f"<img src=x onerror=\"window.{_WINDOW_SLOT}=`{marker}`\">"
    attribute = _ATTRIBUTE_MARKER.fullmatch(marker)
    if attribute is not None:
        # A sanitizer may preserve a data-* value that the application later
        # assigns to innerHTML. Encode the inner markup once so it can only
        # execute if the observed second parsing sink actually exists.
        return f'<span {attribute.group(1)}="{escape(script, quote=True)}">tip</span>'
    return script


def _browser_url(request: ExecutionRequest, replacements: dict[str, str]) -> str:
    """브라우저가 실제로 이동할 URL.

    SPA 의 DOM sink 는 fragment 라우트(`/#/search?q=`)에 있다. HTTP 요청 대상에는
    fragment 가 포함되지 않으므로 `resolved_url` 은 이를 버린다. 브라우저 도구만
    fragment 를 복원해 라우트 안쪽에 파라미터를 싣는다.
    """

    parsed = urlsplit(request.target_url)
    if parsed.fragment == RAW_HASH_CANARY:
        value = request.query_parameters[0][1]
        fragment = quote(replacements.get(value, value), safe="")
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, fragment))
    encoded = [
        (name, replacements.get(value, value))
        for name, value in request.query_parameters
    ]
    if parsed.fragment:
        route, _, existing = parsed.fragment.partition("?")
        pairs = parse_qsl(existing, keep_blank_values=True) + encoded
        fragment = f"{route}?{urlencode(pairs)}" if pairs else route
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, fragment))

    query = parse_qsl(parsed.query, keep_blank_values=True) + encoded
    return urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urlencode(query), "")
    )


def execution_marker_script() -> str:
    """페이지가 기록한 실행 marker만 읽는 고정 JavaScript를 반환한다."""

    return f"() => window.{_WINDOW_SLOT} ?? null"


def dom_reflection_script(marker: str) -> str:
    """페이지 DOM 에 marker 가 도달했는지만 확인하는 고정 JavaScript."""

    return (
        "() => (document.body ? document.body.innerHTML : '')"
        f".includes({marker!r})"
    )


def _execution_markers(request: ExecutionRequest) -> tuple[str, ...]:
    return tuple(
        value
        for _, value in request.query_parameters
        if _MARKER.fullmatch(value) is not None
    )


def _reflection_markers(request: ExecutionRequest) -> tuple[str, ...]:
    return tuple(
        value
        for _, value in request.query_parameters
        if _REFLECTION_MARKER.fullmatch(value) is not None
    )
