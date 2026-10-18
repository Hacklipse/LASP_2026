"""Playwright로 실제 JavaScript 실행 여부를 관측하는 XSS Browser Runtime."""

from __future__ import annotations

import time
import posixpath
from collections.abc import Sequence
from typing import Protocol
from urllib.parse import unquote, urlsplit, urlunsplit

from hacklipse.application import RuntimeEvidenceCollector
from hacklipse.domain import ExecutionRequest, ExecutionResult, HttpRequestKind, RunScope, TaskEnvelope
from hacklipse.ports.errors import ExternalExecutionDisabled

from .http_runtime import HttpExecutionRuntime
from .xss_execution import (
    BROWSER_XSS_TOOL,
    browser_navigation_url,
    dom_reflection_script,
    execution_marker_script,
    postmessage_payload,
    reflection_marker,
    _execution_payload,
)

# SPA 는 DOM 을 클라이언트에서 그린다. domcontentloaded 직후에는 라우트가 아직
# 렌더되지 않아 반사도 실행도 관측되지 않는다. socket.io 를 쓰는 대상이라 networkidle
# 을 기다릴 수 없으므로, 고정 sleep 대신 기대한 marker 조건을 제한 시간 동안 polling한다.
_PROBE_WAIT_TIMEOUT_MS = 5000
_POSTMESSAGE_KINDS = frozenset({
    HttpRequestKind.POSTMESSAGE_CONTROL,
    HttpRequestKind.POSTMESSAGE_REFLECTION,
    HttpRequestKind.POSTMESSAGE_EXECUTION,
})


class BrowserProbeRunner(Protocol):
    """테스트 대역과 실제 Playwright 실행이 공유하는 최소 계약."""

    def __call__(
        self,
        request: ExecutionRequest,
        navigation_url: str,
        expected_marker: str | None,
        cookies: Sequence[tuple[str, str]],
    ) -> ExecutionResult: ...


class PlaywrightBrowserRuntime:
    """HTTP 요청은 기존 Runtime에, XSS 실행 검증만 Chromium에 위임한다.

    브라우저는 매 실행마다 격리된 context로 열고 닫는다. Run의 인증 Cookie는 메모리에서
    context로만 전달하며 결과·감사 로그에는 기록하지 않는다. 페이지의 다른 origin 요청은
    route 단계에서 중단한다.
    """

    def __init__(
        self,
        *,
        http_runtime: HttpExecutionRuntime,
        browser_runner: BrowserProbeRunner | None = None,
        executable_path: str | None = None,
    ) -> None:
        self._http = http_runtime
        self._browser_runner = browser_runner
        self._executable_path = executable_path
        self._collector: RuntimeEvidenceCollector | None = None

    def bind_collector(self, collector: RuntimeEvidenceCollector) -> None:
        self._collector = collector

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        if request.tool != BROWSER_XSS_TOOL:
            return self._http.execute(request)

        navigation_url, marker = browser_navigation_url(request)
        cookies = self._http.session_cookies(request)
        expected = marker or reflection_marker(request)
        if self._browser_runner is not None:
            return self._browser_runner(request, navigation_url, expected, cookies)
        return self._run_playwright(
            request, navigation_url, expected, cookies, collector=self._collector,
            executable_path=self._executable_path,
        )

    def close_session(self, run_id: str) -> None:
        self._http.close_session(run_id)

    def session_cookies(self, request: ExecutionRequest) -> tuple[tuple[str, str], ...]:
        return self._http.session_cookies(request)

    @staticmethod
    def _run_playwright(
        request: ExecutionRequest,
        navigation_url: str,
        expected_marker: str | None,
        cookies: Sequence[tuple[str, str]],
        *,
        collector: RuntimeEvidenceCollector | None = None,
        executable_path: str | None = None,
    ) -> ExecutionResult:
        try:
            from playwright.sync_api import Error as PlaywrightError
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
            from playwright.sync_api import sync_playwright
        except ImportError as error:
            raise ExternalExecutionDisabled(
                "browser XSS validation requires Playwright; install the project "
                "dependencies and run 'playwright install chromium'"
            ) from error

        if request.scope is None:
            raise ExternalExecutionDisabled("browser execution requires an explicit run scope")

        started = time.perf_counter()
        blocked_requests = 0
        transport = None
        try:
            with sync_playwright() as playwright:
                try:
                    launch_options = {"executable_path": executable_path} if executable_path else {}
                    browser = playwright.chromium.launch(headless=True, **launch_options)
                except PlaywrightError as error:
                    raise ExternalExecutionDisabled(
                        "Chromium is unavailable for browser XSS validation; "
                        "run 'playwright install chromium'"
                    ) from error

                try:
                    context = browser.new_context(service_workers="block", accept_downloads=False)
                    context.route_web_socket("**/*", lambda ws: ws.close())
                    context.add_init_script("window.RTCPeerConnection = undefined; window.webkitRTCPeerConnection = undefined;")
                    if cookies:
                        origin = _origin(navigation_url)
                        context.add_cookies(
                            [
                                {"name": name, "value": value, "url": origin}
                                for name, value in cookies
                            ]
                        )
                    postmessage = request.request_kind in _POSTMESSAGE_KINDS
                    attacker = context.new_page() if postmessage else None
                    page = None if postmessage else context.new_page()
                    allowed_origin = _origin_key(navigation_url)

                    def enforce_scope(route) -> None:
                        nonlocal blocked_requests
                        if _url_in_scope(
                            route.request.url, request.scope, allowed_origin
                        ) and route.request.method.upper() in {"GET", "HEAD", "OPTIONS"}:
                            route.continue_()
                        else:
                            blocked_requests += 1
                            route.abort("blockedbyclient")

                    if collector is not None:
                        from .browser_recon import _CollectorTransport

                        transport = _CollectorTransport(
                            collector=collector,
                            task=TaskEnvelope(
                                task_id=request.task_id, run_id=request.run_id,
                                agent_type="browser_xss_runtime",
                                target_url=request.target_url,
                                allowed_tools=("http_get",),
                                credential_ref=request.credential_ref,
                            ),
                            scope=request.scope,
                            remember=lambda *_: request.surface_id,
                            limit=64,
                            deadline=time.monotonic() + request.timeout_seconds,
                            evidence_type="browser_xss_subrequest",
                            reason="load browser XSS page dependency",
                        )
                        if postmessage:
                            context.route("**/*", transport.handle)
                        else:
                            page.route("**/*", transport.handle)
                    else:
                        if postmessage:
                            context.route("**/*", enforce_scope)
                        else:
                            page.route("**/*", enforce_scope)
                    if postmessage:
                        # The fixed data page has a null origin. Its popup remains
                        # reachable through WindowProxy after it navigates to the
                        # target, so every message truly crosses origins.
                        attacker.goto("data:text/html,<button id=launch>Open</button>")
                        attacker.evaluate(
                            "() => document.getElementById('launch').onclick = "
                            "() => { window.__hacklipseTarget = window.open('about:blank'); }"
                        )
                        with attacker.expect_popup() as opened:
                            attacker.click("#launch")
                        page = opened.value
                    response = page.goto(
                        navigation_url,
                        wait_until="domcontentloaded",
                        timeout=max(1, int(request.timeout_seconds * 1000)),
                    )
                    if postmessage:
                        plan = postmessage_payload(request)
                        if plan is not None:
                            event_type, field, marker = plan
                            payload = (
                                f'<span data-hacklipse-postmessage="{marker}"></span>'
                                if request.request_kind is HttpRequestKind.POSTMESSAGE_REFLECTION
                                else _execution_payload(marker)
                            )
                            _send_foreign_message_until_signal(
                                attacker, page, request, event_type, field, payload,
                                expected_marker,
                            )
                    else:
                        _wait_for_probe_signal(
                            page,
                            request,
                            expected_marker,
                            timeout_error=PlaywrightTimeoutError,
                        )
                    observed = page.evaluate(execution_marker_script())
                    executed = bool(
                        expected_marker is not None and observed == expected_marker
                    )
                    reflected = bool(
                        expected_marker is not None
                        and page.evaluate(dom_reflection_script(expected_marker))
                    )
                    status = response.status if response is not None else None
                    final_url = page.url
                finally:
                    browser.close()
        except PlaywrightTimeoutError:
            return _browser_error(request, navigation_url, started, "timeout")
        except PlaywrightError:
            return _browser_error(request, navigation_url, started, "navigation")

        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="browser_execution",
            observation={
                "type": "browser_execution",
                "status": status,
                "method": "GET",
                "requested_url": navigation_url,
                "final_url": final_url,
                "request_kind": request.request_kind.value,
                "script_executed": executed,
                # 값이 DOM 까지 도달했는가. Analysis 가 쓰는 신호이며 실행 증명이 아니다.
                "dom_reflected": reflected,
                # marker 원문은 무해한 canary이며 proof가 어떤 실행을 관측했는지 묶는다.
                "execution_marker": expected_marker if executed else None,
                "reflection_marker": expected_marker if reflected else None,
                "foreign_origin_message": postmessage,
                "blocked_request_count": blocked_requests + (transport.blocked if transport else 0),
                "subrequest_count": transport.sent if transport else None,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
            },
        )


def _send_foreign_message_until_signal(
    attacker, page, request: ExecutionRequest,
    event_type: str, field: str, payload: str, marker: str | None,
) -> None:
    """Retry only while client-side listeners hydrate; no extra HTTP mutation."""

    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

    if attacker.evaluate("() => location.origin") != "null":
        raise ExternalExecutionDisabled("postMessage sender is not a foreign origin")
    deadline = time.monotonic() + min(
        _PROBE_WAIT_TIMEOUT_MS / 1000, request.timeout_seconds,
    )
    signal = (
        dom_reflection_script(marker)
        if request.request_kind is HttpRequestKind.POSTMESSAGE_REFLECTION
        else execution_marker_script()
    )
    while time.monotonic() < deadline:
        attacker.evaluate(
            "({type, field, value}) => "
            "window.__hacklipseTarget.postMessage({type, [field]: value}, '*')",
            {"type": event_type, "field": field, "value": payload},
        )
        try:
            page.wait_for_function(signal, timeout=250)
            return
        except PlaywrightTimeoutError:
            # A missing signal is a negative observation, not a browser error.
            pass


def _wait_for_probe_signal(
    page,
    request: ExecutionRequest,
    expected_marker: str | None,
    *,
    timeout_error: type[Exception],
) -> None:
    """기대한 반사·실행 신호가 나타날 때까지만 bounded polling한다.

    marker가 끝내 나타나지 않는 것은 브라우저 오류가 아니라 정상적인 미탐지다. 따라서
    polling timeout은 삼키고, 이후의 결정적 evaluate가 False를 기록하게 한다.
    """

    if expected_marker is None:
        return
    wait_script = (
        dom_reflection_script(expected_marker)
        if reflection_marker(request) is not None
        else execution_marker_script()
    )
    timeout_ms = min(
        _PROBE_WAIT_TIMEOUT_MS,
        max(1, int(request.timeout_seconds * 1000)),
    )
    try:
        page.wait_for_function(wait_script, timeout=timeout_ms)
    except timeout_error:
        pass


def _browser_error(
    request: ExecutionRequest,
    navigation_url: str,
    started: float,
    error_kind: str,
) -> ExecutionResult:
    return ExecutionResult(
        execution_id=request.execution_id,
        evidence_type="browser_error",
        observation={
            "type": "browser_error",
            "method": "GET",
            "requested_url": navigation_url,
            "request_kind": request.request_kind.value,
            "error_kind": error_kind,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        },
    )


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


def _origin_key(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.casefold()
    return scheme, (parsed.hostname or "").casefold(), parsed.port or (443 if scheme == "https" else 80)


def _url_in_scope(
    url: str,
    scope: RunScope,
    allowed_origin: tuple[str, str, int | None],
) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None or parsed.username is not None or parsed.password is not None:
        return False
    if _origin_key(url) != allowed_origin:
        return False
    allowed_hosts = {host.casefold().rstrip(".") for host in scope.allowed_hosts}
    if parsed.hostname.casefold().rstrip(".") not in allowed_hosts:
        return False
    path = parsed.path or "/"
    decoded = unquote(unquote(path)).replace("\\", "/")
    normalized = posixpath.normpath(decoded)
    return any(
        path.startswith(prefix) and
        (normalized == prefix.rstrip("/") or normalized.startswith(prefix))
        for prefix in scope.allowed_path_prefixes
    )
