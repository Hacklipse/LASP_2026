"""Playwright로 실제 JavaScript 실행 여부를 관측하는 XSS Browser Runtime."""

from __future__ import annotations

import time
from collections.abc import Sequence
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit

from hacklipse.domain import ExecutionRequest, ExecutionResult, RunScope
from hacklipse.ports.errors import ExternalExecutionDisabled

from .http_runtime import HttpExecutionRuntime
from .xss_execution import (
    BROWSER_XSS_TOOL,
    browser_navigation_url,
    dom_reflection_script,
    execution_marker_script,
    reflection_marker,
)

# SPA 는 DOM 을 클라이언트에서 그린다. domcontentloaded 직후에는 라우트가 아직
# 렌더되지 않아 반사도 실행도 관측되지 않는다. socket.io 를 쓰는 대상이 있어
# networkidle 은 기다릴 수 없으므로 고정 정착 시간을 둔다.
_SETTLE_MS = 2000


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
    ) -> None:
        self._http = http_runtime
        self._browser_runner = browser_runner or self._run_playwright

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        if request.tool != BROWSER_XSS_TOOL:
            return self._http.execute(request)

        navigation_url, marker = browser_navigation_url(request)
        cookies = self._http.session_cookies(request)
        return self._browser_runner(
            request, navigation_url, marker or reflection_marker(request), cookies
        )

    def close_session(self, run_id: str) -> None:
        self._http.close_session(run_id)

    @staticmethod
    def _run_playwright(
        request: ExecutionRequest,
        navigation_url: str,
        expected_marker: str | None,
        cookies: Sequence[tuple[str, str]],
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
        try:
            with sync_playwright() as playwright:
                try:
                    browser = playwright.chromium.launch(headless=True)
                except PlaywrightError as error:
                    raise ExternalExecutionDisabled(
                        "Chromium is unavailable for browser XSS validation; "
                        "run 'playwright install chromium'"
                    ) from error

                try:
                    context = browser.new_context()
                    if cookies:
                        origin = _origin(navigation_url)
                        context.add_cookies(
                            [
                                {"name": name, "value": value, "url": origin}
                                for name, value in cookies
                            ]
                        )
                    page = context.new_page()
                    allowed_origin = _origin_key(navigation_url)

                    def enforce_scope(route) -> None:
                        nonlocal blocked_requests
                        if _url_in_scope(
                            route.request.url, request.scope, allowed_origin
                        ):
                            route.continue_()
                        else:
                            blocked_requests += 1
                            route.abort("blockedbyclient")

                    page.route("**/*", enforce_scope)
                    response = page.goto(
                        navigation_url,
                        wait_until="domcontentloaded",
                        timeout=max(1, int(request.timeout_seconds * 1000)),
                    )
                    page.wait_for_timeout(_SETTLE_MS)
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
                "blocked_request_count": blocked_requests,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
            },
        )


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
    return parsed.scheme.casefold(), (parsed.hostname or "").casefold(), parsed.port


def _url_in_scope(
    url: str,
    scope: RunScope,
    allowed_origin: tuple[str, str, int | None],
) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return False
    if _origin_key(url) != allowed_origin:
        return False
    allowed_hosts = {host.casefold().rstrip(".") for host in scope.allowed_hosts}
    if parsed.hostname.casefold().rstrip(".") not in allowed_hosts:
        return False
    path = parsed.path or "/"
    return any(path.startswith(prefix) for prefix in scope.allowed_path_prefixes)
