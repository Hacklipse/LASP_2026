"""고정 XSS probe와 Browser Runtime의 안전 경계를 검증한다."""

from __future__ import annotations

import unittest
from urllib.parse import parse_qsl, urlsplit

from hacklipse.adapters.browser_runtime import PlaywrightBrowserRuntime, _url_in_scope
from hacklipse.adapters.policy import AllowlistPolicyGate
from hacklipse.adapters.xss_execution import (
    BROWSER_XSS_TOOL,
    browser_navigation_url,
)
from hacklipse.domain import (
    ExecutionRequest,
    ExecutionResult,
    HttpRequestKind,
    Run,
    RunScope,
)
from hacklipse.ports.errors import PolicyViolation


_SCOPE = RunScope(allowed_hosts=frozenset({"localhost"}))
_MARKER = "hacklipsexecutionabc123"


def _request(
    *,
    tool: str = BROWSER_XSS_TOOL,
    kind: HttpRequestKind = HttpRequestKind.PROBE,
    value: str = _MARKER,
) -> ExecutionRequest:
    return ExecutionRequest(
        execution_id="exec-1",
        run_id="run-1",
        task_id="task-1",
        tool=tool,
        target_url="http://localhost/vulnerabilities/xss_r/",
        surface_id="surface-1",
        purpose="independent XSS execution probe",
        query_parameters=(("name", value),),
        request_kind=kind,
        validation_id="validation-1",
        scope=_SCOPE,
    )


class _HttpRuntimeStub:
    def __init__(self) -> None:
        self.requests: list[ExecutionRequest] = []

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={"type": "http_response", "status": 200},
        )

    def session_cookies(
        self, request: ExecutionRequest
    ) -> tuple[tuple[str, str], ...]:
        del request
        return (("session", "secret-cookie"),)

    def close_session(self, run_id: str) -> None:
        del run_id


class BrowserProbeContractTests(unittest.TestCase):
    def test_browser_subresources_are_limited_to_the_exact_scoped_origin(self) -> None:
        origin = ("http", "localhost", 4280)

        self.assertTrue(
            _url_in_scope(
                "http://localhost:4280/vulnerabilities/app.js", _SCOPE, origin
            )
        )
        self.assertFalse(
            _url_in_scope(
                "http://localhost:9999/vulnerabilities/app.js", _SCOPE, origin
            )
        )
        self.assertFalse(
            _url_in_scope("https://example.test/tracker.js", _SCOPE, origin)
        )

    def test_runtime_replaces_only_the_marker_with_a_fixed_script(self) -> None:
        """innerHTML 로 삽입된 `<script>` 는 브라우저가 실행하지 않는다.

        SPA 의 DOM sink 를 검증하려면 삽입만으로 이벤트가 발생하는 형태여야 한다.
        형태는 도메인 쪽에 고정되어 있고 marker 만 바뀐다.
        """

        url, marker = browser_navigation_url(_request())

        self.assertEqual(marker, _MARKER)
        parameters = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
        self.assertEqual(
            parameters["name"],
            f'<img src=x onerror="window.__hacklipse_xss_probe__=\'{_MARKER}\'">',
        )

    def test_control_request_never_receives_an_execution_script(self) -> None:
        request = _request(kind=HttpRequestKind.CONTROL, value="hacklipse-control")

        url, marker = browser_navigation_url(request)

        self.assertIsNone(marker)
        self.assertEqual(url, request.resolved_url)

    def test_policy_rejects_a_probe_without_exactly_one_execution_marker(self) -> None:
        run = Run(
            run_id="run-1",
            target_url="http://localhost/",
            scope=_SCOPE,
            policy_profile="safe",
            request_budget=10,
        )

        with self.assertRaises(PolicyViolation):
            AllowlistPolicyGate().validate_execution(
                run, _request(value="ordinary-marker")
            )

    def test_non_browser_tools_stay_on_the_http_runtime(self) -> None:
        http = _HttpRuntimeStub()
        browser_calls: list[tuple[object, ...]] = []

        def browser_runner(*args):
            browser_calls.append(args)
            raise AssertionError("browser runner must not be called")

        runtime = PlaywrightBrowserRuntime(
            http_runtime=http,  # type: ignore[arg-type]
            browser_runner=browser_runner,
        )
        result = runtime.execute(_request(tool="http_get"))

        self.assertEqual(result.evidence_type, "http_response")
        self.assertEqual(http.requests, [_request(tool="http_get")])
        self.assertEqual(browser_calls, [])

    def test_browser_runner_gets_session_cookie_without_storing_it_in_result(self) -> None:
        http = _HttpRuntimeStub()
        received_cookies: list[tuple[tuple[str, str], ...]] = []

        def browser_runner(request, url, marker, cookies):
            del url
            received_cookies.append(tuple(cookies))
            return ExecutionResult(
                execution_id=request.execution_id,
                evidence_type="browser_execution",
                observation={
                    "type": "browser_execution",
                    "script_executed": True,
                    "execution_marker": marker,
                },
            )

        runtime = PlaywrightBrowserRuntime(
            http_runtime=http,  # type: ignore[arg-type]
            browser_runner=browser_runner,
        )
        result = runtime.execute(_request())

        self.assertEqual(received_cookies, [(('session', 'secret-cookie'),)])
        self.assertNotIn("secret-cookie", repr(result))


if __name__ == "__main__":
    unittest.main()
