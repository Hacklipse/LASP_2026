"""Juice Shop 고정 이후 새로 지원하는 두 표면 모양을 검증한다.

DVWA 를 폐기하면서 XSS 와 Path Traversal 의 표면 모양이 바뀌었다.

    XSS             쿼리 반사 → SPA 클라이언트 라우트의 DOM 반사
    Path Traversal  쿼리 디렉터리 탈출 → 경로 자체가 파일인 확장자 필터 우회

여기서는 실제 Juice Shop 없이 결정적으로 그 두 모양을 재현한다. 외부 네트워크와
브라우저에 의존하지 않는다.
"""

from __future__ import annotations

import unittest

from hacklipse.adapters import BrowserXssAnalyzer, HeuristicPathTraversalAnalyzer
from hacklipse.adapters.browser_xss_analysis import BROWSER_XSS_ANALYZER
from hacklipse.adapters.path_traversal_analysis import (
    PATH_TRAVERSAL_BYPASS_OBSERVATION,
    PATH_TRAVERSAL_OBSERVATION,
    PATH_TRAVERSAL_TOOL,
    RESTRICTED_FILE_OBSERVATION,
    path_traversal_bypass_signal,
    validate_path_traversal_request,
)
from hacklipse.adapters.recon import _client_routes, _looks_like_restricted_file
from hacklipse.adapters.routing import DEFAULT_SURFACE_RULES
from hacklipse.adapters.xss_execution import (
    BROWSER_XSS_TOOL,
    XSS_EXECUTION_MARKER_PREFIX,
    XSS_REFLECTION_MARKER_PREFIX,
    browser_navigation_url,
    reflection_marker,
    validate_browser_xss_request,
)
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    AgentResultStatus,
    Candidate,
    DomainInvariantError,
    Evidence,
    ExecutionRequest,
    ExecutionResult,
    HttpRequestKind,
    HttpRequestSpec,
    PATH_TRAVERSAL_BYPASS_SUFFIX,
    Run,
    RunScope,
    Surface,
    TaskEnvelope,
    ValidationProofType,
    ValidationVerdict,
)

_RUN_ID = "run-juice"
_HOST = "local.test"
_SCOPE = RunScope(allowed_hosts=frozenset({_HOST}))


def _request(
    *,
    tool: str = BROWSER_XSS_TOOL,
    url: str = f"http://{_HOST}/#/search",
    value: str = f"{XSS_EXECUTION_MARKER_PREFIX}abc",
    kind: HttpRequestKind = HttpRequestKind.PROBE,
) -> ExecutionRequest:
    return ExecutionRequest(
        execution_id="exec-1",
        run_id=_RUN_ID,
        task_id="task-1",
        tool=tool,
        target_url=url,
        surface_id="surface-1",
        purpose="test",
        request_kind=kind,
        query_parameters=(("q", value),),
        scope=_SCOPE,
    )


class ClientRouteNavigationTests(unittest.TestCase):
    """SPA 의 DOM sink 는 fragment 라우트 안쪽에 있다."""

    def test_probe_parameters_land_inside_the_fragment(self) -> None:
        """HTTP 요청 대상에서 fragment 는 버려진다. 브라우저 도구만 복원한다."""

        url, marker = browser_navigation_url(_request())

        self.assertTrue(url.startswith(f"http://{_HOST}/#/search?q="))
        self.assertEqual(marker, f"{XSS_EXECUTION_MARKER_PREFIX}abc")
        # resolved_url 은 서버로 보낼 대상이므로 라우트를 잃는다. 그것이 정상이다.
        self.assertNotIn("#", _request().resolved_url)

    def test_execution_payload_fires_on_insertion(self) -> None:
        """innerHTML 로 삽입된 `<script>` 는 실행되지 않는다."""

        url, _ = browser_navigation_url(_request())

        self.assertIn("onerror", url)
        self.assertNotIn("script", url.casefold())

    def test_reflection_probe_carries_the_marker_unchanged(self) -> None:
        """Analysis 는 값이 DOM 에 닿는지만 본다. 실행 가능한 문자를 싣지 않는다."""

        request = _request(value=f"{XSS_REFLECTION_MARKER_PREFIX}abc")
        url, execution = browser_navigation_url(request)

        self.assertIsNone(execution)
        self.assertEqual(reflection_marker(request), f"{XSS_REFLECTION_MARKER_PREFIX}abc")
        self.assertIn(f"q={XSS_REFLECTION_MARKER_PREFIX}abc", url)
        self.assertNotIn("onerror", url)

    def test_a_probe_cannot_mix_execution_and_reflection(self) -> None:
        """둘을 섞으면 어느 쪽이 관측을 만들었는지 증명에서 구분할 수 없다."""

        request = ExecutionRequest(
            execution_id="exec-1",
            run_id=_RUN_ID,
            task_id="task-1",
            tool=BROWSER_XSS_TOOL,
            target_url=f"http://{_HOST}/#/search",
            surface_id=None,
            purpose="test",
            request_kind=HttpRequestKind.PROBE,
            query_parameters=(
                ("q", f"{XSS_EXECUTION_MARKER_PREFIX}a"),
                ("r", f"{XSS_REFLECTION_MARKER_PREFIX}b"),
            ),
            scope=_SCOPE,
        )
        with self.assertRaises(ValueError):
            validate_browser_xss_request(request)

    def test_control_carries_no_marker_at_all(self) -> None:
        request = _request(kind=HttpRequestKind.CONTROL, value="hacklipse-control")

        _, marker = browser_navigation_url(request)

        self.assertIsNone(marker)
        self.assertIsNone(reflection_marker(request))


class ClientRouteDiscoveryTests(unittest.TestCase):
    """번들에서 라우트와 그 파라미터를 짝지어 찾는다."""

    def test_navigate_after_the_parameter_declaration(self) -> None:
        """minify 된 번들은 선언을 변수로 분리한다."""

        body = 'search(e){let i={queryParams:{q:e}};return this.router.navigate(["/search"],i)}'

        self.assertEqual(_client_routes(body), {"search": ("q",)})

    def test_navigate_before_the_parameter_declaration(self) -> None:
        body = 'return this.router.navigate(["/track-result"],{queryParams:{id:e}})'

        self.assertEqual(_client_routes(body), {"track-result": ("id",)})

    def test_distant_route_and_parameter_are_not_paired(self) -> None:
        """창을 넓히면 무관한 라우트가 섞인다."""

        body = 'navigate(["/search"])' + "x" * 500 + "queryParams:{unrelated:e}"

        self.assertEqual(_client_routes(body), {})


class ClientRouteRoutingTests(unittest.TestCase):
    """fragment 표면과 HTTP 표면은 서로 다른 Analyzer 로 간다."""

    def test_http_analyzers_never_receive_a_client_route(self) -> None:
        """fragment 는 서버로 전송되지 않는다. HTTP Analyzer 가 받으면 매번 같은
        루트 문서만 받아 신호 없이 예산만 쓴다."""

        route = Surface(
            surface_id="s1",
            run_id=_RUN_ID,
            url=f"http://{_HOST}/#/search",
            method="GET",
            parameters=("q",),
        )
        api = Surface(
            surface_id="s2",
            run_id=_RUN_ID,
            url=f"http://{_HOST}/rest/products/search",
            method="GET",
            parameters=("q",),
        )
        matched = {
            rule.agent_type for rule in DEFAULT_SURFACE_RULES if rule.matches(route)
        }
        self.assertEqual(matched, {BROWSER_XSS_ANALYZER})

        http_matched = {
            rule.agent_type for rule in DEFAULT_SURFACE_RULES if rule.matches(api)
        }
        self.assertNotIn(BROWSER_XSS_ANALYZER, http_matched)
        self.assertIn("xss_analyzer", http_matched)


class _DomRuntime:
    """browser_xss 도구만 흉내 내는 결정적 대역."""

    def __init__(self, *, reflected: bool = True) -> None:
        self.reflected = reflected
        self.requests: list[ExecutionRequest] = []

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        marker = reflection_marker(request)
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="browser_execution",
            observation={
                "type": "browser_execution",
                "status": 200,
                "script_executed": False,
                "dom_reflected": self.reflected,
                "reflection_marker": marker if self.reflected else None,
                "requested_url": request.resolved_url,
            },
        )


def _dom_fixture(*, reflected: bool = True):
    app = build_local_application({}, runtime=_DomRuntime(reflected=reflected))
    app.stores.runs.add(
        Run(
            run_id=_RUN_ID,
            target_url=f"http://{_HOST}/",
            scope=_SCOPE,
            policy_profile="safe",
            request_budget=20,
        )
    )
    app.stores.surfaces.add(
        Surface(
            surface_id="surface-route",
            run_id=_RUN_ID,
            url=f"http://{_HOST}/#/search",
            method="GET",
            parameters=("q",),
        )
    )
    app.stores.candidates.add(
        Candidate(
            candidate_id="cand-xss",
            run_id=_RUN_ID,
            surface_id="surface-route",
            vulnerability_type="XSS",
            hypothesis="client route parameter",
            assigned_agent=BROWSER_XSS_ANALYZER,
            evidence_ids=(),
        )
    )
    app.budget_manager.open_run(_RUN_ID, 20)
    analyzer = BrowserXssAnalyzer(
        candidate_store=app.stores.candidates,
        surface_store=app.stores.surfaces,
        evidence_store=app.stores.evidence,
    )
    app.dispatcher.register(
        BROWSER_XSS_ANALYZER, analyzer, allowed_tools=(BROWSER_XSS_TOOL,)
    )
    return app, analyzer


def _xss_task(evidence_ids: tuple[str, ...] = ()) -> TaskEnvelope:
    return TaskEnvelope(
        task_id="task-xss",
        run_id=_RUN_ID,
        agent_type=BROWSER_XSS_ANALYZER,
        target_url=f"http://{_HOST}/#/search",
        surface_id="surface-route",
        candidate_id="cand-xss",
        allowed_tools=(BROWSER_XSS_TOOL,),
        request_budget=10,
        evidence_ids=evidence_ids,
    )


class BrowserXssAnalysisTests(unittest.TestCase):
    def test_dom_reflection_becomes_a_reflection_observation(self) -> None:
        app, analyzer = _dom_fixture()

        first = analyzer.handle(_xss_task())
        self.assertIs(first.status, AgentResultStatus.NEEDS_EVIDENCE)

        collected = tuple(
            app.collector.collect(
                _RUN_ID,
                f"http://{_HOST}/#/search",
                request,
                task_id="task-xss",
            )
            for request in first.evidence_requests
        )
        result = analyzer.handle(_xss_task(collected))

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        observations = [
            item.observation
            for item in app.stores.evidence.list_by_run(_RUN_ID)
            if item.evidence_type == "observation"
        ]
        self.assertEqual(
            observations,
            [
                {
                    "type": "reflection",
                    "parameter": "q",
                    "control_evidence_id": observations[0]["control_evidence_id"],
                    "probe_evidence_id": observations[0]["probe_evidence_id"],
                    "observed_in": "dom",
                }
            ],
        )

    def test_no_dom_reflection_produces_no_signal(self) -> None:
        app, analyzer = _dom_fixture(reflected=False)

        first = analyzer.handle(_xss_task())
        collected = tuple(
            app.collector.collect(
                _RUN_ID, f"http://{_HOST}/#/search", request, task_id="task-xss"
            )
            for request in first.evidence_requests
        )
        result = analyzer.handle(_xss_task(collected))

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        self.assertEqual(result.new_evidence_ids, ())

    def test_analysis_never_uses_an_execution_marker(self) -> None:
        """실행 증명은 독립 Validation 만 만들 수 있어야 한다."""

        _, analyzer = _dom_fixture()

        requests = analyzer.handle(_xss_task()).evidence_requests
        values = [
            value
            for request in requests
            for _, value in request.http_request.query_parameters
        ]
        self.assertTrue(
            all(value.startswith(XSS_REFLECTION_MARKER_PREFIX) for value in values)
        )
        self.assertFalse(
            any(value.startswith(XSS_EXECUTION_MARKER_PREFIX) for value in values)
        )


class BypassSuffixContractTests(unittest.TestCase):
    """우회 접미사는 도메인이 고정한다."""

    def test_suffix_is_appended_without_re_encoding(self) -> None:
        """다시 quote 하면 `%25`가 `%2525`가 되어 우회가 성립하지 않는다."""

        request = ExecutionRequest(
            execution_id="e",
            run_id=_RUN_ID,
            task_id="t",
            tool=PATH_TRAVERSAL_TOOL,
            target_url=f"http://{_HOST}/ftp/package.json.bak",
            surface_id=None,
            purpose="p",
            request_kind=HttpRequestKind.PATH_TRAVERSAL_PROBE,
            path_suffix=PATH_TRAVERSAL_BYPASS_SUFFIX,
        )

        self.assertEqual(
            request.resolved_url,
            f"http://{_HOST}/ftp/package.json.bak{PATH_TRAVERSAL_BYPASS_SUFFIX}",
        )

    def test_an_arbitrary_suffix_is_rejected(self) -> None:
        with self.assertRaises(DomainInvariantError):
            HttpRequestSpec(
                request_kind=HttpRequestKind.PATH_TRAVERSAL_PROBE,
                path_suffix="/../../etc/passwd",
            )

    def test_a_suffix_outside_the_probe_kind_is_rejected(self) -> None:
        with self.assertRaises(DomainInvariantError):
            HttpRequestSpec(
                request_kind=HttpRequestKind.CONTROL,
                path_suffix=PATH_TRAVERSAL_BYPASS_SUFFIX,
            )

    def test_the_bypass_probe_cannot_add_query_parameters(self) -> None:
        request = ExecutionRequest(
            execution_id="e",
            run_id=_RUN_ID,
            task_id="t",
            tool=PATH_TRAVERSAL_TOOL,
            target_url=f"http://{_HOST}/ftp/package.json.bak",
            surface_id=None,
            purpose="p",
            request_kind=HttpRequestKind.PATH_TRAVERSAL_PROBE,
            query_parameters=(("page", "hacklipse-control"),),
            path_suffix=PATH_TRAVERSAL_BYPASS_SUFFIX,
        )
        with self.assertRaises(ValueError):
            validate_path_traversal_request(request)


def _evidence(evidence_id: str, status: int, body: str) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        run_id=_RUN_ID,
        surface_id="surface-file",
        created_by="runtime",
        evidence_type="http_response",
        observation={"type": "http_response", "status": status, "body": body},
    )


class BypassSignalTests(unittest.TestCase):
    """거부된 파일이 우회 경로로 제공되었다는 차이만 신호로 인정한다."""

    def test_denied_then_served_is_the_signal(self) -> None:
        self.assertTrue(
            path_traversal_bypass_signal(
                _evidence("c", 403, "Only .md and .pdf files are allowed!"),
                _evidence("p", 200, '{"name":"juice-shop"}'),
            )
        )

    def test_a_plain_2xx_control_is_not_a_bypass(self) -> None:
        """서버가 애초에 내주는 파일은 우회가 아니다."""

        self.assertFalse(
            path_traversal_bypass_signal(
                _evidence("c", 200, "public content"),
                _evidence("p", 200, "public content"),
            )
        )

    def test_a_still_denied_probe_is_not_a_bypass(self) -> None:
        self.assertFalse(
            path_traversal_bypass_signal(
                _evidence("c", 403, "denied"), _evidence("p", 403, "denied")
            )
        )

    def test_an_empty_probe_body_is_not_a_read(self) -> None:
        self.assertFalse(
            path_traversal_bypass_signal(
                _evidence("c", 403, "denied"), _evidence("p", 200, "")
            )
        )


class RestrictedFileDetectionTests(unittest.TestCase):
    def test_web_servable_extensions_are_not_flagged(self) -> None:
        self.assertFalse(_looks_like_restricted_file(f"http://{_HOST}/ftp/legal.md"))
        self.assertFalse(_looks_like_restricted_file(f"http://{_HOST}/main.js"))

    def test_backup_and_secret_extensions_are_flagged(self) -> None:
        for name in ("package.json.bak", "encrypt.pyc", "app.env", "db.sql"):
            with self.subTest(name=name):
                self.assertTrue(
                    _looks_like_restricted_file(f"http://{_HOST}/ftp/{name}")
                )


class _BypassRuntime:
    """확장자 필터를 흉내 내는 결정적 대역."""

    def __init__(self, *, vulnerable: bool = True) -> None:
        self.vulnerable = vulnerable
        self.requests: list[ExecutionRequest] = []

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        bypassed = request.resolved_url.endswith(PATH_TRAVERSAL_BYPASS_SUFFIX)
        if bypassed and self.vulnerable:
            status, body = 200, '{"name":"juice-shop"}'
        else:
            status, body = 403, "Only .md and .pdf files are allowed!"
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response",
                "status": status,
                "body": body,
                "requested_url": request.resolved_url,
            },
        )


def _bypass_fixture(*, vulnerable: bool = True):
    url = f"http://{_HOST}/ftp/package.json.bak"
    app = build_local_application({}, runtime=_BypassRuntime(vulnerable=vulnerable))
    app.stores.runs.add(
        Run(
            run_id=_RUN_ID,
            target_url=url,
            scope=_SCOPE,
            policy_profile="safe",
            request_budget=20,
        )
    )
    app.stores.surfaces.add(
        Surface(surface_id="surface-file", run_id=_RUN_ID, url=url, method="GET")
    )
    app.stores.evidence.append(
        Evidence(
            evidence_id="evi-restricted",
            run_id=_RUN_ID,
            surface_id="surface-file",
            created_by="recon",
            evidence_type="observation",
            observation={
                "type": RESTRICTED_FILE_OBSERVATION,
                "parameter": "package.json.bak",
            },
        )
    )
    app.stores.candidates.add(
        Candidate(
            candidate_id="cand-file",
            run_id=_RUN_ID,
            surface_id="surface-file",
            vulnerability_type="Path Traversal",
            hypothesis="restricted file",
            assigned_agent="path_traversal_analyzer",
            evidence_ids=("evi-restricted",),
        )
    )
    app.budget_manager.open_run(_RUN_ID, 20)
    analyzer = HeuristicPathTraversalAnalyzer(
        candidate_store=app.stores.candidates,
        surface_store=app.stores.surfaces,
        evidence_store=app.stores.evidence,
    )
    return app, analyzer, url


def _pt_task(url: str, evidence_ids: tuple[str, ...]) -> TaskEnvelope:
    return TaskEnvelope(
        task_id="task-pt",
        run_id=_RUN_ID,
        agent_type="path_traversal_analyzer",
        target_url=url,
        surface_id="surface-file",
        candidate_id="cand-file",
        allowed_tools=(PATH_TRAVERSAL_TOOL,),
        request_budget=10,
        evidence_ids=evidence_ids,
    )


class BypassAnalysisTests(unittest.TestCase):
    def _run(self, app, analyzer, url):
        task = _pt_task(url, ("evi-restricted",))
        first = analyzer.handle(task)
        self.assertIs(first.status, AgentResultStatus.NEEDS_EVIDENCE)
        collected = tuple(
            app.collector.collect(_RUN_ID, url, request, task_id="task-pt")
            for request in first.evidence_requests
        )
        return analyzer.handle(_pt_task(url, ("evi-restricted", *collected)))

    def test_denied_file_served_through_the_bypass_is_recorded(self) -> None:
        app, analyzer, url = _bypass_fixture()

        result = self._run(app, analyzer, url)

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        signals = [
            item.observation
            for item in app.stores.evidence.list_by_run(_RUN_ID)
            if item.observation.get("type") == PATH_TRAVERSAL_OBSERVATION
        ]
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["parameter"], "package.json.bak")
        self.assertEqual(signals[0]["bypass"], PATH_TRAVERSAL_BYPASS_OBSERVATION)

    def test_a_server_that_keeps_denying_produces_no_signal(self) -> None:
        app, analyzer, url = _bypass_fixture(vulnerable=False)

        result = self._run(app, analyzer, url)

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        self.assertEqual(result.new_evidence_ids, ())


class BypassValidationTests(unittest.TestCase):
    """검증은 분석의 판정을 읽지 않고 자기 세션에서 다시 만든다."""

    def test_confirmed_proof_uses_only_validation_evidence(self) -> None:
        from hacklipse.adapters import ValidationAgent

        app, analyzer, url = _bypass_fixture()
        task = _pt_task(url, ("evi-restricted",))
        first = analyzer.handle(task)
        analysis_ids = tuple(
            app.collector.collect(_RUN_ID, url, request, task_id="task-pt")
            for request in first.evidence_requests
        )
        analyzer.handle(_pt_task(url, ("evi-restricted", *analysis_ids)))

        validator = ValidationAgent(
            candidate_store=app.stores.candidates,
            evidence_store=app.stores.evidence,
            surface_store=app.stores.surfaces,
        )

        def validation_task(evidence_ids: tuple[str, ...]) -> TaskEnvelope:
            return TaskEnvelope(
                task_id="task-val",
                run_id=_RUN_ID,
                agent_type="validation",
                target_url=url,
                surface_id="surface-file",
                candidate_id="cand-file",
                allowed_tools=(PATH_TRAVERSAL_TOOL,),
                request_budget=10,
                validation_id="val-1",
                evidence_ids=evidence_ids,
            )

        analysis_signals = tuple(
            item.evidence_id
            for item in app.stores.evidence.list_by_run(_RUN_ID)
            if item.evidence_type == "observation"
        )
        pending = validator.handle(validation_task(analysis_signals))
        self.assertIs(pending.status, AgentResultStatus.NEEDS_EVIDENCE)
        reproduction = tuple(
            app.collector.collect(
                _RUN_ID, url, request, task_id="task-val", validation_id="val-1"
            )
            for request in pending.evidence_requests
        )
        result = validator.handle(
            validation_task(analysis_signals + reproduction)
        )

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        assert result.validation is not None
        self.assertIs(result.validation.verdict, ValidationVerdict.CONFIRMED)
        proof = result.validation.proof
        assert proof is not None
        self.assertIs(proof.proof_type, ValidationProofType.PATH_TRAVERSAL_FILE_READ)
        # 분석 단계의 증적은 증명에 들어갈 수 없다.
        self.assertTrue(set(proof.evidence_ids).issubset(set(reproduction)))
        self.assertFalse(set(proof.evidence_ids) & set(analysis_ids))


if __name__ == "__main__":
    unittest.main()
