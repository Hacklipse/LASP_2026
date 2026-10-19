"""SQLi baseline이 최소 침해 탐침으로 구문 오류 신호만 만드는지 검증한다.

지키려는 계약은 넷이다.
1. control과 probe가 따옴표 하나만 다르다 — 차이의 원인이 하나로 좁혀진다.
2. control에도 있는 오류는 신호가 아니다 — 원래 깨져 있는 페이지를 취약으로 보지 않는다.
3. 오류 문자열을 숨겨도 상태 차이로 잡는다.
4. 오류가 없으면 제한된 true/false 비교로 blind SQLi 신호를 확인한다.
5. 공격 페이로드는 도메인이 거부한다 — Agent가 만들려 해도 Runtime에 도달하지 못한다.
"""

from __future__ import annotations

import unittest
from dataclasses import replace

from hacklipse.adapters import HeuristicSqliAnalyzer
from hacklipse.adapters.validation import ValidationAgent
from hacklipse.adapters.sqli_analysis import HEURISTIC_SQLI_ANALYZER, sql_boolean_signal
from hacklipse.application.errors import AgentContractError
from hacklipse.ports.errors import BudgetExceeded
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    AgentResultStatus,
    Candidate,
    Evidence,
    DomainInvariantError,
    Evidence,
    ExecutionRequest,
    ExecutionResult,
    HttpRequestKind,
    HttpRequestSpec,
    Run,
    RunScope,
    Surface,
    TaskEnvelope,
    ValidationProofType,
    ValidationVerdict,
)

_RUN_ID = "run-sqli"
_SURFACE_ID = "surface-items"
_CANDIDATE_ID = "candidate-sqli"

_SQLITE_ERROR = "<pre>SQLITE_ERROR: unrecognized token</pre>"


class _SqlRuntime:
    """따옴표가 들어오면 지정한 방식으로 반응하는 결정적 Runtime 대역."""

    def __init__(self, *, mode: str) -> None:
        self.mode = mode
        self.requests: list[ExecutionRequest] = []

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        values = tuple(value for _, value in request.query_parameters)
        injected = any("'" in value for value in values)
        status, body = 200, "<p>항목 1건</p>"
        if self.mode == "error_message" and injected:
            body = _SQLITE_ERROR
        elif self.mode == "status_differential" and injected:
            status, body = 500, "<p>일시적인 오류</p>"
        elif self.mode == "always_broken":
            # 따옴표와 무관하게 항상 오류를 낸다. control에도 있으므로 신호가 아니다.
            body = _SQLITE_ERROR
        elif self.mode == "boolean":
            if any(value.endswith((" AND 1=1", "' AND '1'='1")) for value in values):
                body = "<p>일치하는 항목 1건</p>"
            elif any(value.endswith((" AND 1=2", "' AND '1'='2")) for value in values):
                body = "<p>일치하는 항목 없음</p>"
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


def _fixture(
    *,
    mode: str,
    parameters: tuple[str, ...] = ("id",),
    request_budget: int = 10,
    method: str = "GET",
    observed: tuple[tuple[str, str], ...] = (),
):
    runtime = _SqlRuntime(mode=mode)
    app = build_local_application({}, runtime=runtime)
    app.stores.runs.add(
        Run(
            run_id=_RUN_ID,
            target_url="http://local.test/",
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            policy_profile="safe",
            request_budget=20,
        )
    )
    app.stores.surfaces.add(
        Surface(
            surface_id=_SURFACE_ID,
            run_id=_RUN_ID,
            url="http://local.test/items",
            method=method,
            parameters=parameters,
            observed_query=observed,
        )
    )
    app.stores.candidates.add(
        Candidate(
            candidate_id=_CANDIDATE_ID,
            run_id=_RUN_ID,
            surface_id=_SURFACE_ID,
            vulnerability_type="SQLi",
            hypothesis="parameterized GET surface",
            assigned_agent="sqli_analyzer",
            evidence_ids=(),
        )
    )
    app.budget_manager.open_run(_RUN_ID, 20)
    agent = HeuristicSqliAnalyzer(
        candidate_store=app.stores.candidates,
        surface_store=app.stores.surfaces,
        evidence_store=app.stores.evidence,
        id_factory=iter(str(index) for index in range(100)).__next__,
    )
    task = TaskEnvelope(
        task_id="task-sqli",
        run_id=_RUN_ID,
        agent_type="sqli_analyzer",
        target_url="http://local.test/items",
        surface_id=_SURFACE_ID,
        candidate_id=_CANDIDATE_ID,
        allowed_tools=("http_get", "http_post"),
        request_budget=request_budget,
    )
    return agent, app, runtime, task


def _collect(result, app, task: TaskEnvelope) -> TaskEnvelope:
    ids = list(task.evidence_ids)
    for request in result.evidence_requests:
        ids.append(
            app.collector.collect(
                task.run_id, task.target_url or "", request, task_id=task.task_id
            )
        )
    return replace(
        task,
        evidence_ids=tuple(ids),
        request_budget=app.budget_manager.remaining(task.run_id),
    )


def _signals(app):
    return [
        item.observation
        for item in app.stores.evidence.list_by_run(_RUN_ID)
        if item.observation.get("type") == "sql_error"
    ]


def _boolean_signals(app):
    return [
        item.observation
        for item in app.stores.evidence.list_by_run(_RUN_ID)
        if item.observation.get("type") == "sqli_differential"
    ]


class HeuristicSqliAnalyzerTests(unittest.TestCase):
    def test_boolean_comparison_ignores_the_predicate_echo_itself(self) -> None:
        def response(evidence_id: str, body: str) -> Evidence:
            return Evidence(
                evidence_id=evidence_id,
                run_id=_RUN_ID,
                surface_id=_SURFACE_ID,
                created_by="execution_runtime:http_get",
                evidence_type="http_response",
                observation={"type": "http_response", "status": 200, "body": body},
            )

        true = response("true", "search: abc' AND '1'='1")
        false = response("false", "search: abc' AND '1'='2")

        self.assertIsNone(sql_boolean_signal(true, false))

    # --- 1. 탐침 형태 ---

    def test_control_and_probe_differ_only_by_one_quote(self) -> None:
        agent, app, runtime, task = _fixture(mode="error_message")

        requested = agent.handle(task)
        self.assertIs(requested.status, AgentResultStatus.NEEDS_EVIDENCE)
        _collect(requested, app, task)

        self.assertEqual(
            [request.request_kind for request in runtime.requests],
            [HttpRequestKind.CONTROL, HttpRequestKind.PROBE],
        )
        control = dict(runtime.requests[0].query_parameters)["id"]
        probe = dict(runtime.requests[1].query_parameters)["id"]
        self.assertEqual(probe, control + "'")

    def test_post_form_probe_keeps_values_out_of_the_query_string(self) -> None:
        agent, _, _, task = _fixture(
            mode="error_message", parameters=("category", "submit"), method="POST"
        )

        result = agent.handle(task)

        self.assertEqual(result.status, AgentResultStatus.NEEDS_EVIDENCE)
        self.assertEqual(len(result.evidence_requests), 3)
        for request in result.evidence_requests:
            self.assertEqual(request.suggested_tool, "http_post")
            assert request.http_request is not None
            self.assertEqual(request.http_request.method, "POST")
            self.assertEqual(request.http_request.query_parameters, ())
            self.assertEqual(
                tuple(name for name, _ in request.http_request.form_parameters),
                ("category", "submit"),
            )

    def test_probe_preserves_observed_routing_fields_and_mutates_observed_value(self) -> None:
        agent, _, _, task = _fixture(
            mode="error_message",
            parameters=("action", "nonce", "id"),
            method="POST",
            observed=(("action", "lookup"), ("nonce", "abc"), ("id", "7")),
        )

        result = agent.handle(task)

        control, action_probe, nonce_probe, id_probe = result.evidence_requests
        assert control.http_request is not None
        assert action_probe.http_request is not None
        assert nonce_probe.http_request is not None
        assert id_probe.http_request is not None
        self.assertEqual(
            dict(control.http_request.form_parameters),
            {"action": "lookup", "nonce": "abc", "id": "7"},
        )
        self.assertEqual(
            dict(id_probe.http_request.form_parameters),
            {"action": "lookup", "nonce": "abc", "id": "7'"},
        )

    def test_marker_is_stable_across_calls_so_evidence_matches(self) -> None:
        """무작위 marker를 쓰면 두 번째 호출이 첫 증적을 못 찾아 무한 반복된다."""

        agent, app, runtime, task = _fixture(mode="error_message")
        first = agent.handle(task)
        second = agent.handle(task)

        self.assertEqual(
            [r.http_request.query_parameters for r in first.evidence_requests],
            [r.http_request.query_parameters for r in second.evidence_requests],
        )

    # --- 2. 신호 판정 ---

    def test_error_message_only_on_the_probe_is_a_signal(self) -> None:
        agent, app, _, task = _fixture(mode="error_message")

        requested = agent.handle(task)
        result = agent.handle(_collect(requested, app, task))

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        signals = _signals(app)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["parameter"], "id")
        self.assertEqual(signals[0]["signal"], "error_message")
        self.assertEqual(signals[0]["engine"], "sqlite")
        self.assertIn("control_evidence_id", signals[0])
        self.assertIn("probe_evidence_id", signals[0])

    def test_status_differential_is_a_signal_without_an_error_string(self) -> None:
        agent, app, _, task = _fixture(mode="status_differential")

        requested = agent.handle(task)
        agent.handle(_collect(requested, app, task))

        signals = _signals(app)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["signal"], "status_differential")
        self.assertIsNone(signals[0]["engine"])
        self.assertEqual(signals[0]["control_status"], 200)
        self.assertEqual(signals[0]["probe_status"], 500)

    def test_identical_responses_produce_no_signal(self) -> None:
        agent, app, _, task = _fixture(mode="safe")

        requested = agent.handle(task)
        after_quote = _collect(requested, app, task)
        boolean_requested = agent.handle(after_quote)
        result = agent.handle(_collect(boolean_requested, app, after_quote))

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        self.assertEqual(_signals(app), [])

    def test_error_present_in_the_control_is_not_a_signal(self) -> None:
        """원래부터 깨져 있는 페이지를 주입 성공으로 오인하지 않는다."""

        agent, app, _, task = _fixture(mode="always_broken")

        requested = agent.handle(task)
        after_quote = _collect(requested, app, task)
        boolean_requested = agent.handle(after_quote)
        agent.handle(_collect(boolean_requested, app, after_quote))

        self.assertEqual(_signals(app), [])

    def test_boolean_differential_is_a_signal_when_error_probe_is_silent(self) -> None:
        agent, app, _, task = _fixture(mode="boolean", observed=(("id", "7"),))

        quote_requested = agent.handle(task)
        after_quote = _collect(quote_requested, app, task)
        boolean_requested = agent.handle(after_quote)
        result = agent.handle(_collect(boolean_requested, app, after_quote))

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        self.assertEqual(len(boolean_requested.evidence_requests), 2)
        signals = _boolean_signals(app)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["parameter"], "id")
        self.assertEqual(signals[0]["signal"], "boolean_response_differential")

    def test_each_parameter_is_probed_separately(self) -> None:
        agent, app, runtime, task = _fixture(mode="error_message", parameters=("id", "sort"))

        requested = agent.handle(task)
        agent.handle(_collect(requested, app, task))

        # control 1 + probe 2
        self.assertEqual(len(runtime.requests), 3)
        self.assertEqual({signal["parameter"] for signal in _signals(app)}, {"id", "sort"})
        for request in runtime.requests[1:]:
            quoted = [name for name, value in request.query_parameters if value.endswith("'")]
            self.assertEqual(len(quoted), 1, "탐침은 파라미터 하나만 바꾼다")

    # --- 3. 계약 ---

    def test_non_sqli_candidate_is_a_contract_error(self) -> None:
        agent, app, _, task = _fixture(mode="safe")
        candidate = app.stores.candidates.get(_RUN_ID, _CANDIDATE_ID)
        app.stores.candidates.save(replace(candidate, vulnerability_type="XSS"))

        with self.assertRaises(AgentContractError):
            agent.handle(task)

    def test_insufficient_budget_stops_before_any_request(self) -> None:
        agent, _, runtime, task = _fixture(mode="error_message", request_budget=1)

        # 예산 부족은 계약 위반이 아니다. Orchestrator가 skipped_budget으로 구분한다.
        with self.assertRaises(BudgetExceeded):
            agent.handle(task)
        self.assertEqual(runtime.requests, [])

    # --- 4. 페이로드 차단 ---

    def test_domain_rejects_attack_payloads_in_probe_values(self) -> None:
        """Agent가 만들려 해도 공격 문자열은 Runtime에 도달하지 못한다."""

        for payload in (
            "' OR 1=1--",
            "hacklipse' UNION SELECT 1",
            "hacklipse'; DROP TABLE users",
            "hacklipse' AND SLEEP(5)",
            "../../etc/passwd",
        ):
            with self.subTest(payload=payload), self.assertRaises(DomainInvariantError):
                HttpRequestSpec(
                    query_parameters=(("id", payload),),
                    request_kind=HttpRequestKind.PROBE,
                )

    def test_the_quote_probe_itself_is_allowed(self) -> None:
        spec = HttpRequestSpec(
            query_parameters=(("id", "hacklipsez1a2z3b4'"),),
            request_kind=HttpRequestKind.PROBE,
        )
        self.assertEqual(spec.query_parameters[0][1], "hacklipsez1a2z3b4'")

    def test_analyzer_never_executes_its_own_requests(self) -> None:
        agent, _, runtime, task = _fixture(mode="error_message")

        result = agent.handle(task)

        self.assertIs(result.status, AgentResultStatus.NEEDS_EVIDENCE)
        self.assertEqual(runtime.requests, [], "Agent는 직접 요청하지 않는다")
        self.assertTrue(result.evidence_requests)


class GraphqlSqliPipelineTests(unittest.TestCase):
    def test_schema_derived_read_query_requires_independent_error_reproduction(self):
        runtime = _SqlRuntime(mode="error_message")
        app = build_local_application({}, runtime=runtime)
        app.stores.runs.add(Run(
            run_id=_RUN_ID, target_url="http://local.test/",
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            policy_profile="safe", request_budget=20,
        ))
        app.stores.surfaces.add(Surface(
            surface_id=_SURFACE_ID, run_id=_RUN_ID,
            url="http://local.test/graphql", method="GET",
            discovery_types=("graphql_introspection",),
        ))
        app.stores.evidence.append(Evidence(
            evidence_id="evi-plan", run_id=_RUN_ID, surface_id=_SURFACE_ID,
            created_by="recon", evidence_type="observation",
            observation={"type": "graphql_read_query_plan", "plans": [
                {"field": "search", "argument": "term", "select_typename": True},
            ]},
        ))
        app.stores.candidates.add(Candidate(
            candidate_id=_CANDIDATE_ID, run_id=_RUN_ID,
            surface_id=_SURFACE_ID, vulnerability_type="SQLi",
            hypothesis="schema-derived read query", assigned_agent="sqli_analyzer",
            evidence_ids=("evi-plan",),
        ))
        app.budget_manager.open_run(_RUN_ID, 20)
        analyzer = HeuristicSqliAnalyzer(
            candidate_store=app.stores.candidates,
            surface_store=app.stores.surfaces,
            evidence_store=app.stores.evidence,
        )
        task = TaskEnvelope(
            task_id="task-graphql-analysis", run_id=_RUN_ID,
            agent_type="sqli_analyzer", target_url="http://local.test/graphql",
            surface_id=_SURFACE_ID, candidate_id=_CANDIDATE_ID,
            evidence_ids=("evi-plan",), allowed_tools=("http_get",),
            request_budget=20,
        )
        first = analyzer.handle(task)
        self.assertIs(first.status, AgentResultStatus.NEEDS_EVIDENCE)
        self.assertEqual(len(first.evidence_requests), 2)
        self.assertEqual([item.http_request.request_kind for item in first.evidence_requests], [
            HttpRequestKind.GRAPHQL_QUERY_CONTROL, HttpRequestKind.GRAPHQL_QUERY_PROBE,
        ])
        task = _collect(first, app, task)
        analyzed = analyzer.handle(task)
        self.assertEqual(len(analyzed.new_evidence_ids), 2)
        observations = app.stores.evidence.get_many(_RUN_ID, analyzed.new_evidence_ids)
        self.assertEqual(
            {item.observation.get("type") for item in observations},
            {"graphql_query_probe_result", "sql_error"},
        )

        validator = ValidationAgent(
            candidate_store=app.stores.candidates,
            surface_store=app.stores.surfaces,
            evidence_store=app.stores.evidence,
        )
        validation_task = TaskEnvelope(
            task_id="task-graphql-validation", run_id=_RUN_ID,
            agent_type="validation_agent", surface_id=_SURFACE_ID,
            candidate_id=_CANDIDATE_ID, validation_id="validation-graphql",
            evidence_ids=(*task.evidence_ids, *analyzed.new_evidence_ids),
            allowed_tools=("http_get",), request_budget=20,
        )
        pending = validator.handle(validation_task)
        self.assertIs(pending.status, AgentResultStatus.NEEDS_EVIDENCE)
        self.assertEqual(len(pending.evidence_requests), 2)
        self.assertEqual(runtime.requests[-1].request_kind, HttpRequestKind.GRAPHQL_QUERY_PROBE)
        ids = tuple(app.collector.collect(
            _RUN_ID, "http://local.test/graphql", request,
            task_id=validation_task.task_id, validation_id=validation_task.validation_id,
        ) for request in pending.evidence_requests)
        decided = validator.handle(replace(
            validation_task, evidence_ids=(*validation_task.evidence_ids, *ids)
        ))
        self.assertIs(decided.validation.verdict, ValidationVerdict.CONFIRMED)
        self.assertIs(decided.validation.proof.proof_type, ValidationProofType.SQLI_EFFECT)
        self.assertEqual(len(runtime.requests), 4)


if __name__ == "__main__":
    unittest.main()
