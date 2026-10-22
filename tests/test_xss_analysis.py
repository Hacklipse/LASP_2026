"""결정적 XSS baseline Analyzer의 control/probe와 워크플로 배선을 검증한다."""

from __future__ import annotations

import re
import unittest
from dataclasses import replace
from uuid import uuid4

from hacklipse.adapters import (
    HeuristicXssAnalyzer,
    RuleBasedVulnerabilityRouter,
    SurfaceRoutingRule,
)
from hacklipse.adapters.probing import PAYLOAD_CONTEXTS, payload_contexts
from hacklipse.adapters.xss_analysis import secondary_dom_attribute_sinks
from hacklipse.adapters.xss_execution import (
    _execution_payload, context_execution_marker,
)
from hacklipse.application.errors import AgentContractError
from hacklipse.ports.errors import BudgetExceeded
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Candidate,
    ExecutionRequest,
    ExecutionResult,
    HttpRequestKind,
    Run,
    RunPhase,
    RunRequest,
    RunScope,
    Surface,
    TaskEnvelope,
    ValidationResult,
    ValidationVerdict,
)

_RUN_ID = "run-1"
_SURFACE_ID = "surface-search"
_CANDIDATE_ID = "candidate-xss"


class _ReflectionRuntime:
    """probe query 값을 응답에 반사하거나 제거하는 결정적 Runtime 대역."""

    def __init__(self, *, reflect: bool, template: str = "{}") -> None:
        self.reflect = reflect
        self.template = template
        self.requests: list[ExecutionRequest] = []

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        values = " ".join(value for _, value in request.query_parameters)
        body = self.template.format(values) if self.reflect else "static response"
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response",
                "status": 200,
                "body": body,
                "requested_url": request.resolved_url,
            },
        )


def _task(*, parameters: tuple[str, ...], request_budget: int = 10) -> tuple:
    runtime = _ReflectionRuntime(reflect=True)
    app = build_local_application({}, runtime=runtime)
    run = Run(
        run_id=_RUN_ID,
        target_url="http://local.test/",
        scope=RunScope(allowed_hosts=frozenset({"local.test"})),
        policy_profile="safe",
        request_budget=10,
    )
    surface = Surface(
        surface_id=_SURFACE_ID,
        run_id=_RUN_ID,
        url="http://local.test/search",
        method="GET",
        parameters=parameters,
    )
    candidate = Candidate(
        candidate_id=_CANDIDATE_ID,
        run_id=_RUN_ID,
        surface_id=_SURFACE_ID,
        vulnerability_type="XSS",
        hypothesis="parameterized GET surface",
        assigned_agent="xss_analyzer",
        evidence_ids=(),
    )
    app.stores.runs.add(run)
    app.stores.surfaces.add(surface)
    app.stores.candidates.add(candidate)
    app.budget_manager.open_run(run.run_id, run.request_budget)
    agent = HeuristicXssAnalyzer(
        candidate_store=app.stores.candidates,
        surface_store=app.stores.surfaces,
        evidence_store=app.stores.evidence,
        id_factory=iter((str(index) for index in range(100))).__next__,
    )
    envelope = TaskEnvelope(
        task_id="task-xss",
        run_id=_RUN_ID,
        agent_type="xss_analyzer",
        target_url=surface.url,
        surface_id=surface.surface_id,
        candidate_id=candidate.candidate_id,
        allowed_tools=("http_get",),
        request_budget=request_budget,
    )
    return agent, app, runtime, envelope


def _collect_requested(agent_result, app, task: TaskEnvelope) -> TaskEnvelope:
    evidence_ids = []
    for request in agent_result.evidence_requests:
        evidence_ids.append(
            app.collector.collect(
                task.run_id,
                task.target_url or "",
                request,
                task_id=task.task_id,
            )
        )
    return replace(
        task,
        evidence_ids=tuple(evidence_ids),
        request_budget=app.budget_manager.remaining(task.run_id),
    )


class HeuristicXssAnalyzerTests(unittest.TestCase):
    def test_secondary_attribute_sink_requires_a_direct_html_assignment(self) -> None:
        self.assertEqual(secondary_dom_attribute_sinks(
            'out.innerHTML = DOMPurify.sanitize(raw); '
            'tip.innerHTML = el.getAttribute("data-note");'
        ), ("data-note",))
        self.assertEqual(secondary_dom_attribute_sinks(
            'tip.textContent = el.getAttribute("data-note");'
        ), ())

    def test_reflected_marker_creates_observation(self) -> None:
        agent, app, runtime, task = _task(parameters=("name",))

        requested = agent.handle(task)
        self.assertIs(requested.status, AgentResultStatus.NEEDS_EVIDENCE)
        self.assertEqual(runtime.requests, [])

        result = agent.handle(_collect_requested(requested, app, task))

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        self.assertEqual(
            [request.request_kind for request in runtime.requests],
            [HttpRequestKind.CONTROL, HttpRequestKind.PROBE],
        )
        self.assertEqual(
            runtime.requests[1].query_parameters,
            (("name", "hacklipse7331"),),
        )
        observations = [
            item
            for item in app.stores.evidence.list_by_run(_RUN_ID)
            if item.created_by == "heuristic_xss_analyzer"
        ]
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].observation["type"], "reflection")
        self.assertEqual(observations[0].observation["parameter"], "name")
        self.assertEqual(observations[0].observation["context_source"], "python")
        self.assertEqual(app.budget_manager.remaining(_RUN_ID), 8)

    def test_reflection_records_the_context_python_computed(self) -> None:
        agent, app, runtime, task = _task(parameters=("name",))
        runtime.template = '<script> var name = "{}"; </script>'

        requested = agent.handle(task)
        agent.handle(_collect_requested(requested, app, task))

        observation = next(
            item.observation for item in app.stores.evidence.list_by_run(_RUN_ID)
            if item.observation.get("type") == "reflection"
        )
        # 맥락은 LLM 주장이 아니라 Python이 본문에서 계산한 사실이어야 한다.
        # Validation이 이 값으로 고정 payload를 고른다.
        self.assertEqual(observation["payload_contexts"], ["js_string_double"])
        self.assertEqual(observation["context_source"], "python")

    def test_non_reflected_marker_keeps_only_http_evidence(self) -> None:
        agent, app, runtime, task = _task(parameters=("name",))
        runtime.reflect = False

        requested = agent.handle(task)
        result = agent.handle(_collect_requested(requested, app, task))

        self.assertEqual(result.new_evidence_ids, ())
        self.assertFalse(
            any(
                item.created_by == "heuristic_xss_analyzer"
                for item in app.stores.evidence.list_by_run(_RUN_ID)
            )
        )

    def test_each_parameter_gets_one_probe_after_shared_control(self) -> None:
        agent, app, runtime, task = _task(parameters=("first", "second"))

        requested = agent.handle(task)
        result = agent.handle(_collect_requested(requested, app, task))

        self.assertEqual(len(runtime.requests), 3)
        self.assertEqual(len(result.new_evidence_ids), 2)
        probes = runtime.requests[1:]
        self.assertEqual(
            probes[0].query_parameters,
            (("first", "hacklipse7331"), ("second", "hacklipse-control")),
        )
        self.assertEqual(
            probes[1].query_parameters,
            (("first", "hacklipse-control"), ("second", "hacklipse7331")),
        )
        observations = [
            item.observation["parameter"]
            for item in app.stores.evidence.list_by_run(_RUN_ID)
            if item.created_by == "heuristic_xss_analyzer"
        ]
        self.assertEqual(observations, ["first", "second"])

    def test_request_fingerprint_survives_sanitized_display_url(self) -> None:
        """민감 query 값이 마스킹돼도 Analyzer가 수집 Evidence를 재연결한다."""

        agent, app, _, task = _task(parameters=("csrf_token",))

        requested = agent.handle(task)
        collected_task = _collect_requested(requested, app, task)
        result = agent.handle(collected_task)

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        self.assertEqual(len(result.new_evidence_ids), 1)
        runtime_evidence = [
            item
            for item in app.stores.evidence.list_by_run(_RUN_ID)
            if item.created_by.startswith("execution_runtime:")
        ]
        self.assertTrue(
            all(item.observation.get("request_fingerprint") for item in runtime_evidence)
        )
        self.assertTrue(
            all(
                "%3Credacted%3E" in str(item.observation["requested_url"])
                for item in runtime_evidence
            )
        )

    def test_rejects_missing_tool_and_insufficient_task_budget_before_requests(self) -> None:
        agent, _, runtime, task = _task(parameters=("name",), request_budget=1)
        # 예산 부족은 계약 위반이 아니라 실행하지 못한 상태다. Orchestrator가 이 구분으로
        # 해당 Candidate만 skipped_budget으로 남기고 Run은 계속 진행한다.
        with self.assertRaises(BudgetExceeded):
            agent.handle(task)
        self.assertEqual(runtime.requests, [])

        task = TaskEnvelope(
            task_id=task.task_id,
            run_id=task.run_id,
            agent_type=task.agent_type,
            target_url=task.target_url,
            surface_id=task.surface_id,
            candidate_id=task.candidate_id,
            allowed_tools=(),
            request_budget=10,
        )
        with self.assertRaises(AgentContractError):
            agent.handle(task)
        self.assertEqual(runtime.requests, [])


class PayloadContextTests(unittest.TestCase):
    """반사 맥락은 Python이 본문에서 계산하는 사실이다. payload가 여기서 갈린다."""

    MARKER = "hacklipse7331"

    def _context(self, template: str) -> tuple[str, ...]:
        return payload_contexts(template.replace("{m}", self.MARKER), self.MARKER)

    def test_classifies_each_executable_context(self) -> None:
        cases = (
            ("<p>hello {m}</p>", ("html_text",)),
            ('<div class="box">{m}</div>', ("html_text",)),
            ('<input value="{m}">', ("attribute_double",)),
            ("<input value='{m}'>", ("attribute_single",)),
            ('<iframe src="{m}"></iframe>', ("uri_attribute",)),
            ("<form action='{m}'>", ("uri_attribute",)),
            ('<script> var name = "{m}"; </script>', ("js_string_double",)),
            ("<script> var name = '{m}'; </script>", ("js_string_single",)),
        )
        for template, expected in cases:
            with self.subTest(template=template):
                self.assertEqual(self._context(template), expected)
                for context in expected:
                    self.assertIn(context, PAYLOAD_CONTEXTS)

    def test_refuses_to_guess_a_context_it_cannot_break_out_of(self) -> None:
        # 분류하지 못한 자리는 payload를 고를 근거가 없다. 추측해서 보내지 않는다.
        for template in (
            "<script> var total = {m}; </script>",   # 문자열 리터럴이 아니다
            "<!-- {m} -->",                           # 주석 탈출은 지원하지 않는다
        ):
            with self.subTest(template=template):
                self.assertEqual(self._context(template), ())

    def test_script_quotes_do_not_leak_past_the_closing_tag(self) -> None:
        # </script> 뒤의 반사는 JS 문자열이 아니라 그냥 HTML 본문이다.
        self.assertEqual(
            self._context('<script> var a = "x"; </script> var b = "{m}"'),
            ("html_text",),
        )

    def test_reports_every_distinct_context_of_one_value(self) -> None:
        self.assertEqual(
            self._context('<input value="{m}"><p>{m}</p><iframe src="{m}">'),
            ("attribute_double", "html_text", "uri_attribute"),
        )

    def test_a_missing_or_absent_marker_has_no_context(self) -> None:
        self.assertEqual(payload_contexts(None, self.MARKER), ())
        self.assertEqual(payload_contexts("<p>nothing here</p>", self.MARKER), ())


class ContextPayloadTests(unittest.TestCase):
    """맥락별 payload는 코드에 고정된 형태이며 marker 대입만 한다."""

    CONTEXTS = (
        "js_string_double", "js_string_single", "uri_attribute",
        "attribute_double", "attribute_single",
    )

    def test_each_payload_only_assigns_the_marker(self) -> None:
        for context in self.CONTEXTS:
            with self.subTest(context=context):
                marker = context_execution_marker("validation-1", context)
                payload = _execution_payload(marker)
                self.assertIn(f"=`{marker}`", payload)
                # 외부 전송·임의 실행·DOM 변경 수단이 형태에 들어 있지 않다.
                for forbidden in (
                    "fetch", "XMLHttpRequest", "eval", "import", "document",
                    "cookie", "localStorage", "//http", "src=",
                ):
                    self.assertNotIn(forbidden, payload)

    def test_the_assignment_carries_no_dot_or_quote(self) -> None:
        # "URL처럼 보이지 않는 점 포함 토큰을 지운다"거나 따옴표를 지우는 필터가 흔하다.
        # 대입 자체가 그런 필터에 잘리면 맥락을 알아도 실행을 재현할 수 없다. 맥락을
        # 벗어나는 따옴표는 탈출 자체이므로 대입 부분만 본다.
        for context in self.CONTEXTS:
            with self.subTest(context=context):
                marker = context_execution_marker("validation-1", context)
                payload = _execution_payload(marker)
                start = payload.index("top[")
                assignment = payload[start:payload.index(f"=`{marker}`", start) + len(marker) + 3]
                self.assertNotIn(".", assignment)
                self.assertNotIn('"', assignment)
                self.assertNotIn("'", assignment)

    def test_an_unclassified_context_cannot_bind_a_payload(self) -> None:
        for context in ("unclassified", "html_text", "", "onerror"):
            with self.subTest(context=context):
                with self.assertRaises(ValueError):
                    context_execution_marker("validation-1", context)


class _SurfaceOnlyRecon:
    def __init__(self, surface_store) -> None:
        self._surfaces = surface_store

    def handle(self, task: TaskEnvelope) -> AgentResult:
        surface = Surface(
            surface_id=_SURFACE_ID,
            run_id=task.run_id,
            url="http://local.test/search",
            method="GET",
            parameters=("name",),
        )
        self._surfaces.add(surface)
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            surface_ids=(surface.surface_id,),
        )


class _RejectingValidator:
    def handle(self, task: TaskEnvelope) -> AgentResult:
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            validation=ValidationResult(
                validation_id=task.validation_id or "",
                run_id=task.run_id,
                candidate_id=task.candidate_id or "",
                verdict=ValidationVerdict.REJECTED,
                evidence_ids=(),
                reason="fixture stops before independent validation",
            ),
        )


class HeuristicXssWorkflowTests(unittest.TestCase):
    def test_surface_candidate_runs_through_baseline_analyzer(self) -> None:
        runtime = _ReflectionRuntime(reflect=True)
        router = RuleBasedVulnerabilityRouter(
            rules=(),
            surface_rules=(SurfaceRoutingRule("XSS", "xss_analyzer", priority=0.3),),
        )
        app = build_local_application({}, runtime=runtime, router=router)
        app.dispatcher.register(
            "recon",
            _SurfaceOnlyRecon(app.stores.surfaces),
            allowed_tools=("http_get",),
        )
        app.dispatcher.register(
            "xss_analyzer",
            HeuristicXssAnalyzer(
                candidate_store=app.stores.candidates,
                surface_store=app.stores.surfaces,
                evidence_store=app.stores.evidence,
            ),
            allowed_tools=("http_get",),
        )
        app.dispatcher.register(
            "validation",
            _RejectingValidator(),
            allowed_tools=("http_get",),
        )

        run = app.orchestrator.start(
            RunRequest(
                target_url="http://local.test/",
                scope=RunScope(allowed_hosts=frozenset({"local.test"})),
                request_budget=10,
            )
        )

        self.assertIs(run.phase, RunPhase.DONE)
        candidate = app.stores.candidates.list_by_run(run.run_id)[0]
        self.assertEqual(candidate.status, "rejected")
        self.assertTrue(
            any(
                item.observation.get("type") == "reflection"
                for item in app.stores.evidence.list_by_run(run.run_id)
            )
        )
        self.assertEqual(
            [item.envelope.agent_type for item in app.stores.tasks.list_by_run(run.run_id)],
            [
                "recon",
                "xss_analyzer",
                "evidence_collector",
                "evidence_collector",
                "xss_analyzer",
                "validation",
                "report",
            ],
        )


if __name__ == "__main__":
    unittest.main()


class ProbeMarkerSurvivesSanitizationTests(unittest.TestCase):
    """marker가 PII 마스킹에 삭제되면 반사를 놓치고 '취약하지 않음'으로 보고하게 된다.

    한때 _PHONE 정규식이 "1"로 시작하는 9자리 숫자열을 전부 전화번호로 보아 UUID 기반
    marker의 0.29%가 삭제됐다. 확률적 실패는 재현이 어렵고 조용해서 특히 위험하다.
    """

    def test_generated_markers_have_no_long_digit_runs(self) -> None:
        from hacklipse.adapters.probing import probe_marker

        for raw in ("d3cdc8ab-018c-4d91-864c-182698169bc0", "0" * 40, "1234567890" * 4):
            marker = probe_marker(raw)
            longest = max(
                (len(run) for run in re.findall(r"\d+", marker)), default=0
            )
            self.assertLessEqual(longest, 4, f"{marker}에 긴 숫자열이 남았다")

    def test_markers_survive_the_evidence_sanitizer(self) -> None:
        from hacklipse.adapters.security import SensitiveDataSanitizer
        from hacklipse.adapters.probing import probe_marker

        for index in range(3000):
            marker = probe_marker(str(uuid4()))
            body = f'<html><body><input value="{marker}"></body></html>'
            sanitized = SensitiveDataSanitizer._sanitize_text(body, ())
            self.assertIn(marker, sanitized, f"{index}번째 marker가 삭제됐다: {marker}")

    def test_rejects_a_source_with_no_usable_characters(self) -> None:
        from hacklipse.adapters.probing import probe_marker

        with self.assertRaises(AgentContractError):
            probe_marker("---")
