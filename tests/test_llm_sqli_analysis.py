"""LLM SQLi Agent의 선택권과 실행 권한이 분리되어 있는지 검증한다.

외부 API는 호출하지 않는다. FakeLlmClient는 파라미터 이름만 반환하고, 실제 요청 값과
SQL 오류 신호는 Python이 결정한다.
"""

from __future__ import annotations

import unittest
from dataclasses import replace

from hacklipse.adapters import LlmSqliAnalyzer
from hacklipse.adapters.llm_sqli_analysis import LLM_SQLI_ANALYZER
from hacklipse.application.errors import AgentContractError
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    AgentResultStatus,
    Candidate,
    ExecutionRequest,
    ExecutionResult,
    HttpRequestKind,
    Run,
    RunScope,
    Surface,
    TaskEnvelope,
)
from hacklipse.ports.llm import LlmRequest, LlmResponse

_RUN_ID = "run-llm-sqli"
_SURFACE_ID = "surface-items"
_CANDIDATE_ID = "candidate-sqli"


class _FakeLlmClient:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload
        self.requests: list[LlmRequest] = []

    def complete(self, request: LlmRequest) -> LlmResponse:
        self.requests.append(request)
        return LlmResponse(payload=self.payload, model="fake")


class _SqlRuntime:
    """작은따옴표가 들어온 probe에만 지정된 SQL 오류 차이를 만든다."""

    def __init__(self, *, mode: str = "error_message") -> None:
        self.mode = mode
        self.requests: list[ExecutionRequest] = []

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        injected = any(value.endswith("'") for _, value in request.query_parameters)
        status, body = 200, "normal database result"
        if self.mode == "error_message" and injected:
            body = "You have an error in your SQL syntax"
        elif self.mode == "status_differential" and injected:
            status, body = 500, "internal error"
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
    payload: dict[str, object],
    parameters: tuple[str, ...] = ("id", "Submit"),
    request_budget: int = 10,
    mode: str = "error_message",
):
    llm = _FakeLlmClient(payload)
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
            method="GET",
            parameters=parameters,
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
    agent = LlmSqliAnalyzer(
        llm_client=llm,
        candidate_store=app.stores.candidates,
        surface_store=app.stores.surfaces,
        evidence_store=app.stores.evidence,
        id_factory=iter(str(index) for index in range(100)).__next__,
    )
    task = TaskEnvelope(
        task_id="task-llm-sqli",
        run_id=_RUN_ID,
        agent_type="sqli_analyzer",
        target_url="http://local.test/items",
        surface_id=_SURFACE_ID,
        candidate_id=_CANDIDATE_ID,
        allowed_tools=("http_get",),
        request_budget=request_budget,
    )
    return agent, app, llm, runtime, task


def _collect(result, app, task: TaskEnvelope) -> TaskEnvelope:
    evidence_ids = list(task.evidence_ids) + list(result.new_evidence_ids)
    for request in result.evidence_requests:
        evidence_ids.append(
            app.collector.collect(
                task.run_id, task.target_url or "", request, task_id=task.task_id
            )
        )
    return replace(
        task,
        evidence_ids=tuple(evidence_ids),
        request_budget=app.budget_manager.remaining(task.run_id),
    )


def _signals(app):
    return [
        item
        for item in app.stores.evidence.list_by_run(_RUN_ID)
        if item.observation.get("type") == "sql_error"
    ]


class LlmSqliAnalyzerTests(unittest.TestCase):
    def test_llm_selects_names_but_python_owns_request_values(self) -> None:
        agent, app, llm, runtime, task = _fixture(
            payload={"parameters": ["id"], "reason": "identifier lookup"}
        )

        requested = agent.handle(task)
        self.assertIs(requested.status, AgentResultStatus.NEEDS_EVIDENCE)
        _collect(requested, app, task)

        self.assertEqual(len(llm.requests), 1)
        self.assertEqual(
            [request.request_kind for request in runtime.requests],
            [HttpRequestKind.CONTROL, HttpRequestKind.PROBE],
        )
        control = dict(runtime.requests[0].query_parameters)
        probe = dict(runtime.requests[1].query_parameters)
        self.assertEqual(probe["id"], control["id"] + "'")
        self.assertEqual(probe["Submit"], control["Submit"])
        self.assertTrue(control["id"].startswith("hacklipse"))
        self.assertNotIn("identifier lookup", probe.values())

    def test_python_error_differential_emits_compatible_signal(self) -> None:
        agent, app, _, _, task = _fixture(
            payload={"parameters": ["id"], "reason": "identifier lookup"}
        )

        requested = agent.handle(task)
        result = agent.handle(_collect(requested, app, task))

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        signals = _signals(app)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].created_by, LLM_SQLI_ANALYZER)
        observation = signals[0].observation
        self.assertEqual(observation["parameter"], "id")
        self.assertEqual(observation["signal"], "error_message")
        self.assertEqual(observation["engine"], "mysql")
        self.assertEqual(observation["selection_source"], "llm")
        self.assertIn("control_evidence_id", observation)
        self.assertIn("probe_evidence_id", observation)
        self.assertIn("plan_evidence_id", observation)

    def test_llm_selection_cannot_invent_a_sql_error(self) -> None:
        agent, app, _, _, task = _fixture(
            payload={"parameters": ["id"], "reason": "definitely vulnerable"},
            mode="safe",
        )

        requested = agent.handle(task)
        result = agent.handle(_collect(requested, app, task))

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        self.assertEqual(_signals(app), [])

    def test_parameter_outside_surface_is_a_contract_error(self) -> None:
        agent, _, _, runtime, task = _fixture(
            payload={"parameters": ["password"], "reason": "invented"}
        )

        with self.assertRaises(AgentContractError):
            agent.handle(task)
        self.assertEqual(runtime.requests, [])

    def test_plan_is_reused_without_a_second_llm_call(self) -> None:
        agent, app, llm, _, task = _fixture(
            payload={"parameters": ["id"], "reason": "identifier lookup"}
        )

        requested = agent.handle(task)
        agent.handle(_collect(requested, app, task))

        self.assertEqual(len(llm.requests), 1)
        plans = [
            item
            for item in app.stores.evidence.list_by_run(_RUN_ID)
            if item.observation.get("type") == "sqli_probe_plan"
        ]
        self.assertEqual(len(plans), 1)

    def test_empty_selection_spends_no_http_requests(self) -> None:
        agent, app, llm, runtime, task = _fixture(
            payload={"parameters": [], "reason": "no database-like input"}
        )

        result = agent.handle(task)

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        self.assertEqual(len(llm.requests), 1)
        self.assertEqual(runtime.requests, [])
        self.assertEqual(app.budget_manager.remaining(_RUN_ID), 20)

    def test_budget_truncation_is_recorded(self) -> None:
        agent, app, _, _, task = _fixture(
            payload={"parameters": ["id", "sort", "page"], "reason": "database inputs"},
            parameters=("id", "sort", "page"),
            request_budget=3,
        )

        result = agent.handle(task)

        self.assertEqual(len(result.evidence_requests), 3)
        plan = next(
            item
            for item in app.stores.evidence.list_by_run(_RUN_ID)
            if item.observation.get("type") == "sqli_probe_plan"
        )
        self.assertEqual(plan.observation["parameters"], ["id", "sort"])
        self.assertEqual(plan.observation["dropped_for_budget"], ["page"])

    def test_non_string_reason_is_a_contract_error(self) -> None:
        agent, _, _, runtime, task = _fixture(
            payload={"parameters": ["id"], "reason": ["not", "text"]}
        )

        with self.assertRaises(AgentContractError):
            agent.handle(task)
        self.assertEqual(runtime.requests, [])


if __name__ == "__main__":
    unittest.main()
