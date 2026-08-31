"""LlmXssAnalyzer가 LLM 출력을 신뢰 입력으로 쓰지 않는지 검증한다 (외부 API 호출 없음).

여기서 지키려는 계약은 다섯 가지다.
1. 사실은 Python이 정한다 — LLM이 반사를 주장해도 원문에 marker가 없으면 기각한다.
2. LLM은 값을 만들지 못한다 — 요청 쿼리에는 Python이 정한 marker/control 값만 실린다.
3. 계약 위반은 조용히 넘어가지 않는다 — 없는 파라미터, 모르는 맥락은 예외다.
4. 계획은 Evidence로 고정된다 — 두 번째 호출에서 같은 요청이 복원된다.
5. 프롬프트에 응답 본문 전체가 실리지 않는다.
"""

from __future__ import annotations

import os
import unittest
from dataclasses import replace

from hacklipse.adapters import HeuristicXssAnalyzer, LlmXssAnalyzer
from hacklipse.adapters.llm_xss_analysis import LLM_XSS_ANALYZER
from hacklipse.application.errors import AgentContractError
from hacklipse.bootstrap import API_KEY_ENV, build_llm_client_from_env, build_local_application
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
from hacklipse.ports.errors import LlmCredentialsMissing
from hacklipse.ports.llm import LlmRequest, LlmResponse

_RUN_ID = "run-1"
_SURFACE_ID = "surface-search"
_CANDIDATE_ID = "candidate-xss"


class _FakeLlmClient:
    """계획 요청과 해석 요청을 구분해 고정 응답을 돌려주는 대역."""

    def __init__(self, *, plan: dict, interpretation: dict | None = None) -> None:
        self._plan = plan
        self._interpretation = interpretation or {"reflections": []}
        self.requests: list[LlmRequest] = []

    def complete(self, request: LlmRequest) -> LlmResponse:
        self.requests.append(request)
        schema = request.response_schema or {}
        properties = schema.get("properties", {})
        payload = self._plan if "parameters" in properties else self._interpretation
        return LlmResponse(payload=payload, model="fake")


class _ReflectingRuntime:
    """probe 값을 지정한 템플릿에 끼워 반사하는 결정적 Runtime 대역."""

    def __init__(self, *, template: str = "<p>{values}</p>", reflect: bool = True) -> None:
        self.template = template
        self.reflect = reflect
        self.requests: list[ExecutionRequest] = []

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        values = " ".join(value for _, value in request.query_parameters)
        body = self.template.format(values=values) if self.reflect else "<p>static</p>"
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


def _fixture(
    *,
    llm: _FakeLlmClient,
    parameters: tuple[str, ...] = ("name",),
    request_budget: int = 10,
    runtime: _ReflectingRuntime | None = None,
):
    runtime = runtime or _ReflectingRuntime()
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
            url="http://local.test/search",
            method="GET",
            parameters=parameters,
        )
    )
    app.stores.candidates.add(
        Candidate(
            candidate_id=_CANDIDATE_ID,
            run_id=_RUN_ID,
            surface_id=_SURFACE_ID,
            vulnerability_type="XSS",
            hypothesis="parameterized GET surface",
            assigned_agent="llm_xss_analyzer",
            evidence_ids=(),
        )
    )
    app.budget_manager.open_run(_RUN_ID, 20)
    agent = LlmXssAnalyzer(
        llm_client=llm,
        candidate_store=app.stores.candidates,
        surface_store=app.stores.surfaces,
        evidence_store=app.stores.evidence,
        id_factory=iter(str(index) for index in range(100)).__next__,
    )
    task = TaskEnvelope(
        task_id="task-llm-xss",
        run_id=_RUN_ID,
        agent_type="llm_xss_analyzer",
        target_url="http://local.test/search",
        surface_id=_SURFACE_ID,
        candidate_id=_CANDIDATE_ID,
        allowed_tools=("http_get",),
        request_budget=request_budget,
    )
    return agent, app, runtime, task


def _collect(result, app, task: TaskEnvelope) -> TaskEnvelope:
    """Orchestrator를 대신해 요청을 중앙 수집하고 Evidence를 Task에 반영한다."""

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


class LlmXssAnalyzerTests(unittest.TestCase):
    # --- 1. 사실은 Python이 정한다 ---

    def test_reflection_claim_is_rejected_when_marker_is_absent(self) -> None:
        """LLM이 반사를 주장해도 원문에 marker가 없으면 Observation을 만들지 않는다."""

        llm = _FakeLlmClient(
            plan={"parameters": ["name"], "reason": "looks rendered"},
            interpretation={
                "reflections": [
                    {
                        "parameter": "name",
                        "context": "script_block",
                        "encoded": False,
                        "note": "확신에 찬 거짓 주장",
                    }
                ]
            },
        )
        runtime = _ReflectingRuntime(reflect=False)  # 서버가 값을 반사하지 않는다
        agent, app, _, task = _fixture(llm=llm, runtime=runtime)

        requested = agent.handle(task)
        result = agent.handle(_collect(requested, app, task))

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        reflections = [
            item
            for item in app.stores.evidence.list_by_run(_RUN_ID)
            if item.observation.get("type") == "reflection"
        ]
        self.assertEqual(reflections, [])

    def test_confirmed_reflection_carries_llm_context(self) -> None:
        llm = _FakeLlmClient(
            plan={"parameters": ["name"], "reason": "rendered into the page"},
            interpretation={
                "reflections": [
                    {
                        "parameter": "name",
                        "context": "html_attribute",
                        "encoded": False,
                        "note": "unquoted attribute value",
                    }
                ]
            },
        )
        agent, app, _, task = _fixture(
            llm=llm, runtime=_ReflectingRuntime(template='<a href="{values}">x</a>')
        )

        requested = agent.handle(task)
        result = agent.handle(_collect(requested, app, task))

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        reflections = [
            item
            for item in app.stores.evidence.list_by_run(_RUN_ID)
            if item.observation.get("type") == "reflection"
        ]
        self.assertEqual(len(reflections), 1)
        observation = reflections[0].observation
        self.assertEqual(observation["parameter"], "name")
        self.assertEqual(observation["context"], "html_attribute")
        self.assertIs(observation["encoded"], False)
        self.assertEqual(observation["context_source"], "llm")
        # 근거가 된 원본 두 개를 되짚을 수 있어야 한다.
        self.assertIn("control_evidence_id", observation)
        self.assertIn("probe_evidence_id", observation)

    def test_unclassified_when_llm_omits_a_confirmed_parameter(self) -> None:
        """Python이 확인한 반사는 LLM이 언급하지 않아도 사라지지 않는다."""

        llm = _FakeLlmClient(
            plan={"parameters": ["name"], "reason": "probe it"},
            interpretation={"reflections": []},
        )
        agent, app, _, task = _fixture(llm=llm)

        requested = agent.handle(task)
        agent.handle(_collect(requested, app, task))

        reflections = [
            item
            for item in app.stores.evidence.list_by_run(_RUN_ID)
            if item.observation.get("type") == "reflection"
        ]
        self.assertEqual(len(reflections), 1)
        self.assertEqual(reflections[0].observation["context"], "unclassified")

    # --- 2. LLM은 값을 만들지 못한다 ---

    def test_requests_carry_only_caller_controlled_values(self) -> None:
        llm = _FakeLlmClient(
            plan={"parameters": ["name", "q"], "reason": "both are rendered"}
        )
        agent, app, runtime, task = _fixture(llm=llm, parameters=("name", "q"))

        requested = agent.handle(task)
        _collect(requested, app, task)

        self.assertEqual(
            [request.request_kind for request in runtime.requests],
            [HttpRequestKind.CONTROL, HttpRequestKind.PROBE, HttpRequestKind.PROBE],
        )
        sent = {value for request in runtime.requests for _, value in request.query_parameters}
        marker = {value for value in sent if value != "hacklipse-control"}
        self.assertEqual(len(marker), 1)
        # marker는 Python이 만든 benign 문자열이다. 페이로드 문자가 실릴 자리가 없다.
        self.assertTrue(marker.pop().startswith("hacklipse"))
        for request in runtime.requests:
            self.assertEqual(request.method.upper(), "GET")
            self.assertEqual(request.headers, ())

    # --- 3. 계약 위반은 예외 ---

    def test_parameter_outside_the_surface_is_a_contract_error(self) -> None:
        llm = _FakeLlmClient(
            plan={"parameters": ["name", "admin_token"], "reason": "invented one"}
        )
        agent, _, runtime, task = _fixture(llm=llm)

        with self.assertRaises(AgentContractError):
            agent.handle(task)
        self.assertEqual(runtime.requests, [])

    def test_unknown_reflection_context_is_a_contract_error(self) -> None:
        llm = _FakeLlmClient(
            plan={"parameters": ["name"], "reason": "probe"},
            interpretation={
                "reflections": [
                    {
                        "parameter": "name",
                        "context": "definitely_exploitable",
                        "encoded": False,
                        "note": "",
                    }
                ]
            },
        )
        agent, app, _, task = _fixture(llm=llm)

        requested = agent.handle(task)
        with self.assertRaises(AgentContractError):
            agent.handle(_collect(requested, app, task))

    def test_non_list_plan_is_a_contract_error(self) -> None:
        llm = _FakeLlmClient(plan={"parameters": "name", "reason": "wrong shape"})
        agent, _, _, task = _fixture(llm=llm)

        with self.assertRaises(AgentContractError):
            agent.handle(task)

    def test_empty_selection_spends_no_requests(self) -> None:
        llm = _FakeLlmClient(plan={"parameters": [], "reason": "nothing is rendered"})
        agent, app, runtime, task = _fixture(llm=llm)

        result = agent.handle(task)

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        self.assertEqual(runtime.requests, [])
        self.assertEqual(app.budget_manager.remaining(_RUN_ID), 20)

    def test_budget_truncation_is_recorded_not_silent(self) -> None:
        llm = _FakeLlmClient(
            plan={"parameters": ["a", "b", "c"], "reason": "all three"}
        )
        # control 1 + probe N 이므로 예산 3이면 탐침은 2개까지다.
        agent, app, _, task = _fixture(
            llm=llm, parameters=("a", "b", "c"), request_budget=3
        )

        result = agent.handle(task)

        self.assertEqual(len(result.evidence_requests), 3)  # control + probe 2
        plan = next(
            item
            for item in app.stores.evidence.list_by_run(_RUN_ID)
            if item.observation.get("type") == "xss_probe_plan"
        )
        self.assertEqual(plan.observation["parameters"], ["a", "b"])
        self.assertEqual(plan.observation["dropped_for_budget"], ["c"])

    # --- 4. 계획은 Evidence로 고정된다 ---

    def test_plan_is_reused_instead_of_asked_twice(self) -> None:
        llm = _FakeLlmClient(
            plan={"parameters": ["name"], "reason": "probe"},
            interpretation={"reflections": []},
        )
        agent, app, _, task = _fixture(llm=llm)

        requested = agent.handle(task)
        plan_calls = len(llm.requests)
        agent.handle(_collect(requested, app, task))

        # 두 번째 호출은 계획을 다시 묻지 않고 해석만 요청한다.
        self.assertEqual(plan_calls, 1)
        self.assertEqual(len(llm.requests), 2)
        plans = [
            item
            for item in app.stores.evidence.list_by_run(_RUN_ID)
            if item.observation.get("type") == "xss_probe_plan"
        ]
        self.assertEqual(len(plans), 1)

    # --- 5. 프롬프트 위생 ---

    def test_prompt_carries_an_excerpt_not_the_whole_body(self) -> None:
        filler = "X" * 5000
        llm = _FakeLlmClient(
            plan={"parameters": ["name"], "reason": "probe"},
            interpretation={"reflections": []},
        )
        agent, app, _, task = _fixture(
            llm=llm,
            runtime=_ReflectingRuntime(template=filler + "<p>{values}</p>" + filler),
        )

        requested = agent.handle(task)
        agent.handle(_collect(requested, app, task))

        interpretation = llm.requests[-1]
        content = interpretation.messages[0].content
        self.assertLess(len(content), 1200)
        self.assertNotIn(filler, content)

    # --- 6. 대조군과의 비교 가능성 ---

    def test_emits_the_same_observation_type_as_the_heuristic_baseline(self) -> None:
        """Router와 집계가 두 구현을 같은 축에서 셀 수 있어야 한다."""

        llm = _FakeLlmClient(
            plan={"parameters": ["name"], "reason": "probe"},
            interpretation={
                "reflections": [
                    {"parameter": "name", "context": "html_text", "encoded": False, "note": ""}
                ]
            },
        )
        agent, app, _, task = _fixture(llm=llm)
        requested = agent.handle(task)
        agent.handle(_collect(requested, app, task))

        heuristic_app = build_local_application({}, runtime=_ReflectingRuntime())
        heuristic_app.stores.runs.add(app.stores.runs.get(_RUN_ID))
        heuristic_app.stores.surfaces.add(app.stores.surfaces.get(_RUN_ID, _SURFACE_ID))
        heuristic_app.stores.candidates.add(
            app.stores.candidates.get(_RUN_ID, _CANDIDATE_ID)
        )
        heuristic_app.budget_manager.open_run(_RUN_ID, 20)
        baseline = HeuristicXssAnalyzer(
            candidate_store=heuristic_app.stores.candidates,
            surface_store=heuristic_app.stores.surfaces,
            evidence_store=heuristic_app.stores.evidence,
        )
        baseline_requested = baseline.handle(task)
        baseline.handle(_collect(baseline_requested, heuristic_app, task))

        def observation_types(application) -> list[str]:
            return [
                str(item.observation.get("type"))
                for item in application.stores.evidence.list_by_run(_RUN_ID)
                if item.observation.get("type") == "reflection"
            ]

        self.assertEqual(observation_types(app), ["reflection"])
        self.assertEqual(observation_types(heuristic_app), ["reflection"])
        # 차이는 유형이 아니라 맥락 축의 유무다.
        llm_reflection = next(
            item
            for item in app.stores.evidence.list_by_run(_RUN_ID)
            if item.observation.get("type") == "reflection"
        )
        self.assertEqual(llm_reflection.created_by, LLM_XSS_ANALYZER)
        self.assertIn("context", llm_reflection.observation)


class LlmCredentialInjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = os.environ.get(API_KEY_ENV)

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop(API_KEY_ENV, None)
        else:
            os.environ[API_KEY_ENV] = self._saved

    def test_missing_key_fails_loudly_instead_of_disabling_the_llm(self) -> None:
        os.environ.pop(API_KEY_ENV, None)
        with self.assertRaises(LlmCredentialsMissing):
            build_llm_client_from_env()

    def test_blank_key_is_treated_as_missing(self) -> None:
        os.environ[API_KEY_ENV] = "   "
        with self.assertRaises(LlmCredentialsMissing):
            build_llm_client_from_env()

    def test_key_from_environment_builds_a_client_without_leaking(self) -> None:
        os.environ[API_KEY_ENV] = "sk-ant-test-env-do-not-leak-0123456789"
        client = build_llm_client_from_env(model="claude-sonnet-5")
        self.assertNotIn("do-not-leak", repr(client))

    def test_default_application_has_no_llm_wired(self) -> None:
        """LLM은 명시적으로 주입해야만 붙는다. 기본 조립은 LLM을 모른다."""

        app = build_local_application({})
        self.assertFalse(hasattr(app, "llm_client"))


if __name__ == "__main__":
    unittest.main()
