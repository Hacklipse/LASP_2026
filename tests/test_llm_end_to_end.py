"""표준 배선이 LLM Agent를 끼고 RECON→REPORT까지 도는지 결정적으로 검증한다.

가짜 LlmClient를 쓰므로 외부 API 호출도 비용도 없다. 여기서 확인하는 것은 LLM의 판단
품질이 아니라 배선이다 — Dispatcher 등록, NEEDS_EVIDENCE 루프, 예산 계산, 두 구성의
Task 순서가 같은지.
"""

from __future__ import annotations

import unittest

from hacklipse.bootstrap import (
    build_local_application,
    register_standard_agents,
    standard_router,
)
from hacklipse.domain import ExecutionRequest, ExecutionResult, RunPhase, RunRequest, RunScope
from hacklipse.ports.llm import LlmRequest, LlmResponse

_HOST = "local.test"
_TARGET = f"http://{_HOST}/search?q=seed"


class _ReflectingRuntime:
    """루트 응답에 파라미터 있는 링크를 하나 노출하고, 쿼리 값을 본문에 반사한다."""

    def __init__(self) -> None:
        self.requests: list[ExecutionRequest] = []

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        values = " ".join(value for _, value in request.query_parameters)
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response",
                "status": 200,
                "body": f'<html><body><input value="{values}"></body></html>',
                "requested_url": request.resolved_url,
            },
        )


class _FakeLlmClient:
    def __init__(self) -> None:
        self.calls: list[LlmRequest] = []

    def complete(self, request: LlmRequest) -> LlmResponse:
        self.calls.append(request)
        properties = (request.response_schema or {}).get("properties", {})
        if "parameters" in properties:
            payload = {"parameters": ["q"], "reason": "value is rendered into the page"}
        else:
            payload = {
                "reflections": [
                    {
                        "parameter": "q",
                        "context": "html_attribute",
                        "encoded": False,
                        "note": "quoted attribute value",
                    }
                ]
            }
        return LlmResponse(payload=payload, model="fake")


def _run(*, llm_client=None):
    runtime = _ReflectingRuntime()
    app = build_local_application({}, runtime=runtime, router=standard_router())
    profile = register_standard_agents(app, llm_client=llm_client)
    run = app.orchestrator.start(
        RunRequest(
            target_url=_TARGET,
            scope=RunScope(allowed_hosts=frozenset({_HOST})),
            request_budget=20,
        )
    )
    return app, run, runtime, profile


def _reflections(app, run):
    return [
        item
        for item in app.stores.evidence.list_by_run(run.run_id)
        if item.observation.get("type") == "reflection"
    ]


class LlmWiringEndToEndTests(unittest.TestCase):
    def test_llm_profile_runs_the_full_workflow(self) -> None:
        llm = _FakeLlmClient()
        app, run, runtime, profile = _run(llm_client=llm)

        self.assertEqual(profile, "llm")
        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(
            [item.envelope.agent_type for item in app.stores.tasks.list_by_run(run.run_id)],
            [
                "recon",
                "xss_analyzer",
                "evidence_collector",
                "evidence_collector",
                "xss_analyzer",
                "validation",
                "evidence_collector",
                "validation",
                "report",
            ],
        )
        # 계획 1회 + 해석 1회. 두 번째 analyzer 호출은 계획을 다시 묻지 않는다.
        self.assertEqual(len(llm.calls), 2)
        # Agent는 실행하지 않는다 — 요청은 전부 중앙 Collector를 거친 것이어야 한다.
        self.assertTrue(
            all(request.task_id for request in runtime.requests), "모든 요청에 발신 Task가 있다"
        )

        reflections = _reflections(app, run)
        self.assertEqual(len(reflections), 1)
        self.assertEqual(reflections[0].observation["context"], "html_attribute")
        self.assertEqual(reflections[0].observation["context_source"], "llm")

    def test_heuristic_profile_produces_the_same_task_sequence(self) -> None:
        """대조군과 실험군이 같은 워크플로를 돈다 — 차이는 판단이지 배선이 아니다."""

        llm_app, llm_run, _, _ = _run(llm_client=_FakeLlmClient())
        base_app, base_run, _, profile = _run()

        self.assertEqual(profile, "heuristic")
        self.assertEqual(
            [i.envelope.agent_type for i in base_app.stores.tasks.list_by_run(base_run.run_id)],
            [i.envelope.agent_type for i in llm_app.stores.tasks.list_by_run(llm_run.run_id)],
        )
        # 두 구성 모두 같은 Observation 유형을 만들어 같은 축에서 셀 수 있다.
        self.assertEqual(len(_reflections(base_app, base_run)), 1)
        self.assertEqual(len(_reflections(llm_app, llm_run)), 1)
        # 맥락 축은 LLM 구성에만 있다.
        self.assertNotIn("context", _reflections(base_app, base_run)[0].observation)
        self.assertIn("context", _reflections(llm_app, llm_run)[0].observation)

    def test_no_finding_without_a_validation_proof(self) -> None:
        """반사를 찾아도 proof가 없으면 Finding으로 승격되지 않는다(마일스톤 A 성질)."""

        app, run, _, _ = _run(llm_client=_FakeLlmClient())

        self.assertEqual(app.stores.findings.list_by_run(run.run_id), ())
        candidate = app.stores.candidates.list_by_run(run.run_id)[0]
        self.assertEqual(candidate.status, "suspected")

    def test_router_only_creates_candidates_for_implemented_analyzers(self) -> None:
        """미구현 취약점 유형은 조용히 건너뛰지 않고 Candidate 자체를 만들지 않는다."""

        app, run, _, _ = _run(llm_client=_FakeLlmClient())

        types = {c.vulnerability_type for c in app.stores.candidates.list_by_run(run.run_id)}
        self.assertEqual(types, {"XSS"})


if __name__ == "__main__":
    unittest.main()
