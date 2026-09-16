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
from hacklipse.adapters.path_traversal_analysis import (
    PATH_TRAVERSAL_PROBE_PATH,
    PATH_TRAVERSAL_PROOF_MARKERS,
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


class _SqliDifferentialRuntime:
    """id probe의 작은따옴표에만 SQL 오류를 반환한다."""

    def __init__(self) -> None:
        self.requests: list[ExecutionRequest] = []

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        parameters = dict(request.query_parameters)
        body = "normal database result"
        if "Submit" in parameters and parameters.get("id", "").endswith("'"):
            body = "You have an error in your SQL syntax"
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


class _PathTraversalSafeFileRuntime:
    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        values = dict(request.query_parameters).values()
        body = (
            "\n".join(PATH_TRAVERSAL_PROOF_MARKERS)
            if PATH_TRAVERSAL_PROBE_PATH in values
            else "normal include response"
        )
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={"type": "http_response", "status": 200, "body": body},
        )


class _FakeLlmClient:
    def __init__(self) -> None:
        self.calls: list[LlmRequest] = []

    def complete(self, request: LlmRequest) -> LlmResponse:
        self.calls.append(request)
        properties = (request.response_schema or {}).get("properties", {})
        if "outcome_class" in properties:
            return LlmResponse(
                payload={
                    "outcome_class": "signal_not_observed",
                    "reason": "이번 session의 재현 요청에서 취약점 신호를 관측하지 못함",
                },
                model="fake",
            )
        if "reflections" in properties:
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
        elif "server-side file path" in (request.system or ""):
            payload = {"parameters": ["page"], "reason": "file include input"}
        elif "SQL parser reachability" in (request.system or ""):
            content = "\n".join(message.content for message in request.messages)
            selected = "id" if "Parameters: id" in content else "q"
            payload = {"parameters": [selected], "reason": "likely lookup input"}
        else:
            payload = {"parameters": ["q"], "reason": "value is rendered into the page"}
        return LlmResponse(payload=payload, model="fake")


def _run(*, llm_client=None, validation_review=False):
    runtime = _ReflectingRuntime()
    app = build_local_application({}, runtime=runtime, router=standard_router())
    profile = register_standard_agents(
        app, llm_client=llm_client, validation_review=validation_review
    )
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
                "sqli_analyzer",
                "evidence_collector",
                "evidence_collector",
                "sqli_analyzer",
                "validation",
                "evidence_collector",
                "validation",
                "validation",
                "report",
            ],
        )
        # XSS 계획·해석 각 1회 + SQLi 계획 1회. 재호출은 계획을 다시 묻지 않는다.
        self.assertEqual(len(llm.calls), 3)
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

    def test_validation_review_claim_reaches_the_run_without_touching_the_verdict(self) -> None:
        """Review Claim은 Run Evidence로만 병합되고 판정·재현·외부 요청을 건드리지 않는다."""

        plain_app, plain_run, plain_runtime, _ = _run(llm_client=_FakeLlmClient())
        app, run, runtime, _ = _run(llm_client=_FakeLlmClient(), validation_review=True)

        claims = [
            item
            for item in app.stores.evidence.list_by_run(run.run_id)
            if item.observation.get("type") == "llm_validation_review"
        ]
        self.assertTrue(claims, "비확정 Validation마다 Review Claim이 남는다")
        for claim in claims:
            self.assertEqual(claim.evidence_type, "claim")
            self.assertEqual(claim.created_by, "llm_validation_reviewer")
            self.assertIn(claim.evidence_id, run.evidence_ids)
            # Claim은 proof가 아니다 — 재현 Evidence로도 Candidate 근거로도 새지 않는다.
            for candidate in app.stores.candidates.list_by_run(run.run_id):
                self.assertNotIn(claim.evidence_id, candidate.evidence_ids)

        # Reviewer가 붙어도 결정적 판정과 중앙 실행 요청은 그대로다.
        self.assertEqual(
            [i.envelope.agent_type for i in app.stores.tasks.list_by_run(run.run_id)],
            [i.envelope.agent_type for i in plain_app.stores.tasks.list_by_run(plain_run.run_id)],
        )
        self.assertEqual(len(runtime.requests), len(plain_runtime.requests))
        self.assertEqual(
            app.stores.findings.list_by_run(run.run_id),
            plain_app.stores.findings.list_by_run(plain_run.run_id),
        )

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
        # 구현된 Analyzer가 담당하는 유형만 나온다. SSTI·Path Traversal은 Router 규칙이
        # 있어도 Analyzer가 없으므로 Candidate 자체가 만들어지지 않는다.
        self.assertEqual(types, {"XSS", "SQLi"})

    def test_llm_sqli_reaches_independent_proof_and_finding(self) -> None:
        """LLM 선택 뒤에도 Validation이 독립 요청으로 SQLi를 재현해야 확정한다."""

        llm = _FakeLlmClient()
        runtime = _SqliDifferentialRuntime()
        app = build_local_application(
            {},
            runtime=runtime,
            router=standard_router(vulnerability_types=("SQLi",)),
        )
        register_standard_agents(app, llm_client=llm, recon_max_pages=1)

        run = app.orchestrator.start(
            RunRequest(
                target_url=(
                    "http://local.test/vulnerabilities/sqli/?id=1&Submit=Submit"
                ),
                scope=RunScope(allowed_hosts=frozenset({_HOST})),
                request_budget=30,
            )
        )

        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(len(llm.calls), 1)
        findings = app.stores.findings.list_by_run(run.run_id)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vulnerability_type, "SQLi")
        signal = next(
            item
            for item in app.stores.evidence.list_by_run(run.run_id)
            if item.observation.get("type") == "sql_error"
        )
        self.assertEqual(signal.created_by, "llm_sqli_analyzer")
        proof_evidence = app.stores.evidence.get_many(
            run.run_id, findings[0].evidence_ids
        )
        self.assertTrue(
            all(item.validation_id == findings[0].validation_id for item in proof_evidence)
        )

    def test_llm_path_traversal_reaches_independent_proof_and_finding(self) -> None:
        llm = _FakeLlmClient()
        app = build_local_application(
            {},
            runtime=_PathTraversalSafeFileRuntime(),
            router=standard_router(vulnerability_types=("Path Traversal",)),
        )
        register_standard_agents(app, llm_client=llm, recon_max_pages=1)

        run = app.orchestrator.start(
            RunRequest(
                target_url=(
                    "http://local.test/vulnerabilities/fi/?page=include.php"
                ),
                scope=RunScope(allowed_hosts=frozenset({_HOST})),
                request_budget=20,
            )
        )

        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(len(llm.calls), 1)
        findings = app.stores.findings.list_by_run(run.run_id)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vulnerability_type, "Path Traversal")
        signal = next(
            item
            for item in app.stores.evidence.list_by_run(run.run_id)
            if item.observation.get("type") == "path_traversal_file_read"
        )
        self.assertEqual(signal.created_by, "llm_path_traversal_analyzer")


if __name__ == "__main__":
    unittest.main()
