"""외부 네트워크 없이 전체 워크플로 연결을 검증하는 통합 테스트."""

from __future__ import annotations

import unittest

from hacklipse.adapters import RuleBasedVulnerabilityRouter
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Evidence,
    EvidenceRequest,
    ExecutionResult,
    RunPhase,
    RunRequest,
    RunScope,
    Surface,
    TaskEnvelope,
    TaskStatus,
    ValidationResult,
    ValidationVerdict,
)


class ReconFixtureAgent:
    """Reflection Observation 하나를 생성하는 로컬 Recon 대역."""

    def __init__(self, evidence_store, surface_store) -> None:
        self._evidence = evidence_store
        self._surfaces = surface_store

    def handle(self, task: TaskEnvelope) -> AgentResult:
        # 실제 HTTP 요청 대신 고정된 Surface와 Observation을 Evidence Store에 기록한다.
        evidence_id = f"evi-recon-{task.run_id}"
        self._surfaces.add(
            Surface(
                surface_id="surface-search",
                run_id=task.run_id,
                url="http://local.test/discovered-search",
                method="GET",
                parameters=("q",),
            )
        )
        self._evidence.append(
            Evidence(
                evidence_id=evidence_id,
                run_id=task.run_id,
                surface_id="surface-search",
                created_by="recon_fixture",
                evidence_type="observation",
                observation={"type": "reflection", "parameter": "q"},
            )
        )
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=(evidence_id,),
            surface_ids=("surface-search",),
        )


class XssAnalysisFixtureAgent:
    """Recon Evidence를 읽고 안전한 분석 Observation을 추가하는 대역."""

    def __init__(self, evidence_store) -> None:
        self._evidence = evidence_store

    def handle(self, task: TaskEnvelope) -> AgentResult:
        # Task에 전달된 Evidence ID가 현재 Run에서 실제로 조회되는지 먼저 확인한다.
        self._evidence.get_many(task.run_id, task.evidence_ids)
        evidence_id = f"evi-analysis-{task.task_id}"
        self._evidence.append(
            Evidence(
                evidence_id=evidence_id,
                run_id=task.run_id,
                surface_id=task.surface_id,
                created_by="xss_analysis_fixture",
                evidence_type="analysis_observation",
                observation={"type": "safe_marker_context", "context": "html_body"},
            )
        )
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=(evidence_id,),
            candidate_ids=(task.candidate_id,) if task.candidate_id else (),
        )


class ConfirmingValidationFixtureAgent:
    """현재 Evidence를 두 번 재현했다고 가정하는 확정 Validator 대역."""

    def handle(self, task: TaskEnvelope) -> AgentResult:
        assert task.candidate_id is not None
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            validation=ValidationResult(
                validation_id=f"validation-{task.task_id}",
                run_id=task.run_id,
                candidate_id=task.candidate_id,
                verdict=ValidationVerdict.CONFIRMED,
                evidence_ids=task.evidence_ids,
                reason="local fixture reproduced the observation",
                reproduction_count=2,
            ),
        )


class EvidenceSeekingValidationFixtureAgent:
    """첫 호출에는 추가 증적을 요구하고 두 번째 호출에 확정하는 대역."""

    def __init__(self) -> None:
        self.calls = 0

    def handle(self, task: TaskEnvelope) -> AgentResult:
        self.calls += 1
        assert task.candidate_id is not None
        if self.calls == 1:
            # Validator가 Runtime을 직접 호출하지 않고 EvidenceRequest만 반환하는지 검증한다.
            request = EvidenceRequest(
                evidence_type="browser_execution",
                surface_id=task.surface_id or "surface-search",
                reason="browser confirmation is required",
                suggested_tool="browser_render",
            )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=(request,),
            )
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            validation=ValidationResult(
                validation_id=f"validation-{task.task_id}",
                run_id=task.run_id,
                candidate_id=task.candidate_id,
                verdict=ValidationVerdict.CONFIRMED,
                evidence_ids=task.evidence_ids,
                reason="local runtime evidence confirmed the candidate",
                reproduction_count=1,
            ),
        )


class LocalFixtureRuntime:
    """네트워크 호출 없이 브라우저 실행 결과 형태만 반환하는 Runtime 대역."""

    def __init__(self) -> None:
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="browser_execution",
            observation={"type": "browser_marker_observed"},
            artifact_refs={"render": "fixture://render/result"},
        )


class EndToEndWorkflowTests(unittest.TestCase):
    """정상 흐름과 추가 증적 분기가 끝까지 연결되는지 검사한다."""

    def _application(self, *, validation_agent=None, runtime=None):
        """테스트마다 격리된 메모리 Application과 fixture Agent를 조립한다."""

        # 이 테스트는 기존 Reflection Evidence 경로 하나의 E2E만 검증한다.
        # Surface 기반 다중 Candidate 규칙은 tests/test_routing.py에서 별도로 고정한다.
        app = build_local_application(
            {},
            runtime=runtime,
            router=RuleBasedVulnerabilityRouter(surface_rules=()),
        )
        app.dispatcher.register(
            "recon", ReconFixtureAgent(app.stores.evidence, app.stores.surfaces)
        )
        app.dispatcher.register(
            "xss_analyzer", XssAnalysisFixtureAgent(app.stores.evidence)
        )
        app.dispatcher.register(
            "validation", validation_agent or ConfirmingValidationFixtureAgent()
        )
        return app

    @staticmethod
    def _request() -> RunRequest:
        """외부 대상이 아닌 가상 로컬 호스트 범위의 Run 요청을 만든다."""

        return RunRequest(
            target_url="http://local.test/search",
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            request_budget=10,
        )

    def test_confirmed_candidate_reaches_finding_and_report(self) -> None:
        """confirmed Candidate만 Finding과 보고서로 이어지는지 확인한다."""

        app = self._application()

        run = app.orchestrator.start(self._request())

        self.assertIs(run.phase, RunPhase.DONE)
        evidence = app.stores.evidence.list_by_run(run.run_id)
        candidates = app.stores.candidates.list_by_run(run.run_id)
        findings = app.stores.findings.list_by_run(run.run_id)
        reports = app.stores.reports.list_by_run(run.run_id)
        tasks = app.stores.tasks.list_by_run(run.run_id)
        self.assertEqual(len(evidence), 2)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].status, "confirmed")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "confirmed")
        self.assertEqual(len(reports), 1)
        self.assertIn(findings[0].finding_id, reports[0].content)
        self.assertEqual(
            [item.envelope.agent_type for item in tasks],
            ["recon", "xss_analyzer", "validation", "report"],
        )
        self.assertTrue(all(item.status is TaskStatus.SUCCEEDED for item in tasks))

    def test_evidence_request_returns_through_orchestrator_and_runtime_boundary(self) -> None:
        """추가 증적이 Orchestrator와 공통 Runtime 경계를 왕복하는지 확인한다."""

        validator = EvidenceSeekingValidationFixtureAgent()
        runtime = LocalFixtureRuntime()
        app = self._application(validation_agent=validator, runtime=runtime)

        run = app.orchestrator.start(self._request())

        evidence = app.stores.evidence.list_by_run(run.run_id)
        tasks = app.stores.tasks.list_by_run(run.run_id)
        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(validator.calls, 2)
        self.assertIn("browser_execution", {item.evidence_type for item in evidence})
        self.assertEqual(
            [item.envelope.agent_type for item in tasks],
            [
                "recon",
                "xss_analyzer",
                "validation",
                "evidence_collector",
                "validation",
                "report",
            ],
        )
        self.assertEqual(app.budget_manager.remaining(run.run_id), 9)
        self.assertEqual(
            [request.target_url for request in runtime.requests],
            ["http://local.test/discovered-search"],
        )


if __name__ == "__main__":
    unittest.main()
