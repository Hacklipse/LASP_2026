"""확정 Finding이 Knowledge Plane으로 발행되는 배선의 계약 테스트.

Phase 9-A 는 저장 Core 만 만들었고 어떤 Run 도 KnowledgeBase 를 부르지 않았다.
여기서 고정하는 것은 세 가지다 - 확정 Finding 만 발행된다, KnowledgeBase 를 주지
않으면 아무 일도 일어나지 않는다, 그리고 발행이 실패해도 완주한 Run 을 되돌리지 않는다.
"""

from __future__ import annotations

import unittest

from hacklipse.adapters import InMemoryKnowledgeBase, RuleBasedVulnerabilityRouter
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Evidence,
    EvidenceRequest,
    HttpRequestKind,
    HttpRequestSpec,
    KnowledgeCase,
    KnowledgeQuery,
    ProgressEventKind,
    RunPhase,
    RunRequest,
    RunScope,
    Surface,
    TaskEnvelope,
    ValidationProof,
    ValidationProofType,
    ValidationResult,
    ValidationVerdict,
)

_TARGET = "http://local.test/search"


class _ReconFixture:
    """Reflection Observation 하나와 Surface 하나만 만드는 대역."""

    def __init__(self, evidence_store, surface_store) -> None:
        self._evidence = evidence_store
        self._surfaces = surface_store

    def handle(self, task: TaskEnvelope) -> AgentResult:
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


class _AnalysisFixture:
    def __init__(self, evidence_store) -> None:
        self._evidence = evidence_store

    def handle(self, task: TaskEnvelope) -> AgentResult:
        evidence_id = f"evi-analysis-{task.task_id}"
        self._evidence.append(
            Evidence(
                evidence_id=evidence_id,
                run_id=task.run_id,
                surface_id=task.surface_id,
                created_by="analysis_fixture",
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


class _ConfirmingValidationFixture:
    """독립 세션 증적을 한 번 요청한 뒤 proof 와 함께 확정하는 대역."""

    def __init__(self) -> None:
        self.calls = 0

    def handle(self, task: TaskEnvelope) -> AgentResult:
        self.calls += 1
        assert task.candidate_id is not None
        if self.calls == 1:
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=(
                    EvidenceRequest(
                        evidence_type="http_response",
                        surface_id=task.surface_id or "surface-search",
                        reason="independent reproduction of the reflected parameter",
                        suggested_tool="http_get",
                        http_request=HttpRequestSpec(
                            method="GET",
                            query_parameters=(("q", "hacklipse7331"),),
                            request_kind=HttpRequestKind.PROBE,
                        ),
                    ),
                ),
            )
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            validation=ValidationResult(
                validation_id=task.validation_id or "",
                run_id=task.run_id,
                candidate_id=task.candidate_id,
                verdict=ValidationVerdict.CONFIRMED,
                evidence_ids=(task.evidence_ids[-1],),
                reason="fixture reproduced the execution signal independently",
                reproduction_count=1,
                proof=ValidationProof(
                    proof_type=ValidationProofType.XSS_EXECUTION,
                    evidence_ids=(task.evidence_ids[-1],),
                    summary="fixture observed the expected XSS execution signal",
                ),
            ),
        )


class _LocalRuntime:
    def execute(self, request):
        from hacklipse.domain import ExecutionResult

        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response",
                "status": 200,
                "method": "GET",
                "requested_url": request.resolved_url,
                "request_kind": request.request_kind.value,
                "body": "<p>hacklipse7331</p>",
            },
        )


class _FailingKnowledgeBase:
    """발행이 항상 실패하는 저장소. Run 결과가 뒤집히면 안 된다."""

    def __init__(self) -> None:
        self.attempts = 0

    def publish(self, case: KnowledgeCase) -> None:
        self.attempts += 1
        raise RuntimeError("knowledge storage is unavailable")

    def search(self, query: KnowledgeQuery):
        return ()


def _application(knowledge_base=None):
    app = build_local_application(
        {},
        runtime=_LocalRuntime(),
        router=RuleBasedVulnerabilityRouter(surface_rules=()),
        knowledge_base=knowledge_base,
    )
    app.dispatcher.register(
        "recon",
        _ReconFixture(app.stores.evidence, app.stores.surfaces),
        allowed_tools=("http_get",),
    )
    app.dispatcher.register(
        "xss_analyzer", _AnalysisFixture(app.stores.evidence), allowed_tools=("http_get",)
    )
    app.dispatcher.register(
        "validation", _ConfirmingValidationFixture(), allowed_tools=("http_get",)
    )
    return app


def _request() -> RunRequest:
    return RunRequest(
        target_url=_TARGET,
        scope=RunScope(allowed_hosts=frozenset({"local.test"})),
        request_budget=10,
    )


class KnowledgePublicationTests(unittest.TestCase):
    def test_confirmed_finding_becomes_a_knowledge_case(self) -> None:
        knowledge = InMemoryKnowledgeBase()
        app = _application(knowledge)

        run = app.orchestrator.start(_request())

        self.assertIs(run.phase, RunPhase.DONE)
        findings = app.stores.findings.list_by_run(run.run_id)
        self.assertEqual(len(findings), 1)

        cases = knowledge.search(KnowledgeQuery(category="XSS", text=""))
        self.assertEqual(len(cases), 1)
        case = cases[0]
        self.assertEqual(case.category, "XSS")
        self.assertIn(f"run:{run.run_id}", case.provenance_refs)
        self.assertIn(f"finding:{findings[0].finding_id}", case.provenance_refs)
        self.assertEqual(case.metadata["proof_type"], "xss_execution")

    def test_case_carries_no_target_specific_values(self) -> None:
        """Knowledge Plane 은 재사용 지식만 담는다. 대상 고유 정보는 남지 않는다."""

        knowledge = InMemoryKnowledgeBase()
        app = _application(knowledge)

        run = app.orchestrator.start(_request())
        case = knowledge.search(KnowledgeQuery(category="XSS", text=""))[0]

        blob = " ".join((case.summary, *case.metadata.values()))
        self.assertNotIn("local.test", blob)
        self.assertNotIn("hacklipse7331", blob)
        self.assertNotIn(run.run_id, blob)

    def test_without_a_knowledge_base_nothing_is_published(self) -> None:
        app = _application(None)

        run = app.orchestrator.start(_request())

        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(len(app.stores.findings.list_by_run(run.run_id)), 1)

    def test_publication_failure_does_not_revert_a_completed_run(self) -> None:
        failing = _FailingKnowledgeBase()
        app = _application(failing)

        run = app.orchestrator.start(_request())

        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(failing.attempts, 1)
        self.assertEqual(len(app.stores.findings.list_by_run(run.run_id)), 1)
        self.assertTrue(app.stores.reports.list_by_run(run.run_id))

    def test_skipped_publication_is_reported_on_the_completion_event(self) -> None:
        """조용히 사라지면 무엇이 축적되지 않았는지 알 수 없다."""

        app = _application(_FailingKnowledgeBase())

        run = app.orchestrator.start(_request())

        completed = [
            event
            for event in app.progress_log.list_by_run(run.run_id)
            if event.kind is ProgressEventKind.RUN_COMPLETED
        ]
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0].detail, "knowledge publication skipped: 1")

    def test_successful_publication_leaves_the_completion_event_clean(self) -> None:
        app = _application(InMemoryKnowledgeBase())

        run = app.orchestrator.start(_request())

        completed = [
            event
            for event in app.progress_log.list_by_run(run.run_id)
            if event.kind is ProgressEventKind.RUN_COMPLETED
        ]
        self.assertIsNone(completed[0].detail)


if __name__ == "__main__":
    unittest.main()
