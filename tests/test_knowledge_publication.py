"""확정 Finding이 Knowledge Plane으로 발행되는 배선의 계약 테스트.

Phase 9-A 는 저장 Core 만 만들었고 어떤 Run 도 KnowledgeBase 를 부르지 않았다.
여기서 고정하는 것은 세 가지다 - 확정 Finding 만 발행된다, KnowledgeBase 를 주지
않으면 아무 일도 일어나지 않는다, 그리고 발행이 실패해도 완주한 Run 을 되돌리지 않는다.
"""

from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from hacklipse.adapters import InMemoryKnowledgeBase, RuleBasedVulnerabilityRouter
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    AgentResult,
    ProgressEvent,
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


class _FlakyKnowledgeBase:
    """처음 N번은 실패하고 그 뒤로는 정상 저장하는 대역.

    SQLite 잠금처럼 일시적인 저장 오류를 흉내 낸다. 재개가 실패분만 이어서
    발행하는지, 그리고 이미 발행된 Case 가 중복되지 않는지 본다.
    """

    def __init__(self, fail_times: int) -> None:
        self._left = fail_times
        self._base = InMemoryKnowledgeBase()
        self.attempts = 0

    def publish(self, case: KnowledgeCase) -> None:
        self.attempts += 1
        if self._left > 0:
            self._left -= 1
            raise RuntimeError("knowledge storage is locked")
        self._base.publish(case)

    def search(self, query: KnowledgeQuery):
        return self._base.search(query)


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
        # 발행을 켠 Run 은 성공해도 수치를 남긴다. 0/1 이면 한 건도 못 쌓았다는 뜻이다.
        self.assertEqual(completed[0].detail, "knowledge 0/1")

    def test_successful_publication_is_also_reported(self) -> None:
        """\"0건 발행\"과 \"발행을 안 켬\"이 화면에서 구분돼야 한다."""

        app = _application(InMemoryKnowledgeBase())

        run = app.orchestrator.start(_request())

        completed = [
            event
            for event in app.progress_log.list_by_run(run.run_id)
            if event.kind is ProgressEventKind.RUN_COMPLETED
        ]
        self.assertEqual(completed[0].detail, "knowledge 1/1")

    def test_disabled_publication_reports_nothing(self) -> None:
        app = _application(None)

        run = app.orchestrator.start(_request())

        completed = [
            event
            for event in app.progress_log.list_by_run(run.run_id)
            if event.kind is ProgressEventKind.RUN_COMPLETED
        ]
        self.assertIsNone(completed[0].detail)


    def test_resume_publishes_what_an_interrupted_run_missed(self) -> None:
        """보고서만 남기고 죽은 Run 을 재개하면 Knowledge 가 이어서 쌓여야 한다.

        발행이 _report 의 조기 반환 안에 있으면 여기서 0건으로 남는다.
        """

        knowledge = InMemoryKnowledgeBase()
        app = _application(knowledge)
        run = app.orchestrator.start(_request())
        self.assertEqual(len(knowledge.search(KnowledgeQuery(category="XSS", text=""))), 1)

        # 보고서는 남기고 Knowledge 만 비운 채 REPORT 단계로 되돌린다.
        drained = InMemoryKnowledgeBase()
        app.orchestrator._knowledge = drained
        app.stores.runs.save(
            app.stores.runs.get(run.run_id).with_updates(phase=RunPhase.REPORT)
        )

        resumed = app.orchestrator.resume(run.run_id)

        self.assertIs(resumed.phase, RunPhase.DONE)
        self.assertEqual(len(drained.search(KnowledgeQuery(category="XSS", text=""))), 1)

    def test_retry_publishes_only_what_failed_and_never_duplicates(self) -> None:
        flaky = _FlakyKnowledgeBase(fail_times=1)
        app = _application(flaky)

        run = app.orchestrator.start(_request())
        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(len(flaky.search(KnowledgeQuery(category="XSS", text=""))), 0)

        app.stores.runs.save(
            app.stores.runs.get(run.run_id).with_updates(phase=RunPhase.REPORT)
        )
        app.orchestrator.resume(run.run_id)
        self.assertEqual(len(flaky.search(KnowledgeQuery(category="XSS", text=""))), 1)

        # 한 번 더 재개해도 같은 Case 가 두 개가 되지 않는다.
        app.stores.runs.save(
            app.stores.runs.get(run.run_id).with_updates(phase=RunPhase.REPORT)
        )
        app.orchestrator.resume(run.run_id)
        self.assertEqual(len(flaky.search(KnowledgeQuery(category="XSS", text=""))), 1)

    def test_already_published_run_keeps_its_case_count_on_resume(self) -> None:
        knowledge = InMemoryKnowledgeBase()
        app = _application(knowledge)
        run = app.orchestrator.start(_request())

        app.stores.runs.save(
            app.stores.runs.get(run.run_id).with_updates(phase=RunPhase.REPORT)
        )
        app.orchestrator.resume(run.run_id)

        cases = knowledge.search(KnowledgeQuery(category="XSS", text=""))
        self.assertEqual(len(cases), 1)


class KnowledgeProgressDisplayTests(unittest.TestCase):
    """이벤트에 실린 발행 결과가 실제로 화면에 나오는지 본다.

    이벤트만 검사하면 "데이터는 있는데 아무도 안 본다"를 놓친다.
    """

    def _view_lines(self, detail, *, tty):
        from progress_view import RunProgressView

        stream = io.StringIO()
        stream.isatty = lambda: tty  # type: ignore[method-assign]
        view = RunProgressView(stream=stream)
        view.emit(
            ProgressEvent(
                run_id="run-1",
                sequence=1,
                kind=ProgressEventKind.RUN_COMPLETED,
                phase="done",
                detail=detail,
                budget_used=5,
                budget_total=30,
            )
        )
        view.close()
        return stream.getvalue()

    def test_tty_screen_shows_publication_shortfall(self) -> None:
        out = self._view_lines("knowledge 7/10", tty=True)

        self.assertIn("Knowledge", out)
        self.assertIn("7 / 10", out)
        self.assertIn("3건 발행 실패", out)

    def test_non_tty_log_shows_publication_shortfall(self) -> None:
        out = self._view_lines("knowledge 7/10", tty=False)

        self.assertIn("Knowledge 7/10", out)
        self.assertIn("3건 실패", out)

    def test_full_publication_shows_no_failure_note(self) -> None:
        out = self._view_lines("knowledge 10/10", tty=True)

        self.assertIn("Knowledge", out)
        self.assertNotIn("실패", out)

    def test_disabled_publication_shows_no_knowledge_line(self) -> None:
        self.assertNotIn("Knowledge", self._view_lines(None, tty=True))

    def test_unparsable_detail_is_not_rendered(self) -> None:
        """예외 메시지 같은 임의 문자열이 화면으로 새지 않아야 한다."""

        out = self._view_lines("sqlite3.OperationalError: /secret/path.db", tty=True)

        self.assertNotIn("Knowledge", out)
        self.assertNotIn("secret", out)


if __name__ == "__main__":
    unittest.main()
