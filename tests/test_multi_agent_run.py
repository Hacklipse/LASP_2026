"""한 Run에서 여러 취약점 Agent를 함께 실행할 때의 경계를 검증한다.

여기서 지키려는 것은 "여러 Agent가 돈다"가 아니라 "함께 돌아도 섞이지 않는다"다.
취약점마다 필요한 인증이 다르므로(SQLi는 인증 없음, SSTI는 실습 계정, Access Control은
임시 주체 두 개) 자격증명이 유형 경계를 넘으면 다른 계정 데이터를 읽고도 취약점으로
오인할 수 있다.
"""

from __future__ import annotations

import unittest

from hacklipse.application.task_factory import TaskFactory
from hacklipse.domain import (
    Candidate,
    Run,
    RunScope,
    credential_for_vulnerability,
)

_SCOPE = RunScope(allowed_hosts=frozenset({"127.0.0.1"}), allowed_path_prefixes=("/",))


def _run(**changes) -> Run:
    base = Run(
        run_id="run-1",
        target_url="http://127.0.0.1:3000/",
        scope=_SCOPE,
        policy_profile="safe",
        request_budget=20,
    )
    return base.with_updates(**changes)


def _candidate(vulnerability_type: str, agent: str) -> Candidate:
    return Candidate(
        candidate_id=f"cand-{vulnerability_type}",
        run_id="run-1",
        surface_id="surface-1",
        vulnerability_type=vulnerability_type,
        hypothesis="hypothesis",
        assigned_agent=agent,
        evidence_ids=(),
    )


class VulnerabilityCredentialResolutionTests(unittest.TestCase):
    """유형별 자격증명 해석 규칙."""

    def test_single_vulnerability_run_keeps_using_the_run_credential(self) -> None:
        """등록이 없으면 기존 단일 취약점 Run이므로 Run 기본값을 그대로 쓴다."""

        run = _run(credential_ref="dvwa-session")

        self.assertEqual(credential_for_vulnerability(run, "SQLi"), "dvwa-session")
        self.assertEqual(credential_for_vulnerability(run, "XSS"), "dvwa-session")

    def test_registered_type_uses_its_own_credential(self) -> None:
        run = _run(
            credential_ref="juice-default",
            agent_credentials=(("SSTI", "ssti-token"), ("Access Control", "actor")),
        )

        self.assertEqual(credential_for_vulnerability(run, "SSTI"), "ssti-token")
        self.assertEqual(credential_for_vulnerability(run, "Access Control"), "actor")

    def test_unregistered_type_gets_no_credential_instead_of_the_run_default(
        self,
    ) -> None:
        """선언하지 않은 유형에 Run 기본 세션이 흘러들면 안 된다.

        이것이 이 기능의 핵심 안전 속성이다. Run 기본값으로 되돌리면 SSTI 실습 계정
        세션이 SQLi 요청에 얹히고, 그 응답 차이를 취약점으로 오인할 수 있다.
        """

        run = _run(
            credential_ref="ssti-token",
            agent_credentials=(("SSTI", "ssti-token"),),
        )

        self.assertIsNone(credential_for_vulnerability(run, "SQLi"))


class TaskCredentialSeparationTests(unittest.TestCase):
    """Task 조립 단계에서 유형별 자격증명이 실제로 갈라지는지 확인한다."""

    def setUp(self) -> None:
        self.factory = TaskFactory(id_factory=lambda: "task-1")
        self.run = _run(
            credential_ref="juice-default",
            agent_credentials=(("SSTI", "ssti-token"), ("SQLi", "")),
        )

    def test_analysis_and_validation_tasks_carry_the_type_credential(self) -> None:
        ssti = _candidate("SSTI", "ssti_analyzer")

        analysis = self.factory.analysis(
            self.run, ssti, target_url="http://127.0.0.1:3000/profile", request_budget=5
        )
        validation = self.factory.validation(
            self.run,
            ssti,
            validation_id="validation-1",
            agent_type="validator",
            request_budget=5,
        )

        self.assertEqual(analysis.credential_ref, "ssti-token")
        self.assertEqual(validation.credential_ref, "ssti-token")

    def test_evidence_collection_inherits_the_candidate_credential(self) -> None:
        """증적 수집 Task가 Run 기본값으로 돌아가면 분리가 여기서 무너진다."""

        from hacklipse.domain import EvidenceRequest, HttpRequestSpec

        sqli = _candidate("SQLi", "sqli_analyzer")
        request = EvidenceRequest(
            evidence_type="http_response",
            surface_id="surface-1",
            reason="control",
            suggested_tool="http_get",
            http_request=HttpRequestSpec(method="GET"),
        )

        task = self.factory.evidence_collection(
            self.run,
            sqli,
            request,
            target_url="http://127.0.0.1:3000/rest/products/search",
            agent_type="evidence_collector",
            request_budget=5,
        )

        # SQLi는 빈 문자열로 등록돼 있으므로 자격증명 없이 나가야 한다.
        self.assertFalse(task.credential_ref)
        self.assertNotEqual(task.credential_ref, "juice-default")

    def test_recon_keeps_the_run_credential(self) -> None:
        """Recon은 특정 취약점에 속하지 않으므로 Run 기본 세션으로 돈다."""

        task = self.factory.recon(self.run, agent_type="recon", request_budget=5)

        self.assertEqual(task.credential_ref, "juice-default")


class _SurfaceOnlyReconAgent:
    """Observation 없이 입력 가능한 Surface 하나만 반환하는 Recon 대역.

    이 Surface 하나가 XSS와 SQLi Candidate 두 개를 만든다. 실패 격리를 확인하려면
    한 Run 안에 Candidate가 둘 이상 있어야 한다.
    """

    def __init__(self, surface_store) -> None:
        self._surfaces = surface_store

    def handle(self, task):
        from hacklipse.domain import AgentResult, AgentResultStatus, Surface

        surface = Surface(
            surface_id="surface-search",
            run_id=task.run_id,
            url="http://localhost/search",
            method="GET",
            parameters=("q",),
        )
        self._surfaces.add(surface)
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            surface_ids=(surface.surface_id,),
        )


class _RaisingAnalyzer:
    def __init__(self, error: Exception) -> None:
        self._error = error

    def handle(self, task):
        raise self._error


class _CompletingAnalyzer:
    def handle(self, task):
        from hacklipse.domain import AgentResult, AgentResultStatus

        return AgentResult(task_id=task.task_id, status=AgentResultStatus.COMPLETED)


class _RejectingValidator:
    def handle(self, task):
        from hacklipse.domain import (
            AgentResult,
            AgentResultStatus,
            ValidationResult,
            ValidationVerdict,
        )

        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            validation=ValidationResult(
                validation_id=task.validation_id or "",
                run_id=task.run_id,
                candidate_id=task.candidate_id,
                verdict=ValidationVerdict.REJECTED,
                evidence_ids=(),
                reason="fixture rejects without a proof",
            ),
        )


def _application(xss_analyzer):
    from hacklipse.bootstrap import build_local_application

    app = build_local_application({})
    app.dispatcher.register(
        "recon", _SurfaceOnlyReconAgent(app.stores.surfaces), allowed_tools=("http_get",)
    )
    app.dispatcher.register("xss_analyzer", xss_analyzer, allowed_tools=("http_get",))
    app.dispatcher.register(
        "sqli_analyzer", _CompletingAnalyzer(), allowed_tools=("http_get",)
    )
    app.dispatcher.register("validation", _RejectingValidator(), allowed_tools=("http_get",))
    return app


def _start(app):
    from hacklipse.domain import RunRequest, RunScope

    return app.orchestrator.start(
        RunRequest(
            target_url="http://localhost/",
            scope=RunScope(allowed_hosts=frozenset({"localhost"})),
        )
    )


class CandidateFailureIsolationTests(unittest.TestCase):
    """한 Candidate의 실패가 나머지 Candidate를 취소하지 않아야 한다."""

    def test_target_side_failure_only_fails_its_own_candidate(self) -> None:
        from hacklipse.ports.errors import AuthenticationFailed

        app = _application(_RaisingAnalyzer(AuthenticationFailed("session expired")))

        run = _start(app)

        self.assertEqual(run.phase.value, "done")
        by_type = {
            item.vulnerability_type: item
            for item in app.stores.candidates.list_by_run(run.run_id)
        }
        self.assertEqual(by_type["XSS"].status, "failed")
        self.assertIn("AuthenticationFailed", by_type["XSS"].last_error or "")
        # 같은 Run의 다른 Candidate는 끝까지 진행돼야 한다.
        self.assertEqual(by_type["SQLi"].status, "rejected")
        self.assertIsNone(by_type["SQLi"].last_error)

    def test_contract_violation_still_fails_the_whole_run(self) -> None:
        """Agent가 계약을 어긴 것은 대상 실패가 아니다. 나머지 결과도 신뢰할 수 없다."""

        from hacklipse.application.errors import (
            AgentContractError,
            WorkflowExecutionError,
        )

        app = _application(_RaisingAnalyzer(AgentContractError("forged evidence")))

        with self.assertRaises(WorkflowExecutionError) as caught:
            _start(app)

        self.assertEqual(caught.exception.phase, "analyze")

    def test_missing_analyzer_still_fails_the_whole_run(self) -> None:
        """미등록 Agent는 설정 오류이므로 조용히 건너뛰지 않는다."""

        from hacklipse.application.errors import WorkflowExecutionError
        from hacklipse.bootstrap import build_local_application

        app = build_local_application({})
        app.dispatcher.register(
            "recon",
            _SurfaceOnlyReconAgent(app.stores.surfaces),
            allowed_tools=("http_get",),
        )

        with self.assertRaises(WorkflowExecutionError):
            _start(app)


class _PriorityRouter:
    """우선순위를 일부러 뒤섞어 돌려주는 Router 대역."""

    def __init__(self, ordered_types: tuple[tuple[str, float], ...]) -> None:
        self._ordered = ordered_types

    def route(self, run, surfaces, evidence):
        from hacklipse.domain import RouteDecision

        return tuple(
            RouteDecision(
                candidate=Candidate(
                    candidate_id=f"cand-{name}",
                    run_id=run.run_id,
                    surface_id="surface-search",
                    vulnerability_type=name,
                    hypothesis="h",
                    assigned_agent=f"{name.lower()}_analyzer",
                    evidence_ids=(),
                ),
                priority=priority,
            )
            for name, priority in self._ordered
        )


class CandidatePriorityTests(unittest.TestCase):
    """예산이 모자라면 뒤쪽이 잘리므로 실행 순서가 곧 무엇을 포기할지의 결정이다."""

    def test_candidates_run_in_priority_order(self) -> None:
        from hacklipse.bootstrap import build_local_application

        # Router가 낮은 우선순위를 먼저 돌려줘도 실행 순서는 높은 쪽이 앞서야 한다.
        app = build_local_application(
            {}, router=_PriorityRouter((("low", 0.2), ("high", 0.9), ("mid", 0.5)))
        )
        app.dispatcher.register(
            "recon",
            _SurfaceOnlyReconAgent(app.stores.surfaces),
            allowed_tools=("http_get",),
        )
        for name in ("low", "high", "mid"):
            app.dispatcher.register(
                f"{name}_analyzer", _CompletingAnalyzer(), allowed_tools=("http_get",)
            )
        app.dispatcher.register(
            "validation", _RejectingValidator(), allowed_tools=("http_get",)
        )

        run = _start(app)

        self.assertEqual(
            list(run.candidate_ids), ["cand-high", "cand-mid", "cand-low"]
        )


class _DrainingReconAgent(_SurfaceOnlyReconAgent):
    """Surface를 만들면서 Run 예산을 모두 소진하는 Recon 대역."""

    def __init__(self, surface_store, budget_manager, units: int) -> None:
        super().__init__(surface_store)
        self._budget = budget_manager
        self._units = units

    def handle(self, task):
        result = super().handle(task)
        self._budget.consume(task.run_id, self._units)
        return result


class BudgetStarvationTests(unittest.TestCase):
    """예산 부족은 실패와 구분해서 기록해야 한다.

    실패로 뭉뚱그리면 보고서를 읽는 사람이 "검사했는데 안 나왔다"로 오해한다.
    """

    def test_drained_budget_skips_candidates_before_starting_them(self) -> None:
        from hacklipse.bootstrap import build_local_application
        from hacklipse.domain import CandidateStatus, RunRequest, RunScope

        app = build_local_application({})
        app.dispatcher.register(
            "recon",
            _DrainingReconAgent(app.stores.surfaces, app.budget_manager, units=4),
            allowed_tools=("http_get",),
        )
        app.dispatcher.register(
            "xss_analyzer", _CompletingAnalyzer(), allowed_tools=("http_get",)
        )
        app.dispatcher.register(
            "sqli_analyzer", _CompletingAnalyzer(), allowed_tools=("http_get",)
        )
        app.dispatcher.register(
            "validation", _RejectingValidator(), allowed_tools=("http_get",)
        )

        run = app.orchestrator.start(
            RunRequest(
                target_url="http://localhost/",
                scope=RunScope(allowed_hosts=frozenset({"localhost"})),
                request_budget=4,
            )
        )

        # Run 전체가 죽지 않는다. 이것이 예산 부족을 계약 위반과 분리한 이유다.
        self.assertEqual(run.phase.value, "done")
        candidates = app.stores.candidates.list_by_run(run.run_id)
        self.assertEqual(
            {item.status for item in candidates}, {CandidateStatus.SKIPPED_BUDGET}
        )
        self.assertIn("budget", (candidates[0].last_error or "").casefold())

    def test_analyzer_budget_shortage_is_not_treated_as_a_failure(self) -> None:
        """Analyzer가 남은 예산으로 계획을 못 세우면 그 Candidate만 건너뛴다."""

        from hacklipse.domain import CandidateStatus
        from hacklipse.ports.errors import BudgetExceeded

        app = _application(_RaisingAnalyzer(BudgetExceeded("not enough for probes")))

        run = _start(app)

        self.assertEqual(run.phase.value, "done")
        by_type = {
            item.vulnerability_type: item
            for item in app.stores.candidates.list_by_run(run.run_id)
        }
        self.assertEqual(by_type["XSS"].status, CandidateStatus.SKIPPED_BUDGET)
        self.assertNotEqual(by_type["XSS"].status, "failed")
        # 같은 Run의 다른 Candidate는 정상 진행된다.
        self.assertEqual(by_type["SQLi"].status, "rejected")


class _CountingAnalyzer:
    """몇 번 호출됐는지 세는 Analysis 대역."""

    def __init__(self) -> None:
        self.calls = 0

    def handle(self, task):
        from hacklipse.domain import AgentResult, AgentResultStatus

        self.calls += 1
        return AgentResult(task_id=task.task_id, status=AgentResultStatus.COMPLETED)


def _interrupted_run(candidate_status: str, resume_status: str):
    """예산 때문에 건너뛴 Candidate가 남아 있는 중단된 Run을 만든다.

    실제로는 프로세스가 죽거나 Run이 실패해 영속 저장소에 이 상태로 남는다.
    """

    from hacklipse.adapters import InMemoryBudgetManager
    from hacklipse.bootstrap import build_local_application
    from hacklipse.domain import Run, RunPhase, Surface

    budget = InMemoryBudgetManager()
    app = build_local_application({}, budget_manager=budget)
    analyzer = _CountingAnalyzer()
    app.dispatcher.register("sqli_analyzer", analyzer, allowed_tools=("http_get",))
    app.dispatcher.register(
        "validation", _RejectingValidator(), allowed_tools=("http_get",)
    )

    app.stores.surfaces.add(
        Surface(
            surface_id="surface-search",
            run_id="run-1",
            url="http://localhost/search",
            method="GET",
            parameters=("q",),
        )
    )
    candidate = Candidate(
        candidate_id="cand-sqli",
        run_id="run-1",
        surface_id="surface-search",
        vulnerability_type="SQLi",
        hypothesis="h",
        assigned_agent="sqli_analyzer",
        evidence_ids=(),
        status=candidate_status,
        last_error="request budget exhausted",
        resume_status=resume_status,
    )
    app.stores.candidates.add(candidate)
    app.stores.runs.add(
        Run(
            run_id="run-1",
            target_url="http://localhost/",
            scope=_SCOPE,
            policy_profile="safe",
            request_budget=20,
            phase=RunPhase.ANALYZE,
            candidate_ids=("cand-sqli",),
        )
    )
    # 재개 시점에는 예산이 다시 확보돼 있다.
    budget.open_run("run-1", 20)
    return app, analyzer


class SkippedCandidateResumeTests(unittest.TestCase):
    """예산으로 건너뛴 Candidate는 재개 대상이어야 한다.

    그대로 두면 예산을 늘려 다시 실행해도 영원히 검사되지 않는다. 그러면 보고서는
    "검사하지 못했다"를 계속 유지하는데 실제로는 검사할 수 있는 상태다.
    """

    def test_skipped_before_analysis_is_analyzed_on_resume(self) -> None:
        from hacklipse.domain import CandidateStatus

        app, analyzer = _interrupted_run(CandidateStatus.SKIPPED_BUDGET, "routed")

        run = app.orchestrator.resume("run-1")

        self.assertEqual(run.phase.value, "done")
        self.assertEqual(analyzer.calls, 1)
        candidate = app.stores.candidates.get("run-1", "cand-sqli")
        self.assertEqual(candidate.status, "rejected")
        # 정상 전이가 끝났으므로 건너뜀 흔적은 남지 않는다.
        self.assertIsNone(candidate.last_error)
        self.assertIsNone(candidate.resume_status)

    def test_skipped_before_validation_does_not_repeat_analysis(self) -> None:
        """검증 직전에 멈춘 Candidate를 분석부터 다시 돌리면 예산을 또 쓴다."""

        from hacklipse.domain import CandidateStatus

        app, analyzer = _interrupted_run(CandidateStatus.SKIPPED_BUDGET, "analyzed")

        run = app.orchestrator.resume("run-1")

        self.assertEqual(run.phase.value, "done")
        self.assertEqual(analyzer.calls, 0)
        self.assertEqual(
            app.stores.candidates.get("run-1", "cand-sqli").status, "rejected"
        )

    def test_finished_candidate_is_not_reprocessed(self) -> None:
        """이미 판정이 끝난 Candidate는 재개해도 다시 돌지 않는다."""

        app, analyzer = _interrupted_run("rejected", None)

        app.orchestrator.resume("run-1")

        self.assertEqual(analyzer.calls, 0)


class ProgressSnapshotTests(unittest.TestCase):
    """진행 상태는 Store를 다시 세어 계산한다.

    따로 누적하면 실제 저장 내용과 어긋나고, 어긋난 쪽이 완료를 표시하면 검사되지
    않은 항목이 검사된 것처럼 보인다.
    """

    def test_snapshot_matches_what_the_run_actually_produced(self) -> None:
        from hacklipse.application import build_progress_snapshot

        app = _application(_CompletingAnalyzer())
        run = _start(app)

        snapshot = build_progress_snapshot(
            run, stores=app.stores, budget=app.budget_manager
        )

        self.assertEqual(snapshot.run_id, run.run_id)
        self.assertEqual(snapshot.phase, "done")
        self.assertEqual(snapshot.surface_count, 1)
        self.assertEqual(snapshot.parameter_count, 1)
        self.assertEqual(dict(snapshot.candidates_by_type), {"XSS": 1, "SQLi": 1})
        self.assertEqual(snapshot.candidate_count, 2)
        # 두 Candidate 모두 판정까지 끝났다.
        self.assertEqual(snapshot.validated_count, 2)
        self.assertEqual(snapshot.finding_count, 0)
        self.assertEqual(snapshot.unchecked, ())
        self.assertEqual(snapshot.budget_total, run.request_budget)

    def test_unchecked_separates_failure_from_budget_skip(self) -> None:
        from hacklipse.application import build_progress_snapshot
        from hacklipse.domain import CandidateStatus
        from hacklipse.ports.errors import AuthenticationFailed

        app = _application(_RaisingAnalyzer(AuthenticationFailed("session expired")))
        run = _start(app)

        snapshot = build_progress_snapshot(run, stores=app.stores)

        by_type = {item.vulnerability_type: item for item in snapshot.unchecked}
        self.assertEqual(by_type["XSS"].status, "failed")
        self.assertIn("AuthenticationFailed", by_type["XSS"].reason or "")
        self.assertNotIn("SQLi", by_type)
        self.assertNotIn(CandidateStatus.SKIPPED_BUDGET, {i.status for i in snapshot.unchecked})

    def test_budget_used_is_derived_from_the_manager(self) -> None:
        from hacklipse.application import build_progress_snapshot
        from hacklipse.bootstrap import build_local_application
        from hacklipse.adapters import InMemoryBudgetManager
        from hacklipse.domain import RunRequest, RunScope

        budget = InMemoryBudgetManager()
        app = build_local_application({}, budget_manager=budget)
        app.dispatcher.register(
            "recon",
            _DrainingReconAgent(app.stores.surfaces, budget, units=3),
            allowed_tools=("http_get",),
        )
        for name in ("xss_analyzer", "sqli_analyzer"):
            app.dispatcher.register(name, _CompletingAnalyzer(), allowed_tools=("http_get",))
        app.dispatcher.register(
            "validation", _RejectingValidator(), allowed_tools=("http_get",)
        )
        run = app.orchestrator.start(
            RunRequest(
                target_url="http://localhost/",
                scope=RunScope(allowed_hosts=frozenset({"localhost"})),
                request_budget=10,
            )
        )

        snapshot = build_progress_snapshot(run, stores=app.stores, budget=budget)

        self.assertEqual(snapshot.budget_used, 3)
        self.assertEqual(snapshot.budget_total, 10)

    def test_snapshot_is_json_serializable(self) -> None:
        """웹 UI가 같은 스냅샷을 그대로 조회할 수 있어야 한다."""

        import dataclasses
        import json

        from hacklipse.application import build_progress_snapshot

        app = _application(_CompletingAnalyzer())
        run = _start(app)

        snapshot = build_progress_snapshot(run, stores=app.stores)
        encoded = json.dumps(dataclasses.asdict(snapshot))

        self.assertIn(snapshot.run_id, encoded)


class CandidateStatusTests(unittest.TestCase):
    """상태가 자유 문자열이면 오타가 조용히 통과해 집계를 왜곡한다."""

    def test_unknown_status_is_rejected(self) -> None:
        from hacklipse.domain import CandidateStatus
        from hacklipse.domain.errors import DomainInvariantError

        with self.assertRaises(DomainInvariantError):
            _candidate("SQLi", "sqli_analyzer").set_status("analized")

        # 정상 값은 그대로 통과한다.
        self.assertIs(
            _candidate("SQLi", "sqli_analyzer").set_status(CandidateStatus.ANALYZED).status,
            CandidateStatus.ANALYZED,
        )

    def test_stored_string_is_restored_as_the_enum(self) -> None:
        """저장소에서 문자열로 복원한 Candidate도 같은 검사를 통과해야 한다."""

        from hacklipse.domain import CandidateStatus

        restored = Candidate(
            candidate_id="c",
            run_id="run-1",
            surface_id="s",
            vulnerability_type="SQLi",
            hypothesis="h",
            assigned_agent="a",
            evidence_ids=(),
            status="skipped_budget",
            resume_status="analyzed",
        )

        self.assertIs(restored.status, CandidateStatus.SKIPPED_BUDGET)
        self.assertIs(restored.resume_status, CandidateStatus.ANALYZED)
        # str을 함께 상속하므로 기존 문자열 비교와 저장이 그대로 동작한다.
        self.assertEqual(restored.status, "skipped_budget")


if __name__ == "__main__":
    unittest.main()
