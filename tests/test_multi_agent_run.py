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


if __name__ == "__main__":
    unittest.main()
