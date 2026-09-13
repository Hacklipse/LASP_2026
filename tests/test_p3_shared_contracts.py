"""Report·Validation 공용 계약의 Run 병합 순서와 proof 격리를 검증한다."""

from __future__ import annotations

import unittest

from hacklipse.adapters import MemoryStoreBundle
from hacklipse.application.errors import WorkflowExecutionError
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Candidate,
    CandidateStatus,
    Evidence,
    ReportArtifact,
    Run,
    RunPhase,
    RunScope,
    Surface,
    ValidationProof,
    ValidationProofType,
    ValidationReasonCode,
    ValidationResult,
    ValidationVerdict,
)


class _ClaimingValidator:
    def __init__(
        self,
        evidence_store,
        *,
        confirmed: bool = False,
        wrong_candidate: bool = False,
        foreign_claim: bool = False,
    ) -> None:
        self._evidence = evidence_store
        self._confirmed = confirmed
        self._wrong_candidate = wrong_candidate
        self._foreign_claim = foreign_claim

    def handle(self, task) -> AgentResult:
        claim_id = f"review-{task.validation_id}"
        self._evidence.append(
            Evidence(
                evidence_id=claim_id,
                run_id="run-foreign" if self._foreign_claim else task.run_id,
                surface_id=task.surface_id,
                source_task_id=task.task_id,
                validation_id=task.validation_id,
                created_by="llm_validation_reviewer",
                evidence_type="claim",
            )
        )

        runtime_ids: tuple[str, ...] = ()
        proof = None
        verdict = ValidationVerdict.REJECTED
        if self._confirmed:
            runtime_id = f"runtime-{task.validation_id}"
            self._evidence.append(
                Evidence(
                    evidence_id=runtime_id,
                    run_id=task.run_id,
                    surface_id=task.surface_id,
                    source_task_id=task.task_id,
                    validation_id=task.validation_id,
                    created_by="execution_runtime:http_get",
                    evidence_type="http_response",
                )
            )
            runtime_ids = (runtime_id,)
            verdict = ValidationVerdict.CONFIRMED
            proof = ValidationProof(
                proof_type=ValidationProofType.XSS_EXECUTION,
                evidence_ids=runtime_ids,
                summary="fixture execution signal",
            )

        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=(*runtime_ids, claim_id),
            validation=ValidationResult(
                validation_id=task.validation_id or "",
                run_id=task.run_id,
                candidate_id="candidate-foreign"
                if self._wrong_candidate
                else task.candidate_id or "",
                verdict=verdict,
                evidence_ids=runtime_ids,
                reason="fixture result",
                reproduction_count=len(runtime_ids),
                proof=proof,
                reason_code=ValidationReasonCode.CONFIRMED_PROOF
                if self._confirmed
                else ValidationReasonCode.GENERIC_NO_PROOF,
            ),
        )


class _ClaimingReporter:
    def __init__(
        self,
        evidence_store,
        *,
        format: str = "markdown",
        foreign: bool = False,
        foreign_claim: bool = False,
        extra_foreign_report: bool = False,
    ):
        self._evidence = evidence_store
        self._format = format
        self._foreign = foreign
        self._foreign_claim = foreign_claim
        self._extra_foreign_report = extra_foreign_report
        self.calls = 0

    def handle(self, task) -> AgentResult:
        self.calls += 1
        self._evidence.append(
            Evidence(
                evidence_id="report-claim",
                run_id="run-foreign" if self._foreign_claim else task.run_id,
                surface_id=None,
                source_task_id=task.task_id,
                created_by="llm_report_narrator",
                evidence_type="claim",
            )
        )
        report = ReportArtifact(
            report_id="report-1",
            run_id="run-foreign" if self._foreign else task.run_id,
            format=self._format,
            content="# Fixture report\n",
        )
        reports = (report,)
        if self._extra_foreign_report:
            reports += (
                ReportArtifact(
                    report_id="report-foreign",
                    run_id="run-foreign",
                    format="markdown",
                    content="# Foreign report\n",
                ),
            )
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=("report-claim",),
            reports=reports,
        )


class P3SharedContractTests(unittest.TestCase):
    @staticmethod
    def _application(
        *,
        confirmed: bool = False,
        wrong_candidate: bool = False,
        foreign_claim: bool = False,
        report_format: str = "markdown",
        foreign_report: bool = False,
        foreign_report_claim: bool = False,
        extra_foreign_report: bool = False,
        phase: RunPhase = RunPhase.VALIDATE,
    ):
        stores = MemoryStoreBundle()
        validator = _ClaimingValidator(
            stores.evidence,
            confirmed=confirmed,
            wrong_candidate=wrong_candidate,
            foreign_claim=foreign_claim,
        )
        reporter = _ClaimingReporter(
            stores.evidence,
            format=report_format,
            foreign=foreign_report,
            foreign_claim=foreign_report_claim,
            extra_foreign_report=extra_foreign_report,
        )
        app = build_local_application(
            {"validation": validator, "report": reporter},
            stores=stores,
            agent_allowed_tools={"validation": ("http_get",)},
        )
        run = Run(
            run_id="run-1",
            target_url="http://localhost/",
            scope=RunScope(allowed_hosts=frozenset({"localhost"})),
            policy_profile="safe",
            request_budget=10,
            phase=phase,
            candidate_ids=("candidate-1",) if phase is RunPhase.VALIDATE else (),
        )
        stores.runs.add(run)
        app.budget_manager.open_run(run.run_id, run.request_budget)
        if phase is RunPhase.VALIDATE:
            stores.surfaces.add(
                Surface(
                    surface_id="surface-1",
                    run_id=run.run_id,
                    url="http://localhost/search",
                    method="GET",
                )
            )
            stores.candidates.add(
                Candidate(
                    candidate_id="candidate-1",
                    run_id=run.run_id,
                    surface_id="surface-1",
                    vulnerability_type="XSS",
                    hypothesis="fixture",
                    assigned_agent="xss_analyzer",
                    evidence_ids=(),
                    status=CandidateStatus.ANALYZED,
                )
            )
        return app, reporter

    def test_completed_validation_and_report_claims_join_run(self) -> None:
        app, reporter = self._application()

        result = app.orchestrator.resume("run-1")

        self.assertIs(result.phase, RunPhase.DONE)
        self.assertEqual(len(result.evidence_ids), 2)
        self.assertEqual(len(app.stores.reports.list_by_run("run-1")), 1)
        self.assertEqual(reporter.calls, 1)
        self.assertIs(
            app.stores.candidates.get("run-1", "candidate-1").status,
            CandidateStatus.REJECTED,
        )
        self.assertEqual(app.stores.runs.get("run-1"), result)
        self.assertEqual(app.orchestrator.resume("run-1"), result)
        self.assertEqual(reporter.calls, 1)

    def test_review_claim_never_becomes_finding_proof(self) -> None:
        app, _ = self._application(confirmed=True)

        result = app.orchestrator.resume("run-1")

        finding = app.stores.findings.list_by_run("run-1")[0]
        self.assertIs(finding.proof_type, ValidationProofType.XSS_EXECUTION)
        self.assertEqual(finding.reproduction_count, 1)
        self.assertEqual(len(finding.evidence_ids), 1)
        self.assertTrue(finding.evidence_ids[0].startswith("runtime-"))
        self.assertEqual(len(result.evidence_ids), 3)
        self.assertTrue(all(not item.startswith("review-") for item in finding.evidence_ids))
        self.assertNotIn("report-claim", finding.evidence_ids)

    def test_invalid_validation_contract_does_not_link_claim(self) -> None:
        app, reporter = self._application(wrong_candidate=True)

        with self.assertRaises(WorkflowExecutionError):
            app.orchestrator.resume("run-1")

        failed = app.stores.runs.get("run-1")
        self.assertIs(failed.phase, RunPhase.FAILED)
        self.assertEqual(failed.evidence_ids, ())
        self.assertEqual(reporter.calls, 0)
        self.assertEqual(app.stores.reports.list_by_run("run-1"), ())

    def test_foreign_review_claim_is_a_contract_error(self) -> None:
        app, reporter = self._application(foreign_claim=True)

        with self.assertRaises(WorkflowExecutionError):
            app.orchestrator.resume("run-1")

        failed = app.stores.runs.get("run-1")
        self.assertIs(failed.phase, RunPhase.FAILED)
        self.assertEqual(failed.evidence_ids, ())
        self.assertEqual(reporter.calls, 0)

    def test_invalid_report_format_does_not_link_claim_or_save_artifact(self) -> None:
        app, _ = self._application(report_format=" ", phase=RunPhase.REPORT)

        with self.assertRaises(WorkflowExecutionError):
            app.orchestrator.resume("run-1")

        failed = app.stores.runs.get("run-1")
        self.assertIs(failed.phase, RunPhase.FAILED)
        self.assertEqual(failed.evidence_ids, ())
        self.assertEqual(app.stores.reports.list_by_run("run-1"), ())

    def test_foreign_report_does_not_link_claim_or_save_artifact(self) -> None:
        app, _ = self._application(foreign_report=True, phase=RunPhase.REPORT)

        with self.assertRaises(WorkflowExecutionError):
            app.orchestrator.resume("run-1")

        failed = app.stores.runs.get("run-1")
        self.assertIs(failed.phase, RunPhase.FAILED)
        self.assertEqual(failed.evidence_ids, ())
        self.assertEqual(app.stores.reports.list_by_run("run-1"), ())

    def test_all_report_artifacts_are_checked_before_any_are_saved(self) -> None:
        app, _ = self._application(
            extra_foreign_report=True, phase=RunPhase.REPORT
        )

        with self.assertRaises(WorkflowExecutionError):
            app.orchestrator.resume("run-1")

        failed = app.stores.runs.get("run-1")
        self.assertIs(failed.phase, RunPhase.FAILED)
        self.assertEqual(failed.evidence_ids, ())
        self.assertEqual(app.stores.reports.list_by_run("run-1"), ())

    def test_foreign_report_claim_is_a_contract_error(self) -> None:
        app, _ = self._application(
            foreign_report_claim=True, phase=RunPhase.REPORT
        )

        with self.assertRaises(WorkflowExecutionError):
            app.orchestrator.resume("run-1")

        failed = app.stores.runs.get("run-1")
        self.assertIs(failed.phase, RunPhase.FAILED)
        self.assertEqual(failed.evidence_ids, ())
        self.assertEqual(app.stores.reports.list_by_run("run-1"), ())
