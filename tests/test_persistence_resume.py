"""SQLite 재접속 후 활성 Run과 요청 예산을 함께 재개하는지 검증한다."""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from hacklipse.adapters import ReconAgent, SQLiteBudgetManager, SQLiteStoreBundle
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    ExecutionRequest,
    ExecutionResult,
    ProgressEvent,
    ProgressEventKind,
    Run,
    RunPhase,
    RunScope,
    TaskEnvelope,
    TaskRecord,
    TaskStatus,
)


class _StaticHtmlRuntime:
    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response",
                "status": 200,
                "body": "<html><body><a href='/about'>about</a></body></html>",
            },
        )


class PersistenceResumeTests(unittest.TestCase):
    def test_active_run_resumes_with_persisted_budget_and_stores(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "resume.sqlite3"
            stores = SQLiteStoreBundle(database_path)
            budget = SQLiteBudgetManager(database_path)
            run = Run(
                run_id="run-resume",
                target_url="http://localhost/index.php",
                scope=RunScope(allowed_hosts=frozenset({"localhost"})),
                policy_profile="safe",
                request_budget=5,
                phase=RunPhase.RECON,
            )
            old_task = TaskRecord(
                envelope=TaskEnvelope(
                    task_id="task-before-restart",
                    run_id=run.run_id,
                    agent_type="setup",
                ),
                status=TaskStatus.SUCCEEDED,
                attempts=1,
            )
            stores.runs.add(run)
            stores.tasks.add(old_task)
            budget.open_run(run.run_id, run.request_budget)
            budget.consume(run.run_id, 2)
            stores.close()
            budget.close()

            stores = SQLiteStoreBundle(database_path)
            budget = SQLiteBudgetManager(database_path)
            app = build_local_application(
                {},
                stores=stores,
                budget_manager=budget,
                runtime=_StaticHtmlRuntime(),
            )
            app.dispatcher.register(
                "recon",
                ReconAgent(
                    collector=app.collector,
                    evidence_store=app.stores.evidence,
                    surface_store=app.stores.surfaces,
                ),
                allowed_tools=("http_get",),
            )

            resumed = app.orchestrator.resume(run.run_id)

            self.assertIs(resumed.phase, RunPhase.DONE)
            self.assertEqual(app.budget_manager.remaining(run.run_id), 2)
            tasks = app.stores.tasks.list_by_run(run.run_id)
            self.assertEqual(tasks[0], old_task)
            self.assertEqual(
                [task.envelope.agent_type for task in tasks[1:]], ["recon", "report"]
            )
            self.assertEqual(len(app.stores.evidence.list_by_run(run.run_id)), 1)
            self.assertGreaterEqual(len(app.stores.surfaces.list_by_run(run.run_id)), 1)
            report_count = len(app.stores.reports.list_by_run(run.run_id))
            self.assertEqual(report_count, 1)

            # DONE Run을 다시 resume해도 중복 Task나 Report를 만들지 않는다.
            self.assertEqual(app.orchestrator.resume(run.run_id), resumed)
            self.assertEqual(len(app.stores.reports.list_by_run(run.run_id)), report_count)
            stores.close()
            budget.close()


class SkippedCandidateSqliteResumeTests(unittest.TestCase):
    """예산으로 건너뛴 Candidate 가 SQLite 재시작 후에도 이어져야 한다.

    재개 경로는 프로세스 재시작이다. 메모리 저장소로는 이 경로를 재현할 수 없다.
    """

    def test_skipped_candidate_is_analyzed_after_a_restart(self) -> None:
        from hacklipse.domain import Candidate, CandidateStatus, Surface

        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "skipped.sqlite3"
            stores = SQLiteStoreBundle(database_path)
            budget = SQLiteBudgetManager(database_path)
            run = Run(
                run_id="run-skipped",
                target_url="http://localhost/",
                scope=RunScope(allowed_hosts=frozenset({"localhost"})),
                policy_profile="safe",
                request_budget=20,
                phase=RunPhase.ANALYZE,
                candidate_ids=("cand-sqli",),
            )
            stores.surfaces.add(
                Surface(
                    surface_id="surface-search",
                    run_id=run.run_id,
                    url="http://localhost/search",
                    method="GET",
                    parameters=("q",),
                )
            )
            stores.candidates.add(
                Candidate(
                    candidate_id="cand-sqli",
                    run_id=run.run_id,
                    surface_id="surface-search",
                    vulnerability_type="SQLi",
                    hypothesis="h",
                    assigned_agent="sqli_analyzer",
                    evidence_ids=(),
                    status=CandidateStatus.SKIPPED_BUDGET,
                    last_error="request budget exhausted",
                    resume_status=CandidateStatus.ROUTED,
                )
            )
            stores.runs.add(run)
            budget.open_run(run.run_id, run.request_budget)
            stores.close()
            budget.close()

            # 프로세스가 다시 뜬 상황. 저장소만 보고 이어서 실행한다.
            stores = SQLiteStoreBundle(database_path)
            budget = SQLiteBudgetManager(database_path)
            app = build_local_application(
                {}, stores=stores, budget_manager=budget, runtime=_StaticHtmlRuntime()
            )
            calls = []

            class _Analyzer:
                def handle(self, task):
                    from hacklipse.domain import AgentResult, AgentResultStatus

                    calls.append(task.candidate_id)
                    return AgentResult(
                        task_id=task.task_id, status=AgentResultStatus.COMPLETED
                    )

            class _Validator:
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

            app.dispatcher.register("sqli_analyzer", _Analyzer(), allowed_tools=("http_get",))
            app.dispatcher.register("validation", _Validator(), allowed_tools=("http_get",))

            resumed = app.orchestrator.resume(run.run_id)

            self.assertIs(resumed.phase, RunPhase.DONE)
            self.assertEqual(calls, ["cand-sqli"])
            candidate = app.stores.candidates.get(run.run_id, "cand-sqli")
            self.assertIs(candidate.status, CandidateStatus.REJECTED)
            self.assertIsNone(candidate.resume_status)
            stores.close()
            budget.close()


def _recon_app(stores, budget):
    app = build_local_application(
        {}, stores=stores, budget_manager=budget, runtime=_StaticHtmlRuntime()
    )
    app.dispatcher.register(
        "recon",
        ReconAgent(
            collector=app.collector,
            evidence_store=app.stores.evidence,
            surface_store=app.stores.surfaces,
        ),
        allowed_tools=("http_get",),
    )
    return app


def _seeded_run(run_id: str) -> Run:
    return Run(
        run_id=run_id,
        target_url="http://localhost/index.php",
        scope=RunScope(allowed_hosts=frozenset({"localhost"})),
        policy_profile="safe",
        request_budget=10,
        phase=RunPhase.RECON,
    )


class ProgressEventPersistenceTests(unittest.TestCase):
    """진행 사건이 프로세스 재시작을 넘어 남아야 한다.

    작업(Candidate 상태)은 복원되는데 진행 상태만 사라지면, 재개 화면이
    "아무 일도 없었다"로 보인다.
    """

    def test_events_survive_a_process_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "progress.sqlite3"
            stores = SQLiteStoreBundle(database_path)
            budget = SQLiteBudgetManager(database_path)
            run = _seeded_run("run-progress")
            stores.runs.add(run)
            budget.open_run(run.run_id, run.request_budget)
            _recon_app(stores, budget).orchestrator.resume(run.run_id)
            first_pass = stores.progress.list_by_run(run.run_id)
            stores.close()
            budget.close()

            self.assertTrue(first_pass)

            reopened = SQLiteStoreBundle(database_path)
            try:
                restored = reopened.progress.list_by_run(run.run_id)
            finally:
                reopened.close()

            self.assertEqual(restored, first_pass)
            self.assertIs(restored[0].kind, ProgressEventKind.PHASE_CHANGED)

    def test_a_duplicate_sequence_is_ignored(self) -> None:
        """재개가 이미 알린 구간을 다시 알려도 사건이 두 번 쌓이지 않는다."""

        with tempfile.TemporaryDirectory() as directory:
            stores = SQLiteStoreBundle(Path(directory) / "dup.sqlite3")
            try:
                event = ProgressEvent(
                    run_id="run-dup",
                    sequence=1,
                    kind=ProgressEventKind.RUN_STARTED,
                    phase="init",
                    budget_total=10,
                )
                stores.progress.emit(event)
                stores.progress.emit(event)

                self.assertEqual(stores.progress.list_by_run("run-dup"), (event,))
            finally:
                stores.close()

    def test_resume_continues_the_sequence_instead_of_colliding(self) -> None:
        """0부터 다시 매기면 저장된 순번과 겹쳐 재개 구간이 통째로 사라진다."""

        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "seq.sqlite3"
            stores = SQLiteStoreBundle(database_path)
            budget = SQLiteBudgetManager(database_path)
            run = _seeded_run("run-seq")
            stores.runs.add(run)
            budget.open_run(run.run_id, run.request_budget)
            _recon_app(stores, budget).orchestrator.resume(run.run_id)
            before = stores.progress.list_by_run(run.run_id)
            stores.close()
            budget.close()

            # 완료된 Run은 즉시 반환하므로 다시 진행할 구간을 만들어 준다.
            stores = SQLiteStoreBundle(database_path)
            budget = SQLiteBudgetManager(database_path)
            stores.runs.save(replace(stores.runs.get(run.run_id), phase=RunPhase.RECON))
            _recon_app(stores, budget).orchestrator.resume(run.run_id)
            after = stores.progress.list_by_run(run.run_id)
            stores.close()
            budget.close()

            sequences = [item.sequence for item in after]
            self.assertEqual(sequences, sorted(set(sequences)))
            self.assertGreater(len(after), len(before))
            self.assertEqual(after[: len(before)], before)

    def test_resume_does_not_rewind_elapsed_time(self) -> None:
        """하나의 Run 안에서 경과 시간이 뒤로 흐르면 단계 비용을 잘못 읽는다."""

        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "elapsed.sqlite3"
            stores = SQLiteStoreBundle(database_path)
            budget = SQLiteBudgetManager(database_path)
            run = _seeded_run("run-elapsed")
            stores.runs.add(run)
            budget.open_run(run.run_id, run.request_budget)
            _recon_app(stores, budget).orchestrator.resume(run.run_id)
            stores.close()
            budget.close()

            stores = SQLiteStoreBundle(database_path)
            budget = SQLiteBudgetManager(database_path)
            stores.runs.save(replace(stores.runs.get(run.run_id), phase=RunPhase.RECON))
            _recon_app(stores, budget).orchestrator.resume(run.run_id)
            events = stores.progress.list_by_run(run.run_id)
            stores.close()
            budget.close()

            elapsed = [item.elapsed_ms for item in events]
            self.assertEqual(elapsed, sorted(elapsed))


class ProgressLogSelectionTests(unittest.TestCase):
    def test_a_persistent_store_bundle_persists_progress_too(self) -> None:
        """저장소 선택 하나로 진행 사건까지 따라가야 한다."""

        with tempfile.TemporaryDirectory() as directory:
            stores = SQLiteStoreBundle(Path(directory) / "select.sqlite3")
            budget = SQLiteBudgetManager(Path(directory) / "select.sqlite3")
            try:
                app = build_local_application(
                    {}, stores=stores, budget_manager=budget, runtime=_StaticHtmlRuntime()
                )
                self.assertIs(app.progress_log, stores.progress)
            finally:
                stores.close()
                budget.close()


class ReportV2PersistenceTests(unittest.TestCase):
    def test_report_resumes_with_persisted_proof_and_budget_and_is_reused(self) -> None:
        import json
        import sqlite3

        from hacklipse.adapters.reporting import MarkdownReportAgent
        from hacklipse.adapters.llm_report_narrative import deterministic_fallback
        from hacklipse.adapters.report_contract import (
            NarratorFingerprintConfig, serialize_report_facts,
        )
        from hacklipse.domain import Candidate, CandidateStatus, Evidence, Finding, Surface, ValidationProofType

        class Narrator:
            def __init__(self):
                self.calls = 0

            def narrate(self, facts, *, timeout_seconds=60.0):
                self.calls += 1
                return deterministic_fallback(
                    "timeout", llm_calls=1, model="fixture-model", elapsed_ms=1.0,
                )

        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "report-v2.sqlite3"
            stores = SQLiteStoreBundle(database_path)
            budget = SQLiteBudgetManager(database_path)
            run = Run(
                run_id="run-report-v2", target_url="http://localhost/search",
                scope=RunScope(allowed_hosts=frozenset({"localhost"})), policy_profile="safe",
                request_budget=20, phase=RunPhase.REPORT,
                finding_ids=("finding-proof", "finding-legacy"),
                candidate_ids=("candidate-proof", "candidate-legacy"),
                surface_ids=("surface-search",), evidence_ids=("evi-proof", "evi-legacy"),
            )
            try:
                stores.runs.add(run)
                budget.open_run(run.run_id, 20)
                budget.consume(run.run_id, 7)
                stores.surfaces.add(Surface(surface_id="surface-search", run_id=run.run_id, url=run.target_url, method="GET", parameters=("q",)))
                for label in ("proof", "legacy"):
                    stores.candidates.add(Candidate(
                        candidate_id=f"candidate-{label}", run_id=run.run_id,
                        surface_id="surface-search", vulnerability_type="XSS", hypothesis="fixture",
                        assigned_agent="xss_analyzer", evidence_ids=(f"evi-{label}",), status=CandidateStatus.CONFIRMED,
                    ))
                    stores.evidence.append(Evidence(
                        evidence_id=f"evi-{label}", run_id=run.run_id, surface_id="surface-search",
                        created_by="fixture", evidence_type="http_response", observation={"body": "private-body"},
                    ))
                    stores.findings.add(Finding(
                        finding_id=f"finding-{label}", run_id=run.run_id, candidate_id=f"candidate-{label}",
                        validation_id=f"validation-{label}", vulnerability_type="XSS", surface_id="surface-search",
                        evidence_ids=(f"evi-{label}",),
                        proof_type=ValidationProofType.XSS_EXECUTION if label == "proof" else None,
                        reproduction_count=2 if label == "proof" else 0,
                    ))
            finally:
                stores.close()
                budget.close()

            # P-3 이전 레코드처럼 proof 필드가 아예 없는 데이터도 그대로 읽는다.
            with sqlite3.connect(database_path) as connection:
                data = json.loads(connection.execute("SELECT data FROM findings WHERE finding_id = ?", ("finding-legacy",)).fetchone()[0])
                data.pop("proof_type")
                data.pop("reproduction_count")
                connection.execute("UPDATE findings SET data = ? WHERE finding_id = ?", (json.dumps(data), "finding-legacy"))

            previous_report = None
            previous_facts = None
            for restart in range(2):
                stores = SQLiteStoreBundle(database_path)
                budget = SQLiteBudgetManager(database_path)
                try:
                    narrator = Narrator()
                    narrator_config = NarratorFingerprintConfig(
                        model="fixture-model", prompt_version="fixture-v1",
                    )
                    reporter = MarkdownReportAgent(
                        finding_store=stores.findings, evidence_store=stores.evidence,
                        candidate_store=stores.candidates, surface_store=stores.surfaces,
                        run_store=stores.runs, budget_manager=budget, format_version="v2",
                        narrator=narrator, narrator_config=narrator_config,
                    )
                    app = build_local_application({"report": reporter}, stores=stores, budget_manager=budget)
                    resumed = app.orchestrator.resume(run.run_id)
                    self.assertIs(resumed.phase, RunPhase.DONE)
                    reports = stores.reports.list_by_run(run.run_id)
                    self.assertEqual(len(reports), 1)
                    report = reports[0]
                    task = TaskEnvelope(task_id="offline", run_id=run.run_id, agent_type="report", finding_ids=run.finding_ids)
                    facts = serialize_report_facts(reporter.collect_facts(task))
                    self.assertIn("재현 횟수: 2", report.content)
                    self.assertIn("검증 상세를 사용할 수 없음", report.content)
                    self.assertIn("사용 요청 예산: 7", report.content)
                    self.assertNotIn("private-body", report.content + facts)
                    self.assertEqual(len(stores.tasks.list_by_run(run.run_id)), 1)
                    claims = [
                        item for item in stores.evidence.list_by_run(run.run_id)
                        if item.created_by == "llm_report_narrator"
                    ]
                    self.assertEqual(len(claims), 1)
                    self.assertIn(claims[0].evidence_id, resumed.evidence_ids)
                    self.assertEqual(narrator.calls, 0 if restart else 1)
                    if restart:
                        self.assertEqual(report, previous_report)
                        self.assertEqual(facts, previous_facts)
                    previous_report, previous_facts = report, facts
                finally:
                    stores.close()
                    budget.close()


if __name__ == "__main__":
    unittest.main()
