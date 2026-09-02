"""SQLite 재접속 후 활성 Run과 요청 예산을 함께 재개하는지 검증한다."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hacklipse.adapters import ReconAgent, SQLiteBudgetManager, SQLiteStoreBundle
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    ExecutionRequest,
    ExecutionResult,
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


if __name__ == "__main__":
    unittest.main()
