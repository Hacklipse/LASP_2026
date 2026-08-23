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


if __name__ == "__main__":
    unittest.main()
