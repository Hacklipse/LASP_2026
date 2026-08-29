"""SQLite 저장소가 InMemory 저장소의 계약과 타입을 보존하는지 검증한다."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from hacklipse.adapters import SQLiteBudgetManager, SQLiteStoreBundle
from hacklipse.domain import (
    Candidate,
    Evidence,
    EvidenceRequest,
    Finding,
    HttpRequestKind,
    HttpRequestSpec,
    ReportArtifact,
    Run,
    RunPhase,
    RunScope,
    Surface,
    TaskEnvelope,
    TaskRecord,
    TaskStatus,
)
from hacklipse.ports.errors import (
    BudgetExceeded,
    DuplicateRecord,
    RecordNotFound,
)


class SQLiteStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.database_path = Path(self._temporary.name) / "hacklipse.sqlite3"
        self.stores = SQLiteStoreBundle(self.database_path)

    def tearDown(self) -> None:
        self.stores.close()
        self._temporary.cleanup()

    @staticmethod
    def _run() -> Run:
        return Run(
            run_id="run-1",
            target_url="http://localhost/index.php",
            scope=RunScope(
                allowed_hosts=frozenset({"localhost", "local.test"}),
                allowed_path_prefixes=("/", "/vulnerabilities/"),
            ),
            policy_profile="safe",
            request_budget=10,
            phase=RunPhase.RECON,
            evidence_ids=("evi-1",),
            surface_ids=("surface-1",),
        )

    @staticmethod
    def _task() -> TaskRecord:
        return TaskRecord(
            envelope=TaskEnvelope(
                task_id="task-1",
                run_id="run-1",
                agent_type="evidence_collector",
                target_url="http://localhost/index.php",
                surface_id="surface-1",
                evidence_ids=("evi-1",),
                finding_ids=("finding-1",),
                allowed_tools=("http_get",),
                request_budget=9,
                credential_ref="credential-local",
                evidence_request=EvidenceRequest(
                    evidence_type="page_fetch",
                    surface_id="surface-1",
                    reason="round trip",
                    suggested_tool="http_get",
                    http_request=HttpRequestSpec(
                        method="POST",
                        query_parameters=(("next", "/home"), ("id", "1"), ("id", "2")),
                        headers=(("Content-Type", "application/x-www-form-urlencoded"),),
                        body="name=테스트",
                        request_kind=HttpRequestKind.PROBE,
                    ),
                ),
            ),
            status=TaskStatus.RUNNING,
            attempts=2,
            error="retrying",
        )

    @staticmethod
    def _evidence(evidence_id: str = "evi-1") -> Evidence:
        return Evidence(
            evidence_id=evidence_id,
            run_id="run-1",
            surface_id="surface-1",
            created_by="execution_runtime:http_get",
            evidence_type="http_response",
            observation={
                "status": 200,
                "headers": [
                    ["set-cookie", "a=1"],
                    ["set-cookie", "b=2"],
                ],
                "body": "한글 응답",
                "truncated": False,
            },
            artifact_refs={"body": "artifact://body/1"},
            content_hash="abc123",
            created_at=datetime(2026, 8, 23, 1, 2, 3, tzinfo=timezone.utc),
        )

    @staticmethod
    def _surface() -> Surface:
        return Surface(
            surface_id="surface-1",
            run_id="run-1",
            url="http://localhost/search?q=한글",
            method="GET",
            parameters=("q", "page"),
            requires_auth=True,
        )

    @staticmethod
    def _candidate() -> Candidate:
        return Candidate(
            candidate_id="candidate-1",
            run_id="run-1",
            surface_id="surface-1",
            vulnerability_type="XSS",
            hypothesis="reflection in HTML",
            assigned_agent="xss_analyzer",
            evidence_ids=("evi-1",),
            status="analyzed",
        )

    @staticmethod
    def _finding() -> Finding:
        return Finding(
            finding_id="finding-1",
            run_id="run-1",
            candidate_id="candidate-1",
            validation_id="validation-1",
            vulnerability_type="XSS",
            surface_id="surface-1",
            evidence_ids=("evi-1",),
            severity="medium",
            remediation_refs=("OWASP-XSS",),
        )

    @staticmethod
    def _report() -> ReportArtifact:
        return ReportArtifact(
            report_id="report-1",
            run_id="run-1",
            format="markdown",
            content="# 결과\n\n확인됨\n",
        )

    def test_all_seven_stores_round_trip_after_reopen(self) -> None:
        run = self._run()
        task = self._task()
        evidence = self._evidence()
        surface = self._surface()
        candidate = self._candidate()
        finding = self._finding()
        report = self._report()

        self.stores.runs.add(run)
        self.stores.tasks.add(task)
        self.stores.evidence.append(evidence)
        self.stores.surfaces.add(surface)
        self.stores.candidates.add(candidate)
        self.stores.findings.add(finding)
        self.stores.reports.add(report)
        self.stores.close()

        self.stores = SQLiteStoreBundle(self.database_path)
        self.assertEqual(self.stores.runs.get("run-1"), run)
        self.assertEqual(self.stores.tasks.get("task-1"), task)
        self.assertEqual(self.stores.evidence.get("run-1", "evi-1"), evidence)
        self.assertEqual(self.stores.surfaces.get("run-1", "surface-1"), surface)
        self.assertEqual(
            self.stores.candidates.get("run-1", "candidate-1"), candidate
        )
        self.assertEqual(self.stores.findings.get("run-1", "finding-1"), finding)
        self.assertEqual(self.stores.reports.list_by_run("run-1"), (report,))

    def test_add_rejects_duplicate_and_save_requires_existing_record(self) -> None:
        run = self._run()
        self.stores.runs.add(run)
        with self.assertRaises(DuplicateRecord):
            self.stores.runs.add(run)
        with self.assertRaises(RecordNotFound):
            self.stores.runs.save(run.with_updates(run_id="run-missing"))
        with self.assertRaises(RecordNotFound):
            self.stores.tasks.save(self._task())
        with self.assertRaises(RecordNotFound):
            self.stores.candidates.save(self._candidate())

    def test_save_updates_mutable_store_records(self) -> None:
        run = self._run()
        task = self._task()
        candidate = self._candidate()
        self.stores.runs.add(run)
        self.stores.tasks.add(task)
        self.stores.candidates.add(candidate)

        updated_run = run.with_updates(phase=RunPhase.ROUTE)
        updated_task = task.with_status(TaskStatus.SUCCEEDED, attempts=3)
        updated_candidate = candidate.set_status("confirmed")
        self.stores.runs.save(updated_run)
        self.stores.tasks.save(updated_task)
        self.stores.candidates.save(updated_candidate)

        self.assertEqual(self.stores.runs.get("run-1"), updated_run)
        self.assertEqual(self.stores.tasks.get("task-1"), updated_task)
        self.assertEqual(
            self.stores.candidates.get("run-1", "candidate-1"), updated_candidate
        )

    def test_run_scoped_stores_hide_records_from_other_runs(self) -> None:
        self.stores.evidence.append(self._evidence())
        self.stores.surfaces.add(self._surface())
        self.stores.candidates.add(self._candidate())
        self.stores.findings.add(self._finding())

        for lookup in (
            lambda: self.stores.evidence.get("run-2", "evi-1"),
            lambda: self.stores.surfaces.get("run-2", "surface-1"),
            lambda: self.stores.candidates.get("run-2", "candidate-1"),
            lambda: self.stores.findings.get("run-2", "finding-1"),
        ):
            with self.assertRaises(RecordNotFound):
                lookup()

    def test_list_and_get_many_preserve_requested_order(self) -> None:
        first = self._evidence("evi-1")
        second = self._evidence("evi-2")
        self.stores.evidence.append(first)
        self.stores.evidence.append(second)

        self.assertEqual(self.stores.evidence.list_by_run("run-1"), (first, second))
        self.assertEqual(
            self.stores.evidence.get_many("run-1", ("evi-2", "evi-1")),
            (second, first),
        )

    def test_evidence_is_append_only_and_invalid_json_is_not_inserted(self) -> None:
        evidence = self._evidence()
        self.stores.evidence.append(evidence)
        with self.assertRaises(DuplicateRecord):
            self.stores.evidence.append(evidence)
        self.assertFalse(hasattr(self.stores.evidence, "save"))

        invalid = Evidence(
            evidence_id="evi-invalid",
            run_id="run-1",
            surface_id=None,
            created_by="fixture",
            evidence_type="invalid",
            observation={"unsupported": object()},
        )
        with self.assertRaises(ValueError):
            self.stores.evidence.append(invalid)
        with self.assertRaises(RecordNotFound):
            self.stores.evidence.get("run-1", "evi-invalid")


class SQLiteBudgetManagerTests(unittest.TestCase):
    def test_budget_is_atomic_and_persists_after_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "budget.sqlite3"
            budget = SQLiteBudgetManager(database_path)
            budget.open_run("run-1", 5)
            budget.consume("run-1", 2)
            budget.close()

            budget = SQLiteBudgetManager(database_path)
            self.assertEqual(budget.remaining("run-1"), 3)
            with self.assertRaises(BudgetExceeded):
                budget.consume("run-1", 4)
            self.assertEqual(budget.remaining("run-1"), 3)
            with self.assertRaises(DuplicateRecord):
                budget.open_run("run-1", 5)
            with self.assertRaises(RecordNotFound):
                budget.remaining("run-missing")
            budget.close()


if __name__ == "__main__":
    unittest.main()
