"""SQLite 저장소가 InMemory 저장소의 계약과 타입을 보존하는지 검증한다."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from hacklipse.adapters import SQLiteBudgetManager, SQLiteStoreBundle
from hacklipse.domain import (
    AccessIdentifierLocation,
    AccessPrincipalRole,
    Candidate,
    Evidence,
    EvidenceRequest,
    Finding,
    HttpRequestKind,
    HttpRequestSpec,
    KnowledgeHint,
    ReportArtifact,
    Run,
    RunExecutionProfile,
    RunPhase,
    RunScope,
    Surface,
    TaskEnvelope,
    TaskRecord,
    TaskStatus,
    ValidationProofType,
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
            execution_profile=RunExecutionProfile(
                analysis_profile="llm",
                recon_mode="hybrid",
                surface_collection_mode="deterministic",
                router_mode="hybrid",
                router_review="ambiguous",
                compare_routers=True,
                orchestrator_mode="hybrid",
                budget_allocation_mode="hybrid",
                validation_mode="llm",
                report_mode="llm",
                llm_provider="gemini",
                llm_model="gemini-2.5-flash",
                llm_rpm_limit=14,
            ),
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
                knowledge_hints=(
                    KnowledgeHint(
                        case_id="case-prior-xss",
                        category="XSS",
                        summary="Confirmed generalized reflection pattern.",
                        metadata={"surface_method": "GET"},
                    ),
                ),
                finding_ids=("finding-1",),
                allowed_tools=("http_get",),
                request_budget=9,
                credential_ref="credential-local",
                validation_id="validation-1",
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
                        request_kind=HttpRequestKind.CONTROL,
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
            source_task_id="task-1",
            validation_id="validation-1",
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

    def test_legacy_run_without_execution_profile_uses_safe_defaults(self) -> None:
        self.stores.runs.add(self._run())
        self.stores.close()

        # P-2 이전 Run JSON에는 실행 조건이 없었다. 기존 DB는 schema
        # version을 올리거나 내려쓰지 않고 결정적 기본값으로 열린다.
        with sqlite3.connect(self.database_path) as connection:
            row = connection.execute(
                "SELECT data FROM runs WHERE run_id = ?", ("run-1",)
            ).fetchone()
            assert row is not None
            stored = json.loads(row[0])
            stored.pop("execution_profile")
            connection.execute(
                "UPDATE runs SET data = ? WHERE run_id = ?",
                (json.dumps(stored), "run-1"),
            )

        self.stores = SQLiteStoreBundle(self.database_path)
        self.assertEqual(
            self.stores.runs.get("run-1").execution_profile,
            RunExecutionProfile(recorded=False),
        )

    def test_older_execution_profile_defaults_to_adaptive_collection(self) -> None:
        self.stores.runs.add(self._run())
        self.stores.close()

        # P-1 이전에 저장된 P-2 profile에는 수집 정책 필드만 없다.
        with sqlite3.connect(self.database_path) as connection:
            row = connection.execute(
                "SELECT data FROM runs WHERE run_id = ?", ("run-1",)
            ).fetchone()
            assert row is not None
            stored = json.loads(row[0])
            stored["execution_profile"].pop("surface_collection_mode")
            connection.execute(
                "UPDATE runs SET data = ? WHERE run_id = ?",
                (json.dumps(stored), "run-1"),
            )

        self.stores = SQLiteStoreBundle(self.database_path)
        restored = self.stores.runs.get("run-1")
        self.assertTrue(restored.execution_profile.recorded)
        self.assertEqual(
            restored.execution_profile.surface_collection_mode,
            "adaptive",
        )

    def test_finding_proof_facts_round_trip_and_legacy_json_defaults(self) -> None:
        proved = replace(
            self._finding(),
            proof_type=ValidationProofType.XSS_EXECUTION,
            reproduction_count=2,
        )
        legacy = replace(self._finding(), finding_id="finding-legacy")
        self.stores.findings.add(proved)
        self.stores.findings.add(legacy)
        self.stores.close()

        # 예전 DB의 Finding JSON에는 두 필드가 아예 없었다. schema version은 그대로다.
        with sqlite3.connect(self.database_path) as connection:
            row = connection.execute(
                "SELECT data FROM findings WHERE finding_id = ?", ("finding-legacy",)
            ).fetchone()
            assert row is not None
            stored = json.loads(row[0])
            stored.pop("proof_type")
            stored.pop("reproduction_count")
            connection.execute(
                "UPDATE findings SET data = ? WHERE finding_id = ?",
                (json.dumps(stored), "finding-legacy"),
            )

        self.stores = SQLiteStoreBundle(self.database_path)
        restored = self.stores.findings.get("run-1", "finding-1")
        old_restored = self.stores.findings.get("run-1", "finding-legacy")
        self.assertEqual(restored, proved)
        self.assertIs(restored.proof_type, ValidationProofType.XSS_EXECUTION)
        self.assertIsNone(old_restored.proof_type)
        self.assertEqual(old_restored.reproduction_count, 0)

    def test_access_control_path_request_and_role_survive_task_resume(self) -> None:
        task = TaskRecord(
            envelope=TaskEnvelope(
                task_id="task-access-path",
                run_id="run-1",
                agent_type="evidence_collector",
                target_url="http://local.test/users/2",
                surface_id="surface-1",
                allowed_tools=("access_control_probe",),
                evidence_request=EvidenceRequest(
                    evidence_type="http_response",
                    surface_id="surface-1",
                    reason="owner control",
                    suggested_tool="access_control_probe",
                    principal_role=AccessPrincipalRole.OWNER,
                    http_request=HttpRequestSpec(
                        request_kind=HttpRequestKind.ACCESS_CONTROL_PROBE,
                        identifier_parameter="user_id",
                        identifier_location=AccessIdentifierLocation.PATH,
                        path_identifier_index=2,
                        path_identifier_value="1",
                    ),
                ),
            )
        )
        self.stores.tasks.add(task)
        self.stores.close()

        self.stores = SQLiteStoreBundle(self.database_path)
        restored = self.stores.tasks.get("task-access-path")

        self.assertEqual(restored, task)
        self.assertIs(
            restored.envelope.evidence_request.principal_role,
            AccessPrincipalRole.OWNER,
        )
        self.assertIs(
            restored.envelope.evidence_request.http_request.identifier_location,
            AccessIdentifierLocation.PATH,
        )

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
