"""Phase 9-A Knowledge Plane의 일반화·저장·검색 경계를 검증한다."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hacklipse.adapters.knowledge import (
    knowledge_case_id,
    InMemoryKnowledgeBase,
    KnowledgeCaseFactory,
    SQLiteKnowledgeBase,
)
from hacklipse.adapters.sqlite_store import SQLiteStoreBundle
from hacklipse.domain import (
    Candidate,
    Evidence,
    Finding,
    KnowledgeCase,
    KnowledgeQuery,
    Surface,
)
from hacklipse.ports.errors import DuplicateRecord


class KnowledgeCaseFactoryTests(unittest.TestCase):
    @staticmethod
    def _surface(*, run_id: str = "run-1") -> Surface:
        return Surface(
            surface_id="surface-1",
            run_id=run_id,
            url=(
                "https://target.invalid/users/alice@example.test/"
                "123e4567-e89b-12d3-a456-426614174000?token=raw-secret#result"
            ),
            method="get",
            parameters=("q", "q", "unsafe parameter"),
            requires_auth=True,
        )

    @staticmethod
    def _candidate(
        *,
        run_id: str = "run-1",
        surface_id: str = "surface-1",
        status: str = "confirmed",
    ) -> Candidate:
        return Candidate(
            candidate_id="candidate-1",
            run_id=run_id,
            surface_id=surface_id,
            vulnerability_type="XSS",
            # 이 자유 텍스트는 KnowledgeCase에 절대 복사되면 안 된다.
            hypothesis="victim@example.test Authorization: Bearer raw-token",
            assigned_agent="xss_analyzer",
            evidence_ids=("evidence-1",),
            status=status,
        )

    @staticmethod
    def _finding(
        *,
        run_id: str = "run-1",
        finding_id: str = "finding-1",
        validation_id: str = "validation-1",
        candidate_id: str = "candidate-1",
        surface_id: str = "surface-1",
        vulnerability_type: str = "XSS",
    ) -> Finding:
        return Finding(
            finding_id=finding_id,
            run_id=run_id,
            candidate_id=candidate_id,
            validation_id=validation_id,
            vulnerability_type=vulnerability_type,
            surface_id=surface_id,
            evidence_ids=("evidence-1",),
            severity="high",
        )

    def test_generalizes_only_structured_confirmed_finding_fields(self) -> None:
        case = KnowledgeCaseFactory().from_finding(
            self._finding(), self._candidate(), self._surface()
        )

        # case_id는 일반화된 패턴에서 결정된다. 같은 Finding 재시도뿐 아니라 다른
        # Run에서 같은 패턴을 다시 확인해도 검색 가능한 Case가 늘어나지 않는다.
        again = KnowledgeCaseFactory().from_finding(
            self._finding(), self._candidate(), self._surface()
        )
        another_run = KnowledgeCaseFactory().from_finding(
            self._finding(
                run_id="run-2",
                finding_id="finding-2",
                validation_id="validation-2",
            ),
            self._candidate(run_id="run-2"),
            self._surface(run_id="run-2"),
        )
        self.assertEqual(case.case_id, again.case_id)
        self.assertEqual(case.case_id, another_run.case_id)
        self.assertEqual(
            case.case_id,
            knowledge_case_id(
                category=case.category,
                summary=case.summary,
                metadata=case.metadata,
            ),
        )
        self.assertEqual(case.category, "XSS")
        self.assertEqual(
            case.provenance_refs,
            ("run:run-1", "finding:finding-1", "validation:validation-1"),
        )
        self.assertEqual(case.metadata["surface_path"], "/users/{value}/{id}")
        self.assertEqual(case.metadata["parameter_names"], "q,{parameter}")
        self.assertEqual(case.metadata["parameter_count"], "2")
        self.assertEqual(case.metadata["surface_method"], "GET")
        self.assertEqual(case.metadata["requires_auth"], "true")
        serialized = repr(case)
        for raw_value in (
            "target.invalid",
            "raw-secret",
            "alice@example.test",
            "victim@example.test",
            "raw-token",
        ):
            self.assertNotIn(raw_value, serialized)

    def test_rejects_unconfirmed_or_unrelated_sources(self) -> None:
        factory = KnowledgeCaseFactory()

        with self.assertRaisesRegex(ValueError, "confirmed candidate"):
            factory.from_finding(
                self._finding(),
                self._candidate(status="analyzed"),
                self._surface(),
            )
        with self.assertRaisesRegex(ValueError, "same run"):
            factory.from_finding(
                self._finding(),
                self._candidate(),
                self._surface(run_id="run-other"),
            )
        with self.assertRaisesRegex(ValueError, "reference its candidate"):
            factory.from_finding(
                self._finding(candidate_id="candidate-other"),
                self._candidate(),
                self._surface(),
            )

    def test_rejects_vulnerability_without_a_structured_proof_type(self) -> None:
        candidate = Candidate(
            candidate_id="candidate-1",
            run_id="run-1",
            surface_id="surface-1",
            vulnerability_type="Unknown",
            hypothesis="generic",
            assigned_agent="unknown_analyzer",
            evidence_ids=("evidence-1",),
            status="confirmed",
        )
        with self.assertRaisesRegex(ValueError, "supported vulnerability proof type"):
            KnowledgeCaseFactory().from_finding(
                self._finding(vulnerability_type="Unknown"),
                candidate,
                self._surface(),
            )

    def test_preserves_only_structured_parameters_that_produced_a_probe_signal(self) -> None:
        surface = Surface(
            surface_id="surface-1",
            run_id="run-1",
            url="https://target.invalid/dataerasure",
            method="POST",
            parameters=("email", "securityAnswer"),
        )
        candidate = Candidate(
            candidate_id="candidate-1",
            run_id="run-1",
            surface_id="surface-1",
            vulnerability_type="Path Traversal",
            hypothesis="server render parameter",
            assigned_agent="path_traversal_analyzer",
            evidence_ids=("evidence-layout", "evidence-unrelated"),
            status="confirmed",
        )
        finding = self._finding(vulnerability_type="Path Traversal")
        evidence = (
            Evidence(
                evidence_id="evidence-layout",
                run_id="run-1",
                surface_id="surface-1",
                created_by="llm_path_traversal_analyzer",
                evidence_type="observation",
                observation={
                    "type": "path_traversal_file_read",
                    "parameter": "layout",
                },
            ),
            Evidence(
                evidence_id="evidence-unrelated",
                run_id="run-1",
                surface_id="surface-1",
                created_by="recon",
                evidence_type="observation",
                observation={"type": "reflection", "parameter": "email"},
            ),
        )

        factory = KnowledgeCaseFactory()
        original = factory.from_finding(finding, candidate, surface)
        case = factory.from_finding(finding, candidate, surface, evidence)

        self.assertEqual(case.case_id, original.case_id)
        self.assertEqual(case.metadata["signal_parameter_names"], "layout")
        self.assertEqual(case.metadata["parameter_names"], "email,securityAnswer")


class KnowledgeBaseContractTests(unittest.TestCase):
    @staticmethod
    def _case(
        case_id: str,
        *,
        provenance_id: str | None = None,
        category: str = "XSS",
        summary: str = "Confirmed XSS using independent execution validation.",
        proof_type: str = "xss_execution",
    ) -> KnowledgeCase:
        source = provenance_id or case_id
        return KnowledgeCase(
            case_id=case_id,
            category=category,
            summary=summary,
            provenance_refs=(
                f"run:{source}",
                f"finding:{source}",
                f"validation:{source}",
            ),
            metadata={
                "proof_type": proof_type,
                "surface_method": "GET",
                "surface_path": "/search",
            },
        )

    def test_memory_store_is_append_only_and_copies_mutable_metadata(self) -> None:
        knowledge = InMemoryKnowledgeBase()
        metadata = {
            "proof_type": "xss_execution",
            "surface_path": "/search",
        }
        case = KnowledgeCase(
            case_id="case-1",
            category="XSS",
            summary="Confirmed XSS using independent execution validation.",
            provenance_refs=("run:run-1", "finding:finding-1", "validation:validation-1"),
            metadata=metadata,
        )
        knowledge.publish(case)
        metadata["surface_path"] = "/changed"

        stored = knowledge.search(KnowledgeQuery(category="xss", text="execution"))
        self.assertEqual(stored[0].metadata["surface_path"], "/search")
        with self.assertRaises(DuplicateRecord):
            knowledge.publish(case)

    def test_signal_parameter_enriches_existing_case_without_changing_identity(self) -> None:
        knowledge = InMemoryKnowledgeBase()
        original = self._case("case-pattern", provenance_id="run-1")
        enriched = KnowledgeCase(
            case_id=original.case_id,
            category=original.category,
            summary=original.summary,
            provenance_refs=("run:run-2", "finding:run-2", "validation:run-2"),
            metadata={**original.metadata, "signal_parameter_names": "layout"},
        )

        knowledge.publish(original)
        knowledge.publish(enriched)

        stored = knowledge.search(KnowledgeQuery(category="XSS", text=""))
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0].metadata["signal_parameter_names"], "layout")
        self.assertEqual(
            knowledge_case_id(
                category=enriched.category,
                summary=enriched.summary,
                metadata=enriched.metadata,
            ),
            knowledge_case_id(
                category=original.category,
                summary=original.summary,
                metadata=original.metadata,
            ),
        )

    def test_search_is_category_scoped_ranked_and_stable(self) -> None:
        knowledge = InMemoryKnowledgeBase()
        knowledge.publish(
            self._case("case-1", summary="Confirmed XSS using browser validation.")
        )
        knowledge.publish(
            self._case(
                "case-2",
                summary="Confirmed XSS using browser independent validation.",
            )
        )
        knowledge.publish(
            self._case(
                "case-3",
                category="SQLi",
                summary="Confirmed SQLi using browser execution validation.",
                proof_type="sqli_effect",
            )
        )

        result = knowledge.search(
            KnowledgeQuery(category="XSS", text="browser independent", limit=2)
        )
        self.assertEqual(tuple(case.case_id for case in result), ("case-2", "case-1"))
        all_xss = knowledge.search(KnowledgeQuery(category="xss", text="", limit=10))
        self.assertEqual(tuple(case.case_id for case in all_xss), ("case-1", "case-2"))
        self.assertEqual(
            knowledge.search(KnowledgeQuery(category="XSS", text="unrelated")), ()
        )

    def test_same_pattern_from_another_run_keeps_one_case_and_both_provenances(
        self,
    ) -> None:
        knowledge = InMemoryKnowledgeBase()
        first = self._case("case-pattern", provenance_id="run-1")
        second = self._case("case-pattern", provenance_id="run-2")

        knowledge.publish(first)
        knowledge.publish(second)

        cases = knowledge.search(KnowledgeQuery(category="XSS", text="", limit=10))
        self.assertEqual(len(cases), 1)
        self.assertIn("run:run-1", cases[0].provenance_refs)
        self.assertIn("run:run-2", cases[0].provenance_refs)
        with self.assertRaises(DuplicateRecord):
            knowledge.publish(second)

    def test_publication_rejects_sensitive_or_untraceable_cases(self) -> None:
        knowledge = InMemoryKnowledgeBase()
        sensitive = KnowledgeCase(
            case_id="case-sensitive",
            category="XSS",
            summary="Contact victim@example.test for the confirmed result.",
            provenance_refs=("run:run-1", "finding:finding-1", "validation:validation-1"),
        )
        missing_validation = KnowledgeCase(
            case_id="case-untraceable",
            category="XSS",
            summary="Confirmed XSS using independent execution validation.",
            provenance_refs=("run:run-1", "finding:finding-1"),
        )

        with self.assertRaisesRegex(ValueError, "sensitive"):
            knowledge.publish(sensitive)
        with self.assertRaisesRegex(ValueError, "include run, finding, and validation"):
            knowledge.publish(missing_validation)

    def test_query_limits_are_enforced(self) -> None:
        knowledge = InMemoryKnowledgeBase()
        for query in (
            KnowledgeQuery(category="", text="x"),
            KnowledgeQuery(category="XSS", text="x", limit=0),
            KnowledgeQuery(category="XSS", text="x", limit=101),
        ):
            with self.subTest(query=query), self.assertRaises(ValueError):
                knowledge.search(query)


class SQLiteKnowledgeBaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.database_path = Path(self._temporary.name) / "hacklipse.sqlite3"

    def tearDown(self) -> None:
        self._temporary.cleanup()

    @staticmethod
    def _case() -> KnowledgeCase:
        return KnowledgeCase(
            case_id="case-persisted",
            category="Path Traversal",
            summary=(
                "Confirmed Path Traversal using independent file read validation."
            ),
            provenance_refs=("run:run-1", "finding:finding-1", "validation:validation-1"),
            metadata={
                "proof_type": "path_traversal_file_read",
                "surface_method": "GET",
                "surface_path": "/download",
            },
        )

    def test_persists_across_reopen_and_rejects_duplicate(self) -> None:
        with SQLiteKnowledgeBase(self.database_path) as knowledge:
            knowledge.publish(self._case())
            with self.assertRaises(DuplicateRecord):
                knowledge.publish(self._case())

        with SQLiteKnowledgeBase(self.database_path) as reopened:
            result = reopened.search(
                KnowledgeQuery(category="path traversal", text="file read")
            )
        self.assertEqual(result, (self._case(),))

    def test_persists_multiple_observations_without_duplicating_the_case(self) -> None:
        first = self._case()
        second = KnowledgeCase(
            case_id=first.case_id,
            category=first.category,
            summary=first.summary,
            provenance_refs=(
                "run:run-2",
                "finding:finding-2",
                "validation:validation-2",
            ),
            metadata=first.metadata,
        )
        with SQLiteKnowledgeBase(self.database_path) as knowledge:
            knowledge.publish(first)
            knowledge.publish(second)

        with SQLiteKnowledgeBase(self.database_path) as reopened:
            result = reopened.search(
                KnowledgeQuery(category="Path Traversal", text="validation")
            )

        self.assertEqual(len(result), 1)
        self.assertIn("run:run-1", result[0].provenance_refs)
        self.assertIn("run:run-2", result[0].provenance_refs)

    def test_existing_case_is_enriched_when_same_observation_is_republished(self) -> None:
        original = self._case()
        enriched = KnowledgeCase(
            case_id=original.case_id,
            category=original.category,
            summary=original.summary,
            provenance_refs=original.provenance_refs,
            metadata={**original.metadata, "signal_parameter_names": "layout"},
        )
        with SQLiteKnowledgeBase(self.database_path) as knowledge:
            knowledge.publish(original)
            with self.assertRaises(DuplicateRecord):
                knowledge.publish(enriched)

        with SQLiteKnowledgeBase(self.database_path) as reopened:
            cases = reopened.search(
                KnowledgeQuery(category="Path Traversal", text="")
            )

        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0].metadata["signal_parameter_names"], "layout")

    def test_coexists_with_existing_store_bundle_schema(self) -> None:
        stores = SQLiteStoreBundle(self.database_path)
        try:
            with SQLiteKnowledgeBase(self.database_path) as knowledge:
                knowledge.publish(self._case())
                self.assertEqual(
                    knowledge.search(
                        KnowledgeQuery(category="Path Traversal", text="validation")
                    ),
                    (self._case(),),
                )
        finally:
            stores.close()

        # 기존 schema_version 검사와 Store 초기화가 Knowledge 전용 테이블 때문에
        # 깨지지 않는지 재개방으로 확인한다.
        reopened_stores = SQLiteStoreBundle(self.database_path)
        reopened_stores.close()


if __name__ == "__main__":
    unittest.main()
