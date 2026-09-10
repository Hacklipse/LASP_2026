"""Knowledge 검색 결과가 현재 Run의 Evidence와 분리되는 계약을 검증한다."""

from __future__ import annotations

import unittest

from hacklipse.adapters import InMemoryKnowledgeBase
from hacklipse.application import KnowledgeContextProvider
from hacklipse.domain import Candidate, KnowledgeCase, Surface


def _case(
    *, case_id: str, category: str = "SQLi", run_id: str = "run-prior"
) -> KnowledgeCase:
    proof_type = "sqli_effect" if category == "SQLi" else "xss_execution"
    return KnowledgeCase(
        case_id=case_id,
        category=category,
        summary=(
            f"Confirmed {category} on an unauthenticated GET parameterized surface "
            f"using independent {proof_type} validation."
        ),
        provenance_refs=(
            f"run:{run_id}",
            f"finding:finding-{run_id}",
            f"validation:validation-{run_id}",
        ),
        metadata={
            "parameter_count": "1",
            "parameter_names": "q",
            "proof_type": proof_type,
            "requires_auth": "false",
            "severity": "unrated",
            "surface_kind": "parameterized",
            "surface_method": "GET",
            "surface_path": "/rest/products/search",
        },
    )


def _candidate(run_id: str = "run-current") -> Candidate:
    return Candidate(
        candidate_id="candidate-current",
        run_id=run_id,
        surface_id="surface-current",
        vulnerability_type="SQLi",
        hypothesis="parameterized search surface",
        assigned_agent="sqli_analyzer",
        evidence_ids=(),
    )


def _surface(run_id: str = "run-current") -> Surface:
    return Surface(
        surface_id="surface-current",
        run_id=run_id,
        url="http://current.test/rest/products/search?q=ignored",
        method="GET",
        parameters=("q",),
    )


class KnowledgeContextProviderTests(unittest.TestCase):
    def test_related_prior_case_becomes_a_provenance_free_hint(self) -> None:
        knowledge = InMemoryKnowledgeBase()
        knowledge.publish(_case(case_id="case-related"))
        knowledge.publish(_case(case_id="case-other-category", category="XSS"))
        provider = KnowledgeContextProvider(knowledge, limit=3)

        hints = provider.for_candidate(_candidate(), _surface())

        self.assertEqual(tuple(item.case_id for item in hints), ("case-related",))
        self.assertEqual(hints[0].category, "SQLi")
        self.assertEqual(hints[0].metadata["surface_path"], "/rest/products/search")
        self.assertFalse(hasattr(hints[0], "provenance_refs"))

    def test_current_run_case_is_not_fed_back_into_its_own_analysis(self) -> None:
        knowledge = InMemoryKnowledgeBase()
        knowledge.publish(
            _case(case_id="case-current", run_id="run-current")
        )
        provider = KnowledgeContextProvider(knowledge)

        self.assertEqual(provider.for_candidate(_candidate(), _surface()), ())

    def test_same_category_and_common_tokens_do_not_make_a_case_related(self) -> None:
        knowledge = InMemoryKnowledgeBase()
        knowledge.publish(_case(case_id="case-search"))
        provider = KnowledgeContextProvider(knowledge)
        unrelated = Surface(
            surface_id="surface-current",
            run_id="run-current",
            url="http://current.test/profile?q=ignored",
            method="GET",
            parameters=("q",),
        )

        self.assertEqual(provider.for_candidate(_candidate(), unrelated), ())

    def test_confirmed_signal_parameter_can_relate_a_different_path(self) -> None:
        knowledge = InMemoryKnowledgeBase()
        knowledge.publish(
            KnowledgeCase(
                case_id="case-signal",
                category="Path Traversal",
                summary=(
                    "Confirmed Path Traversal on an unauthenticated POST parameterized "
                    "surface using independent path_traversal_file_read validation."
                ),
                provenance_refs=(
                    "run:run-prior",
                    "finding:finding-prior",
                    "validation:validation-prior",
                ),
                metadata={
                    "parameter_names": "layout",
                    "proof_type": "path_traversal_file_read",
                    "requires_auth": "false",
                    "signal_parameter_names": "layout",
                    "surface_method": "POST",
                    "surface_path": "/dataerasure",
                },
            )
        )
        provider = KnowledgeContextProvider(knowledge)
        candidate = Candidate(
            candidate_id="candidate-current",
            run_id="run-current",
            surface_id="surface-current",
            vulnerability_type="Path Traversal",
            hypothesis="render input",
            assigned_agent="path_traversal_analyzer",
            evidence_ids=(),
        )
        surface = Surface(
            surface_id="surface-current",
            run_id="run-current",
            url="http://current.test/account/export",
            method="POST",
            parameters=("layout",),
        )

        hints = provider.for_candidate(candidate, surface)

        self.assertEqual(tuple(item.case_id for item in hints), ("case-signal",))

    def test_candidate_and_surface_must_share_run_and_identity(self) -> None:
        provider = KnowledgeContextProvider(InMemoryKnowledgeBase())

        with self.assertRaises(ValueError):
            provider.for_candidate(_candidate(), _surface("run-other"))

        wrong_surface = Surface(
            surface_id="surface-other",
            run_id="run-current",
            url="http://current.test/search",
            method="GET",
            parameters=("q",),
        )
        with self.assertRaises(ValueError):
            provider.for_candidate(_candidate(), wrong_surface)

    def test_search_does_not_send_target_values_to_the_store(self) -> None:
        class RecordingKnowledgeBase:
            def __init__(self) -> None:
                self.query = None

            def publish(self, case) -> None:
                del case

            def search(self, query):
                self.query = query
                return ()

        knowledge = RecordingKnowledgeBase()
        provider = KnowledgeContextProvider(knowledge)
        surface = Surface(
            surface_id="surface-current",
            run_id="run-current",
            url="http://private.test/users/317/export?q=secret-value",
            method="GET",
            parameters=("q",),
        )

        provider.for_candidate(_candidate(), surface)

        assert knowledge.query is not None
        self.assertEqual(knowledge.query.text, "")
        self.assertNotIn("private.test", knowledge.query.text)
        self.assertNotIn("317", knowledge.query.text)
        self.assertNotIn("secret-value", knowledge.query.text)


if __name__ == "__main__":
    unittest.main()
