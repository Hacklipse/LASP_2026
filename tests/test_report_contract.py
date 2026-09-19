"""Store/LLM 없이 공통 facts와 캐시 키의 안정성·안전성을 검증한다."""

from dataclasses import FrozenInstanceError, replace
import json
import unittest

from hacklipse.adapters.report_contract import (
    CONTRACT_VERSION, MAX_PATH_HINT_LENGTH, PROOF_DESCRIPTIONS,
    FindingReportFact, NarratorFingerprintConfig, RunReportFacts,
    finding_fact_id, report_facts_hash, report_input_fingerprint,
    serialize_report_facts, surface_path_hint,
)
from hacklipse.domain import CandidateStatus, ValidationProofType


def example_facts() -> RunReportFacts:
    return RunReportFacts(
        run_id="run-1", format_version="v2",
        candidate_counts=tuple((status, int(status is CandidateStatus.CONFIRMED)) for status in CandidateStatus),
        findings=(FindingReportFact(
            fact_id="finding:one", finding_id="finding-1", vulnerability_type="XSS",
            surface_path_hint="/users/{value}", proof_type=ValidationProofType.XSS_EXECUTION,
            reproduction_count=2,
        ),),
        request_budget_total=20, request_budget_used=3, surface_count=1, parameter_count=1,
    )


class ReportContractTests(unittest.TestCase):
    def test_serialization_contract_has_explicit_fields_and_order(self):
        facts = example_facts()
        payload = json.loads(serialize_report_facts(facts))
        self.assertEqual(CONTRACT_VERSION, "report-facts-v1")
        self.assertEqual(payload, {
            "contract_version": "report-facts-v1", "run_id": "run-1", "format_version": "v2",
            "fact_ids": ["run:scope", "run:request-budget",
                         "run:candidates:routed", "run:candidates:analyzed",
                         "run:candidates:confirmed", "run:candidates:suspected",
                         "run:candidates:rejected", "run:candidates:blocked",
                         "run:candidates:failed", "run:candidates:skipped_budget", "finding:one"],
            "candidate_counts": [["routed", 0], ["analyzed", 0], ["confirmed", 1],
                                 ["suspected", 0], ["rejected", 0], ["blocked", 0],
                                 ["failed", 0], ["skipped_budget", 0]],
            "findings": [{
                "fact_id": "finding:one", "finding_id": "finding-1", "vulnerability_type": "XSS",
                "surface_path_hint": "/users/{value}", "proof_type": "xss_execution",
                "reproduction_count": 2,
                "proof_description": "독립 browser control/probe 비교에서 probe 실행 신호 확인",
            }],
            "request_budget_total": 20, "request_budget_used": 3,
            "surface_count": 1, "parameter_count": 1,
        })
        self.assertEqual(serialize_report_facts(facts), json.dumps(
            payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")))
        self.assertEqual(report_facts_hash(facts), "bab3904f0ed279e884428b67fe3add3ce9692129ab6af3812b6c17c7495059c2")
        self.assertEqual(report_input_fingerprint(facts), "88624c4254a0440d31eb439d7968b91a3e39dd4e2923dd6fa8c829e3d58251e5")

    def test_input_order_does_not_change_json_or_fingerprint(self):
        facts = example_facts()
        other = replace(facts.findings[0], finding_id="finding-2", fact_id="finding:two")
        forward = replace(facts, findings=(*facts.findings, other))
        reverse = replace(facts, findings=(other, *facts.findings), candidate_counts=tuple(reversed(facts.candidate_counts)))
        self.assertEqual(serialize_report_facts(forward), serialize_report_facts(reverse))
        self.assertEqual(report_input_fingerprint(forward), report_input_fingerprint(reverse))
        with self.assertRaises(FrozenInstanceError):
            facts.run_id = "changed"

    def test_every_fact_value_affects_the_cache_key(self):
        facts = example_facts()
        changes = [
            replace(facts, run_id="run-2"), replace(facts, request_budget_total=21),
            replace(facts, request_budget_used=4), replace(facts, request_budget_used=None),
            replace(facts, surface_count=2), replace(facts, parameter_count=2),
            replace(facts, candidate_counts=tuple((s, c + int(s is CandidateStatus.FAILED)) for s, c in facts.candidate_counts)),
        ]
        for update in (
            {"finding_id": "finding-2"}, {"fact_id": "finding:two"},
            {"vulnerability_type": "SQLi"}, {"surface_path_hint": "/search"},
            {"proof_type": ValidationProofType.SQLI_EFFECT}, {"reproduction_count": 3},
            {"proof_type": None, "reproduction_count": 0},
        ):
            changes.append(replace(facts, findings=(replace(facts.findings[0], **update),)))
        for changed in changes:
            with self.subTest(changed=changed):
                self.assertNotEqual(report_input_fingerprint(facts), report_input_fingerprint(changed))
                self.assertNotEqual(report_facts_hash(facts), report_facts_hash(changed))

    def test_only_explicit_narrator_settings_enter_fingerprint(self):
        facts = example_facts()
        config = NarratorFingerprintConfig(model="test-model", prompt_version="v1")
        original_hash = report_facts_hash(facts)
        for key, value in (
            ("model", "other-model"), ("prompt_version", "v2"), ("max_output_tokens", 1500),
            ("temperature", 0.5), ("run_summary_max_chars", 700), ("finding_summary_max_chars", 300),
        ):
            self.assertNotEqual(report_input_fingerprint(facts, config),
                                report_input_fingerprint(facts, replace(config, **{key: value})))
        self.assertNotEqual(report_input_fingerprint(facts), report_input_fingerprint(facts, config))
        self.assertEqual(report_facts_hash(facts), original_hash)
        self.assertEqual(report_input_fingerprint(facts, config), report_input_fingerprint(facts, replace(config, temperature=0)))
        with self.assertRaises(TypeError):
            NarratorFingerprintConfig(model="m", prompt_version="v1", api_key="secret")
        for temperature in (float("nan"), float("inf"), -1, True):
            with self.assertRaises(ValueError):
                replace(config, temperature=temperature)

    def test_missing_duplicate_or_untyped_statuses_are_rejected(self):
        facts = example_facts()
        for counts in (
            facts.candidate_counts[:-1], facts.candidate_counts + (facts.candidate_counts[0],),
            tuple((s.value, c) for s, c in facts.candidate_counts),
            tuple((s, -1) for s, _ in facts.candidate_counts),
        ):
            with self.assertRaises(ValueError):
                replace(facts, candidate_counts=counts)
        for update in ({"format_version": "v1"}, {"request_budget_used": 21},
                       {"surface_count": True}, {"findings": facts.findings * 2}):
            with self.assertRaises(ValueError):
                replace(facts, **update)

    def test_legacy_proof_does_not_claim_reproduction(self):
        finding = example_facts().findings[0]
        old = replace(finding, proof_type=None, reproduction_count=0)
        self.assertEqual(old.proof_description, "검증 상세를 사용할 수 없음")
        for update in ({"proof_type": None}, {"reproduction_count": 0}, {"proof_type": "xss_execution"}):
            with self.assertRaises(ValueError):
                replace(finding, **update)
        self.assertEqual(set(PROOF_DESCRIPTIONS), set(ValidationProofType))

    def test_paths_are_generalized_bounded_and_idempotent(self):
        examples = {
            "https://user:password@example.test/users/123?token=secret#marker": "/users/{value}",
            "/objects/550e8400-e29b-41d4-a716-446655440000": "/objects/{value}",
            "/files/" + "a" * 80: "/files/{value}",
            "/%3Cscript%3E/%252fsecret": "/{value}/{value}",
            "/reset/token/shortsecret": "/reset/{value}/{value}",
            "/search/abCDEfGhIJ": "/search/{value}",
            "/api/../search": "/api/{value}/search",
            "/search?q=payload": "/search",
            "http://[malformed": "/{value}",
        }
        for raw, expected in examples.items():
            with self.subTest(raw=raw):
                hint = surface_path_hint(raw)
                self.assertEqual(hint, expected)
                self.assertEqual(surface_path_hint(hint), hint)
        hint = surface_path_hint("/search" * 100)
        self.assertLessEqual(len(hint), MAX_PATH_HINT_LENGTH)
        self.assertEqual(surface_path_hint(hint), hint)
        with self.assertRaises(ValueError):
            replace(example_facts().findings[0], surface_path_hint="/users/123?secret=yes")

    def test_fact_ids_are_stable_and_separate_from_run_facts(self):
        self.assertEqual(finding_fact_id("finding-1"), finding_fact_id("finding-1"))
        self.assertNotEqual(finding_fact_id("finding-1"), finding_fact_id("finding-2"))
        with self.assertRaises(ValueError):
            replace(example_facts().findings[0], fact_id="run:scope")


if __name__ == "__main__":
    unittest.main()
