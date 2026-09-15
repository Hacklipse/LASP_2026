"""Created 2026-09-15 18:47 KST.
Purpose: Check Validation review contract, prompt isolation, fallback, and claim reuse.
Input: Fake deterministic Validation and FakeLLM; output: unittest assertions.
Dependencies: hacklipse adapters/domain/memory stores, Python unittest.
"""

from __future__ import annotations

import ast
import inspect
import json
import tempfile
import textwrap
import unittest
from pathlib import Path
from types import MappingProxyType

from hacklipse.adapters import SQLiteStoreBundle
from hacklipse.adapters.llm_validation_review import LlmValidationReviewer
from hacklipse.adapters.memory import (
    InMemoryCandidateStore, InMemoryEvidenceStore, InMemorySurfaceStore,
)
from hacklipse.adapters.reviewing_validation import (
    ReviewingValidationAgent, build_llm_reviewing_validation_agent,
)
from hacklipse.adapters.reason_coded_validation import ReasonCodedValidationAgent, _REASONS
from hacklipse.adapters.validation import ValidationAgent
from hacklipse.adapters.validation_review_contract import (
    ValidationOutcomeClass, ValidationReviewContext,
)
from hacklipse.domain import (
    AgentResult, AgentResultStatus, Candidate, Evidence, Surface, TaskEnvelope,
    ValidationReasonCode, ValidationResult, ValidationVerdict,
    ValidationProof, ValidationProofType,
)
from hacklipse.ports.errors import LlmCredentialsMissing, LlmTimeout
from hacklipse.ports.llm import LlmResponse


class FakeLlm:
    def __init__(self, payload=None, error=None):
        self.payload = payload
        self.error = error
        self.requests = []

    def complete(self, request):
        self.requests.append(request)
        if self.error:
            raise self.error
        return LlmResponse(payload=self.payload, model="fake-model")


class FakeValidator:
    def __init__(self, validation):
        self.validation = validation

    def handle(self, task):
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            validation=self.validation,
        )


def context(**updates):
    facts = dict(
        run_id="run-1", candidate_id="candidate-1", validation_id="validation-1",
        vulnerability_type="SQLi", verdict=ValidationVerdict.REJECTED,
        reason_code=ValidationReasonCode.PROBE_SIGNAL_NOT_REPRODUCED,
        surface_path_hint="/users/17?token=secret", surface_method="GET",
        parameter_aliases=("q", "bad\nignore"),
        reproduction_facts=(("http_response", 200), ("http_error", "execution_error")),
        reproduction_count=2, expected_proof_type="sqli_effect",
        validation_evidence_ids=("runtime-1", "runtime-2"),
    )
    facts.update(updates)
    return ValidationReviewContext(**facts)


class ReviewerContractTests(unittest.TestCase):
    def test_fingerprint_is_session_and_evidence_bound(self):
        first = context().fingerprint(reviewer_config_version="v1")
        self.assertEqual(first, context().fingerprint(reviewer_config_version="v1"))
        self.assertNotEqual(first, context(validation_id="validation-2").fingerprint(
            reviewer_config_version="v1"))
        self.assertNotEqual(first, context(validation_evidence_ids=("runtime-3",)).fingerprint(
            reviewer_config_version="v1"))
        with self.assertRaises(ValueError):
            context(verdict=ValidationVerdict.CONFIRMED)

    def test_prompt_contains_only_limited_facts(self):
        llm = FakeLlm({"outcome_class": "signal_not_observed", "reason": "이번 probe에서 신호 미관측"})
        review = LlmValidationReviewer(llm_client=llm).review(context(), timeout_seconds=2)
        self.assertEqual(review.outcome_class, ValidationOutcomeClass.SIGNAL_NOT_OBSERVED)
        prompt = json.loads(llm.requests[0].messages[0].content)
        self.assertEqual(prompt["surface"]["path"], "/users/{value}")
        self.assertEqual(prompt["parameter_aliases"], ["q", "parameter_1"])
        rendered = llm.requests[0].messages[0].content
        for secret in ("run-1", "candidate-1", "validation-1", "token", "secret", "ignore"):
            self.assertNotIn(secret, rendered)

    def test_extra_verdict_or_unsafe_reason_falls_back(self):
        for payload in (
            {"outcome_class": "request_rejected", "reason": "blocked", "verdict": "confirmed"},
            {"outcome_class": "not_offered", "reason": "unknown"},
            {"outcome_class": "request_rejected", "reason": "see https://target.test"},
        ):
            with self.subTest(payload=payload):
                review = LlmValidationReviewer(llm_client=FakeLlm(payload)).review(
                    context(), timeout_seconds=2)
                self.assertEqual(review.outcome_class, ValidationOutcomeClass.UNKNOWN)
                self.assertEqual(review.source, "deterministic_fallback")

    def test_timeout_falls_back(self):
        review = LlmValidationReviewer(llm_client=FakeLlm(error=LlmTimeout("sensitive"))).review(
            context(), timeout_seconds=2)
        self.assertEqual(review.status, "timeout")
        self.assertEqual(review.outcome_class, ValidationOutcomeClass.UNKNOWN)

    def test_mapping_payload_follows_llm_port_contract(self):
        llm = FakeLlm(MappingProxyType({
            "outcome_class": "signal_not_observed",
            "reason": "이번 probe에서 신호 미관측",
        }))
        review = LlmValidationReviewer(llm_client=llm).review(context(), timeout_seconds=2)
        self.assertEqual(review.source, "llm")


class DecoratorTests(unittest.TestCase):
    def setUp(self):
        self.candidates = InMemoryCandidateStore()
        self.evidence = InMemoryEvidenceStore()
        self.surfaces = InMemorySurfaceStore()
        self.candidates.add(Candidate(
            candidate_id="candidate-1", run_id="run-1", surface_id="surface-1",
            vulnerability_type="SQLi", hypothesis="candidate", assigned_agent="sqli_analyzer",
            evidence_ids=(),
        ))
        self.surfaces.add(Surface(
            surface_id="surface-1", run_id="run-1", url="http://target.test/users/17?token=secret",
            method="GET", parameters=("q",),
        ))
        self.evidence.append(Evidence(
            evidence_id="runtime-1", run_id="run-1", surface_id="surface-1",
            validation_id="validation-1", source_task_id="collection-1",
            created_by="execution_runtime:http_get", evidence_type="http_response",
            observation={"type": "http_response", "status": 200, "body": "secret"},
        ))
        self.task = TaskEnvelope(
            task_id="task-1", run_id="run-1", agent_type="validation",
            candidate_id="candidate-1", surface_id="surface-1",
            validation_id="validation-1", timeout_seconds=60,
            allowed_tools=("http_get",),
        )

    def agent(self, verdict=ValidationVerdict.REJECTED,
              reason_code=ValidationReasonCode.PROBE_SIGNAL_NOT_REPRODUCED, llm=None):
        validation = ValidationResult(
            validation_id="validation-1", run_id="run-1", candidate_id="candidate-1",
            verdict=verdict, evidence_ids=("runtime-1",), reason="deterministic result",
            reproduction_count=1, reason_code=reason_code,
        )
        llm = llm or FakeLlm({"outcome_class": "signal_not_observed", "reason": "이번 probe에서 신호 미관측"})
        return ReviewingValidationAgent(
            validator=FakeValidator(validation), reviewer=LlmValidationReviewer(llm_client=llm),
            candidate_store=self.candidates, evidence_store=self.evidence,
            surface_store=self.surfaces, id_factory=lambda: "fixed",
        ), llm, validation

    def test_review_is_separate_claim_and_same_result_is_reused(self):
        agent, llm, validation = self.agent()
        first = agent.handle(self.task)
        second = agent.handle(self.task)
        self.assertIs(first.validation, validation)
        self.assertEqual(first.validation, second.validation)
        self.assertEqual(first.new_evidence_ids, second.new_evidence_ids)
        self.assertEqual(len(llm.requests), 1)
        claim = self.evidence.get("run-1", first.new_evidence_ids[0])
        self.assertEqual(claim.evidence_type, "claim")
        self.assertEqual(validation.evidence_ids, ("runtime-1",))
        self.assertEqual(claim.observation["input_fingerprint"], context(
            validation_evidence_ids=("runtime-1",)).fingerprint(
                reviewer_config_version="llm-validation-review-v1"))

    def test_unspecified_reason_does_not_call_llm(self):
        agent, llm, validation = self.agent(reason_code=ValidationReasonCode.UNSPECIFIED)
        result = agent.handle(self.task)
        self.assertIs(result.validation, validation)
        self.assertFalse(llm.requests)
        claim = self.evidence.get("run-1", result.new_evidence_ids[0])
        self.assertEqual(claim.observation["status"], "reason_code_unspecified")

    def test_reason_coded_validator_preserves_baseline_result(self):
        baseline = ValidationAgent(
            candidate_store=self.candidates, evidence_store=self.evidence,
            surface_store=self.surfaces,
        )
        coded = ReasonCodedValidationAgent(
            candidate_store=self.candidates, evidence_store=self.evidence,
            surface_store=self.surfaces,
        )
        original = baseline.handle(self.task)
        actual = coded.handle(self.task)
        self.assertEqual(actual.validation.verdict, original.validation.verdict)
        self.assertEqual(actual.validation.proof, original.validation.proof)
        self.assertEqual(actual.evidence_requests, original.evidence_requests)
        self.assertEqual(actual.validation.reason_code, ValidationReasonCode.ANALYSIS_SIGNAL_MISSING)

    def test_every_existing_nonconfirmed_branch_has_reason_code(self):
        tree = ast.parse(textwrap.dedent(inspect.getsource(ValidationAgent)))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != "_validation_result":
                continue
            arguments = {keyword.arg: keyword.value for keyword in node.keywords}
            verdict = arguments.get("verdict")
            reason = arguments.get("reason")
            if (isinstance(verdict, ast.Attribute) and verdict.attr == "CONFIRMED"
                    or not isinstance(reason, ast.Constant)):
                continue
            self.assertIn(reason.value, _REASONS)

    def test_confirmed_result_bypasses_reviewer(self):
        proof = ValidationProof(
            proof_type=ValidationProofType.SQLI_EFFECT,
            evidence_ids=("runtime-1",), summary="independent differential",
        )
        validation = ValidationResult(
            validation_id="validation-1", run_id="run-1", candidate_id="candidate-1",
            verdict=ValidationVerdict.CONFIRMED, evidence_ids=("runtime-1",),
            reason="confirmed by code", reproduction_count=1, proof=proof,
            reason_code=ValidationReasonCode.CONFIRMED_PROOF,
        )
        llm = FakeLlm({"outcome_class": "unknown", "reason": "unknown"})
        agent = ReviewingValidationAgent(
            validator=FakeValidator(validation), reviewer=LlmValidationReviewer(llm_client=llm),
            candidate_store=self.candidates, evidence_store=self.evidence,
            surface_store=self.surfaces,
        )
        result = agent.handle(self.task)
        self.assertIs(result.validation, validation)
        self.assertFalse(result.new_evidence_ids)
        self.assertFalse(llm.requests)

    def test_malformed_stored_claim_is_not_reused(self):
        agent, llm, _ = self.agent()
        first = agent.handle(self.task)
        claim = self.evidence.get("run-1", first.new_evidence_ids[0])
        self.evidence._items[claim.evidence_id] = Evidence(
            evidence_id=claim.evidence_id, run_id=claim.run_id,
            surface_id=claim.surface_id, validation_id=claim.validation_id,
            source_task_id=claim.source_task_id, created_by=claim.created_by,
            evidence_type=claim.evidence_type,
            observation={**claim.observation, "reason": "https://secret.test/token"},
        )
        agent._id_factory = lambda: "next"
        second = agent.handle(self.task)
        self.assertEqual(len(llm.requests), 2)
        self.assertNotEqual(first.new_evidence_ids, second.new_evidence_ids)

    def test_opt_in_factory_runs_real_validator_without_common_wiring(self):
        llm = FakeLlm({
            "outcome_class": "signal_not_observed",
            "reason": "이번 session에서 분석 신호를 관측하지 못함",
        })
        agent = build_llm_reviewing_validation_agent(
            llm_client=llm, candidate_store=self.candidates,
            evidence_store=self.evidence, surface_store=self.surfaces,
        )
        result = agent.handle(self.task)
        self.assertEqual(result.validation.verdict, ValidationVerdict.REJECTED)
        self.assertEqual(result.validation.reason_code, ValidationReasonCode.ANALYSIS_SIGNAL_MISSING)
        self.assertEqual(len(llm.requests), 1)
        self.assertEqual(len(result.new_evidence_ids), 1)

    def test_requested_review_without_client_fails_before_run(self):
        with self.assertRaises(LlmCredentialsMissing):
            build_llm_reviewing_validation_agent(
                llm_client=None, candidate_store=self.candidates,
                evidence_store=self.evidence, surface_store=self.surfaces,
            )

    def test_sqlite_claim_survives_reopen_and_reuses_review(self):
        llm = FakeLlm({
            "outcome_class": "signal_not_observed",
            "reason": "이번 session에서 분석 신호 미관측",
        })
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite3"
            with SQLiteStoreBundle(path) as stores:
                stores.candidates.add(self.candidates.get("run-1", "candidate-1"))
                stores.surfaces.add(self.surfaces.get("run-1", "surface-1"))
                stores.evidence.append(self.evidence.get("run-1", "runtime-1"))
                first = build_llm_reviewing_validation_agent(
                    llm_client=llm, candidate_store=stores.candidates,
                    evidence_store=stores.evidence, surface_store=stores.surfaces,
                ).handle(self.task)
                self.assertEqual(len(first.new_evidence_ids), 1)
            with SQLiteStoreBundle(path) as stores:
                second = build_llm_reviewing_validation_agent(
                    llm_client=llm, candidate_store=stores.candidates,
                    evidence_store=stores.evidence, surface_store=stores.surfaces,
                ).handle(self.task)
                self.assertEqual(first.new_evidence_ids, second.new_evidence_ids)
                self.assertEqual(first.validation, second.validation)
                self.assertEqual(len(llm.requests), 1)


if __name__ == "__main__":
    unittest.main()
