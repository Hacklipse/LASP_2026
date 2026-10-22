"""두 실행기의 profile/router 조합을 실제 배선하되 대상 실행 직전에 중단한다."""

from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import unicodedata
import unittest
from datetime import datetime, timezone
from pathlib import Path
from itertools import product
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import run_dvwa_baseline as dvwa
import run_juice_shop_baseline as juice
from hacklipse.adapters import (
    HeuristicSqliAnalyzer, LlmReportNarrator, LlmSqliAnalyzer,
    RuleBasedVulnerabilityRouter,
)
from hacklipse.adapters.routing_audit import AuditedVulnerabilityRouter
from hacklipse.adapters.paired_routing import PairedVulnerabilityRouter
from hacklipse.adapters.llm_recon_planner import LlmReconPlanner
from hacklipse.adapters.llm_iterative_recon import LlmIterativeReconPlanner
from hacklipse.adapters.reviewing_validation import ReviewingValidationAgent
from hacklipse.adapters.agentic_probe import AgenticHttpProbeAgent
from hacklipse.adapters.analysis_llm_fallback import FallbackAnalysisAgent
from hacklipse.adapters.report_contract import SsrfReviewFact
from hacklipse.application import Orchestrator
from hacklipse.application.errors import AgentContractError
from hacklipse.bootstrap import build_local_application, register_standard_agents
from hacklipse.domain import (
    Candidate,
    CandidateStatus,
    Evidence,
    Run,
    RunScope,
    SsrfExecutionApproval,
    SsrfDestinationRule,
    SsrfPolicyAssertion,
    SsrfPolicyEvidenceStatus,
    SsrfPolicySource,
    SsrfVerificationStrategy,
    Surface,
    ValidationReasonCode,
)
from hacklipse.ports.errors import LlmCredentialsMissing


class _StopBeforeExecution(RuntimeError):
    pass


class _NoCallsLlm:
    def complete(self, request):
        raise AssertionError("CLI wiring test must not call an LLM")


class _FakeLocalCallback:
    origin = "http://127.0.0.1:39123"
    public_oast = False
    operator_owned = True

    def __init__(self, **kwargs):
        pass

    def close(self):
        pass


class RoutingCliTests(unittest.TestCase):
    def test_owned_local_receiver_requires_explicit_review_gate(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            status = juice.main([
                "runner", "http://127.0.0.1:3000/", "--vuln", "auto",
                "--recon-entry", "base-url", "--ssrf-owned-local-receiver",
            ])
        self.assertEqual(status, 2)
        self.assertIn("--ssrf-review", output.getvalue())

    def test_ssrf_opaque_reference_prompt_rejects_secret_like_input(self):
        answers = iter((
            "operator:sk-THISISALONGSECRETKEY1234567890",
            "operator:alice",
        ))
        with contextlib.redirect_stdout(io.StringIO()):
            value = juice._prompt_opaque_ssrf_reference(
                "reference: ",
                input_fn=lambda _: next(answers),
                required_prefix="operator:",
            )
        self.assertEqual(value, "operator:alice")

    def test_ssrf_review_gate_registers_only_exact_value_free_selection(self):
        surface = Surface(
            surface_id="surface-1",
            run_id="run-1",
            url="http://local.test/private/token/raw-secret?url=raw-secret",
            method="GET",
            parameters=("url",),
        )
        evidence = (
            Evidence(
                evidence_id="evi-review-1",
                run_id="run-1",
                surface_id="surface-1",
                created_by="recon",
                evidence_type="observation",
                observation={
                    "type": "ssrf_url_fetch_review",
                    "parameter_names": ["url"],
                    "parameter_sources": [
                        {"name": "url", "source": "observed_query"},
                    ],
                },
            ),
            Evidence(
                evidence_id="evi-hint-1",
                run_id="run-1",
                surface_id="surface-1",
                created_by="recon",
                evidence_type="observation",
                observation={
                    "type": "ssrf_destination_hint",
                    "destination_origin": "http://service.internal:8025",
                    "path_hint": "/private/token/raw-secret",
                    "source": "openapi_document",
                },
            ),
        )
        app = SimpleNamespace(
            stores=SimpleNamespace(
                surfaces=SimpleNamespace(list_by_run=lambda _: (surface,)),
                evidence=SimpleNamespace(list_by_run=lambda _: evidence),
            ),
            collector=Mock(),
            ssrf_reviews=Mock(),
        )
        run = SimpleNamespace(run_id="run-1", surface_ids=("surface-1",))
        answers = iter((
            "1", "1", "y",
            "https://must-not-be-accepted.invalid/private?token=secret",
            "operator:alice",
        ))

        with contextlib.redirect_stdout(io.StringIO()) as output:
            juice._run_ssrf_review_gate(
                app, run, callback_mode="local_callback",
                input_fn=lambda _: next(answers),
            )

        kwargs = app.collector.register_ssrf_review.call_args.kwargs
        self.assertEqual(kwargs["run_id"], "run-1")
        self.assertEqual(kwargs["parameter"], "url")
        self.assertEqual(kwargs["hint_evidence_id"], "evi-hint-1")
        self.assertEqual(
            kwargs["approval"].verification_endpoint_ref,
            "callback-local_callback",
        )
        self.assertEqual(kwargs["approval"].surface_id, "surface-1")
        self.assertEqual(kwargs["approval"].approved_by, "operator:alice")
        self.assertIsNone(kwargs["destination_policy"])
        self.assertFalse(kwargs["hint_use_approved"])
        self.assertIsNone(kwargs["approved_destination_url"])
        self.assertNotIn("raw-secret", output.getvalue())
        self.assertNotIn("must-not-be-accepted", output.getvalue())
        app.ssrf_reviews.skip.assert_not_called()

    def test_ssrf_review_uses_operator_owned_endpoint_with_exact_surface_policy(self):
        reviewed_surface = Surface(
            surface_id="surface-fetch", run_id="run-1",
            url="http://local.test/api/fetch", method="GET", parameters=("url",),
        )
        source_surface = Surface(
            surface_id="surface-document", run_id="run-1",
            url="http://local.test/openapi.json", method="GET", parameters=(),
        )
        evidence = (
            Evidence(
                evidence_id="evi-review", run_id="run-1", surface_id="surface-fetch",
                created_by="recon", evidence_type="observation",
                observation={
                    "type": "ssrf_url_fetch_review", "parameter_names": ["url"],
                    "parameter_sources": [{"name": "url", "source": "openapi_declaration"}],
                },
            ),
            Evidence(
                evidence_id="evi-hint", run_id="run-1", surface_id="surface-document",
                created_by="recon", evidence_type="observation",
                observation={
                    "type": "ssrf_destination_hint",
                    "destination_origin": "http://service.internal:8025",
                    "path_hint": "/private/token/{redacted}",
                    "destination_fingerprint": "a" * 64,
                    "probe_authorized": False,
                    "source": "openapi_document",
                },
            ),
        )
        app = SimpleNamespace(
            stores=SimpleNamespace(
                surfaces=SimpleNamespace(list_by_run=lambda _: (
                    reviewed_surface, source_surface,
                )),
                evidence=SimpleNamespace(list_by_run=lambda _: evidence),
            ),
            collector=Mock(), ssrf_reviews=Mock(),
            register_ssrf_canary_proof=Mock(),
            ssrf_verification_endpoint_ref=Mock(return_value="endpoint-private-ref"),
        )
        run = SimpleNamespace(
            run_id="run-1", surface_ids=("surface-fetch", "surface-document"),
        )
        exact_url = "http://service.internal:8025/private/token/RAW-SECRET-1234567890"
        marker = "harmless-owned-marker-5f7c2d13"
        answers = iter((
            "1", "1", "y", "y", "y", "y",
            "operator:fetch-v1", "operator:alice",
        ))
        with (
            patch.dict(os.environ, {"HACKLIPSE_SSRF_CANARY_MARKER": marker}),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            completed = juice._run_ssrf_review_gate(
                app, run, callback_mode="off", input_fn=lambda _: next(answers),
                secret_input_fn=lambda _: exact_url,
                allow_initial_internal=True,
            )

        self.assertTrue(completed)
        registration = app.collector.register_ssrf_review.call_args.kwargs
        policy = registration["destination_policy"]
        self.assertEqual(registration["parameter"], "url")
        self.assertEqual(registration["hint_evidence_id"], "evi-hint")
        self.assertTrue(registration["hint_use_approved"])
        self.assertEqual(registration["approved_destination_url"], exact_url)
        self.assertEqual(policy.surface_id, "surface-fetch")
        self.assertIs(policy.destination_rule, SsrfDestinationRule.FORBIDDEN)
        self.assertIs(policy.source_type, SsrfPolicySource.OPERATOR_ATTESTATION)
        self.assertEqual(policy.source_reference, "operator:fetch-v1")
        self.assertEqual(policy.destination_origin, "http://service.internal:8025")
        self.assertIs(
            policy.assertion,
            SsrfPolicyAssertion.TARGET_MUST_NOT_REACH_DESTINATION,
        )
        self.assertIs(policy.evidence_status, SsrfPolicyEvidenceStatus.ATTESTED)
        self.assertEqual(registration["approval"].approved_by, "operator:alice")
        self.assertEqual(
            registration["approval"].verification_endpoint_ref,
            "endpoint-private-ref",
        )
        app.ssrf_verification_endpoint_ref.assert_called_once_with("run-1", exact_url)
        app.register_ssrf_canary_proof.assert_called_once()
        proof_run_id, proof = app.register_ssrf_canary_proof.call_args.args
        self.assertEqual(proof_run_id, "run-1")
        self.assertEqual(proof.url, exact_url)
        self.assertIs(proof.destination_policy, policy)
        self.assertNotIn(exact_url, output.getvalue())
        self.assertNotIn(marker, output.getvalue())
        self.assertIn("source Surface surface-document", output.getvalue())
        app.ssrf_reviews.skip.assert_not_called()

    def test_ssrf_review_can_activate_separate_owned_receiver_without_url_input(self):
        surface = Surface(
            surface_id="surface-fetch", run_id="run-1",
            url="http://local.test/api/fetch?url=redacted", method="GET",
            parameters=("url",),
        )
        evidence = (Evidence(
            evidence_id="evi-review", run_id="run-1", surface_id="surface-fetch",
            created_by="recon", evidence_type="observation",
            observation={
                "type": "ssrf_url_fetch_review", "parameter_names": ["url"],
                "parameter_sources": [{"name": "url", "source": "observed_query"}],
            },
        ),)
        app = SimpleNamespace(
            stores=SimpleNamespace(
                surfaces=SimpleNamespace(list_by_run=lambda _: (surface,)),
                evidence=SimpleNamespace(list_by_run=lambda _: evidence),
            ),
            collector=Mock(), ssrf_reviews=Mock(),
            ssrf_owned_receiver_origin="http://127.0.0.1:39124",
            ssrf_owned_receiver_endpoint_ref=Mock(return_value="endpoint-owned-ref"),
        )
        run = SimpleNamespace(run_id="run-1", surface_ids=("surface-fetch",))
        answers = iter(("1", "y", "y", "operator:alice", "y", "operator:deny-v1"))

        with contextlib.redirect_stdout(io.StringIO()) as output:
            completed = juice._run_ssrf_review_gate(
                app, run, callback_mode="off", owned_receiver_mode=True,
                input_fn=lambda _: next(answers),
            )

        self.assertTrue(completed)
        registered = app.collector.register_ssrf_review.call_args.kwargs
        self.assertEqual(
            registered["approval"].verification_endpoint_ref,
            "endpoint-owned-ref",
        )
        self.assertEqual(registered["approved_destination_url"], app.ssrf_owned_receiver_origin)
        self.assertEqual(
            registered["destination_policy"].destination_origin,
            "http://127.0.0.1:39124",
        )
        self.assertFalse(registered["hint_use_approved"])
        self.assertNotIn("39124", output.getvalue())
        app.ssrf_reviews.skip.assert_not_called()

    def test_selected_hint_stays_reference_only_without_hint_use_approval(self):
        surface = Surface(
            surface_id="surface-1", run_id="run-1",
            url="http://local.test/api/fetch", method="GET", parameters=("url",),
        )
        evidence = (
            Evidence(
                evidence_id="evi-review", run_id="run-1", surface_id="surface-1",
                created_by="recon", evidence_type="observation",
                observation={
                    "type": "ssrf_url_fetch_review", "parameter_names": ["url"],
                    "parameter_sources": [{"name": "url", "source": "observed_query"}],
                },
            ),
            Evidence(
                evidence_id="evi-hint", run_id="run-1", surface_id="surface-1",
                created_by="recon", evidence_type="observation",
                observation={
                    "type": "ssrf_destination_hint",
                    "destination_origin": "http://different.internal:8025",
                    "path_hint": "/different",
                    "destination_fingerprint": "b" * 64,
                    "probe_authorized": False,
                    "source": "openapi_document",
                },
            ),
        )
        app = SimpleNamespace(
            stores=SimpleNamespace(
                surfaces=SimpleNamespace(list_by_run=lambda _: (surface,)),
                evidence=SimpleNamespace(list_by_run=lambda _: evidence),
            ),
            collector=Mock(), ssrf_reviews=Mock(),
            register_ssrf_canary_proof=Mock(),
            ssrf_verification_endpoint_ref=Mock(return_value="endpoint-private-ref"),
        )
        run = SimpleNamespace(run_id="run-1", surface_ids=("surface-1",))
        answers = iter(("1", "1", "y", "y", "n", "n", "operator:alice"))
        with (
            patch.dict(os.environ, {"HACKLIPSE_SSRF_CANARY_MARKER": "owned-marker-5f7c2d13"}),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            juice._run_ssrf_review_gate(
                app, run, callback_mode="off", input_fn=lambda _: next(answers),
                secret_input_fn=lambda _: "http://service.internal:8025/approved-check",
                allow_initial_internal=True,
            )
        app.ssrf_reviews.skip.assert_not_called()
        registration = app.collector.register_ssrf_review.call_args.kwargs
        self.assertIsNone(registration["destination_policy"])
        self.assertEqual(registration["hint_evidence_id"], "evi-hint")
        self.assertFalse(registration["hint_use_approved"])
        self.assertEqual(
            registration["approved_destination_url"],
            "http://service.internal:8025/approved-check",
        )
        self.assertEqual(registration["approval"].surface_id, "surface-1")
        proof = app.register_ssrf_canary_proof.call_args.args[1]
        self.assertEqual(proof.surface_id, "surface-1")
        self.assertIsNone(proof.destination_policy)

    def test_hint_binding_mismatch_skips_without_registering_canary(self):
        surface = Surface(
            surface_id="surface-1", run_id="run-1",
            url="http://local.test/api/fetch", method="GET", parameters=("url",),
        )
        evidence = (
            Evidence(
                evidence_id="evi-review", run_id="run-1", surface_id="surface-1",
                created_by="recon", evidence_type="observation",
                observation={
                    "type": "ssrf_url_fetch_review", "parameter_names": ["url"],
                    "parameter_sources": [{"name": "url", "source": "observed_query"}],
                },
            ),
            Evidence(
                evidence_id="evi-hint", run_id="run-1", surface_id="surface-1",
                created_by="recon", evidence_type="observation",
                observation={
                    "type": "ssrf_destination_hint",
                    "destination_origin": "http://service.internal:8025",
                    "path_hint": "/expected",
                    "destination_fingerprint": "c" * 64,
                    "probe_authorized": False,
                    "source": "openapi_document",
                },
            ),
        )
        collector = Mock()
        collector.register_ssrf_review.side_effect = AgentContractError(
            "SSRF approved destination does not match the selected Recon hint"
        )
        app = SimpleNamespace(
            stores=SimpleNamespace(
                surfaces=SimpleNamespace(list_by_run=lambda _: (surface,)),
                evidence=SimpleNamespace(list_by_run=lambda _: evidence),
            ),
            collector=collector, ssrf_reviews=Mock(),
            register_ssrf_canary_proof=Mock(),
            ssrf_verification_endpoint_ref=Mock(return_value="endpoint-private-ref"),
        )
        answers = iter(("1", "1", "y", "y", "y", "n", "operator:alice"))
        with (
            patch.dict(
                os.environ,
                {"HACKLIPSE_SSRF_CANARY_MARKER": "owned-marker-5f7c2d13"},
            ),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            completed = juice._run_ssrf_review_gate(
                app, SimpleNamespace(run_id="run-1", surface_ids=("surface-1",)),
                callback_mode="off", input_fn=lambda _: next(answers),
                secret_input_fn=lambda _: "http://service.internal:8025/wrong",
                allow_initial_internal=True,
            )

        self.assertTrue(completed)
        submitted = collector.register_ssrf_review.call_args.kwargs
        self.assertTrue(submitted["hint_use_approved"])
        self.assertEqual(
            submitted["approved_destination_url"],
            "http://service.internal:8025/wrong",
        )
        app.register_ssrf_canary_proof.assert_not_called()
        app.ssrf_reviews.skip.assert_called_once_with(
            "run-1", SsrfVerificationStrategy.INTERNAL_CANARY,
        )
        self.assertIn("일치하지 않아", output.getvalue())
        self.assertNotIn(
            "http://service.internal:8025/wrong", output.getvalue(),
        )

    def test_ssrf_review_gate_skip_releases_without_registration(self):
        surface = Surface(
            surface_id="surface-1", run_id="run-1",
            url="http://local.test/api/fetch", method="GET", parameters=("url",),
        )
        review = Evidence(
            evidence_id="evi-review-1", run_id="run-1", surface_id="surface-1",
            created_by="recon", evidence_type="observation",
            observation={
                "type": "ssrf_url_fetch_review",
                "parameter_names": ["url"],
                "parameter_sources": [{"name": "url", "source": "openapi_query"}],
            },
        )
        app = SimpleNamespace(
            stores=SimpleNamespace(
                surfaces=SimpleNamespace(list_by_run=lambda _: (surface,)),
                evidence=SimpleNamespace(list_by_run=lambda _: (review,)),
            ),
            collector=Mock(), ssrf_reviews=Mock(),
        )
        run = SimpleNamespace(run_id="run-1", surface_ids=("surface-1",))

        with contextlib.redirect_stdout(io.StringIO()):
            juice._run_ssrf_review_gate(
                app, run, callback_mode="local_callback", input_fn=lambda _: "",
            )

        app.ssrf_reviews.skip.assert_called_once_with(
            "run-1", SsrfVerificationStrategy.PASSIVE,
        )
        app.collector.register_ssrf_review.assert_not_called()

    def test_ssrf_review_waits_for_optional_recon_when_no_coordinate_exists(self):
        app = SimpleNamespace(
            stores=SimpleNamespace(
                surfaces=SimpleNamespace(list_by_run=lambda _: ()),
                evidence=SimpleNamespace(list_by_run=lambda _: ()),
            ),
            collector=Mock(), ssrf_reviews=Mock(),
        )
        run = SimpleNamespace(run_id="run-1", surface_ids=())

        with contextlib.redirect_stdout(io.StringIO()):
            finished = juice._run_ssrf_review_gate(
                app, run, callback_mode="local_callback",
            )

        self.assertFalse(finished)
        app.ssrf_reviews.skip.assert_not_called()
        app.collector.register_ssrf_review.assert_not_called()

    def test_ssrf_internal_followup_reuses_ab_proven_coordinate(self):
        app = build_local_application({})
        run = Run(
            run_id="run-followup",
            target_url="http://local.test/",
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            policy_profile="safe",
            request_budget=8,
            surface_ids=("surface-fetch",),
            candidate_ids=("candidate-callback",),
        )
        surface = Surface(
            surface_id="surface-fetch",
            run_id=run.run_id,
            url="http://local.test/api/fetch?url=old",
            method="GET",
            parameters=("url",),
            observed_query=(("url", "old"),),
        )
        review = Evidence(
            evidence_id="evi-review",
            run_id=run.run_id,
            surface_id=surface.surface_id,
            created_by="recon",
            evidence_type="observation",
            observation={
                "type": "ssrf_url_fetch_review",
                "parameter_names": ["url"],
                "parameter_sources": [
                    {"name": "url", "source": "observed_query"},
                ],
            },
        )
        app.stores.runs.add(run)
        app.stores.surfaces.add(surface)
        app.stores.evidence.append(review)
        app.stores.candidates.add(Candidate(
            candidate_id="candidate-callback",
            run_id=run.run_id,
            surface_id=surface.surface_id,
            vulnerability_type="SSRF",
            hypothesis="callback A/B observed",
            assigned_agent="ssrf_analyzer",
            evidence_ids=(),
            status=CandidateStatus.SUSPECTED,
            validation_reason_code=ValidationReasonCode.SSRF_CALLBACK_ONLY,
            exploration_parameters=("url",),
        ))
        app.collector.register_ssrf_review(
            run_id=run.run_id,
            parameter="url",
            hint_evidence_id=review.evidence_id,
            approval=SsrfExecutionApproval(
                approval_id="approval-callback",
                surface_id=surface.surface_id,
                verification_endpoint_ref="callback-local-test",
                approved_by="operator-test",
                approved_at=datetime.now(timezone.utc),
            ),
            destination_policy=None,
            verification_strategy=SsrfVerificationStrategy.CALLBACK,
        )
        marker = "owned-marker-followup-2026"
        exact_url = "http://service.internal:8025/proof"
        answers = iter(("y", "y", "n", "operator:alice"))

        with (
            patch.dict(os.environ, {"HACKLIPSE_SSRF_CANARY_MARKER": marker}),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            approved = juice._run_ssrf_internal_followup_gate(
                app,
                app.stores.runs.get(run.run_id),
                input_fn=lambda _: next(answers),
                secret_input_fn=lambda _: exact_url,
            )

        self.assertTrue(approved)
        internal = app.ssrf_reviews.get_for_run(
            run.run_id, SsrfVerificationStrategy.INTERNAL_CANARY,
        )
        self.assertIsNotNone(internal)
        self.assertEqual(internal.surface_id, surface.surface_id)
        self.assertEqual(internal.parameter, "url")
        self.assertIsNotNone(app.collector.ssrf_canary_proof_for_run(run.run_id))
        self.assertNotIn(exact_url, output.getvalue())
        self.assertNotIn(marker, output.getvalue())

        # Simulate an interrupted follow-up that kept the opaque approval but
        # lost only the process-local exact endpoint and marker binding.
        app.collector._ssrf_run_canaries.pop(run.run_id)
        with (
            patch.dict(os.environ, {"HACKLIPSE_SSRF_CANARY_MARKER": marker}),
            contextlib.redirect_stdout(io.StringIO()) as rejected_output,
        ):
            rejected = juice._run_ssrf_internal_followup_gate(
                app,
                app.stores.runs.get(run.run_id),
                input_fn=lambda _: self.fail("stored approval must not be replaced"),
                secret_input_fn=lambda _: "http://different.internal:8025/proof",
            )
        self.assertFalse(rejected)
        self.assertIsNone(app.collector.ssrf_canary_proof_for_run(run.run_id))
        self.assertNotIn("different.internal", rejected_output.getvalue())

        with (
            patch.dict(os.environ, {"HACKLIPSE_SSRF_CANARY_MARKER": marker}),
            contextlib.redirect_stdout(io.StringIO()) as restored_output,
        ):
            restored = juice._run_ssrf_internal_followup_gate(
                app,
                app.stores.runs.get(run.run_id),
                input_fn=lambda _: self.fail("stored approval must not be replaced"),
                secret_input_fn=lambda _: exact_url,
            )
        self.assertTrue(restored)
        self.assertIsNotNone(app.collector.ssrf_canary_proof_for_run(run.run_id))
        self.assertNotIn(exact_url, restored_output.getvalue())
        self.assertNotIn(marker, restored_output.getvalue())

    def test_ssrf_passive_summary_distinguishes_unverified_from_no_finding(self):
        review = SsrfReviewFact(
            url_surface_count=2,
            manual_analysis_completed=True,
            execution_approval_registered=False,
            destination_policy_registered=False,
            destination_policy_source="",
            observation_recorded=False,
            verification_performed=False,
            final_status="REVIEW_REQUIRED",
            reason_code="ssrf_manual_review_required",
        )

        output = "\n".join(juice._ssrf_review_summary_lines(review))

        self.assertIn("URL 처리 Surface 2개", output)
        self.assertIn("서버 요청 확인  미수행", output)
        self.assertIn("운영자 검토 필요", output)
        self.assertIn("Callback 전략   NOT_CONFIGURED", output)
        self.assertIn("Canary 전략     NOT_CONFIGURED", output)
        self.assertIn("취약점 없음 판정이 아닙니다", output)

    def test_ssrf_summary_displays_independent_strategy_states_and_surface(self):
        review = SsrfReviewFact(
            url_surface_count=1,
            manual_analysis_completed=True,
            execution_approval_registered=True,
            destination_policy_registered=False,
            destination_policy_source="",
            observation_recorded=True,
            verification_performed=True,
            final_status="CANARY_OBSERVED_POLICY_PENDING",
            reason_code="ssrf_policy_evidence_pending",
            callback_status="PROVIDER_BLOCKED",
            canary_status="ACCESS_OBSERVED_POLICY_PENDING",
            approved_surface_id="surface-1",
        )

        output = "\n".join(juice._ssrf_review_summary_lines(review))

        self.assertIn("Callback 전략   PROVIDER_BLOCKED", output)
        self.assertIn("Canary 전략     ACCESS_OBSERVED_POLICY_PENDING", output)
        self.assertIn("승인 Surface     surface-1", output)

    def test_ssrf_recon_only_summary_says_pending_and_unused(self):
        review = SsrfReviewFact(
            url_surface_count=1,
            manual_analysis_completed=False,
            execution_approval_registered=False,
            destination_policy_registered=False,
            destination_policy_source="",
            observation_recorded=False,
            verification_performed=False,
            final_status="REVIEW_REQUIRED",
            reason_code="ssrf_manual_review_required",
        )

        output = unicodedata.normalize(
            "NFD", "\n".join(juice._ssrf_review_summary_lines(review)),
        )

        self.assertIn("운영자 검토: 대기", output)
        self.assertIn("아직 검사에 사용되지 않음", output)
        self.assertNotIn("SSRF 분석: 운영자 검토 등록", output)

    def test_ssrf_canary_requires_callback_and_explicit_rule(self):
        with (
            patch("builtins.input") as prompt,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            status = juice.main([
                "runner", "http://localhost:3000/", "--vuln", "auto",
                "--recon-entry", "base-url", "--ssrf-canary-url",
                "http://canary.internal/proof", "--ssrf-canary-consent",
            ])
        self.assertEqual(status, 2)
        self.assertIn("--ssrf-review", output.getvalue())
        prompt.assert_not_called()

    def test_ssrf_canary_cli_rejects_legacy_string_policy_contract(self):
        marker = "harmless-canary-marker-5f7c2d13"
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.dict(os.environ, {"HACKLIPSE_SSRF_CANARY_MARKER": marker}),
                patch.object(juice, "LocalSsrfCallbackService", _FakeLocalCallback),
                patch.object(juice, "build_local_application",
                             wraps=build_local_application) as assemble,
                patch.object(Orchestrator, "start", side_effect=_StopBeforeExecution),
                patch.object(juice.getpass, "getpass", return_value=""),
                patch("builtins.input", return_value="y"),
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                status = juice.main([
                    "runner", "http://127.0.0.1:3000/", "--vuln", "auto",
                    "--recon-entry", "base-url", "--ssrf-local-callback",
                    "--ssrf-canary-url", "http://canary.internal/proof",
                    "--ssrf-canary-policy-ref", "operator:deny-canary-v1",
                    "--ssrf-canary-consent",
                    "--routing-log", str(Path(directory) / "routing.jsonl"),
                ])
        self.assertEqual(status, 2)
        self.assertIn("--ssrf-review", output.getvalue())
        assemble.assert_not_called()
        self.assertNotIn(marker, output.getvalue())

    def test_juice_shop_auto_requires_answer_blind_base_url_entry(self):
        with (
            patch.object(juice, "build_local_application") as assemble,
            patch("builtins.input") as prompt,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            status = juice.main([
                "runner", "http://localhost:3000/", "--vuln", "auto",
            ])

        self.assertEqual(status, 2)
        self.assertIn("--recon-entry base-url", output.getvalue())
        assemble.assert_not_called()
        prompt.assert_not_called()

    def test_juice_shop_auto_uses_all_router_types_without_target_setup(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(juice, "build_run_router", wraps=juice.build_run_router) as router,
                patch.object(juice, "register_standard_agents", wraps=register_standard_agents) as register,
                patch.object(juice, "_prompt_access_control_accounts") as access_prompt,
                patch.object(juice, "_provision_path_traversal_account") as provision,
                patch.object(Orchestrator, "start", side_effect=_StopBeforeExecution) as start,
                patch.object(
                    juice.getpass, "getpass", return_value=""
                ) as secret_prompt,
                patch("builtins.input", return_value="y"),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                with self.assertRaises(_StopBeforeExecution):
                    juice.main([
                        "runner", "http://localhost:3000/", "--vuln", "auto",
                        "--recon-entry", "base-url",
                        "--routing-log", str(Path(directory) / "routing.jsonl"),
                    ])

        self.assertIsNone(router.call_args.kwargs["vulnerability_types"])
        self.assertEqual(
            register.call_args.args[0].orchestrator._config.max_evidence_rounds, 2,
        )
        request = start.call_args.args[0]
        self.assertEqual(request.target_url, "http://localhost:3000/")
        self.assertEqual(request.execution_profile.recon_entry_mode, "base-url")
        self.assertEqual(register.call_args.kwargs["recon_seed_urls"], ())
        self.assertFalse(
            register.call_args.kwargs["recon_infer_unlinked_render_parameters"]
        )
        self.assertIsNone(
            register.call_args.args[0].orchestrator._config.post_recon_gate
        )
        access_prompt.assert_not_called()
        provision.assert_not_called()
        secret_prompt.assert_called_once()

    def test_ssrf_review_without_callback_can_offer_operator_owned_endpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(
                    juice, "build_local_application", wraps=build_local_application,
                ) as assemble,
                patch.object(
                    juice, "register_standard_agents", wraps=register_standard_agents,
                ) as register,
                patch.object(Orchestrator, "start", side_effect=_StopBeforeExecution),
                patch.object(juice.getpass, "getpass", return_value=""),
                patch("builtins.input", return_value="y"),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                with self.assertRaises(_StopBeforeExecution):
                    juice.main([
                        "runner", "http://localhost:3000/", "--vuln", "auto",
                        "--recon-entry", "base-url", "--ssrf-review",
                        "--routing-log", str(Path(directory) / "routing.jsonl"),
                    ])
        self.assertIsNone(assemble.call_args.kwargs["ssrf_callback_service"])
        self.assertIsNotNone(
            register.call_args.args[0].orchestrator._config.post_recon_gate
        )

    def test_ssrf_review_flag_wires_post_recon_gate_with_callback(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(juice, "LocalSsrfCallbackService", _FakeLocalCallback),
                patch.object(
                    juice, "build_run_router", wraps=juice.build_run_router,
                ) as router,
                patch.object(
                    juice, "build_local_application", wraps=build_local_application,
                ) as assemble,
                patch.object(
                    juice, "register_standard_agents", wraps=register_standard_agents,
                ) as register,
                patch.object(Orchestrator, "start", side_effect=_StopBeforeExecution),
                patch.object(juice.getpass, "getpass", return_value=""),
                patch("builtins.input", return_value="y"),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                with self.assertRaises(_StopBeforeExecution):
                    juice.main([
                        "runner", "http://localhost:3000/", "--vuln", "auto",
                        "--recon-entry", "base-url", "--ssrf-review",
                        "--ssrf-local-callback",
                        "--routing-log", str(Path(directory) / "routing.jsonl"),
                    ])

        self.assertIsInstance(
            assemble.call_args.kwargs["ssrf_callback_service"], _FakeLocalCallback,
        )
        self.assertIsNone(router.call_args.kwargs["ssrf_callback_service"])
        self.assertTrue(callable(
            register.call_args.args[0].orchestrator._config.post_recon_gate
        ))

    def test_owned_local_receiver_is_separate_and_explicitly_injected(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(juice, "LocalSsrfCallbackService", _FakeLocalCallback),
                patch.object(
                    juice, "build_local_application", wraps=build_local_application,
                ) as assemble,
                patch.object(
                    juice, "register_standard_agents", wraps=register_standard_agents,
                ),
                patch.object(Orchestrator, "start", side_effect=_StopBeforeExecution),
                patch.object(juice.getpass, "getpass", return_value=""),
                patch("builtins.input", return_value="y"),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                with self.assertRaises(_StopBeforeExecution):
                    juice.main([
                        "runner", "http://localhost:3000/", "--vuln", "auto",
                        "--recon-entry", "base-url", "--ssrf-review",
                        "--ssrf-owned-local-receiver",
                        "--routing-log", str(Path(directory) / "routing.jsonl"),
                    ])

        self.assertIsNone(assemble.call_args.kwargs["ssrf_callback_service"])
        self.assertIsInstance(
            assemble.call_args.kwargs["ssrf_owned_receiver_service"],
            _FakeLocalCallback,
        )

    def test_juice_shop_state_change_approval_is_explicitly_wired_and_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(
                    juice,
                    "build_local_application",
                    wraps=build_local_application,
                ) as assemble,
                patch.object(
                    Orchestrator,
                    "start",
                    side_effect=_StopBeforeExecution,
                ) as start,
                patch.object(juice.getpass, "getpass", return_value=""),
                patch("builtins.input", return_value="y"),
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                with self.assertRaises(_StopBeforeExecution):
                    juice.main([
                        "runner",
                        "http://localhost:3000/",
                        "--vuln",
                        "auto",
                        "--recon-entry",
                        "base-url",
                        "--approve-state-changing",
                        "--routing-log",
                        str(Path(directory) / "routing.jsonl"),
                    ])

        self.assertEqual(
            assemble.call_args.kwargs["default_approval_ref"],
            juice._STATE_CHANGING_APPROVAL_REF,
        )
        self.assertIn(
            juice._STATE_CHANGING_APPROVAL_REF,
            assemble.call_args.kwargs["approval_gate"]._approved,
        )
        self.assertIn(
            juice.SSTI_APPROVAL_REF,
            assemble.call_args.kwargs["approval_gate"]._approved,
        )
        self.assertIn(
            juice.PATH_TRAVERSAL_POST_APPROVAL_REF,
            assemble.call_args.kwargs["approval_gate"]._approved,
        )
        request = start.call_args.args[0]
        self.assertTrue(request.execution_profile.state_changing_approved)
        self.assertIn("대상 데이터나 세션이 변경될 수 있습니다", output.getvalue())

    def test_juice_shop_auto_binds_optional_session_to_the_run(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(
                    juice,
                    "build_local_application",
                    wraps=build_local_application,
                ) as assemble,
                patch.object(
                    Orchestrator,
                    "start",
                    side_effect=_StopBeforeExecution,
                ) as start,
                patch.object(
                    juice.getpass,
                    "getpass",
                    return_value="token=private-session-value; language=ko",
                ),
                patch("builtins.input", return_value="y"),
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                with self.assertRaises(_StopBeforeExecution):
                    juice.main([
                        "runner",
                        "http://localhost:3000/",
                        "--vuln",
                        "auto",
                        "--recon-entry",
                        "base-url",
                        "--routing-log",
                        str(Path(directory) / "routing.jsonl"),
                    ])

        request = start.call_args.args[0]
        self.assertEqual(
            request.credential_ref,
            juice._AUTO_SESSION_CREDENTIAL_REF,
        )
        self.assertNotIn("private-session-value", output.getvalue())

    def test_juice_shop_base_url_entry_discards_type_specific_target_and_seeds(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(juice, "build_gemini_llm_client_from_env", return_value=_NoCallsLlm()),
                patch.object(juice, "register_standard_agents", wraps=register_standard_agents) as register,
                patch.object(Orchestrator, "start", side_effect=_StopBeforeExecution) as start,
                patch("builtins.input", return_value="y"),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                with self.assertRaises(_StopBeforeExecution):
                    juice.main([
                        "runner", "http://localhost:3000/", "--vuln", "sqli",
                        "--recon", "agentic", "--recon-entry", "base-url",
                        "--llm-model", "fixture-model",
                        "--routing-log", str(Path(directory) / "routing.jsonl"),
                    ])

            request = start.call_args.args[0]
            self.assertEqual(request.target_url, "http://localhost:3000/")
            self.assertEqual(request.execution_profile.recon_entry_mode, "base-url")
            self.assertEqual(register.call_args.kwargs["recon_seed_urls"], ())
            self.assertFalse(
                register.call_args.kwargs["recon_infer_unlinked_render_parameters"]
            )
            self.assertGreater(register.call_args.kwargs["recon_max_pages"], 1)

    def test_validation_review_rejects_heuristic_profile_before_setup(self):
        for runner in (dvwa, juice):
            with self.subTest(runner=runner.__name__):
                with (
                    patch.object(runner, "build_gemini_llm_client_from_env") as llm_builder,
                    patch.object(runner, "build_local_application") as assemble,
                    patch("builtins.input") as prompt,
                    contextlib.redirect_stdout(io.StringIO()) as output,
                ):
                    status = runner.main([
                        "runner", "http://localhost:3000/", "--validation-review",
                    ])
                self.assertEqual(status, 2)
                self.assertIn("--profile llm", output.getvalue())
                llm_builder.assert_not_called()
                assemble.assert_not_called()
                prompt.assert_not_called()

    def test_validation_review_is_registered_and_recorded_in_llm_profile(self):
        for runner in (dvwa, juice):
            with self.subTest(runner=runner.__name__), tempfile.TemporaryDirectory() as directory:
                with (
                    patch.object(runner, "build_gemini_llm_client_from_env", return_value=_NoCallsLlm()),
                    patch.object(runner, "register_standard_agents", wraps=register_standard_agents) as register,
                    patch.object(Orchestrator, "start", side_effect=_StopBeforeExecution) as start,
                    patch("builtins.input", return_value="y"),
                    patch.object(runner.getpass, "getpass", return_value="fixture-password"),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    with self.assertRaises(_StopBeforeExecution):
                        runner.main([
                            "runner", "http://localhost:3000/", "--vuln", "sqli",
                            "--profile", "llm", "--validation-review",
                            "--routing-log", str(Path(directory) / "routing.jsonl"),
                        ])
                app = register.call_args.args[0]
                self.assertIsInstance(app.dispatcher._agents["validation"], ReviewingValidationAgent)
                request = start.call_args.args[0]
                self.assertEqual(request.execution_profile.validation_mode, "llm")

    def test_llm_report_is_registered_and_recorded_independently(self):
        for runner in (dvwa, juice):
            with self.subTest(runner=runner.__name__), tempfile.TemporaryDirectory() as directory:
                built_apps = []

                def assemble_app(*args, **kwargs):
                    app = build_local_application(*args, **kwargs)
                    built_apps.append(app)
                    return app

                with (
                    patch.object(runner, "build_gemini_llm_client_from_env", return_value=_NoCallsLlm()),
                    patch.object(runner, "build_local_application", side_effect=assemble_app),
                    patch.object(Orchestrator, "start", side_effect=_StopBeforeExecution) as start,
                    patch("builtins.input", return_value="y"),
                    patch.object(runner.getpass, "getpass", return_value="fixture-password"),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    with self.assertRaises(_StopBeforeExecution):
                        runner.main([
                            "runner", "http://localhost:3000/", "--vuln", "sqli",
                            "--report", "llm", "--llm-model", "fixture-model",
                            "--routing-log", str(Path(directory) / "routing.jsonl"),
                        ])
                app = built_apps[0]
                reporter = app.dispatcher._agents["report"]
                self.assertEqual(reporter._format_version, "v2")
                self.assertIsInstance(reporter._narrator, LlmReportNarrator)
                request = start.call_args.args[0]
                self.assertEqual(request.execution_profile.report_mode, "llm")
                self.assertEqual(request.execution_profile.analysis_profile, "heuristic")

    def test_all_profile_router_combinations_keep_analysis_selection_independent(self):
        for runner in (dvwa, juice):
            for profile in ("heuristic", "llm"):
                for mode, recon, compare in product(("heuristic", "hybrid", "agentic"), ("heuristic", "hybrid", "agentic"), (False, True)):
                    if mode == "agentic" and compare:
                        continue
                    with self.subTest(runner=runner.__name__, profile=profile, router=mode, recon=recon, compare=compare), tempfile.TemporaryDirectory() as directory:
                        with (
                            patch.object(runner, "build_gemini_llm_client_from_env", return_value=_NoCallsLlm()) as builder,
                            patch.object(runner, "build_local_application", wraps=build_local_application) as assemble,
                            patch.object(runner, "register_standard_agents", wraps=register_standard_agents) as register,
                            patch.object(Orchestrator, "start", side_effect=_StopBeforeExecution),
                            patch("builtins.input", return_value="y"),
                            patch.object(runner.getpass, "getpass", return_value="fixture-password"),
                            contextlib.redirect_stdout(io.StringIO()),
                        ):
                            path = Path(directory) / "routing.jsonl"
                            with self.assertRaises(_StopBeforeExecution):
                                runner.main([
                                    "runner", "http://localhost:3000/", "--vuln", "sqli",
                                    "--profile", profile, "--router", mode, "--recon", recon,
                                    "--surface-collection", "deterministic",
                                    "--routing-log", str(path), "--llm-model", "fixture-model",
                                    *(["--compare-routers"] if compare else []),
                                ])
                            self.assertEqual(builder.call_count, int(profile == "llm" or mode in {"hybrid", "agentic"} or recon in {"hybrid", "agentic"} or compare))
                            router = assemble.call_args.kwargs["router"]
                            if compare:
                                self.assertIsInstance(router, PairedVulnerabilityRouter)
                                self.assertEqual(router.primary, mode)
                                router = router.hybrid if mode == "hybrid" else router.heuristic
                            self.assertIsInstance(router, AuditedVulnerabilityRouter)
                            self.assertIsInstance(router.router, RuleBasedVulnerabilityRouter)
                            self.assertEqual(router.router._advisor is not None, mode in {"hybrid", "agentic"})
                            self.assertEqual(
                                router.router._advisor_mode,
                                "primary" if mode == "agentic" else "supplemental",
                            )
                            self.assertEqual(register.call_args.kwargs["llm_client"] is not None, profile == "llm")
                            app = register.call_args.args[0]
                            if recon == "hybrid":
                                self.assertIsInstance(app.dispatcher._agents["recon"]._planner, LlmReconPlanner)
                                self.assertIsNone(app.dispatcher._agents["recon"]._iterative_planner)
                            elif recon == "agentic":
                                self.assertIsNone(app.dispatcher._agents["recon"]._planner)
                                self.assertIsInstance(
                                    app.dispatcher._agents["recon"]._iterative_planner,
                                    LlmIterativeReconPlanner,
                                )
                            else:
                                self.assertIsNone(app.dispatcher._agents["recon"]._planner)
                                self.assertIsNone(app.dispatcher._agents["recon"]._iterative_planner)
                            self.assertEqual(
                                app.dispatcher._agents["recon"]._surface_collection_mode,
                                "deterministic",
                            )
                            request = Orchestrator.start.call_args.args[0]
                            self.assertEqual(
                                request.execution_profile.surface_collection_mode,
                                "deterministic",
                            )
                            analyzer = app.dispatcher._agents["sqli_analyzer"]
                            if mode == "agentic":
                                self.assertIsInstance(analyzer, AgenticHttpProbeAgent)
                                self.assertEqual(analyzer._llm is not None, profile == "llm")
                                analyzer = analyzer._analyzer
                            if profile == "llm":
                                self.assertIsInstance(analyzer, FallbackAnalysisAgent)
                                analyzer = analyzer._primary
                            self.assertIsInstance(analyzer, LlmSqliAnalyzer if profile == "llm" else HeuristicSqliAnalyzer)
                            # 초기화만 했으며 Run/외부 HTTP/LLM 호출은 아직 시작하지 않았다.
                            self.assertEqual(path.read_text(), "")

    def test_missing_router_llm_credentials_stop_before_auth_or_log_creation(self):
        for runner, flags in product((dvwa, juice), (["--router", "hybrid"], ["--router", "agentic"], ["--recon", "hybrid"], ["--compare-routers"])):
            with self.subTest(runner=runner.__name__, flags=flags), tempfile.TemporaryDirectory() as directory:
                with (
                    patch.object(runner, "build_gemini_llm_client_from_env", side_effect=LlmCredentialsMissing("missing")),
                    patch("builtins.input") as prompt,
                    patch.object(runner, "build_local_application") as assemble,
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    path = Path(directory) / "routing.jsonl"
                    status = runner.main(["runner", "http://localhost:3000/", "--vuln", "sqli", *flags, "--routing-log", str(path)])
                    self.assertEqual(status, 2)
                    prompt.assert_not_called()
                    assemble.assert_not_called()
                    self.assertFalse(path.exists())

    def test_unwritable_log_stops_before_target_actions(self):
        for runner in (dvwa, juice):
            with self.subTest(runner=runner.__name__), tempfile.TemporaryDirectory() as directory:
                with patch("builtins.input") as prompt, patch.object(runner, "build_local_application") as assemble, contextlib.redirect_stdout(io.StringIO()):
                    # 파일 대신 디렉터리 경로를 전달해 플랫폼 공통 쓰기 오류를 유도한다.
                    status = runner.main(["runner", "http://localhost:3000/", "--vuln", "sqli", "--routing-log", directory])
                    self.assertEqual(status, 2)
                    prompt.assert_not_called()
                    assemble.assert_not_called()

    def test_public_oast_does_not_start_without_explicit_consent(self):
        with (
            patch("builtins.input") as prompt,
            patch.object(juice, "InteractshCliCallbackService") as provider,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            status = juice.main([
                "runner", "http://127.0.0.1:3000/", "--vuln", "auto",
                "--recon-entry", "base-url", "--ssrf-oast", "public_interactsh",
            ])
        self.assertEqual(status, 2)
        prompt.assert_not_called()
        provider.assert_not_called()

    def test_oast_start_failure_still_reaches_internal_review_assembly(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("builtins.input", return_value="y"),
            patch.object(juice.getpass, "getpass", return_value=""),
            patch.object(
                juice, "InteractshCliCallbackService",
                side_effect=OSError("provider unavailable"),
            ) as provider,
            patch.object(juice, "build_run_router", return_value=object()) as router,
            patch.object(
                juice, "build_local_application",
                side_effect=RuntimeError("assembly reached"),
            ) as build,
            contextlib.redirect_stdout(io.StringIO()) as output,
            self.assertRaisesRegex(RuntimeError, "assembly reached"),
        ):
            juice.main([
                "runner", "http://127.0.0.1:3000/", "--vuln", "auto",
                "--recon-entry", "base-url", "--ssrf-review",
                "--ssrf-oast", "public_interactsh",
                "--ssrf-public-oast-consent",
                "--routing-log", str(Path(directory) / "routing.jsonl"),
            ])

        self.assertIsNone(router.call_args.kwargs["ssrf_callback_service"])
        self.assertIsNone(build.call_args.kwargs["ssrf_callback_service"])
        self.assertTrue(provider.call_args.kwargs["public_oast"])
        self.assertTrue(provider.call_args.kwargs["public_oast_consent"])
        self.assertIn("callback 전략만 비활성화", output.getvalue())

    def test_unprotected_private_oast_reaches_confirmation_without_token(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("builtins.input", return_value="n") as prompt,
            patch.object(juice, "InteractshCliCallbackService") as provider,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            status = juice.main([
                "runner", "http://127.0.0.1:3000/", "--vuln", "auto",
                "--recon-entry", "base-url", "--ssrf-oast", "private_interactsh",
                "--ssrf-interactsh-server", "https://oast.example",
                "--routing-log", str(Path(directory) / "routing.jsonl"),
            ])
        self.assertEqual(status, 2)
        prompt.assert_called_once()
        self.assertIn("취소했습니다", output.getvalue())
        provider.assert_not_called()

    def test_help_exposes_router_and_audit_options(self):
        for runner in (dvwa, juice):
            with self.subTest(runner=runner.__name__), contextlib.redirect_stdout(io.StringIO()) as output:
                with self.assertRaises(SystemExit) as result:
                    runner.main(["runner", "--help"])
                self.assertEqual(result.exception.code, 0)
                self.assertIn("--router {heuristic,hybrid,agentic}", output.getvalue())
                self.assertIn("--llm-rpm-limit", output.getvalue())
                self.assertIn("--routing-log", output.getvalue())
                self.assertIn(
                    "--recon {heuristic,hybrid,agentic}", output.getvalue()
                )
                self.assertIn(
                    "--surface-collection {adaptive,deterministic}",
                    output.getvalue(),
                )
                self.assertIn("--compare-routers", output.getvalue())
                self.assertIn("--router-review", output.getvalue())
                self.assertIn("--report {heuristic,llm}", output.getvalue())
                if runner is juice:
                    self.assertIn("--ssrf-review", output.getvalue())


if __name__ == "__main__":
    unittest.main()
