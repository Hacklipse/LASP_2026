"""웹 대시보드의 요청 경계와 CLI 동등성을 검증한다.

여기서 확인하는 것은 세 가지다.

    ① 화면에서 고른 값이 실제 배선과 RunExecutionProfile 기록에 그대로 간다
    ② 다른 출처가 /api/run 으로 Run 을 시작할 수 없다
    ③ 비밀(계정 비밀번호·token)이 화면 상태 어디에도 남지 않는다

실제 Juice Shop 5종 통합 실행은 대상이 떠 있어야 하므로 기본적으로 건너뛴다.
돌리려면 npm start 로 Juice Shop 을 띄우고 아래 두 환경변수를 준다.

    HACKLIPSE_JUICE_SHOP_URL=http://127.0.0.1:3001/
    HACKLIPSE_JUICE_SHOP_DB=/path/to/juice-shop/data/juiceshop.sqlite
    HACKLIPSE_JUICE_ACTOR=email:password
    HACKLIPSE_JUICE_OWNER=email:password
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from unittest.mock import Mock

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT / "scripts"))

import serve_dashboard as sd  # noqa: E402
import run_juice_shop_baseline as juice_cli  # noqa: E402
from dashboard_core import (  # noqa: E402
    MODE_GENERIC,
    MODE_JUICE_SHOP,
    AccessAccounts,
    DashboardState,
    RunOptions,
    RunSecrets,
    RunSupervisor,
    SsrfReviewSubmission,
)
from hacklipse.adapters import (  # noqa: E402
    InMemorySsrfReviewRegistry,
    MemoryStoreBundle,
    SsrfReviewRegistration,
)
from hacklipse.domain import (  # noqa: E402
    Candidate,
    Evidence,
    Run,
    RunScope,
    SsrfDestinationRule,
    SsrfPolicyAssertion,
    SsrfPolicyEvidenceStatus,
    SsrfPolicySource,
    Surface,
)
from routing_options import execution_profile_from_args  # noqa: E402


def _defaults() -> RunOptions:
    return RunOptions(target="http://127.0.0.1:3000/")


class BudgetDefaultTests(unittest.TestCase):
    def test_browser_recon_option_is_parsed_and_recorded(self) -> None:
        options, _ = sd.parse_run_payload({"target": "http://127.0.0.1:3000/", "browser_recon": True}, _defaults())
        self.assertTrue(options.browser_recon)
        self.assertTrue(execution_profile_from_args(options.to_namespace()).browser_recon_enabled)

    def test_cli_and_dashboard_use_conservative_defaults(self) -> None:
        self.assertEqual(juice_cli._DEFAULT_BUDGET, 20)
        self.assertEqual(juice_cli._ALL_MODE_BUDGET, 80)
        self.assertEqual(RunOptions(
            target="http://127.0.0.1:3000/", mode=MODE_JUICE_SHOP,
            vuln="ssti",
        ).resolved_budget(), 20)
        self.assertEqual(RunOptions(
            target="http://127.0.0.1:3000/", mode=MODE_JUICE_SHOP,
            vuln="xss",
        ).resolved_budget(), 20)
        self.assertEqual(RunOptions(
            target="http://127.0.0.1:3000/", mode=MODE_JUICE_SHOP,
            vuln="path_traversal",
        ).resolved_budget(), 20)
        self.assertEqual(RunOptions(
            target="http://127.0.0.1:3000/", mode=MODE_JUICE_SHOP,
            vuln="all",
        ).resolved_budget(), 80)
        self.assertEqual(_defaults().resolved_budget(), 80)

    def test_explicit_500_remains_available_and_version_is_recorded(self) -> None:
        options = RunOptions(
            target="http://127.0.0.1:3000/", mode=MODE_JUICE_SHOP,
            vuln="all", budget=500, code_version="feat/capability-driven-routing",
        )
        self.assertEqual(sd._require_budget({"budget": 500}), 500)
        self.assertEqual(options.resolved_budget(), 500)
        self.assertEqual(
            execution_profile_from_args(options.to_namespace()).code_version,
            "feat/capability-driven-routing",
        )


class DashboardMarkupTests(unittest.TestCase):
    """접기 UI의 정적 계약이 HTML과 JavaScript 양쪽에서 유지된다."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.html = (_ROOT / "web" / "index.html").read_text(encoding="utf-8")
        cls.javascript = (_ROOT / "web" / "app.js").read_text(encoding="utf-8")

    def test_run_conditions_have_two_controls_for_the_same_collapsible_body(self) -> None:
        self.assertIn('id="setup-body" hidden', self.html)
        self.assertEqual(self.html.count('aria-controls="setup-body"'), 2)
        self.assertIn('id="setup-panel-toggle"', self.html)
        self.assertIn("function setSetupExpanded(expanded)", self.javascript)

    def test_findings_use_per_type_accordions_instead_of_one_flat_body(self) -> None:
        self.assertIn('id="findings-groups"', self.html)
        self.assertNotIn('id="findings-body"', self.html)
        self.assertIn('class="finding-group-toggle"', self.javascript)
        self.assertIn('aria-expanded="${expanded}"', self.javascript)
        self.assertIn("const expandedFindingGroups = new Set();", self.javascript)

    def test_ssrf_review_panel_keeps_passive_and_active_states_distinct(self) -> None:
        self.assertIn('id="ssrf-review"', self.html)
        for status in (
            "REVIEW_REQUIRED",
            "CALLBACK_OBSERVED",
            "CANARY_OBSERVED_POLICY_PENDING",
            "CONFIRMED_POLICY_VIOLATION",
            "CALLBACK_PROVIDER_BLOCKED",
            "OBSERVATION_PROVIDER_BLOCKED",
            "EXECUTION_APPROVAL_PENDING",
            "POLICY_EVIDENCE_PENDING",
            "VALIDATION_BUDGET_INSUFFICIENT",
            "ALLOWED_DESTINATION",
            "CALLBACK_NOT_OBSERVED",
            "CALLBACK_ANALYSIS_OBSERVED",
            "CALLBACK_NOT_REPRODUCED",
            "CANARY_ANALYSIS_OBSERVED",
            "CANARY_NOT_REPRODUCED",
            "OWNED_RECEIVER_OBSERVED_POLICY_PENDING",
            "OWNED_RECEIVER_ANALYSIS_OBSERVED",
            "OWNED_RECEIVER_NOT_REPRODUCED",
            "OWNED_RECEIVER_NOT_OBSERVED",
            "OWNED_RECEIVER_PROVIDER_BLOCKED",
            "VALIDATION_REPRODUCED",
            "VALIDATION_NOT_REPRODUCED",
        ):
            self.assertIn(status, self.javascript)
        self.assertIn("운영자 검토: 대기", self.javascript)
        self.assertIn("아직 검사에 사용되지 않음", self.javascript)
        self.assertIn("운영자 검토 등록", self.javascript)
        self.assertIn("operator:", self.javascript)
        self.assertIn("review.callback_status", self.javascript)
        self.assertIn("review.canary_status", self.javascript)
        self.assertIn("review.owned_receiver_status", self.javascript)
        self.assertIn("review.approved_surface_id", self.javascript)
        self.assertIn('id="ssrf-review-hint-consent"', self.html)
        self.assertIn('id="ssrf-review-owned-receiver"', self.html)
        self.assertIn("use_owned_receiver:", self.javascript)
        self.assertIn("hint_use_approved:", self.javascript)
        self.assertNotIn('value="config_allowlist"', self.html)
        self.assertNotIn('value="openapi_allowlist"', self.html)


class PayloadValidationTests(unittest.TestCase):
    """계약을 벗어난 입력은 Run 으로 넘어가기 전에 막힌다."""

    def _parse(self, **overrides):
        payload = {"target": "http://127.0.0.1:3000/", **overrides}
        return sd.parse_run_payload(payload, _defaults())

    def test_accepts_a_minimal_payload(self) -> None:
        options, secrets = self._parse()
        self.assertEqual(options.mode, MODE_GENERIC)
        self.assertEqual(options.profile, "heuristic")
        self.assertEqual(secrets.ssti_token, "")

    def test_structured_ssrf_review_accepts_only_opaque_refs(self) -> None:
        action, review = sd.parse_ssrf_review_payload({
            "action": "register",
            "run_id": "run-1",
            "surface_id": "surface-1",
            "parameter": "url",
            "hint_evidence_id": "evi-hint-1",
            "verification_endpoint_ref": "verification-service:v1",
            "approved_by": "team-member",
            "destination_rule": "unknown",
            "policy_source": "",
            "source_reference": "",
        })
        self.assertEqual(action, "register")
        assert review is not None
        self.assertEqual(review.run_id, "run-1")
        self.assertIsNone(review.destination_rule)
        self.assertIsNone(review.policy_source)
        self.assertFalse(review.hint_use_approved)

        for field in ("verification_endpoint_ref",):
            payload = {
                "action": "register",
                "run_id": "run-1",
                "surface_id": "surface-1",
                "parameter": "url",
                "verification_endpoint_ref": "verification-service:v1",
                "approved_by": "team-member",
                "destination_rule": "unknown",
                "policy_source": "",
                "source_reference": "",
                field: "https://example.invalid/private?token=value",
            }
            with self.subTest(field=field), self.assertRaises(sd.RequestRejected):
                sd.parse_ssrf_review_payload(payload)

        secret_payload = {
            "action": "register",
            "run_id": "run-1",
            "surface_id": "surface-1",
            "parameter": "url",
            "verification_endpoint_ref": "verification-service:v1",
            "approved_by": "sk-THISISALONGSECRETKEY1234567890",
            "destination_rule": "unknown",
            "policy_source": "",
            "source_reference": "",
        }
        with self.assertRaises(sd.RequestRejected):
            sd.parse_ssrf_review_payload(secret_payload)

    def test_internal_ssrf_review_allows_execution_without_policy(self) -> None:
        payload = {
            "action": "register", "run_id": "run-1", "surface_id": "surface-1",
            "parameter": "url", "approved_by": "team-member",
            "hint_evidence_id": "evi-hint-1",
            "verification_url": "http://verification.internal/health",
            "execution_consent": True, "hint_use_approved": True,
            "destination_rule": "forbidden",
            "policy_source": "operator_attestation",
            "source_reference": "operator:ssrf-1",
        }
        action, review = sd.parse_ssrf_review_payload(payload)
        self.assertEqual(action, "register")
        assert review is not None
        self.assertEqual(review.verification_url, payload["verification_url"])
        self.assertNotIn(payload["verification_url"], repr(review))
        self.assertTrue(review.hint_use_approved)
        _, no_policy = sd.parse_ssrf_review_payload({
            **payload,
            "destination_rule": "unknown",
            "policy_source": "",
            "source_reference": "",
        })
        assert no_policy is not None
        self.assertIsNone(no_policy.destination_rule)
        self.assertIsNone(no_policy.policy_source)
        _, allowed = sd.parse_ssrf_review_payload({
            **payload,
            "destination_rule": "allowed",
            "source_reference": "operator:ssrf-allowed-1",
        })
        assert allowed is not None
        self.assertIs(allowed.destination_rule, SsrfDestinationRule.ALLOWED)
        for source, reference in (
            ("config_allowlist", "config:ssrf-egress-v1"),
            ("openapi_allowlist", "openapi:fetch-policy-v1"),
        ):
            with self.subTest(source=source), self.assertRaises(sd.RequestRejected):
                sd.parse_ssrf_review_payload({
                    **payload, "policy_source": source, "source_reference": reference,
                })
        for changed in (
            {"execution_consent": False},
            {"policy_source": "openapi_allowlist"},
            {"verification_endpoint_ref": "verification-service:v1"},
        ):
            with self.subTest(changed=changed), self.assertRaises(sd.RequestRejected):
                sd.parse_ssrf_review_payload({**payload, **changed})
        with self.assertRaises(sd.RequestRejected):
            sd.parse_ssrf_review_payload({
                **payload,
                "source_reference": "operator:sk-THISISALONGSECRETKEY1234567890",
            })
        for changed in (
            {"hint_evidence_id": ""},
            {
                "verification_url": "",
                "execution_consent": False,
                "verification_endpoint_ref": "verification-service:v1",
            },
        ):
            with self.subTest(changed=changed), self.assertRaises(sd.RequestRejected):
                sd.parse_ssrf_review_payload({**payload, **changed})

    def test_owned_receiver_review_requires_explicit_consent_and_no_url(self) -> None:
        payload = {
            "action": "register", "run_id": "run-1",
            "surface_id": "surface-1", "parameter": "url",
            "approved_by": "team-member", "hint_evidence_id": "",
            "use_owned_receiver": True, "execution_consent": True,
            "destination_rule": "forbidden",
            "policy_source": "operator_attestation",
            "source_reference": "operator:receiver-policy-v1",
        }
        _, review = sd.parse_ssrf_review_payload(payload)
        assert review is not None
        self.assertTrue(review.use_owned_receiver)
        self.assertEqual(review.verification_endpoint_ref, "")
        self.assertEqual(review.verification_url, "")
        for changed in (
            {"execution_consent": False},
            {"verification_url": "http://internal.example/health"},
            {"verification_endpoint_ref": "verification-service:v1"},
            {"hint_use_approved": True, "hint_evidence_id": "evi-hint-1"},
        ):
            with self.subTest(changed=changed), self.assertRaises(sd.RequestRejected):
                sd.parse_ssrf_review_payload({**payload, **changed})

    def test_ssrf_review_skip_still_requires_exact_run_id(self) -> None:
        action, review = sd.parse_ssrf_review_payload({
            "action": "skip", "run_id": "run-1",
        })
        self.assertEqual(action, "skip")
        self.assertIsNone(review)
        with self.assertRaises(sd.RequestRejected):
            sd.parse_ssrf_review_payload({"action": "skip", "run_id": ""})

    def test_review_gate_allows_operator_verification_without_external_callback(self) -> None:
        options, secrets = self._parse(ssrf_review_gate=True, ssrf_oast="off")
        supervisor = RunSupervisor(
            allowed_hosts=frozenset({"127.0.0.1"}), defaults=_defaults(),
        )
        self.assertTrue(options.ssrf_review_gate)
        self.assertFalse(options.ssrf_local_callback)
        self.assertIsNone(supervisor.validate(options, secrets))

    def test_local_ssrf_callback_is_explicit_and_loopback_only(self) -> None:
        options, _ = self._parse(ssrf_local_callback=True)
        self.assertTrue(options.ssrf_local_callback)
        supervisor = RunSupervisor(
            allowed_hosts=frozenset({"127.0.0.1", "example.com"}), defaults=_defaults(),
        )
        self.assertIsNone(supervisor.validate(options, RunSecrets()))
        remote = RunOptions(target="https://example.com/", ssrf_local_callback=True)
        self.assertIn("loopback", supervisor.validate(remote, RunSecrets()) or "")
        targeted = RunOptions(
            target="http://127.0.0.1:3000/", mode=MODE_JUICE_SHOP,
            vuln="sqli", ssrf_local_callback=True,
        )
        self.assertIn("자동·전체", supervisor.validate(targeted, RunSecrets()) or "")

    def test_owned_local_receiver_requires_review_and_loopback(self) -> None:
        supervisor = RunSupervisor(
            allowed_hosts=frozenset({"127.0.0.1", "example.com"}), defaults=_defaults(),
        )
        missing_review = RunOptions(
            target="http://127.0.0.1:3000/", ssrf_owned_local_receiver=True,
        )
        self.assertIn("승인 절차", supervisor.validate(missing_review, RunSecrets()) or "")
        enabled = replace(missing_review, ssrf_review_gate=True)
        self.assertIsNone(supervisor.validate(enabled, RunSecrets()))
        remote = replace(enabled, target="https://example.com/")
        self.assertIn("loopback", supervisor.validate(remote, RunSecrets()) or "")

    def test_public_oast_requires_consent_and_private_token_stays_out_of_options(self) -> None:
        supervisor = RunSupervisor(
            allowed_hosts=frozenset({"127.0.0.1"}), defaults=_defaults(),
        )
        public, _ = self._parse(ssrf_oast="public_interactsh")
        self.assertIn("동의", supervisor.validate(public, RunSecrets()) or "")
        consented, _ = self._parse(
            ssrf_oast="public_interactsh", ssrf_public_oast_consent=True,
        )
        self.assertIsNone(supervisor.validate(consented, RunSecrets()))
        profile = execution_profile_from_args(consented.to_namespace())
        self.assertEqual(profile.ssrf_oast_mode, "public_interactsh")
        self.assertTrue(profile.ssrf_public_oast_consented)
        private, secrets = self._parse(
            ssrf_oast="private_interactsh",
            ssrf_interactsh_server="https://oast.example",
            interactsh_token="private-secret",
        )
        self.assertIsNone(supervisor.validate(private, secrets))
        self.assertNotIn("private-secret", repr(private))
        self.assertNotIn("private-secret", repr(secrets))
        unprotected, empty_secrets = self._parse(
            ssrf_oast="private_interactsh",
            ssrf_interactsh_server="https://oast.example",
        )
        self.assertIsNone(supervisor.validate(unprotected, empty_secrets))
        missing_server, _ = self._parse(ssrf_oast="private_interactsh")
        self.assertIn("서버 주소", supervisor.validate(missing_server, RunSecrets()) or "")

    def test_rejects_unknown_enum_values(self) -> None:
        for field, value in (
            ("mode", "nope"),
            ("vuln", "zzz"),
            ("router", "evil"),
            ("report", "banana"),
            ("surface_collection", "random"),
        ):
            with self.subTest(field=field):
                with self.assertRaises(sd.RequestRejected):
                    self._parse(**{field: value})

    def test_rejects_wrong_types(self) -> None:
        for field, value in (
            ("target", 123),
            ("validation_review", "yes"),
            ("budget", "40"),
            ("llm_rpm_limit", 0),
            ("access_accounts", "actor"),
        ):
            with self.subTest(field=field):
                with self.assertRaises(sd.RequestRejected):
                    self._parse(**{field: value})

    def test_rejects_out_of_range_budget(self) -> None:
        for value in (-1, 0.5, sd.MAX_BUDGET + 1):
            with self.subTest(value=value):
                with self.assertRaises(sd.RequestRejected):
                    self._parse(budget=value)

    def test_absent_budget_means_the_per_type_default(self) -> None:
        options, _ = self._parse(mode=MODE_JUICE_SHOP, vuln="sqli")
        self.assertEqual(options.budget, 0)
        self.assertGreater(options.resolved_budget(), 0)

    def test_rejects_overlong_strings(self) -> None:
        with self.assertRaises(sd.RequestRejected):
            self._parse(target="http://127.0.0.1/" + "a" * 400)

    def test_rejects_an_engine_without_its_key(self) -> None:
        for engine in ("llm:anthropic", "llm:gemini"):
            env = sd.ENGINE_BY_ID[engine]["key_env"]
            with self.subTest(engine=engine), _without_env(env):
                with self.assertRaises(sd.RequestRejected):
                    self._parse(engine=engine)


class ExecutionProfileFidelityTests(unittest.TestCase):
    """화면 선택이 그대로 기록된다. 선택지만 보이고 실행은 고정값이면 안 된다."""

    def test_dashboard_allows_two_analysis_rounds_for_staged_analyzers(self) -> None:
        for router in ("agentic", "heuristic"):
            with self.subTest(router=router):
                options = RunOptions(
                    target="http://127.0.0.1:3000/", router=router,
                )
                supervisor = RunSupervisor(
                    allowed_hosts=frozenset({"127.0.0.1"}), defaults=options,
                )
                with (
                    patch.object(supervisor, "_build_llm_client", return_value=(None, None)),
                    patch("dashboard_core.build_run_router", return_value=object()),
                    patch("dashboard_core.build_local_application", side_effect=RuntimeError("stop before execution")) as build,
                    self.assertRaisesRegex(RuntimeError, "stop before execution"),
                ):
                    supervisor._execute_run(options, RunSecrets())
                self.assertEqual(build.call_args.kwargs["config"].max_evidence_rounds, 2)
                self.assertIsNone(
                    build.call_args.kwargs["config"].post_recon_gate
                )

    def test_dashboard_review_gate_is_explicitly_opt_in(self) -> None:
        options = RunOptions(
            target="http://127.0.0.1:3000/", ssrf_review_gate=True,
        )
        supervisor = RunSupervisor(
            allowed_hosts=frozenset({"127.0.0.1"}), defaults=options,
        )
        with (
            patch.object(supervisor, "_build_llm_client", return_value=(None, None)),
            patch("dashboard_core.build_run_router", return_value=object()),
            patch(
                "dashboard_core.build_local_application",
                side_effect=RuntimeError("stop before execution"),
            ) as build,
            self.assertRaisesRegex(RuntimeError, "stop before execution"),
        ):
            supervisor._execute_run(options, RunSecrets())

        self.assertTrue(callable(
            build.call_args.kwargs["config"].post_recon_gate
        ))

    def test_oast_session_closes_when_application_assembly_fails(self) -> None:
        options = RunOptions(
            target="http://127.0.0.1:3000/", ssrf_oast="public_interactsh",
            ssrf_public_oast_consent=True,
        )
        supervisor = RunSupervisor(
            allowed_hosts=frozenset({"127.0.0.1"}), defaults=options,
        )
        provider = Mock(origin="https://oast.pro")
        provider.public_oast = True
        with (
            patch.object(supervisor, "_build_llm_client", return_value=(None, None)),
            patch(
                "dashboard_core.InteractshCliCallbackService", return_value=provider,
            ) as constructor,
            patch("dashboard_core.build_run_router", return_value=object()),
            patch("dashboard_core.build_local_application", side_effect=RuntimeError("assembly failed")),
            self.assertRaisesRegex(RuntimeError, "assembly failed"),
        ):
            supervisor._execute_run(options, RunSecrets())
        self.assertTrue(constructor.call_args.kwargs["public_oast"])
        self.assertTrue(constructor.call_args.kwargs["public_oast_consent"])
        provider.close.assert_called_once()

    def test_owned_receiver_is_separate_and_closes_on_assembly_failure(self) -> None:
        options = RunOptions(
            target="http://127.0.0.1:3000/",
            ssrf_review_gate=True,
            ssrf_owned_local_receiver=True,
        )
        supervisor = RunSupervisor(
            allowed_hosts=frozenset({"127.0.0.1"}), defaults=options,
        )
        class Receiver:
            origin = "http://127.0.0.1:39124"
            public_oast = False
            operator_owned = True

            def __init__(self):
                self.close = Mock()

        with (
            patch.object(supervisor, "_build_llm_client", return_value=(None, None)),
            patch("dashboard_core.LocalSsrfCallbackService", Receiver),
            patch("dashboard_core.build_run_router", return_value=object()),
            patch(
                "dashboard_core.build_local_application",
                side_effect=RuntimeError("assembly failed"),
            ) as build,
            self.assertRaisesRegex(RuntimeError, "assembly failed"),
        ):
            supervisor._execute_run(options, RunSecrets())

        receiver = build.call_args.kwargs["ssrf_owned_receiver_service"]
        self.assertIsNone(build.call_args.kwargs["ssrf_callback_service"])
        self.assertIsInstance(receiver, Receiver)
        receiver.close.assert_called_once()

    def test_oast_start_failure_disables_only_callback_strategy(self) -> None:
        options = RunOptions(
            target="http://127.0.0.1:3000/", ssrf_oast="public_interactsh",
            ssrf_public_oast_consent=True, ssrf_review_gate=True,
        )
        supervisor = RunSupervisor(
            allowed_hosts=frozenset({"127.0.0.1"}), defaults=options,
        )
        with (
            patch.object(supervisor, "_build_llm_client", return_value=(None, None)),
            patch(
                "dashboard_core.InteractshCliCallbackService",
                side_effect=OSError("provider unavailable"),
            ),
            patch("dashboard_core.build_run_router", return_value=object()) as router,
            patch(
                "dashboard_core.build_local_application",
                side_effect=RuntimeError("assembly reached"),
            ) as build,
            self.assertRaisesRegex(RuntimeError, "assembly reached"),
        ):
            supervisor._execute_run(options, RunSecrets())

        self.assertIsNone(router.call_args.kwargs["ssrf_callback_service"])
        self.assertIsNone(build.call_args.kwargs["ssrf_callback_service"])
        events = supervisor.state.read(0)["events"]
        self.assertIn(
            "callback 전략만 비활성화",
            "\n".join(item["detail"] for item in events),
        )

    def test_every_choice_reaches_the_recorded_profile(self) -> None:
        options = RunOptions(
            target="http://127.0.0.1:3000/",
            profile="llm",
            recon="hybrid",
            recon_entry="base-url",
            surface_collection="deterministic",
            router="hybrid",
            router_review="ambiguous",
            orchestrator="hybrid",
            budget_allocation="hybrid",
            validation_review=True,
            report="llm",
            llm_provider="gemini",
            llm_rpm_limit=9,
        )
        profile = execution_profile_from_args(
            options.to_namespace(),
            selected_model=options.resolved_model(),
            llm_rpm_limit=options.llm_rpm_limit,
        )
        self.assertEqual(profile.analysis_profile, "llm")
        self.assertEqual(profile.recon_mode, "hybrid")
        self.assertEqual(profile.recon_entry_mode, "base-url")
        self.assertEqual(profile.surface_collection_mode, "deterministic")
        self.assertEqual(profile.router_mode, "hybrid")
        self.assertEqual(profile.router_review, "ambiguous")
        self.assertEqual(profile.orchestrator_mode, "hybrid")
        self.assertEqual(profile.budget_allocation_mode, "hybrid")
        self.assertEqual(profile.validation_mode, "llm")
        self.assertEqual(profile.report_mode, "llm")
        self.assertEqual(profile.llm_provider, "gemini")
        self.assertEqual(profile.llm_rpm_limit, 9)
        self.assertTrue(profile.llm_model)

    def test_a_deterministic_run_records_no_llm(self) -> None:
        options = RunOptions(target="http://127.0.0.1:3000/")
        profile = execution_profile_from_args(
            options.to_namespace(), selected_model=options.resolved_model()
        )
        self.assertEqual(profile.analysis_profile, "heuristic")
        self.assertEqual(profile.llm_provider, "")
        self.assertEqual(profile.llm_model, "")


class ModeGatingTests(unittest.TestCase):
    """범용 대상에는 Juice Shop 전용 준비를 적용하지 않는다."""

    def test_generic_mode_asks_for_no_accounts_or_browser(self) -> None:
        options = RunOptions(target="http://127.0.0.1:8000/", mode=MODE_GENERIC)
        self.assertFalse(options.needs_access_accounts)
        self.assertFalse(options.needs_path_account)
        self.assertFalse(options.needs_ssti_token)
        self.assertFalse(options.needs_browser)

    def test_juice_shop_all_requires_accounts_and_a_browser(self) -> None:
        options = RunOptions(
            target="http://127.0.0.1:3000/", mode=MODE_JUICE_SHOP, vuln="all"
        )
        self.assertTrue(options.needs_access_accounts)
        self.assertTrue(options.needs_path_account)
        self.assertTrue(options.needs_browser)

    def test_juice_shop_auto_is_answer_blind_and_needs_no_target_setup(self) -> None:
        supervisor = RunSupervisor(
            allowed_hosts=frozenset({"127.0.0.1"}), defaults=_defaults()
        )
        targeted = RunOptions(
            target="http://127.0.0.1:3000/",
            mode=MODE_JUICE_SHOP,
            vuln="auto",
        )
        self.assertIn(
            "base-url", supervisor.validate(targeted, RunSecrets()) or ""
        )

        options = RunOptions(
            target="http://127.0.0.1:3000/",
            mode=MODE_JUICE_SHOP,
            vuln="auto",
            recon_entry="base-url",
        )
        self.assertIsNone(supervisor.validate(options, RunSecrets()))
        self.assertTrue(options.broad_scan)
        self.assertTrue(options.needs_browser)
        self.assertFalse(options.needs_access_accounts)
        self.assertFalse(options.needs_path_account)
        self.assertFalse(options.needs_ssti_token)

    def test_validation_review_needs_the_llm_profile(self) -> None:
        supervisor = RunSupervisor(
            allowed_hosts=frozenset({"127.0.0.1"}), defaults=_defaults()
        )
        options = RunOptions(
            target="http://127.0.0.1:3000/", validation_review=True, profile="heuristic"
        )
        self.assertIsNotNone(supervisor.validate(options, RunSecrets()))

    def test_access_control_without_accounts_is_refused(self) -> None:
        supervisor = RunSupervisor(
            allowed_hosts=frozenset({"127.0.0.1"}), defaults=_defaults()
        )
        options = RunOptions(
            target="http://127.0.0.1:3000/", mode=MODE_JUICE_SHOP, vuln="access_control"
        )
        self.assertIn("ACTOR", supervisor.validate(options, RunSecrets()) or "")

    def test_targets_outside_the_allowlist_are_refused(self) -> None:
        supervisor = RunSupervisor(
            allowed_hosts=frozenset({"127.0.0.1"}), defaults=_defaults()
        )
        options = RunOptions(target="http://example.com/")
        self.assertIn("허용 대상이 아니다", supervisor.validate(options, RunSecrets()) or "")


class SecretContainmentTests(unittest.TestCase):
    """비밀은 화면 상태에 애초에 들어가지 않는다."""

    def test_run_options_carry_no_secret_field(self) -> None:
        fields = set(RunOptions.__dataclass_fields__)
        for forbidden in ("password", "token", "email", "cookie"):
            self.assertFalse(
                any(forbidden in name for name in fields),
                f"RunOptions 에 비밀처럼 보이는 필드가 있다: {forbidden}",
            )

    def test_state_serialisation_never_contains_the_inputs(self) -> None:
        options = RunOptions(
            target="http://127.0.0.1:3000/", mode=MODE_JUICE_SHOP, vuln="all"
        )
        state = DashboardState(budget=40, target=options.target)
        state.begin(options, engine_label="Heuristic")
        state.note("ACTOR/OWNER 테스트 계정 로그인 중")
        rendered = json.dumps(state.read(0), ensure_ascii=False)
        for secret in ("super-secret-pw", "actor@example.test", "token-value"):
            self.assertNotIn(secret, rendered)

    def test_access_accounts_hide_values_in_repr(self) -> None:
        accounts = AccessAccounts(
            actor_email="actor@example.test",
            actor_password="super-secret-pw",
            owner_email="owner@example.test",
            owner_password="another-secret",
        )
        self.assertNotIn("super-secret-pw", repr(accounts))
        self.assertNotIn("actor@example.test", repr(accounts))

    def test_identical_accounts_are_refused(self) -> None:
        accounts = AccessAccounts(
            actor_email="same@example.test",
            actor_password="a",
            owner_email="SAME@example.test",
            owner_password="b",
        )
        with self.assertRaises(ValueError):
            accounts.to_cli_inputs()

    def test_candidate_api_masks_secret_surface_path(self) -> None:
        secret = "DEMO-SECRET-0123456789"
        stores = MemoryStoreBundle()
        run = Run(
            run_id="run-secret-path",
            target_url="http://local.test/",
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            policy_profile="safe",
            request_budget=20,
        )
        surface = Surface(
            surface_id="surface-secret-path", run_id=run.run_id,
            url=f"http://local.test/api/private/token/{secret}?url=redacted",
            method="GET", parameters=("url",),
        )
        candidate = Candidate(
            candidate_id="candidate-secret-path", run_id=run.run_id,
            surface_id=surface.surface_id, vulnerability_type="SSRF",
            hypothesis="observed URL input", assigned_agent="ssrf_analyzer",
            evidence_ids=(),
        )
        stores.runs.add(run)
        stores.surfaces.add(surface)
        stores.candidates.add(candidate)
        supervisor = RunSupervisor(
            allowed_hosts=frozenset({"local.test"}), defaults=_defaults(),
        )
        supervisor._app = SimpleNamespace(
            stores=stores,
            budget_manager=None,
            collector=SimpleNamespace(ssrf_callback_usage=(0, 0)),
        )

        supervisor._refresh(run.run_id)
        view = supervisor.state.read(0)

        self.assertEqual(
            view["candidates"][0]["path"],
            "/api/private/token/{redacted}",
        )
        self.assertNotIn(secret, json.dumps(view, ensure_ascii=False))


class SsrfReviewGateTests(unittest.TestCase):
    _HINT_URL = "http://service.internal:8025/private/token/DEMO-SECRET"

    def _supervisor(self):
        stores = MemoryStoreBundle()
        stores.surfaces.add(Surface(
            surface_id="surface-1",
            run_id="run-1",
            url=(
                "http://local.test/api/fetch/token/"
                "DEMO-SECRET-0123456789?url=redacted"
            ),
            method="GET",
            parameters=("url",),
        ))
        stores.surfaces.add(Surface(
            surface_id="surface-openapi", run_id="run-1",
            url="http://local.test/openapi.json", method="GET", parameters=(),
        ))
        stores.evidence.append(Evidence(
            evidence_id="evi-review-1",
            run_id="run-1",
            surface_id="surface-1",
            created_by="recon",
            evidence_type="observation",
            observation={
                "type": "ssrf_url_fetch_review",
                "parameter_names": ["url"],
                "parameter_sources": [{"name": "url", "source": "observed_query"}],
            },
        ))
        stores.evidence.append(Evidence(
            evidence_id="evi-hint-1",
            run_id="run-1",
            surface_id="surface-openapi",
            created_by="recon",
            evidence_type="observation",
            observation={
                "type": "ssrf_destination_hint",
                "destination_origin": "http://service.internal:8025",
                "path_hint": "/private/token/{redacted}",
                "destination_fingerprint": "a" * 64,
                "source": "openapi_document",
                "probe_authorized": False,
            },
        ))
        registry = InMemorySsrfReviewRegistry()
        collector = Mock()
        collector.ssrf_owned_receiver_enabled = False

        def register(**kwargs):
            if (
                kwargs["hint_use_approved"]
                and kwargs["approved_destination_url"] != self._HINT_URL
            ):
                raise ValueError("approved URL does not match the selected Recon hint")
            registry.register(SsrfReviewRegistration(
                run_id=kwargs["run_id"],
                parameter=kwargs["parameter"],
                hint_evidence_id=kwargs["hint_evidence_id"],
                execution_approval=kwargs["approval"],
                verification_strategy=kwargs["verification_strategy"],
                destination_policy=kwargs["destination_policy"],
                hint_use_approved=kwargs["hint_use_approved"],
            ))

        collector.register_ssrf_review.side_effect = register
        supervisor = RunSupervisor(
            allowed_hosts=frozenset({"local.test"}), defaults=_defaults(),
        )
        supervisor._app = SimpleNamespace(
            stores=stores, collector=collector, ssrf_reviews=registry,
            register_ssrf_canary_proof=Mock(),
            ssrf_verification_endpoint_ref=Mock(return_value="endpoint-opaque-1"),
            ssrf_owned_receiver_origin=None,
            ssrf_owned_receiver_endpoint_ref=Mock(return_value="endpoint-owned-1"),
        )
        return supervisor, registry, collector

    def test_same_run_gate_registers_exact_coordinate_before_releasing(self) -> None:
        supervisor, registry, collector = self._supervisor()
        run = SimpleNamespace(run_id="run-1")
        thread = threading.Thread(target=supervisor._wait_for_ssrf_review, args=(run,))
        thread.start()
        deadline = time.monotonic() + 2
        while not supervisor.state.read(0)["ssrf_review_pending"] and time.monotonic() < deadline:
            time.sleep(0.01)
        view = supervisor.state.read(0)
        self.assertTrue(view["ssrf_review_pending"])
        self.assertEqual(
            view["ssrf_review_options"]["surfaces"][0]["path"],
            "/api/fetch/token/{redacted}",
        )
        self.assertNotIn("DEMO-SECRET", json.dumps(view["ssrf_review_options"]))
        self.assertEqual(view["ssrf_review_options"]["hints"][0]["source_path"], "/openapi.json")
        supervisor.register_ssrf_review(SsrfReviewSubmission(
            run_id="run-1",
            surface_id="surface-1",
            parameter="url",
            hint_evidence_id="evi-hint-1",
            verification_endpoint_ref="verification-service:v1",
            approved_by="team-member",
            destination_rule=None,
            policy_source=None,
            source_reference="",
        ))
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        registration = registry.get(
            run_id="run-1", surface_id="surface-1", parameter="url",
        )
        self.assertIsNotNone(registration)
        assert registration is not None
        self.assertEqual(
            registration.execution_approval.verification_endpoint_ref,
            "verification-service:v1",
        )
        self.assertFalse(supervisor.state.read(0)["ssrf_review_pending"])
        collector.register_ssrf_review.assert_called_once()
        registered = collector.register_ssrf_review.call_args.kwargs
        self.assertFalse(registered["hint_use_approved"])
        self.assertIsNone(registered["approved_destination_url"])

    def test_internal_ssrf_review_registers_only_after_valid_marker_and_policy(self) -> None:
        supervisor, _, collector = self._supervisor()
        supervisor._ssrf_review_pending_run_id = "run-1"
        verification_url = self._HINT_URL
        submission = SsrfReviewSubmission(
            run_id="run-1", surface_id="surface-1", parameter="url",
            verification_endpoint_ref="", approved_by="team-member",
            hint_evidence_id="evi-hint-1",
            destination_rule=SsrfDestinationRule.FORBIDDEN,
            policy_source=SsrfPolicySource.OPERATOR_ATTESTATION,
            source_reference="operator:ssrf-1",
            verification_url=verification_url,
            execution_consent=True,
            hint_use_approved=True,
        )
        self.assertNotIn(verification_url, repr(submission))
        with patch.dict(os.environ, {"HACKLIPSE_SSRF_CANARY_MARKER": ""}):
            with self.assertRaises(ValueError):
                supervisor.register_ssrf_review(submission)
        collector.register_ssrf_review.assert_not_called()
        self.assertIsNone(supervisor._app.ssrf_reviews.get_for_run("run-1"))
        with patch.dict(os.environ, {"HACKLIPSE_SSRF_CANARY_MARKER": "stable-test-marker-12345"}):
            supervisor.register_ssrf_review(submission)
        collector.register_ssrf_review.assert_called_once()
        supervisor._app.register_ssrf_canary_proof.assert_called_once()
        call = supervisor._app.register_ssrf_canary_proof.call_args
        self.assertEqual(call.args[0], "run-1")
        self.assertEqual(call.args[1].url, verification_url)
        policy = collector.register_ssrf_review.call_args.kwargs["destination_policy"]
        self.assertEqual(policy.destination_origin, "http://service.internal:8025")
        self.assertIs(
            policy.assertion,
            SsrfPolicyAssertion.TARGET_MUST_NOT_REACH_DESTINATION,
        )
        self.assertIs(policy.evidence_status, SsrfPolicyEvidenceStatus.ATTESTED)
        registration = collector.register_ssrf_review.call_args.kwargs
        self.assertTrue(registration["hint_use_approved"])
        self.assertEqual(registration["approved_destination_url"], verification_url)
        supervisor._app.ssrf_verification_endpoint_ref.assert_called_once_with(
            "run-1", verification_url,
        )
        self.assertNotIn(verification_url, json.dumps(supervisor.state.read(0)))

    def test_internal_ssrf_review_registers_canary_without_policy(self) -> None:
        supervisor, _, collector = self._supervisor()
        supervisor._ssrf_review_pending_run_id = "run-1"
        verification_url = "http://verification.internal/health"
        submission = SsrfReviewSubmission(
            run_id="run-1", surface_id="surface-1", parameter="url",
            verification_endpoint_ref="", approved_by="team-member",
            hint_evidence_id="evi-hint-1",
            verification_url=verification_url,
            execution_consent=True,
        )
        with patch.dict(
            os.environ, {"HACKLIPSE_SSRF_CANARY_MARKER": "stable-test-marker-12345"},
        ):
            supervisor.register_ssrf_review(submission)

        registration = collector.register_ssrf_review.call_args.kwargs
        self.assertIsNone(registration["destination_policy"])
        self.assertFalse(registration["hint_use_approved"])
        self.assertEqual(registration["approved_destination_url"], verification_url)
        proof = supervisor._app.register_ssrf_canary_proof.call_args.args[1]
        self.assertEqual(proof.surface_id, "surface-1")
        self.assertIsNone(proof.destination_policy)
        self.assertTrue(proof.operator_approved)

    def test_owned_receiver_review_registers_exact_surface_without_raw_url_state(self) -> None:
        supervisor, _, collector = self._supervisor()
        supervisor._ssrf_review_pending_run_id = "run-1"
        collector.ssrf_owned_receiver_enabled = True
        supervisor._app.ssrf_owned_receiver_origin = "http://127.0.0.1:39124"
        submission = SsrfReviewSubmission(
            run_id="run-1", surface_id="surface-1", parameter="url",
            verification_endpoint_ref="", approved_by="team-member",
            destination_rule=SsrfDestinationRule.FORBIDDEN,
            policy_source=SsrfPolicySource.OPERATOR_ATTESTATION,
            source_reference="operator:receiver-policy-v1",
            execution_consent=True,
            use_owned_receiver=True,
        )

        supervisor.register_ssrf_review(submission)

        registered = collector.register_ssrf_review.call_args.kwargs
        self.assertEqual(
            registered["approval"].verification_endpoint_ref,
            "endpoint-owned-1",
        )
        self.assertEqual(
            registered["destination_policy"].destination_origin,
            "http://127.0.0.1:39124",
        )
        self.assertEqual(
            registered["approved_destination_url"],
            "http://127.0.0.1:39124",
        )
        supervisor._app.register_ssrf_canary_proof.assert_not_called()
        self.assertNotIn("39124", json.dumps(supervisor.state.read(0)))

    def test_hint_use_mismatch_keeps_review_pending_and_registers_no_canary(self) -> None:
        supervisor, _, collector = self._supervisor()
        supervisor._ssrf_review_pending_run_id = "run-1"
        wrong_url = "http://service.internal:8025/wrong"
        submission = SsrfReviewSubmission(
            run_id="run-1", surface_id="surface-1", parameter="url",
            verification_endpoint_ref="", approved_by="team-member",
            hint_evidence_id="evi-hint-1",
            verification_url=wrong_url,
            execution_consent=True,
            hint_use_approved=True,
        )
        with (
            patch.dict(
                os.environ,
                {"HACKLIPSE_SSRF_CANARY_MARKER": "stable-test-marker-12345"},
            ),
            self.assertRaises(ValueError),
        ):
            supervisor.register_ssrf_review(submission)

        submitted = collector.register_ssrf_review.call_args.kwargs
        self.assertTrue(submitted["hint_use_approved"])
        self.assertEqual(submitted["approved_destination_url"], wrong_url)
        supervisor._app.register_ssrf_canary_proof.assert_not_called()
        self.assertEqual(supervisor._ssrf_review_pending_run_id, "run-1")

    def test_stale_run_and_unlisted_coordinate_cannot_release_gate(self) -> None:
        supervisor, _, _ = self._supervisor()
        supervisor._ssrf_review_pending_run_id = "run-1"
        base = dict(
            surface_id="surface-1",
            parameter="url",
            verification_endpoint_ref="verification-service:v1",
            approved_by="team-member",
        )
        with self.assertRaises(RuntimeError):
            supervisor.register_ssrf_review(SsrfReviewSubmission(run_id="run-2", **base))
        with self.assertRaises(ValueError):
            supervisor.register_ssrf_review(SsrfReviewSubmission(
                run_id="run-1", **{**base, "parameter": "other"},
            ))
        with self.assertRaises(ValueError):
            supervisor.register_ssrf_review(SsrfReviewSubmission(
                run_id="run-1",
                **{
                    **base,
                    "hint_evidence_id": "evi-hint-1",
                    "verification_endpoint_ref": "evi-hint-1",
                },
            ))


class HttpBoundaryTests(unittest.TestCase):
    """다른 출처가 이 API 로 Run 을 시작할 수 없다."""

    @classmethod
    def setUpClass(cls) -> None:
        import socket
        from http.server import ThreadingHTTPServer

        cls.supervisor = RunSupervisor(
            allowed_hosts=frozenset({"127.0.0.1"}), defaults=_defaults()
        )
        cls.token = "test-csrf-token"
        # 핸들러는 만들 때의 포트로 같은 출처를 판단한다. 포트를 먼저 정하고 한 번만 만든다.
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            cls.port = probe.getsockname()[1]
        options = sd.parse_args(["--port", str(cls.port)])
        cls.server = ThreadingHTTPServer(
            ("127.0.0.1", cls.port), sd.make_handler(cls.supervisor, options, cls.token)
        )
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def _post(
        self, *, path="/api/run", token=None, origin=None,
        content_type="application/json", body=None,
    ):
        request = urllib.request.Request(
            f"{self.base}{path}",
            data=json.dumps(body or {"target": "http://127.0.0.1:3000/"}).encode(),
            method="POST",
        )
        request.add_header("Content-Type", content_type)
        if token is not None:
            request.add_header(sd.CSRF_HEADER, token)
        if origin is not None:
            request.add_header("Origin", origin)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def test_config_exposes_no_key_values(self) -> None:
        with urllib.request.urlopen(f"{self.base}/api/config", timeout=5) as response:
            config = json.loads(response.read())
        rendered = json.dumps(config)
        self.assertIn("csrf_token", config)
        for engine in config["engines"]:
            self.assertIn("available", engine)
        for variable in (sd.ANTHROPIC_API_KEY_ENV, sd.GEMINI_API_KEY_ENV):
            value = os.environ.get(variable, "").strip()
            if value:
                self.assertNotIn(value, rendered)

    def test_missing_csrf_token_is_refused(self) -> None:
        status, body = self._post()
        self.assertEqual(status, 403)
        self.assertIn(sd.CSRF_HEADER, body["error"])

    def test_wrong_csrf_token_is_refused(self) -> None:
        status, _ = self._post(token="not-the-token")
        self.assertEqual(status, 403)

    def test_ssrf_review_endpoint_uses_the_same_csrf_boundary(self) -> None:
        status, body = self._post(
            path="/api/ssrf-review",
            body={"action": "skip", "run_id": "run-stale"},
        )
        self.assertEqual(status, 403)
        self.assertIn(sd.CSRF_HEADER, body["error"])

    def test_ssrf_review_endpoint_rejects_a_stale_run(self) -> None:
        status, body = self._post(
            path="/api/ssrf-review",
            token=self.token,
            origin=self.base,
            body={"action": "skip", "run_id": "run-stale"},
        )
        self.assertEqual(status, 409)
        self.assertIn("Run", body["error"])

    def test_foreign_origin_is_refused(self) -> None:
        status, body = self._post(token=self.token, origin="http://evil.example")
        self.assertEqual(status, 403)
        self.assertIn("Origin", body["error"])

    def test_form_content_type_is_refused(self) -> None:
        status, body = self._post(
            token=self.token, content_type="application/x-www-form-urlencoded"
        )
        self.assertEqual(status, 403)
        self.assertIn("application/json", body["error"])

    def test_no_cors_headers_are_offered(self) -> None:
        with urllib.request.urlopen(f"{self.base}/api/config", timeout=5) as response:
            self.assertIsNone(response.headers.get("Access-Control-Allow-Origin"))
            self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")

    def test_invalid_payload_is_refused_before_the_run_starts(self) -> None:
        status, body = self._post(
            token=self.token,
            origin=self.base,
            body={"target": "http://127.0.0.1:3000/", "router": "evil"},
        )
        self.assertEqual(status, 400)
        self.assertIn("router", body["error"])
        self.assertFalse(self.supervisor.state.running)

    def test_unknown_routes_are_not_served(self) -> None:
        request = urllib.request.Request(f"{self.base}/api/secret", method="GET")
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(caught.exception.code, 404)


class FailureCleanupTests(unittest.TestCase):
    """실패해도 credential 참조와 세션은 반드시 정리된다."""

    def test_setup_error_marks_the_run_failed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            options = RunOptions(
                target="http://127.0.0.1:9/",
                knowledge_db=directory,  # 디렉터리는 SQLite DB 파일로 열 수 없다.
                routing_log=str(Path(directory) / "routing.jsonl"),
            )
            supervisor = RunSupervisor(
                allowed_hosts=frozenset({"127.0.0.1"}), defaults=options
            )
            self.assertIsNone(supervisor.validate(options, RunSecrets()))
            with patch("dashboard_core.traceback.print_exc"):
                supervisor.start(options, RunSecrets())
                supervisor._thread.join(timeout=5)
            self.assertFalse(supervisor._thread.is_alive())
            view = supervisor.state.read(0)
            self.assertEqual(view["status"], "failed")
            self.assertIn("OperationalError", view["error"])

    def test_a_failing_run_still_clears_credentials(self) -> None:
        supervisor = RunSupervisor(
            allowed_hosts=frozenset({"127.0.0.1"}), defaults=_defaults()
        )
        # 아무것도 듣고 있지 않은 포트. Recon 이 실패하고 Run 이 끝난다.
        options = RunOptions(target="http://127.0.0.1:9/", budget=3)
        supervisor.start(options, RunSecrets())
        deadline = time.monotonic() + 40
        while supervisor.state.running and time.monotonic() < deadline:
            time.sleep(0.2)
        self.assertFalse(supervisor.state.running, "Run 이 끝나지 않았다")
        view = supervisor.state.read(0)
        self.assertIn(view["status"], {"done", "failed"})
        notes = [
            item["detail"]
            for item in view["events"]
            if item["kind"] == "dashboard_note"
        ]
        self.assertIn("세션 credential 메모리 참조 폐기 완료", notes)


@unittest.skipUnless(
    os.environ.get("HACKLIPSE_JUICE_SHOP_URL"),
    "HACKLIPSE_JUICE_SHOP_URL 이 없으면 건너뛴다 (npm start 로 Juice Shop 을 띄운다)",
)
class JuiceShopIntegrationTests(unittest.TestCase):
    """웹에서 시작한 한 Run 이 5종을 Candidate→Analysis→Validation→Report 까지 끌고 간다."""

    def test_all_five_types_reach_a_verdict(self) -> None:
        actor = os.environ["HACKLIPSE_JUICE_ACTOR"].split(":", 1)
        owner = os.environ["HACKLIPSE_JUICE_OWNER"].split(":", 1)
        supervisor = RunSupervisor(
            allowed_hosts=frozenset({"127.0.0.1"}), defaults=_defaults()
        )
        options = RunOptions(
            target=os.environ["HACKLIPSE_JUICE_SHOP_URL"],
            mode=MODE_JUICE_SHOP,
            vuln="all",
            budget=120,
            juice_shop_db=os.environ["HACKLIPSE_JUICE_SHOP_DB"],
        )
        secrets = RunSecrets(
            access=AccessAccounts(
                actor_email=actor[0],
                actor_password=actor[1],
                owner_email=owner[0],
                owner_password=owner[1],
            )
        )
        self.assertIsNone(supervisor.validate(options, secrets))
        supervisor.start(options, secrets)
        deadline = time.monotonic() + 600
        while supervisor.state.running and time.monotonic() < deadline:
            time.sleep(1)
        view = supervisor.state.read(0)
        self.assertEqual(view["status"], "done", view["error"])

        types = {
            item["vulnerability_type"]
            for item in view["candidates"]
            if item["status"] in {"confirmed", "suspected", "rejected", "blocked"}
        }
        self.assertEqual(
            types,
            {"SQLi", "XSS", "Access Control", "Path Traversal", "SSTI"},
            "다섯 유형이 모두 판정까지 가지 않았다",
        )
        self.assertTrue(view["report"], "보고서가 없다")
        # 비밀은 결과 어디에도 없다.
        rendered = json.dumps(view, ensure_ascii=False)
        for secret in (actor[1], owner[1], actor[0], owner[0]):
            self.assertNotIn(secret, rendered)


class _without_env:
    """환경변수를 잠시 지운다. 키 유무에 따른 분기를 시험할 때 쓴다."""

    def __init__(self, name: str) -> None:
        self._name = name
        self._previous: str | None = None

    def __enter__(self):
        self._previous = os.environ.pop(self._name, None)
        return self

    def __exit__(self, *_exc) -> None:
        if self._previous is not None:
            os.environ[self._name] = self._previous


if __name__ == "__main__":
    unittest.main()
