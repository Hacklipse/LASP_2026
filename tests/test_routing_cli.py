"""두 실행기의 profile/router 조합을 실제 배선하되 대상 실행 직전에 중단한다."""

from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from itertools import product
from unittest.mock import patch

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
from hacklipse.application import Orchestrator
from hacklipse.bootstrap import build_local_application, register_standard_agents
from hacklipse.ports.errors import LlmCredentialsMissing


class _StopBeforeExecution(RuntimeError):
    pass


class _NoCallsLlm:
    def complete(self, request):
        raise AssertionError("CLI wiring test must not call an LLM")


class RoutingCliTests(unittest.TestCase):
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
        request = start.call_args.args[0]
        self.assertEqual(request.target_url, "http://localhost:3000/")
        self.assertEqual(request.execution_profile.recon_entry_mode, "base-url")
        self.assertEqual(register.call_args.kwargs["recon_seed_urls"], ())
        self.assertFalse(
            register.call_args.kwargs["recon_infer_unlinked_render_parameters"]
        )
        access_prompt.assert_not_called()
        provision.assert_not_called()
        secret_prompt.assert_called_once()

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


if __name__ == "__main__":
    unittest.main()
