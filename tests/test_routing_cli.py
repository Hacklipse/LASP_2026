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
from hacklipse.adapters import HeuristicSqliAnalyzer, LlmSqliAnalyzer, RuleBasedVulnerabilityRouter
from hacklipse.adapters.routing_audit import AuditedVulnerabilityRouter
from hacklipse.adapters.paired_routing import PairedVulnerabilityRouter
from hacklipse.adapters.llm_recon_planner import LlmReconPlanner
from hacklipse.application import Orchestrator
from hacklipse.bootstrap import build_local_application, register_standard_agents
from hacklipse.ports.errors import LlmCredentialsMissing


class _StopBeforeExecution(RuntimeError):
    pass


class _NoCallsLlm:
    def complete(self, request):
        raise AssertionError("CLI wiring test must not call an LLM")


class RoutingCliTests(unittest.TestCase):
    def test_all_profile_router_combinations_keep_analysis_selection_independent(self):
        for runner in (dvwa, juice):
            for profile in ("heuristic", "llm"):
                for mode, recon, compare in product(("heuristic", "hybrid"), ("heuristic", "hybrid"), (False, True)):
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
                                    "--routing-log", str(path), "--llm-model", "fixture-model",
                                    *(["--compare-routers"] if compare else []),
                                ])
                            self.assertEqual(builder.call_count, int(profile == "llm" or mode == "hybrid" or recon == "hybrid" or compare))
                            router = assemble.call_args.kwargs["router"]
                            if compare:
                                self.assertIsInstance(router, PairedVulnerabilityRouter)
                                self.assertEqual(router.primary, mode)
                                router = router.hybrid if mode == "hybrid" else router.heuristic
                            self.assertIsInstance(router, AuditedVulnerabilityRouter)
                            self.assertIsInstance(router.router, RuleBasedVulnerabilityRouter)
                            self.assertEqual(router.router._advisor is not None, mode == "hybrid")
                            self.assertEqual(register.call_args.kwargs["llm_client"] is not None, profile == "llm")
                            app = register.call_args.args[0]
                            if recon == "hybrid":
                                self.assertIsInstance(app.dispatcher._agents["recon"]._planner, LlmReconPlanner)
                            else:
                                self.assertIsNone(app.dispatcher._agents["recon"]._planner)
                            self.assertIsInstance(app.dispatcher._agents["sqli_analyzer"], LlmSqliAnalyzer if profile == "llm" else HeuristicSqliAnalyzer)
                            # 초기화만 했으며 Run/외부 HTTP/LLM 호출은 아직 시작하지 않았다.
                            self.assertEqual(path.read_text(), "")

    def test_missing_router_llm_credentials_stop_before_auth_or_log_creation(self):
        for runner, flags in product((dvwa, juice), (["--router", "hybrid"], ["--recon", "hybrid"], ["--compare-routers"])):
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
                self.assertIn("--router {heuristic,hybrid}", output.getvalue())
                self.assertIn("--llm-rpm-limit", output.getvalue())
                self.assertIn("--routing-log", output.getvalue())
                self.assertIn("--recon {heuristic,hybrid}", output.getvalue())
                self.assertIn("--compare-routers", output.getvalue())
                self.assertIn("--router-review", output.getvalue())


if __name__ == "__main__":
    unittest.main()
