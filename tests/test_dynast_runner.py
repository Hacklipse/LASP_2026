"""DynAST 진입점의 기본 실행 조건, 산출물, 대상별 준비 경로 차단을 검증한다."""

from __future__ import annotations

import contextlib
import io
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import run_dynast_baseline as dynast
import run_juice_shop_baseline as shared
from hacklipse.application import Orchestrator
from hacklipse.domain import ExecutionResult


class _Stop(RuntimeError):
    pass


class _Runtime:
    def __init__(self):
        self.calls = []
        self.closed = []

    def execute(self, request):
        self.calls.append(request)
        return ExecutionResult(
            execution_id=request.execution_id, evidence_type="http_response",
            observation={"type": "http_response", "status": 200,
                         "content_type": "text/html", "body": "<html><body>fixture</body></html>"},
        )

    def close_session(self, run_id):
        self.closed.append(run_id)


class DynastRunnerTests(unittest.TestCase):
    def test_help_names_dynast_and_exposes_only_answer_blind_modes(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(SystemExit) as ended:
                dynast.main(["run_dynast_baseline.py", "--help"])
        self.assertEqual(ended.exception.code, 0)
        help_text = output.getvalue()
        self.assertIn("DynAST-Bench", help_text)
        self.assertIn("--vuln {auto}", help_text)
        self.assertIn("--recon-entry {base-url}", help_text)
        self.assertIn("--no-browser-recon", help_text)
        self.assertIn("--anonymous", help_text)
        self.assertIn("실행별 Markdown", help_text)
        self.assertNotIn("Juice Shop", help_text)
        self.assertNotIn("--juice-shop-db", help_text)

    def test_targeted_setup_modes_and_external_hosts_are_rejected_before_execution(self):
        for options in (["--vuln", "all"], ["--vuln", "ssti"], ["--recon-entry", "targeted"], ["--juice-shop-db", "db.sqlite"]):
            with self.subTest(options=options), patch.object(shared, "build_local_application") as build, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as ended:
                    dynast.main(["dynast", "http://localhost:13322/", *options])
                self.assertEqual(ended.exception.code, 2)
                build.assert_not_called()
        with patch.object(shared, "build_local_application") as build, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(dynast.main(["dynast", "https://example.invalid/"]), 2)
        self.assertIn("DynAST-Bench 대상만", output.getvalue())
        build.assert_not_called()

    def test_defaults_enable_browser_and_never_prepare_target_specific_accounts(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(dynast, "DEFAULT_ARTIFACT_DIRECTORY", Path(directory)))
            stack.enter_context(patch("builtins.input", return_value="y"))
            stack.enter_context(patch.object(shared.getpass, "getpass", return_value=""))
            setup = stack.enter_context(patch.object(shared, "_provision_path_traversal_account"))
            login = stack.enter_context(patch.object(shared, "_authenticate_access_control_accounts"))
            register = stack.enter_context(patch.object(shared, "register_standard_agents", wraps=shared.register_standard_agents))
            start = stack.enter_context(patch.object(Orchestrator, "start", side_effect=_Stop))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            with self.assertRaises(_Stop):
                dynast.main(["dynast", "http://localhost:13322/"])
            request = start.call_args.args[0]
            self.assertEqual(request.target_url, "http://localhost:13322/")
            self.assertEqual(request.request_budget, 80)
            self.assertEqual(request.execution_profile.recon_entry_mode, "base-url")
            self.assertTrue(request.execution_profile.browser_recon_enabled)
            self.assertTrue(register.call_args.kwargs["recon_browser_enabled"])
            self.assertFalse(register.call_args.kwargs["recon_infer_unlinked_render_parameters"])
            self.assertEqual(register.call_args.kwargs["recon_seed_urls"], ())
            setup.assert_not_called()
            login.assert_not_called()

    def test_anonymous_option_skips_terminal_cookie_prompt(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(dynast, "DEFAULT_ARTIFACT_DIRECTORY", Path(directory)))
            stack.enter_context(patch("builtins.input", return_value="y"))
            getpass = stack.enter_context(patch.object(shared.getpass, "getpass"))
            start = stack.enter_context(patch.object(Orchestrator, "start", side_effect=_Stop))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            with self.assertRaises(_Stop):
                dynast.main(["dynast", "http://localhost:13322/", "--anonymous"])
            getpass.assert_not_called()
            self.assertIsNone(start.call_args.args[0].credential_ref)

    def test_stdin_session_skips_terminal_prompt_and_binds_credential(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(dynast, "DEFAULT_ARTIFACT_DIRECTORY", Path(directory)))
            stack.enter_context(patch("builtins.input", return_value="y"))
            stack.enter_context(patch.object(shared.sys, "stdin", io.StringIO("sid=private-test-session\n")))
            getpass = stack.enter_context(patch.object(shared.getpass, "getpass"))
            start = stack.enter_context(patch.object(Orchestrator, "start", side_effect=_Stop))
            output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            with self.assertRaises(_Stop):
                dynast.main([
                    "dynast", "http://localhost:13322/", "--session-cookie-stdin",
                ])
            getpass.assert_not_called()
            self.assertEqual(start.call_args.args[0].credential_ref,
                             shared._AUTO_SESSION_CREDENTIAL_REF)
            self.assertNotIn("private-test-session", output.getvalue())

    def test_session_stdin_and_anonymous_are_mutually_exclusive(self):
        with patch.object(shared, "build_local_application") as build, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(dynast.main([
                "dynast", "http://localhost:13322/", "--anonymous",
                "--session-cookie-stdin",
            ]), 2)
        build.assert_not_called()

    def test_explicit_browser_executable_reaches_common_browser_recon(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            executable = Path(directory) / "chromium"
            executable.write_bytes(b"")
            executable.chmod(0o700)
            stack.enter_context(patch.object(dynast, "DEFAULT_ARTIFACT_DIRECTORY", Path(directory)))
            stack.enter_context(patch("builtins.input", return_value="y"))
            register = stack.enter_context(patch.object(
                shared, "register_standard_agents", wraps=shared.register_standard_agents,
            ))
            stack.enter_context(patch.object(Orchestrator, "start", side_effect=_Stop))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            with self.assertRaises(_Stop):
                dynast.main([
                    "dynast", "http://localhost:13322/", "--anonymous",
                    "--browser-executable", str(executable),
                ])
            self.assertEqual(register.call_args.kwargs["recon_browser_executable_path"],
                             str(executable.resolve()))

    def test_completed_run_saves_dynast_artifacts_and_honors_static_override(self):
        runtime = _Runtime()
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(dynast, "DEFAULT_ARTIFACT_DIRECTORY", Path(directory)))
            stack.enter_context(patch.object(shared, "HttpExecutionRuntime", return_value=runtime))
            stack.enter_context(patch("builtins.input", return_value="y"))
            stack.enter_context(patch.object(shared.getpass, "getpass", return_value=""))
            output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            status = dynast.main(["dynast", "http://localhost:13322/", "--no-browser-recon", "--code-version", "fixture"])
            self.assertEqual(status, 0)
            reports = list(Path(directory).glob("dynast-*.md"))
            logs = list(Path(directory).glob("dynast-*.jsonl"))
            self.assertEqual(len(reports), 1)
            self.assertEqual(len(logs), 1)
            self.assertEqual(reports[0].stem, logs[0].stem)
            records = [json.loads(line) for line in logs[0].read_text().splitlines()]
            result = next(x for x in records if x["event"] == "run_result")
            self.assertEqual(result["phase"], "done")
            self.assertEqual(result["code_version"], "fixture")
            self.assertEqual(result["requests_used"], 2)
            self.assertFalse(result["browser_recon_enabled"])
            self.assertEqual(result["stage_funnel"]["candidate_count"], 0)
            self.assertEqual(result["stage_funnel"]["discovered_surface_count"], 1)
            self.assertEqual(result["recon_frontier"][0]["attempted_url_count"], 2)
            self.assertEqual(result["recon_frontier"][0]["unvisited_count"], 0)
            self.assertEqual(len(runtime.calls), 2)
            self.assertEqual(runtime.closed, [result["run_id"]])
            self.assertIn("DynAST-Bench 자동 탐색 실행 결과", output.getvalue())
            self.assertIn("[실행하지 못한 Analyzer 계약]", output.getvalue())
            self.assertIn("Surface는 발견했지만 현재 Analyzer 실행 조건을 만족하는 입력 좌표가 없습니다.", output.getvalue())
            self.assertNotIn("Juice Shop", output.getvalue())

    def test_scorer_export_requires_explicit_app_variant_and_code_version(self):
        for extra in (
            ["--app", "nextjs"],
            ["--variant", "safe"],
            ["--app", "nextjs", "--variant", "safe"],
        ):
            with self.subTest(extra=extra), patch.object(shared, "build_local_application") as build, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(dynast.main(["dynast", "http://localhost:13322/", *extra]), 2)
                build.assert_not_called()

    def test_completed_run_exports_explicit_safe_twin_scoring_files(self):
        runtime = _Runtime()
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(dynast, "DEFAULT_ARTIFACT_DIRECTORY", Path(directory)))
            stack.enter_context(patch.object(shared, "HttpExecutionRuntime", return_value=runtime))
            stack.enter_context(patch("builtins.input", return_value="y"))
            stack.enter_context(patch.object(shared.getpass, "getpass", return_value=""))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            self.assertEqual(dynast.main([
                "dynast", "http://localhost:13322/", "--no-browser-recon",
                "--app", "nextjs", "--variant", "safe", "--code-version", "fixture",
            ]), 0)
            findings_path, = Path(directory).glob("dynast-*.findings.json")
            endpoints_path, = Path(directory).glob("dynast-*.endpoints.json")
            findings = json.loads(findings_path.read_text())
            endpoints = json.loads(endpoints_path.read_text())
            self.assertEqual(findings["schema"], "dynast-bench.findings/v1")
            self.assertEqual(findings["run"], {"app": "nextjs", "variant": "safe"})
            self.assertEqual(findings["findings"], [])
            self.assertEqual(endpoints["run"], findings["run"])
            self.assertEqual(endpoints["endpoints"], [{"method": "GET", "path": "/"}])
            self.assertEqual(stat.S_IMODE(findings_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(endpoints_path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
