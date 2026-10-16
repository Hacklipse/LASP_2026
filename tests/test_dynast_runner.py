"""DynAST 진입점의 기본 실행 조건, 산출물, 대상별 준비 경로 차단을 검증한다."""

from __future__ import annotations

import contextlib
import io
import json
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
            self.assertEqual(result["requests_used"], 1)
            self.assertFalse(result["browser_recon_enabled"])
            self.assertEqual(len(runtime.calls), 1)
            self.assertEqual(runtime.closed, [result["run_id"]])
            self.assertIn("DynAST-Bench 자동 탐색 실행 결과", output.getvalue())
            self.assertIn("[실행하지 못한 Analyzer 계약]", output.getvalue())
            self.assertIn("Surface는 발견했지만 현재 Analyzer 실행 조건을 만족하는 입력 좌표가 없습니다.", output.getvalue())
            self.assertNotIn("Juice Shop", output.getvalue())


if __name__ == "__main__":
    unittest.main()
