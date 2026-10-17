"""Repeated evaluation resets both twins and never sends answer keys to the scanner."""

from __future__ import annotations

import json
import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import evaluate_dynast


class DynastEvaluationTests(unittest.TestCase):
    def test_seeded_session_uses_only_local_login_and_keeps_cookie_in_memory(self):
        requests = []

        class Response:
            status = 200

            def getheaders(self):
                return [("Set-Cookie", "sid=test-session; HttpOnly"),
                        ("Set-Cookie", "token=test-token; HttpOnly")]

            def read(self, limit):
                return b"{}"

        class Connection:
            def __init__(self, host, port, timeout):
                requests.append((host, port, timeout))

            def request(self, method, path, body, headers):
                requests.append((method, path, json.loads(body), headers))

            def getresponse(self):
                return Response()

            def close(self):
                pass

        with tempfile.TemporaryDirectory() as directory:
            seed = Path(directory) / "vulnerable-apps/nextjs/vuln/prisma/seed.mjs"
            seed.parent.mkdir(parents=True)
            seed.write_text('{ email: "user@local.invalid", pw: "fixture-password", role: "user" }')
            with patch.object(evaluate_dynast.http.client, "HTTPConnection", Connection):
                cookie = evaluate_dynast._nextjs_seeded_session(
                    Path(directory), "vuln", "http://127.0.0.1:13311/"
                )
        self.assertEqual(cookie, "sid=test-session; token=test-token")
        self.assertEqual(requests[0][:2], ("127.0.0.1", 13311))
        self.assertEqual(requests[1][0:2], ("POST", "/api/auth/login"))

    def test_stage_rates_use_only_completed_count_denominators(self):
        rates = evaluate_dynast._funnel_rates({
            "discovered_surface_count": 10,
            "candidate_surface_count": 4,
            "candidate_count": 8,
            "analysis_attempted_count": 6,
            "analysis_succeeded_count": 4,
            "validation_succeeded_count": 2,
        })
        self.assertEqual(rates, {
            "surface_to_candidate": 0.4,
            "candidate_to_analysis": 0.75,
            "analysis_to_validation": 0.5,
        })
        self.assertIsNone(evaluate_dynast._funnel_rates({
            "candidate_count": 0, "analysis_attempted_count": 0,
        })["candidate_to_analysis"])

    def test_rejects_nonlocal_or_credentialed_reset_targets(self):
        for url in ("https://elsewhere.invalid/", "http://user:pass@localhost/",
                    "http://localhost/?token=hidden"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                evaluate_dynast._local_target(url)

    def test_score_brief_reads_safe_findings_separately_from_total_fp(self):
        brief = evaluate_dynast._score_brief({
            "counts": {"tp": 2, "fp": 3, "fn": 4},
            "runs": [{"variant": "vuln", "findings": 4},
                     {"variant": "safe", "findings": 1}],
        })
        self.assertEqual(brief, {"tp": 2, "fp": 3, "fn": 4, "safe_findings": 1})
        with self.assertRaises(ValueError):
            evaluate_dynast._score_brief({"counts": {"tp": 2, "fp": 3, "fn": 4}})

    def test_seeded_session_is_sent_by_stdin_without_a_terminal_prompt(self):
        cookie = "sid=private-test-session; token=private-test-token"
        scanner_commands = []

        def execute(command, **kwargs):
            if command[1] == "reset":
                return subprocess.CompletedProcess(command, 0,
                    '{"target":"http://127.0.0.1:13322/"}', "")
            scanner_commands.append((command, kwargs))
            return subprocess.CompletedProcess(command, 1, "", "")

        with tempfile.TemporaryDirectory() as directory, patch.object(
            evaluate_dynast.shutil, "which", return_value="/local/dynast-bench"
        ), patch.object(evaluate_dynast.subprocess, "run", side_effect=execute), patch.object(
            evaluate_dynast, "_nextjs_seeded_session", return_value=cookie
        ), redirect_stdout(io.StringIO()) as output:
            bench_root = Path(directory) / "bench"
            cli_source = bench_root / "dynast-bench" / "dynast-bench.ts"
            cli_source.parent.mkdir(parents=True)
            cli_source.write_text("")
            status = evaluate_dynast.main([
                "nextjs", "--iterations", "1", "--code-version", "candidate-1",
                "--bench-root", str(bench_root),
                "--output-dir", str(Path(directory) / "evaluation"),
                "--no-browser-recon", "--approve-state-changing",
                "--nextjs-test-session",
            ])
        self.assertEqual(status, 1)  # The fake scanner deliberately fails.
        self.assertEqual(len(scanner_commands), 1)
        command, kwargs = scanner_commands[0]
        self.assertIn("--session-cookie-stdin", command)
        self.assertNotIn("--anonymous", command)
        self.assertEqual(kwargs["input"], "y\n" + cookie + "\n")
        self.assertNotIn(cookie, output.getvalue())

    def test_resets_each_twin_and_records_miss_categories(self):
        calls = []

        def execute(command, **kwargs):
            calls.append((command, kwargs))
            if command[1] == "reset":
                self.assertIn("--solo", command)
                self.assertIn("--no-build", command)
                variant = command[command.index("--variant") + 1]
                return subprocess.CompletedProcess(command, 0, json.dumps({
                    "target": "http://127.0.0.1:13322/" if variant == "vuln"
                    else "http://127.0.0.1:13323/",
                }), "")
            if command[1].endswith("run_dynast_baseline.py"):
                log = Path(command[command.index("--routing-log") + 1])
                log.write_text(json.dumps({
                    "event": "run_result", "run_id": "run-test", "phase": "done",
                    "code_version": "candidate-1", "request_budget": 80,
                    "requests_used": 12, "finding_count": 1,
                    "candidate_status_counts": {"confirmed": 1},
                    "browser_recon": [{"status": "completed", "page_count": 1,
                                       "browser_version": "fixture"}],
                    "browser_recon_enabled": True, "authenticated": False,
                    "state_changing_approved": True,
                    "budget_allocation_mode": "heuristic",
                }) + "\n")
                self.assertIn("--anonymous", command)
                self.assertIn("--approve-state-changing", command)
                self.assertEqual(command[command.index("--budget-allocation") + 1], "heuristic")
                self.assertEqual(kwargs["input"], "y\n")
                self.assertIn("--browser-executable", command)
                self.assertFalse(any(k.startswith("DYNAST_BENCH_") for k in kwargs["env"]))
                return subprocess.CompletedProcess(command, 0, "", "")
            if command[1] == "score":
                return subprocess.CompletedProcess(command, 0, json.dumps({
                    "counts": {"tp": 1, "fp": 1, "fn": 3},
                    "runs": [{"variant": "vuln", "findings": 1},
                             {"variant": "safe", "findings": 1}],
                }), "")
            if command[1] == "coverage":
                return subprocess.CompletedProcess(command, 0, json.dumps({
                    "tracks": {"coverage": {
                        "discovery_misses": ["missing-route"],
                        "analysis_misses": ["missed-proof"],
                        "unmapped_vulns": [],
                    }},
                }), "")
            self.fail(f"unexpected command: {command}")

        with tempfile.TemporaryDirectory() as directory, patch.object(
            evaluate_dynast.shutil, "which", return_value="/local/dynast-bench"
        ), patch.object(evaluate_dynast.subprocess, "run", side_effect=execute), patch.dict(
            os.environ, {"DYNAST_BENCH_GROUND_TRUTH": "/secret/key"}
        ):
            output_dir = Path(directory) / "evaluation"
            browser = Path(directory) / "chromium"
            browser.write_bytes(b"")
            browser.chmod(0o700)
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(evaluate_dynast.main([
                    "nextjs", "--iterations", "2", "--code-version", "candidate-1",
                    "--output-dir", str(output_dir), "--browser-executable", str(browser),
                    "--solo",
                    "--no-build",
                    "--approve-state-changing",
                    "--budget-allocation", "heuristic",
                ]), 0)
            summary = json.loads((output_dir / "summary.json").read_text())
            self.assertEqual(summary["scored_iterations"], 2)
            self.assertEqual(summary["score_totals"], {
                "tp": 2, "fp": 2, "fn": 6, "safe_findings": 2,
            })
            self.assertIn("[1/2] 채점: TP 1 | FP 1 | FN 3 | safe Finding 1", output.getvalue())
            self.assertIn("2회 합계 (반복 검사 건수): TP 2 | FP 2 | FN 6 | safe Finding 2", output.getvalue())
            self.assertTrue(summary["state_changing_approved"])
            self.assertEqual(summary["budget_allocation_mode"], "heuristic")
            self.assertEqual(summary["target_mode"], "solo")
            self.assertTrue(summary["target_images_reused"])
            diagnosis = json.loads((output_dir / "01-diagnosis.json").read_text())
            self.assertEqual(diagnosis["discovery_misses"], ["missing-route"])
            self.assertEqual(diagnosis["analysis_misses"], ["missed-proof"])
            self.assertEqual(diagnosis["candidate_status_counts"], {"confirmed": 1})
            self.assertEqual([c[0][1] for c in calls].count("reset"), 4)
            self.assertEqual([c[0][1] for c in calls].count("score"), 2)
            self.assertEqual([c[0][1] for c in calls].count("coverage"), 4)

    def test_unavailable_browser_stops_before_scoring_or_further_resets(self):
        calls = []

        def execute(command, **kwargs):
            calls.append(command)
            if command[1] == "reset":
                return subprocess.CompletedProcess(command, 0, '{"target":"http://127.0.0.1:13322/"}', "")
            if command[1].endswith("run_dynast_baseline.py"):
                log = Path(command[command.index("--routing-log") + 1])
                log.write_text(json.dumps({
                    "event": "run_result", "phase": "done", "code_version": "candidate-1",
                    "request_budget": 80, "requests_used": 9,
                    "browser_recon_enabled": True, "authenticated": False,
                    "state_changing_approved": False,
                    "budget_allocation_mode": "off",
                    "browser_recon": [{"status": "unavailable", "page_count": 0}],
                }) + "\n")
                return subprocess.CompletedProcess(command, 0, "", "")
            self.fail(f"unexpected command: {command}")

        with tempfile.TemporaryDirectory() as directory, patch.object(
            evaluate_dynast.shutil, "which", return_value="/local/dynast-bench"
        ), patch.object(evaluate_dynast.subprocess, "run", side_effect=execute):
            output_dir = Path(directory) / "evaluation"
            self.assertEqual(evaluate_dynast.main([
                "nextjs", "--iterations", "3", "--code-version", "candidate-1",
                "--output-dir", str(output_dir),
            ]), 1)
            summary = json.loads((output_dir / "summary.json").read_text())
            self.assertEqual(len(summary["legs"]), 1)
            self.assertEqual(summary["legs"][0]["error"], "browser_recon_unavailable")
            self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
