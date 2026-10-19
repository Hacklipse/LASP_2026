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
import run_juice_shop_baseline


def _healthy_stack(command, variant: str, target: str):
    return subprocess.CompletedProcess(command, 0, json.dumps({"stacks": [{
        "app": command[2], "variant": variant, "mode": "solo",
        "containers_running": 1, "containers_total": 1,
        "target": target, "healthy": True,
    }]}), "")


class DynastEvaluationTests(unittest.TestCase):
    def test_llmchat_session_reads_literal_user_fixture_without_importing_it(self):
        requests = []

        class Response:
            status = 200

            def getheaders(self):
                return [("Set-Cookie", "session=fixture-session; HttpOnly")]

            def read(self, limit):
                return b"{}"

        class Connection:
            def __init__(self, host, port, timeout):
                requests.append((host, port))

            def request(self, method, path, body, headers):
                requests.append((method, path, json.loads(body)))

            def getresponse(self):
                return Response()

            def close(self):
                pass

        with tempfile.TemporaryDirectory() as directory:
            seed = Path(directory) / "vulnerable-apps/llmchat/vuln/app.py"
            seed.parent.mkdir(parents=True)
            seed.write_text(
                'USERS = {"admin": {"email": "admin@local.invalid", '
                '"password": "admin-pass", "role": "admin", "isAdmin": True}, '
                '"reader": {"email": "reader@local.invalid", '
                '"password": "reader-pass", "role": "user", "isAdmin": False}}'
            )
            with patch.object(evaluate_dynast.http.client, "HTTPConnection", Connection):
                cookie = evaluate_dynast._llmchat_seeded_session(
                    Path(directory), "vuln", "http://127.0.0.1:13319/"
                )
        self.assertEqual(cookie, "session=fixture-session")
        self.assertEqual(requests[0], ("127.0.0.1", 13319))
        self.assertEqual(requests[1][:2], ("POST", "/api/auth/login"))
        self.assertEqual(requests[1][2]["email"], "reader@local.invalid")
        self.assertNotIn("reader-pass", cookie)

    def test_graphql_session_keeps_bearer_in_memory_and_accepts_loopback_only(self):
        requests = []

        class Response:
            status = 200

            def read(self, limit):
                return b'{"data":{"login":{"token":"fixture.token"}}}'

        class Connection:
            def __init__(self, host, port, timeout):
                requests.append((host, port))

            def request(self, method, path, body, headers):
                requests.append((method, path, json.loads(body), headers))

            def getresponse(self):
                return Response()

            def close(self):
                pass

        with tempfile.TemporaryDirectory() as directory:
            seed = Path(directory) / "vulnerable-apps/graphql/vuln/src/main.ts"
            seed.parent.mkdir(parents=True)
            seed.write_text('const users = [[acme, "user@local.invalid", '
                            '"fixture-password", "Reader", "user", false, "x", "y"]];')
            with patch.object(evaluate_dynast.http.client, "HTTPConnection", Connection):
                authorization = evaluate_dynast._graphql_seeded_authorization(
                    Path(directory), "vuln", "http://127.0.0.1:13315/"
                )
                with self.assertRaisesRegex(RuntimeError, "local HTTP target"):
                    evaluate_dynast._graphql_seeded_authorization(
                        Path(directory), "vuln", "http://example.test/"
                    )
        self.assertEqual(authorization, "Bearer fixture.token")
        self.assertEqual(requests[0], ("127.0.0.1", 13315))
        self.assertEqual(requests[1][0:2], ("POST", "/graphql"))
        self.assertIn("mutation Login", requests[1][2]["query"])
        self.assertNotIn("fixture-password", authorization)

    def test_bearer_parser_rejects_newlines_and_unscoped_header_text(self):
        with patch.object(run_juice_shop_baseline.sys, "stdin", io.StringIO("Bearer fixture.token\n")):
            credential = run_juice_shop_baseline._read_session_authorization_stdin()
        self.assertEqual(credential.authorization, "Bearer fixture.token")
        for value in ("Basic secret\n", "Bearer x extra\n"):
            with patch.object(run_juice_shop_baseline.sys, "stdin", io.StringIO(value)):
                with self.assertRaises(ValueError):
                    run_juice_shop_baseline._read_session_authorization_stdin()

    def test_command_failure_reports_category_without_raw_stderr(self):
        with patch.object(evaluate_dynast.subprocess, "run", return_value=
            subprocess.CompletedProcess(
                ["dynast", "reset"], 1, "", "health timed out; cookie=private-value"
            )
        ):
            with self.assertRaisesRegex(RuntimeError, "reset failed: timeout") as raised:
                evaluate_dynast._json_command(
                    ["dynast", "reset"], cwd=Path("/unused"), env={}
                )
        self.assertNotIn("private-value", str(raised.exception))

    def test_reset_failure_preserves_partial_pair_summary_without_private_output(self):
        calls = []

        def execute(command, **kwargs):
            calls.append(command)
            if command[1] == "reset":
                variant = command[command.index("--variant") + 1]
                if variant == "safe":
                    return subprocess.CompletedProcess(
                        command, 1, "", "health timed out; cookie=private-value"
                    )
                return subprocess.CompletedProcess(
                    command, 0, '{"target":"http://127.0.0.1:13311/"}', ""
                )
            if command[1] == "status":
                return _healthy_stack(command, "vuln", "http://127.0.0.1:13311/")
            if command[1].endswith("run_dynast_baseline.py"):
                log = Path(command[command.index("--routing-log") + 1])
                log.write_text(json.dumps({
                    "event": "run_result", "phase": "done", "code_version": "candidate-1",
                    "request_budget": 80, "requests_used": 1,
                    "browser_recon_enabled": False, "authenticated": False,
                    "state_changing_approved": False, "budget_allocation_mode": "off",
                }) + "\n")
                return subprocess.CompletedProcess(command, 0, "", "")
            return subprocess.CompletedProcess(command, 1, "", "")

        with tempfile.TemporaryDirectory() as directory, patch.object(
            evaluate_dynast.shutil, "which", return_value="/local/dynast-bench"
        ), patch.object(
            evaluate_dynast.subprocess, "run", side_effect=execute
        ), redirect_stdout(io.StringIO()) as output:
            bench_root = Path(directory) / "bench"
            cli_source = bench_root / "dynast-bench" / "dynast-bench.ts"
            cli_source.parent.mkdir(parents=True)
            cli_source.write_text("")
            output_dir = Path(directory) / "evaluation"
            status = evaluate_dynast.main([
                "golang", "--iterations", "1", "--code-version", "candidate-1",
                "--bench-root", str(bench_root), "--output-dir", str(output_dir),
                "--no-browser-recon",
            ])
            summary = json.loads((output_dir / "summary.json").read_text())

        self.assertEqual(status, 1)
        self.assertEqual(len(summary["legs"]), 2)
        self.assertEqual(summary["legs"][1]["error"], "reset_timeout")
        self.assertEqual(summary["scored_iterations"], 0)
        self.assertNotIn("private-value", output.getvalue() + repr(summary))
        self.assertEqual([Path(item[1]).name for item in calls],
                         ["reset", "status", "run_dynast_baseline.py", "reset"])

    def test_stage_chain_joins_routing_gap_to_final_candidate_without_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "route.jsonl"
            records = [
                {
                    "event": "routing_decision", "status": "completed",
                    "routing_input_manifest": {"surfaces": [
                        {"surface_id": "s1", "surface_key": "key-1", "method": "GET",
                         "path": "/search", "parameter_names": ["q"],
                         "observation_types": ["http_response"]},
                        {"surface_id": "s2", "surface_key": "key-2", "method": "POST",
                         "path": "/submit", "parameter_names": [],
                         "observation_types": ["script_request_structure"]},
                    ]},
                    "surface_reviews": [
                        {"surface_id": "s1", "candidate_ids": ["c1"],
                         "unrouted_reason": None, "capability_gaps": {}},
                        {"surface_id": "s2", "candidate_ids": [],
                         "unrouted_reason": "capability_requirements_unmet",
                         "capability_gaps": {"post": ["required_observation"]}},
                    ],
                },
                {"event": "run_result", "candidates": [
                    {"candidate_id": "c1", "vulnerability_type": "XSS",
                     "status": "rejected", "analysis_task_states": ["succeeded"],
                     "validation_task_states": ["succeeded"],
                     "validation_reason_code": "probe_signal_not_reproduced"},
                ]},
            ]
            path.write_text("\n".join(json.dumps(item) for item in records) + "\n")
            chain = evaluate_dynast._stage_chain(path)
        self.assertEqual(len(chain), 2)
        self.assertEqual(chain[0]["candidates"][0]["status"], "rejected")
        self.assertEqual(chain[0]["candidates"][0]["validation_reason_code"],
                         "probe_signal_not_reproduced")
        self.assertEqual(chain[1]["route_reason"], "capability_requirements_unmet")
        self.assertEqual(chain[1]["capability_gaps"], {"post": ["required_observation"]})
        self.assertNotIn("secret", json.dumps(chain))

    def test_common_auto_runner_defaults_keep_analysis_valid_and_allocation_explicit(self):
        captured = []

        def inspect(args):
            captured.append((args.profile, args.budget_allocation))
            return "stop before target access"

        with redirect_stdout(io.StringIO()):
            status = run_juice_shop_baseline.main(
                ["runner", "http://127.0.0.1:3000/"],
                auto_runner_name="DynAST", validate_args=inspect,
            )
        self.assertEqual(status, 2)
        self.assertEqual(captured, [("heuristic", "off")])

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

    def test_swagger_session_uses_non_admin_fixture_and_keeps_cookie_in_memory(self):
        requests = []

        class Response:
            status = 200

            def getheaders(self):
                return [("Set-Cookie", "uid=fixture-session; HttpOnly")]

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
            seed = Path(directory) / "vulnerable-apps/swagger/vuln/app/seed.py"
            seed.parent.mkdir(parents=True)
            seed.write_text(
                'admin = User(email="admin@local.invalid", '
                'password_hash=md5_password("admin-secret"), '
                'role="admin", is_admin=True)\n'
                'reader = User(email="reader@local.invalid", '
                'password_hash=md5_password("reader-secret"), '
                'role="user", is_admin=False)\n'
            )
            with patch.object(evaluate_dynast.http.client, "HTTPConnection", Connection):
                cookie = evaluate_dynast._swagger_seeded_session(
                    Path(directory), "vuln", "http://127.0.0.1:13326/"
                )
        self.assertEqual(cookie, "uid=fixture-session")
        self.assertEqual(requests[0][:2], ("127.0.0.1", 13326))
        self.assertEqual(requests[1][0:2], ("POST", "/api/auth/login"))
        self.assertEqual(requests[1][2]["email"], "reader@local.invalid")
        self.assertNotIn("reader-secret", cookie)

    def test_swagger_access_sessions_use_observed_own_objects(self):
        requests = []

        class Response:
            status = 200

            def __init__(self, cookie, path):
                self.cookie = cookie
                self.path = path

            def read(self, limit):
                if self.path.startswith("/api/v1/users/"):
                    return json.dumps({"orgSlug": "first" if self.cookie == "uid=first" else "second"}).encode()
                if self.path == "/api/v1/posts":
                    return json.dumps({"results": [{"id": 11}, {"id": 22}]}).encode()
                return json.dumps({"orgSlug": "first" if self.path.endswith("/11") else "second"}).encode()

        class Connection:
            def __init__(self, host, port, timeout):
                pass

            def request(self, method, path, headers):
                requests.append((method, path, headers))
                self.cookie, self.path = headers["Cookie"], path

            def getresponse(self):
                return Response(self.cookie, self.path)

            def close(self):
                pass

        with patch.object(evaluate_dynast, "_swagger_test_accounts", return_value=(("a", "secret-a"), ("b", "secret-b"))), \
             patch.object(evaluate_dynast, "_swagger_login", side_effect=(("uid=first", 3), ("uid=second", 4))), \
             patch.object(evaluate_dynast.http.client, "HTTPConnection", Connection):
            sessions = evaluate_dynast._swagger_access_sessions(
                Path("/unused"), "vuln", "http://127.0.0.1:13326/"
            )
        self.assertEqual(sessions, ("uid=first", "uid=second", "11", "22"))
        self.assertEqual([item[:2] for item in requests], [
            ("GET", "/api/v1/users/3"), ("GET", "/api/v1/posts"),
            ("GET", "/api/v1/posts/11"), ("GET", "/api/v1/users/4"),
            ("GET", "/api/v1/posts"), ("GET", "/api/v1/posts/11"),
            ("GET", "/api/v1/posts/22"),
        ])
        self.assertNotIn("secret", repr(requests))

    def test_fastapi_session_uses_non_admin_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            seed = Path(directory) / "vulnerable-apps/fastapi/safe/app/seed.py"
            seed.parent.mkdir(parents=True)
            seed.write_text(
                'admin = User(email="admin@local.invalid", '
                'password_hash=md5_password("admin-secret"), '
                'role="admin", is_admin=True)\n'
                'reader = User(email="reader@local.invalid", '
                'password_hash=md5_password("reader-secret"), '
                'role="user", is_admin=False)\n'
            )
            with patch.object(evaluate_dynast, "_swagger_login", return_value=("uid=private", 2)) as login:
                cookie = evaluate_dynast._fastapi_seeded_session(
                    Path(directory), "safe", "http://127.0.0.1:13322/"
                )
        self.assertEqual(cookie, "uid=private")
        self.assertEqual(login.call_args.args[1][0], "reader@local.invalid")
        self.assertNotIn("reader-secret", cookie)

    def test_gin_session_uses_non_admin_fixture(self):
        requests = []

        class Response:
            status = 200

            def getheaders(self):
                return [("Set-Cookie", "session=private-value; HttpOnly")]

            def read(self, limit):
                return b"{}"

        class Connection:
            def __init__(self, host, port, timeout):
                requests.append((host, port))

            def request(self, method, path, body, headers):
                requests.append((method, path, json.loads(body), headers))

            def getresponse(self):
                return Response()

            def close(self):
                pass

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "vulnerable-apps/gin/vuln/main.go"
            source.parent.mkdir(parents=True)
            source.write_text(
                'insertUser("admin@local.invalid", "admin-secret", "admin", true, acme)\n'
                'insertUser("reader@local.invalid", "reader-secret", "user", false, acme)\n'
            )
            with patch.object(evaluate_dynast.http.client, "HTTPConnection", Connection):
                cookie = evaluate_dynast._gin_seeded_session(
                    Path(directory), "vuln", "http://127.0.0.1:13313/"
                )
        self.assertEqual(cookie, "session=private-value")
        self.assertEqual(requests[1][0:2], ("POST", "/api/auth/login"))
        self.assertEqual(requests[1][2]["email"], "reader@local.invalid")
        self.assertNotIn("reader-secret", cookie)

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

    def test_reset_target_must_be_bound_to_requested_variant(self):
        target = "http://127.0.0.1:13322/"
        with patch.object(
            evaluate_dynast, "_json_command",
            return_value={"stacks": [{
                "app": "nextjs", "variant": "safe", "target": target,
                "healthy": True, "containers_running": 4,
                "containers_total": 4,
            }]},
        ):
            with self.assertRaisesRegex(ValueError, "variant_mismatch"):
                evaluate_dynast._verify_running_stack(
                    "/local/dynast-bench", Path("/local/bench"), {},
                    "nextjs", "vuln", target,
                )

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
            if command[1] == "status":
                return _healthy_stack(command, "vuln", "http://127.0.0.1:13322/")
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
        self.assertEqual(command[command.index("--budget-allocation") + 1], "off")
        self.assertEqual(kwargs["input"], "y\n" + cookie + "\n")
        self.assertNotIn(cookie, output.getvalue())

    def test_two_principal_sessions_are_stdin_only_and_mode_is_recorded(self):
        scanner_commands = []

        def execute(command, **kwargs):
            if command[1] == "reset":
                return subprocess.CompletedProcess(command, 0,
                    '{"target":"http://127.0.0.1:13326/"}', "")
            if command[1] == "status":
                return _healthy_stack(command, "vuln", "http://127.0.0.1:13326/")
            scanner_commands.append((command, kwargs))
            return subprocess.CompletedProcess(command, 1, "", "")

        with tempfile.TemporaryDirectory() as directory, patch.object(
            evaluate_dynast.shutil, "which", return_value="/local/dynast-bench"
        ), patch.object(evaluate_dynast.subprocess, "run", side_effect=execute), patch.object(
            evaluate_dynast, "_swagger_access_sessions",
            return_value=("uid=actor-private", "uid=owner-private", "11", "22"),
        ), redirect_stdout(io.StringIO()) as output:
            bench_root = Path(directory) / "bench"
            cli_source = bench_root / "dynast-bench" / "dynast-bench.ts"
            cli_source.parent.mkdir(parents=True)
            cli_source.write_text("")
            output_dir = Path(directory) / "evaluation"
            status = evaluate_dynast.main([
                "swagger", "--iterations", "1", "--code-version", "candidate-1",
                "--bench-root", str(bench_root), "--output-dir", str(output_dir),
                "--no-browser-recon", "--approve-state-changing",
                "--swagger-access-test-sessions",
            ])
            summary = json.loads((output_dir / "summary.json").read_text())
        self.assertEqual(status, 1)
        command, kwargs = scanner_commands[0]
        self.assertEqual(summary["test_session_mode"], "swagger_two_principals")
        self.assertEqual(summary["legs"][0]["test_principal_count"], 2)
        self.assertIn("--owner-session-cookie-stdin", command)
        self.assertEqual(kwargs["input"], "y\nuid=actor-private\nuid=owner-private\n")
        self.assertNotIn("actor-private", repr(command) + output.getvalue())
        self.assertNotIn("owner-private", repr(command) + output.getvalue())

    def test_resets_each_twin_and_records_miss_categories(self):
        calls = []
        last_variant = ["vuln"]

        def execute(command, **kwargs):
            calls.append((command, kwargs))
            if command[1] == "reset":
                self.assertIn("--solo", command)
                self.assertIn("--no-build", command)
                variant = command[command.index("--variant") + 1]
                last_variant[0] = variant
                return subprocess.CompletedProcess(command, 0, json.dumps({
                    "target": "http://127.0.0.1:13322/" if variant == "vuln"
                    else "http://127.0.0.1:13323/",
                }), "")
            if command[1] == "status":
                target = "http://127.0.0.1:13322/" if last_variant[0] == "vuln" else "http://127.0.0.1:13323/"
                return _healthy_stack(command, last_variant[0], target)
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
                    "router_mode": "agentic", "llm_model": "gemini-3.5-flash-lite",
                }) + "\n")
                self.assertIn("--anonymous", command)
                self.assertIn("--approve-state-changing", command)
                self.assertEqual(command[command.index("--budget-allocation") + 1], "heuristic")
                self.assertEqual(command[command.index("--router") + 1], "agentic")
                self.assertEqual(command[command.index("--llm-model") + 1], "gemini-3.5-flash-lite")
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
                    "--router", "agentic", "--llm-model", "gemini-3.5-flash-lite",
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
            self.assertEqual(summary["router_mode"], "agentic")
            self.assertEqual(summary["llm_model"], "gemini-3.5-flash-lite")
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
            if command[1] == "status":
                return _healthy_stack(command, "vuln", "http://127.0.0.1:13322/")
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
            self.assertEqual(len(calls), 3)


if __name__ == "__main__":
    unittest.main()
