"""실험 입력 동일성, 후보 차이, fallback 및 실제 Run 결과의 연결을 검증한다."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from compare_routers import compare_records, latest_run, main, replay
from routing_options import append_run_result
from hacklipse.adapters.routing_audit import input_fingerprint, routing_input_fingerprint, surface_key
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import Candidate, CandidateStatus, Evidence, Run, RunScope, Surface


ROOT = Path(__file__).resolve().parents[1]


def _args(directory, failure="none"):
    return argparse.Namespace(
        fixture=str(ROOT / "tests/fixtures/router_comparison.json"),
        provider="fixture", model=None, failure=failure,
        routing_log=str(Path(directory) / "routing.jsonl"),
    )


class RouterComparisonTests(unittest.TestCase):
    def test_fixed_replay_reports_exact_candidate_delta_without_claiming_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            args = _args(directory)
            comparison = replay(args)
            self.assertTrue(comparison["same_router_input"])
            self.assertTrue(comparison["same_raw_recon_input"])
            self.assertEqual(comparison["input_manifest_delta"]["surface_structure_equal"], True)
            self.assertTrue(comparison["same_analysis_profile"])
            self.assertEqual(comparison["candidate_counts"], {"heuristic": 5, "hybrid": 7})
            self.assertEqual(len(comparison["added"]), 2)
            self.assertTrue(all(item["vulnerability_type"] == "Path Traversal" for item in comparison["added"]))
            self.assertEqual(comparison["removed"], [])
            self.assertEqual(comparison["changed"], [])
            self.assertFalse(comparison["analysis_comparison_available"])
            self.assertEqual(comparison["analysis_results"], {"heuristic": None, "hybrid": None})
            self.assertIsNone(comparison["router_cost"]["monetary_cost"])
            self.assertEqual(comparison["router_cost"]["hybrid"]["llm"]["status"], "partial")

    def test_timeout_replay_has_no_candidate_or_priority_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            comparison = replay(_args(directory, failure="timeout"))
            self.assertEqual(comparison["candidate_counts"], {"heuristic": 5, "hybrid": 5})
            for key in ("added", "removed", "changed"):
                self.assertEqual(comparison[key], [])
            self.assertEqual(comparison["router_cost"]["hybrid"]["llm"]["status"], "timeout")
            self.assertIsNone(comparison["router_cost"]["hybrid"]["llm"]["usage"])

    def test_logs_comparison_selects_latest_run_and_warns_on_changed_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            args = _args(directory)
            replay(args)
            replay(args)
            baseline, _ = latest_run(args.routing_log, "heuristic")
            hybrid, _ = latest_run(args.routing_log, "hybrid")
            changed_manifest = json.loads(json.dumps(hybrid["routing_input_manifest"]))
            changed_manifest["surfaces"][0]["method"] = "POST"
            changed = dict(hybrid, input_fingerprint="different-input",
                           routing_input_fingerprint="different-routing-input",
                           routing_input_manifest=changed_manifest)
            comparison = compare_records(baseline, changed)
            self.assertFalse(comparison["same_router_input"])
            self.assertIn("not a controlled", comparison["comparison_warning"])
            with self.assertRaises(ValueError):
                latest_run(args.routing_log, "missing-mode")
            changed_scope = dict(hybrid, configuration=dict(hybrid["configuration"], vulnerability_types="SQLi"))
            self.assertFalse(compare_records(baseline, changed_scope)["same_vulnerability_scope"])

            raw_only = dict(hybrid, input_fingerprint="dynamic-response-body")
            raw_comparison = compare_records(baseline, raw_only)
            self.assertTrue(raw_comparison["same_router_input"])
            self.assertFalse(raw_comparison["same_raw_recon_input"])

    def test_analysis_results_are_compared_only_when_both_are_present(self):
        with tempfile.TemporaryDirectory() as directory:
            args = _args(directory)
            replay(args)
            baseline, _ = latest_run(args.routing_log, "heuristic")
            hybrid, _ = latest_run(args.routing_log, "hybrid")
            left = {"finding_count": 0, "requests_used": 3, "candidate_status_counts": {"blocked": 1}}
            right = {"finding_count": 1, "requests_used": 5, "candidate_status_counts": {"confirmed": 1}}
            result = compare_records(baseline, hybrid, left, right)
            self.assertTrue(result["analysis_comparison_available"])
            self.assertEqual(result["analysis_delta"], {
                "finding_count": 1, "requests_used": 2,
                "candidate_status_counts": {"blocked": -1, "confirmed": 1},
            })
            self.assertIsNone(compare_records(baseline, hybrid, left, None)["analysis_delta"])

    def test_fingerprint_ignores_generated_ids_but_detects_input_changes(self):
        run = Run(run_id="first", target_url="http://localhost/", policy_profile="safe",
                  scope=RunScope(allowed_hosts=frozenset({"localhost"})), request_budget=10)
        surface = Surface(surface_id="one", run_id="first", url="http://localhost/render", method="GET", parameters=("q",))
        evidence = Evidence(evidence_id="e1", run_id="first", surface_id="one", created_by="recon",
                            evidence_type="observation", observation={"type": "reflection"})
        other_run = replace(run, run_id="second")
        other_surface = replace(surface, run_id="second", surface_id="two")
        other_evidence = replace(evidence, run_id="second", evidence_id="e2", surface_id="two")
        first = input_fingerprint(run, (surface,), (evidence,))
        self.assertEqual(first, input_fingerprint(other_run, (other_surface,), (other_evidence,)))
        self.assertEqual(
            routing_input_fingerprint(run, (surface,), (evidence,)),
            routing_input_fingerprint(other_run, (other_surface,), (other_evidence,)),
        )
        self.assertEqual(surface_key(surface), surface_key(other_surface))
        self.assertNotEqual(first, input_fingerprint(run, (replace(surface, method="POST"),), (evidence,)))
        self.assertNotEqual(first, input_fingerprint(run, (surface,), (replace(evidence, observation={"type": "sql_error"}),)))

        response = replace(evidence, evidence_type="http_response",
                           observation={"type": "http_response", "body": "dynamic-one"})
        changed_body = replace(response, observation={"type": "http_response", "body": "dynamic-two"})
        self.assertNotEqual(input_fingerprint(run, (surface,), (response,)),
                            input_fingerprint(run, (surface,), (changed_body,)))
        self.assertEqual(routing_input_fingerprint(run, (surface,), (response,)),
                         routing_input_fingerprint(run, (surface,), (changed_body,)))

    def test_live_run_summary_retains_status_and_budget_without_raw_surface(self):
        with tempfile.TemporaryDirectory() as directory:
            args = _args(directory)
            args.router = "heuristic"
            args.profile = "heuristic"
            app = build_local_application({})
            run = Run(run_id="result-run", target_url="http://localhost/", policy_profile="safe",
                      scope=RunScope(allowed_hosts=frozenset({"localhost"})), request_budget=10)
            # 실제 실행에서는 Orchestrator.start가 예산을 초기화한다.
            app.budget_manager.open_run(run.run_id, run.request_budget)
            app.stores.surfaces.add(Surface(surface_id="surface", run_id=run.run_id,
                                           url="http://localhost/?q=private-value", method="GET", parameters=("q",)))
            app.stores.candidates.add(Candidate(
                candidate_id="candidate", run_id=run.run_id, surface_id="surface",
                vulnerability_type="SQLi", assigned_agent="sqli_analyzer", hypothesis="fixture",
                evidence_ids=(), status=CandidateStatus.BLOCKED,
            ))
            append_run_result(args, app, run)
            record = json.loads(Path(args.routing_log).read_text())
            self.assertEqual(record["candidate_status_counts"], {"blocked": 1})
            self.assertEqual(record["requests_used"], 0)
            self.assertEqual(record["finding_count"], 0)
            self.assertNotIn("private-value", json.dumps(record))

    def test_comparison_cli_appends_results(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            path = str(Path(directory) / "routes.jsonl")
            output = str(Path(directory) / "comparison.jsonl")
            self.assertEqual(main(["replay", "--routing-log", path, "--output", output]), 0)
            self.assertEqual(main(["logs", "--baseline-log", path, "--hybrid-log", path, "--output", output]), 0)
            results = [json.loads(line) for line in Path(output).read_text().splitlines()]
            self.assertEqual(len(results), 2)
            self.assertTrue(all(record["same_router_input"] for record in results))


if __name__ == "__main__":
    unittest.main()
