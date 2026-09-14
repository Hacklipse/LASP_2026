"""반복 A/B가 다른 입력이나 기록 누락을 효과로 잘못 해석하지 않는지 검증한다."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from compare_orchestrator_runs import compare_pair, main  # noqa: E402
from run_orchestrator_ab import _initial_fetch_failed  # noqa: E402


def _route(run_id: str, surface_keys=("home",), *, raw="raw-a") -> dict:
    return {
        "event": "routing_decision", "run_id": run_id, "status": "completed",
        "configuration": {"vulnerability_types": "XSS"},
        "input_fingerprint": raw,
        "routing_input_fingerprint": "same-meaning",
        "routing_input_manifest": {
            "surfaces": [
                {"surface_key": key, "comparison_surface_key": key}
                for key in surface_keys
            ]
        },
        "final_decisions": [
            {
                "surface_key": key, "routing_surface_key": key,
                "routing_surface_occurrence": 0, "vulnerability_type": "XSS",
            }
            for key in surface_keys
        ],
    }


def _result(run_id: str, mode: str, *, candidates=None, **changes) -> dict:
    result = {
        "event": "run_result", "run_id": run_id,
        "execution_profile_recorded": True,
        "analysis_profile": "heuristic", "recon_mode": "heuristic",
        "surface_collection_mode": "deterministic",
        "router_mode": "heuristic", "router_review": "weak",
        "compare_routers": False, "orchestrator_mode": mode,
        "budget_allocation_mode": "heuristic",
        "validation_mode": "heuristic", "report_mode": "heuristic",
        "request_budget": 80, "llm_provider": "gemini" if mode == "hybrid" else "",
        "llm_model": "fixture-model" if mode == "hybrid" else "",
        "llm_rpm_limit": 14 if mode == "hybrid" else None,
        "phase": "done", "extra_recon_rounds": 0,
        "finding_count": 1, "requests_used": 25,
        "candidates": candidates or [{
            "surface_key": "home", "vulnerability_type": "XSS", "status": "confirmed"
        }],
        "candidate_status_counts": {"confirmed": 1},
    }
    result.update(changes)
    return result


def _run(run_id: str, mode: str, *, raw="raw-a") -> dict:
    return {
        "routes": [_route(run_id, raw=raw)],
        "result": _result(run_id, mode),
    }


class OrchestratorAbComparisonTests(unittest.TestCase):
    def test_controlled_pair_ignores_raw_response_changes_and_counts_extra_recon_yield(self):
        baseline = _run("baseline", "heuristic")
        hybrid = _run("hybrid", "hybrid", raw="raw-b")
        hybrid["routes"].append(_route("hybrid", ("home", "extra-page")))
        hybrid["result"].update({
            "extra_recon_rounds": 1, "finding_count": 2, "requests_used": 29,
            "candidates": [
                {"surface_key": "home", "vulnerability_type": "XSS", "status": "confirmed"},
                {"surface_key": "extra-page", "vulnerability_type": "XSS", "status": "confirmed"},
            ],
        })

        comparison = compare_pair(baseline, hybrid)

        self.assertTrue(comparison["eligible"])
        self.assertFalse(comparison["same_raw_recon_input"])
        self.assertEqual(comparison["hybrid"]["new_surface_count"], 1)
        self.assertEqual(comparison["hybrid"]["new_candidate_count"], 1)
        self.assertEqual(comparison["hybrid"]["new_confirmed_candidate_count"], 1)
        self.assertEqual(comparison["delta_hybrid_minus_baseline"]["finding_count"], 1)
        self.assertEqual(comparison["delta_hybrid_minus_baseline"]["requests_used"], 4)

    def test_unrecorded_profile_or_different_surface_blocks_causal_pair(self):
        baseline = _run("baseline", "heuristic")
        hybrid = _run("hybrid", "hybrid")
        hybrid["result"]["execution_profile_recorded"] = False
        hybrid["routes"][0]["routing_input_manifest"]["surfaces"] = [
            {"surface_key": "different", "comparison_surface_key": "different"}
        ]

        comparison = compare_pair(baseline, hybrid)

        self.assertFalse(comparison["eligible"])
        self.assertIn("unrecorded_execution_profile", comparison["reasons"])
        self.assertIn("different_initial_surface_manifest", comparison["reasons"])

    def test_observed_query_change_does_not_change_p1_surface_manifest(self):
        baseline = _run("baseline", "heuristic")
        hybrid = _run("hybrid", "hybrid")
        hybrid["routes"][0]["routing_input_manifest"]["surfaces"][0]["surface_key"] = "strict-observed-query-b"
        hybrid["routes"][0]["final_decisions"][0]["surface_key"] = "strict-observed-query-b"
        hybrid["result"]["candidates"][0]["surface_key"] = "strict-observed-query-b"

        comparison = compare_pair(baseline, hybrid)

        self.assertTrue(comparison["eligible"])
        self.assertTrue(comparison["same_initial_surface_manifest"])

    def test_shared_llm_model_mismatch_is_not_a_controlled_orchestrator_test(self):
        baseline = _run("baseline", "heuristic")
        hybrid = _run("hybrid", "hybrid")
        baseline["result"].update({
            "analysis_profile": "llm", "llm_provider": "gemini",
            "llm_model": "model-a", "llm_rpm_limit": 14,
        })
        hybrid["result"].update({"analysis_profile": "llm", "llm_model": "model-b"})

        comparison = compare_pair(baseline, hybrid)

        self.assertFalse(comparison["eligible"])
        self.assertIn("llm_model", comparison["different_fixed_condition_names"])

    def test_unpaired_run_is_reported_without_silent_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runs.jsonl"
            records = [
                _route("baseline-a"), _result("baseline-a", "heuristic"),
                _route("baseline-b"), _result("baseline-b", "heuristic"),
                _route("hybrid", raw="raw-b"), _result("hybrid", "hybrid"),
            ]
            path.write_text("".join(json.dumps(record) + "\n" for record in records))
            with contextlib.redirect_stdout(io.StringIO()) as output:
                exit_code = main([str(path)])
            report = json.loads(output.getvalue())

        self.assertEqual(exit_code, 1)
        self.assertEqual(report["unpaired_run_counts"], {"heuristic": 1, "hybrid": 0})
        self.assertEqual(report["summary"]["pair_count"], 1)
        self.assertEqual(len(report["available_runs"]), 3)

    def test_runner_stops_after_a_denied_initial_http_fetch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runs.jsonl"
            failed = _route("first")
            failed["surface_count"] = 1
            failed["routing_input_manifest"]["evidence"] = [
                {"observation_type": "http_error"}
            ]
            path.write_text(json.dumps(failed) + "\n")
            self.assertTrue(_initial_fetch_failed(path))
            failed["routing_input_manifest"]["evidence"][0]["observation_type"] = "http_response"
            path.write_text(json.dumps(failed) + "\n")
            self.assertFalse(_initial_fetch_failed(path))


if __name__ == "__main__":
    unittest.main()
