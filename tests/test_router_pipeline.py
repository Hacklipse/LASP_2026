"""Real Recon/Planner/Router/Analyzer/Validator pipeline; only HTTP and model are doubles."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from compare_routers import compare_records, latest_run
from routing_options import append_run_result
from hacklipse.adapters import SQLiteStoreBundle, StaticApprovalGate
from hacklipse.adapters.paired_routing import PairedVulnerabilityRouter
from hacklipse.adapters.path_traversal_analysis import (
    PATH_TRAVERSAL_FORM_PROBE_PATH, PATH_TRAVERSAL_FORM_PROOF_MARKERS,
    PATH_TRAVERSAL_POST_APPROVAL_REF, PATH_TRAVERSAL_PROBE_PATH,
    PATH_TRAVERSAL_PROOF_MARKERS, PATH_TRAVERSAL_TOOL,
)
from hacklipse.adapters.routing_audit import JsonlRoutingAuditLog
from hacklipse.adapters.sqlite_store import _decode_candidate
from hacklipse.bootstrap import build_local_application, register_standard_agents, standard_recon_planner, standard_router
from hacklipse.domain import Candidate, CandidateStatus, DomainInvariantError, ExecutionResult, RunPhase, RunRequest, RunScope
from hacklipse.ports.errors import LlmCredentialsMissing, LlmTimeout
from hacklipse.ports.llm import LlmResponse


class _Model:
    def __init__(self, *, fail_recon=False, fail_router=False):
        self.fail_recon, self.fail_router = fail_recon, fail_router
        self.roles = []

    def complete(self, request):
        content = request.messages[0].content
        if "ranked_surface_ids" in request.response_schema["properties"]:
            self.roles.append("recon")
            if self.fail_recon:
                raise LlmTimeout("test timeout")
            payload = {"ranked_surface_ids": re.findall(r"surface_id=(\S+) method=", content),
                       "action": "continue", "reason": "Visit discovered documents"}
        else:
            self.roles.append("router")
            if self.fail_router:
                raise LlmTimeout("test timeout")
            payload = {"suggestions": [{
                "surface_id": surface_id,
                "vulnerability_type": "Path Traversal",
                "reason": "Explore the observed opaque input using a fixed safe-file probe",
            } for surface_id in re.findall(r"surface_id=(\S+) method=\S+ path=\S+ kind=\S+ parameters=\[blob\]", content)]}
        return LlmResponse(payload=payload, model="pipeline-fixture")


class _Runtime:
    def __init__(self, *, method="GET", vulnerable=True):
        self.method, self.vulnerable = method, vulnerable
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        path = urlsplit(request.resolved_url).path
        if path == "/":
            body = '<html><body><script src="/main.js"></script></body></html>'
            if self.method == "POST":
                body += '<form action="/render" method="POST"><input name="blob"></form>'
        elif path == "/main.js":
            body = "class Nav {\n toA(){ window.location.assign('/a') }\n toB(){ window.location.assign('/b') }\n}\n"
        elif path == "/a":
            body = '<form action="/render" method="GET"><input name="blob"></form>' if self.method == "GET" else '<html></html>'
        else:
            body = "<html>normal</html>"
            values = dict(request.query_parameters).values()
            form_values = dict(parse_qsl(request.body or "")).values()
            if self.vulnerable and PATH_TRAVERSAL_PROBE_PATH in values:
                body = "\n".join(PATH_TRAVERSAL_PROOF_MARKERS)
            if self.vulnerable and PATH_TRAVERSAL_FORM_PROBE_PATH in form_values:
                body = "\n".join(PATH_TRAVERSAL_FORM_PROOF_MARKERS)
        return ExecutionResult(execution_id=request.execution_id, evidence_type="http_response",
                               observation={"type": "http_response", "status": 200,
                                            "body": body, "requested_url": request.resolved_url})


def _execute(*, mode="hybrid", recon="hybrid", compare=True, log=None, method="GET",
             vulnerable=True, approved=True, fail_recon=False, fail_router=False):
    model = _Model(fail_recon=fail_recon, fail_router=fail_router)
    runtime = _Runtime(method=method, vulnerable=vulnerable)
    router = standard_router(("Path Traversal",), mode=mode, llm_client=model,
                             compare=compare, audit_log=log,
                             audit_metadata={"analysis_profile": "heuristic", "recon_mode": recon})
    app = build_local_application({}, runtime=runtime, router=router,
                                  approval_gate=StaticApprovalGate((PATH_TRAVERSAL_POST_APPROVAL_REF,) if approved else ()))
    register_standard_agents(app, recon_max_pages=6,
                             recon_planner=standard_recon_planner(mode=recon, llm_client=model))
    run = app.orchestrator.start(RunRequest(target_url="http://local.test/",
                                           scope=RunScope(allowed_hosts=frozenset({"local.test"})),
                                           request_budget=30))
    return app, run, runtime, model


class RouterPipelineTests(unittest.TestCase):
    def test_paired_routers_receive_identical_objects_in_identical_order(self):
        calls = []

        class Capture:
            def __init__(self, result):
                self.result = result

            def route(self, *args):
                calls.append(args)
                return self.result

        baseline, hybrid = (), (object(),)
        router = PairedVulnerabilityRouter(heuristic=Capture(baseline), hybrid=Capture(hybrid), primary="hybrid")
        run, surfaces, evidence = object(), [object(), object()], [object(), object()]
        self.assertIs(router.route(run, surfaces, evidence), hybrid)
        self.assertEqual(len(calls), 2)
        for left, right in zip(*calls):
            self.assertIs(left, right)
        self.assertEqual(calls[0][1], tuple(surfaces))
        self.assertEqual(calls[0][2], tuple(evidence))

    def test_joint_planner_router_reaches_real_analysis_and_independent_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "paired.jsonl")
            app, run, runtime, model = _execute(log=JsonlRoutingAuditLog(path), method="GET")
            self.assertIs(run.phase, RunPhase.DONE)
            self.assertEqual(model.roles, ["recon", "router"])
            self.assertEqual(len(app.stores.findings.list_by_run(run.run_id)), 1)
            candidates = app.stores.candidates.list_by_run(run.run_id)
            self.assertEqual(len(candidates), 1)
            self.assertIs(candidates[0].status, CandidateStatus.CONFIRMED)
            self.assertEqual(candidates[0].exploration_parameters, ("blob",))
            probes = [r for r in runtime.requests if r.tool == PATH_TRAVERSAL_TOOL]
            self.assertEqual(len(probes), 4)  # analyzer control/probe + independent validator repeat
            findings = app.stores.findings.list_by_run(run.run_id)
            proof = app.stores.evidence.get_many(run.run_id, findings[0].evidence_ids)
            self.assertEqual(len(proof), 2)
            self.assertTrue(all(e.validation_id == findings[0].validation_id for e in proof))
            self.assertEqual(sum(urlsplit(r.resolved_url).path == "/main.js" for r in runtime.requests), 1)
            evidence = app.stores.evidence.list_by_run(run.run_id)
            self.assertFalse(any(e.observation.get("type") == "url_or_file_parameter" for e in evidence))
            self.assertTrue(any(e.observation.get("type") == "recon_plan" for e in evidence))
            baseline, _ = latest_run(path, "heuristic")
            hybrid, _ = latest_run(path, "hybrid")
            self.assertEqual(hybrid["final_decisions"][0]["evidence_ids"], [])
            self.assertEqual(hybrid["final_decisions"][0]["exploration_parameters"], ["blob"])
            append_run_result(argparse.Namespace(router="hybrid", profile="heuristic", recon="hybrid", routing_log=path), app, run)
            _, primary_result = latest_run(path, "hybrid")
            _, shadow_result = latest_run(path, "heuristic")
            comparison = compare_records(baseline, hybrid, shadow_result, primary_result)
            self.assertTrue(comparison["same_router_input"])
            self.assertTrue(comparison["paired_run"])
            self.assertEqual(comparison["candidate_counts"], {"heuristic": 0, "hybrid": 1})
            self.assertFalse(comparison["analysis_comparison_available"])
            self.assertIn("Only the selected", comparison["comparison_warning"])

    def test_generic_post_surface_is_not_sent_to_router_or_probed(self):
        app, run, runtime, model = _execute(method="POST")

        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(model.roles, ["recon"])
        self.assertEqual(app.stores.candidates.list_by_run(run.run_id), ())
        self.assertFalse(any(r.tool == PATH_TRAVERSAL_TOOL for r in runtime.requests))

    def test_shadow_hybrid_does_not_store_or_execute_candidates(self):
        app, run, runtime, model = _execute(mode="heuristic")
        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(model.roles, ["recon", "router"])
        self.assertEqual(tuple(app.stores.candidates.list_by_run(run.run_id)), ())
        self.assertFalse(any(r.tool == PATH_TRAVERSAL_TOOL for r in runtime.requests))

    def test_heuristic_baseline_has_no_new_probes_or_model_calls(self):
        app, run, runtime, model = _execute(mode="heuristic", recon="heuristic", compare=False)
        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(model.roles, [])
        self.assertFalse(any(r.tool == PATH_TRAVERSAL_TOOL for r in runtime.requests))

    def test_router_failure_preserves_baseline_and_recon_failure_still_routes(self):
        for fail_recon, fail_router, expected in ((True, False, 1), (False, True, 0), (True, True, 0)):
            with self.subTest(recon=fail_recon, router=fail_router):
                app, run, runtime, _ = _execute(fail_recon=fail_recon, fail_router=fail_router)
                self.assertIs(run.phase, RunPhase.DONE)
                self.assertEqual(len(app.stores.findings.list_by_run(run.run_id)), expected)
                if fail_router:
                    self.assertFalse(any(r.tool == PATH_TRAVERSAL_TOOL for r in runtime.requests))

    def test_unproven_llm_hypothesis_is_probed_but_not_confirmed(self):
        app, run, runtime, _ = _execute(vulnerable=False)
        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(len(app.stores.findings.list_by_run(run.run_id)), 0)
        self.assertIs(app.stores.candidates.list_by_run(run.run_id)[0].status, CandidateStatus.REJECTED)
        self.assertTrue(any(r.tool == PATH_TRAVERSAL_TOOL for r in runtime.requests))

    def test_post_proposal_cannot_bypass_approval(self):
        app, run, runtime, _ = _execute(method="POST", approved=False)
        self.assertEqual(len(app.stores.findings.list_by_run(run.run_id)), 0)
        self.assertFalse(any(r.method == "POST" for r in runtime.requests))

    def test_bootstrap_requires_explicit_clients_and_valid_modes(self):
        for call in (lambda: standard_router(compare=True), lambda: standard_recon_planner(mode="hybrid")):
            with self.assertRaises(LlmCredentialsMissing):
                call()
        with self.assertRaises(ValueError):
            standard_recon_planner(mode="unknown")
        self.assertIsNone(standard_recon_planner())


class ExplorationPersistenceTests(unittest.TestCase):
    def test_candidate_roundtrip_and_legacy_snapshot(self):
        candidate = Candidate(candidate_id="c", run_id="r", surface_id="s", vulnerability_type="Path Traversal",
                              hypothesis="explore", assigned_agent="path_traversal_analyzer", evidence_ids=(), exploration_parameters=("blob",))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "store.sqlite"
            with SQLiteStoreBundle(path) as stores:
                stores.candidates.add(candidate)
            with SQLiteStoreBundle(path) as stores:
                self.assertEqual(stores.candidates.get("r", "c"), candidate)
        value = asdict(candidate)
        value.pop("exploration_parameters")
        self.assertEqual(_decode_candidate(json.dumps(value)).exploration_parameters, ())

    def test_exploration_names_are_a_unique_immutable_tuple(self):
        for names in (["blob"], ("",), ("blob", "blob"), ("bad\nname",), (1,)):
            with self.subTest(names=names), self.assertRaises(DomainInvariantError):
                Candidate(candidate_id="c", run_id="r", surface_id="s", vulnerability_type="Path Traversal",
                          hypothesis="explore", assigned_agent="path_traversal_analyzer", evidence_ids=(), exploration_parameters=names)


if __name__ == "__main__":
    unittest.main()
