"""The benchmark export must score only proven results and never leak request values."""

from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from dynast_scoring import build_dynast_documents
from hacklipse.adapters.memory import MemoryStoreBundle
from hacklipse.domain import (
    Evidence, Finding, Run, RunExecutionProfile, RunPhase, RunScope, Surface,
    ValidationProofType,
)


class DynastScoringTests(unittest.TestCase):
    def setUp(self):
        self.stores = MemoryStoreBundle()
        self.app = SimpleNamespace(stores=self.stores)
        self.run = Run(
            run_id="run-1", target_url="http://localhost:13322/", scope=RunScope(
                allowed_hosts=frozenset({"localhost"}),
            ), policy_profile="safe", request_budget=80, phase=RunPhase.DONE,
            execution_profile=RunExecutionProfile(code_version="candidate-1"),
        )

    def test_exports_confirmed_finding_and_discovery_without_secret_values(self):
        self.stores.surfaces.add(Surface(
            surface_id="post", run_id="run-1",
            url="http://localhost:13322/posts#private-canary", method="GET",
            parameters=("fragment",), discovery_types=("browser_hash_probe",),
        ))
        self.stores.surfaces.add(Surface(
            surface_id="login", run_id="run-1",
            url="http://localhost:13322/api/auth/login?token=secret-value", method="POST",
            parameters=("email", "password"), discovery_types=("browser_request",),
        ))
        self.stores.surfaces.add(Surface(
            surface_id="list", run_id="run-1",
            url="http://localhost:13322/api/posts/7?auth=secret-value", method="GET",
            parameters=("q",), discovery_types=("js_reference",),
        ))
        self.stores.evidence.append(Evidence(
            evidence_id="blocked", run_id="run-1", surface_id="login",
            created_by="browser_recon", evidence_type="observation",
            observation={"type": "browser_request_structure", "sent": False},
        ))
        self.stores.findings.add(Finding(
            finding_id="finding-1", run_id="run-1", candidate_id="candidate-1",
            validation_id="validation-1", vulnerability_type="XSS", surface_id="post",
            evidence_ids=("evi-1",), proof_type=ValidationProofType.XSS_EXECUTION,
            reproduction_count=1, severity="high",
        ))

        findings, endpoints = build_dynast_documents(
            self.app, self.run, app_name="nextjs", variant="vuln",
        )
        self.assertEqual(findings["run"], {"app": "nextjs", "variant": "vuln"})
        record, = findings["findings"]
        self.assertEqual(record["cwe"], "CWE-79")
        self.assertEqual(record["location"]["http"], {
            "method": "GET", "path": "/posts", "param": "fragment", "param_in": "fragment",
        })
        self.assertTrue(record["exploited"])
        self.assertEqual(endpoints["endpoints"], [
            {"method": "GET", "path": "/posts", "params": ["fragment"]},
            {"method": "GET", "path": "/api/posts/7", "params": ["q"]},
        ])
        self.assertNotIn("secret-value", str((findings, endpoints)))
        self.assertNotIn("private-canary", str((findings, endpoints)))

    def test_incomplete_run_and_missing_code_version_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "incomplete"):
            build_dynast_documents(self.app, replace(self.run, phase=RunPhase.FAILED),
                                   app_name="nextjs", variant="vuln")
        with self.assertRaisesRegex(ValueError, "code version"):
            build_dynast_documents(self.app, replace(
                self.run, execution_profile=RunExecutionProfile(code_version=""),
            ), app_name="nextjs", variant="safe")

    def test_transmitted_post_is_counted_but_secret_path_segment_is_masked(self):
        self.stores.surfaces.add(Surface(
            surface_id="post", run_id="run-1",
            url="http://localhost:13322/api/token/short-secret", method="POST",
            parameters=("email",), discovery_types=("browser_request",),
        ))
        self.stores.evidence.append(Evidence(
            evidence_id="sent", run_id="run-1", surface_id="post",
            created_by="browser_recon", evidence_type="observation",
            observation={"type": "browser_request_structure", "sent": True},
        ))
        _, endpoints = build_dynast_documents(self.app, self.run,
                                              app_name="nextjs", variant="vuln")
        self.assertEqual(endpoints["endpoints"], [{
            "method": "POST", "path": "/api/{value}/{value}", "params": ["email"],
        }])


if __name__ == "__main__":
    unittest.main()
