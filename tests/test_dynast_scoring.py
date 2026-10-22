"""The benchmark export must score only proven results and never leak request values."""

from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import dynast_scoring
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

    def test_embedded_basic_header_uses_observed_document_entry(self):
        self.stores.surfaces.add(Surface(
            surface_id="document", run_id="run-1",
            url="http://localhost:13322/connected/apps", method="GET",
            discovery_types=("browser_navigation",),
        ))
        self.stores.surfaces.add(Surface(
            surface_id="script", run_id="run-1",
            url="http://localhost:13322/static/app-123.js", method="GET",
            discovery_types=("browser_javascript_response",),
        ))
        self.stores.evidence.append(Evidence(
            evidence_id="reference", run_id="run-1", surface_id="script",
            created_by="browser_recon", evidence_type="observation",
            observation={"type": "client_script_reference",
                         "document_surface_id": "document"},
        ))
        self.stores.evidence.append(Evidence(
            evidence_id="signal", run_id="run-1", surface_id="script",
            created_by="sensitive_exposure_analyzer", evidence_type="observation",
            observation={"type": "sensitive_json_exposure",
                         "field_paths": ["fetch.authorization"]},
        ))
        self.stores.findings.add(Finding(
            finding_id="finding-basic", run_id="run-1", candidate_id="candidate-basic",
            validation_id="validation-basic", vulnerability_type="Sensitive Data Exposure",
            surface_id="script", evidence_ids=("signal",),
            proof_type=ValidationProofType.SENSITIVE_DATA_EXPOSURE,
            reproduction_count=1, severity="high",
        ))
        findings, _ = build_dynast_documents(
            self.app, self.run, app_name="sample", variant="vuln",
        )
        self.assertEqual(findings["findings"][0]["cwe"], "CWE-522")
        self.assertEqual(findings["findings"][0]["location"]["http"], {
            "method": "GET", "path": "/connected/apps",
        })

    def test_exports_only_operations_backed_by_successful_schema_response(self):
        self.stores.surfaces.add(Surface(
            surface_id="graphql", run_id="run-1",
            url="http://localhost:13322/graphql", method="GET",
            discovery_types=("graphql_introspection",),
        ))
        self.stores.evidence.append(Evidence(
            evidence_id="schema", run_id="run-1", surface_id=None,
            created_by="execution_runtime:http_get", evidence_type="http_response",
            observation={"status": 200, "content_type": "application/json"},
        ))
        for evidence_id, source_id, operation in (
            ("observed", "schema", "posts"),
            ("unbacked", "missing", "secretField"),
        ):
            self.stores.evidence.append(Evidence(
                evidence_id=evidence_id, run_id="run-1", surface_id="graphql",
                created_by="recon", evidence_type="observation",
                observation={
                    "type": "graphql_schema_operation", "graphql_kind": "query",
                    "operation": operation, "schema_evidence_id": source_id,
                },
            ))
        _, endpoints = build_dynast_documents(
            self.app, self.run, app_name="graphql", variant="vuln",
        )
        self.assertIn({"kind": "graphql", "graphql_kind": "query", "op": "posts"},
                      endpoints["endpoints"])
        self.assertFalse(any(item.get("op") == "secretField" for item in endpoints["endpoints"]))


class DynastCweMappingTests(unittest.TestCase):
    """모든 proof type 이 CWE 를 갖는지 고정한다.

    매핑이 빠지면 finding 은 그대로 내보내지면서 ``cwe`` 필드만 사라진다. 수출은
    성공한 것처럼 보이고 스코어러는 그 finding 을 분류하지 못하므로, 조용히 통과하는
    실패가 된다. Access Control 과 Arbitrary File Read 가 실제로 그렇게 빠져 있었다.
    """

    def test_every_proof_type_has_a_cwe(self) -> None:
        missing = [
            item.name for item in ValidationProofType if item not in dynast_scoring._CWE
        ]
        self.assertEqual(missing, [])

    def test_file_read_and_object_access_cwes(self) -> None:
        self.assertEqual(
            dynast_scoring._CWE[ValidationProofType.ARBITRARY_FILE_READ], "CWE-36"
        )
        self.assertEqual(
            dynast_scoring._CWE[ValidationProofType.UNAUTHORIZED_OBJECT_ACCESS],
            "CWE-639",
        )
        # 상대 탈출과 절대 경로는 서로 다른 CWE 로 나간다. 같은 값이면 둘을 나눈
        # 이유가 수출 결과에서 사라진다.
        self.assertNotEqual(
            dynast_scoring._CWE[ValidationProofType.PATH_TRAVERSAL_FILE_READ],
            dynast_scoring._CWE[ValidationProofType.ARBITRARY_FILE_READ],
        )


if __name__ == "__main__":
    unittest.main()
