"""Passive credential exposure requires independent analysis and validation fetches."""

from __future__ import annotations

import unittest

from hacklipse.adapters.sensitive_exposure import exposed_json_field_paths
from hacklipse.bootstrap import build_local_application, register_standard_agents, standard_router
from hacklipse.domain import ExecutionResult, RunPhase, RunRequest, RunScope, ValidationProofType


def _html(exposed: bool) -> str:
    config = (
        '{"locale":"en","smtp":{"pass":"unreported-value"},'
        '"internalAdminToken":"another-unreported-value"}'
        if exposed else '{"locale":"en","publicApiBase":"/api"}'
    )
    return '<html><body><script type="application/json">' + config + '</script></body></html>'


class _Runtime:
    def __init__(self, exposed: bool):
        self.exposed = exposed
        self.calls = 0

    def execute(self, request):
        self.calls += 1
        return ExecutionResult(
            execution_id=request.execution_id, evidence_type="http_response",
            observation={"type": "http_response", "status": 200,
                         "content_type": "text/html", "body": _html(self.exposed),
                         "requested_url": request.resolved_url},
        )


class SensitiveExposureTests(unittest.TestCase):
    def test_parser_retains_only_credential_field_paths(self):
        fields = exposed_json_field_paths({"status": 200, "content_type": "text/html", "body": _html(True)})
        self.assertEqual(fields, ("internalAdminToken", "smtp.pass"))
        self.assertEqual(exposed_json_field_paths({"status": 200, "content_type": "text/html", "body": _html(False)}), ())
        documentation = '<script type="application/json">{"form":{"password":"example-only-value"}}</script>'
        self.assertEqual(exposed_json_field_paths({"status": 200, "content_type": "text/html", "body": documentation}), ())

    def test_pipeline_confirms_only_reproduced_public_exposure(self):
        for exposed in (True, False):
            with self.subTest(exposed=exposed):
                runtime = _Runtime(exposed)
                app = build_local_application(
                    {}, runtime=runtime,
                    router=standard_router(("Sensitive Data Exposure",)),
                )
                register_standard_agents(app, recon_max_pages=1)
                run = app.orchestrator.start(RunRequest(
                    target_url="http://local.test/",
                    scope=RunScope(allowed_hosts=frozenset({"local.test"})),
                    request_budget=20,
                ))
                self.assertEqual(run.phase, RunPhase.DONE)
                findings = app.stores.findings.list_by_run(run.run_id)
                self.assertEqual(len(findings), int(exposed))
                if exposed:
                    self.assertEqual(findings[0].proof_type, ValidationProofType.SENSITIVE_DATA_EXPOSURE)
                    self.assertGreaterEqual(runtime.calls, 3)
                observations = [item.observation for item in app.stores.evidence.list_by_run(run.run_id)
                                if item.evidence_type == "observation"]
                self.assertNotIn("unreported-value", str(observations))
