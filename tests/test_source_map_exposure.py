"""Public source map findings require original content and independent fetching."""

from __future__ import annotations

import json
import unittest
from urllib.parse import urlsplit

from hacklipse.adapters.source_map_exposure import (
    exposed_source_map_signature, source_map_urls,
)
from hacklipse.bootstrap import build_local_application, register_standard_agents, standard_router
from hacklipse.domain import (
    ExecutionResult, RunPhase, RunRequest, RunScope, ValidationProofType,
)


_SOURCE = "export function example() { return 'generic fixture content'; }\n" * 3


class _Runtime:
    def __init__(self, *, exposed: bool) -> None:
        self.exposed = exposed
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        path = urlsplit(request.resolved_url).path
        if path == "/":
            status, media, body = 200, "text/html", '<script src="/static/app.js"></script>'
        elif path == "/static/app.js":
            status, media, body = 200, "text/javascript", (
                "console.log('ready');\n//# sourceMappingURL=app.js.map"
            )
        elif path == "/static/app.js.map" and self.exposed:
            status, media = 200, "application/json"
            body = json.dumps({
                "version": 3, "sources": ["webpack:///src/app.ts"],
                "sourcesContent": [_SOURCE], "mappings": "",
            })
        else:
            status, media, body = 404, "text/plain", "missing"
        return ExecutionResult(
            execution_id=request.execution_id, evidence_type="http_response",
            observation={
                "type": "http_response", "status": status, "content_type": media,
                "body": body, "requested_url": request.resolved_url,
            },
        )


class SourceMapExposureTests(unittest.TestCase):
    def test_source_map_claims_are_opt_in_for_automatic_routing(self) -> None:
        runtime = _Runtime(exposed=True)
        app = build_local_application({}, runtime=runtime, router=standard_router())
        register_standard_agents(app, recon_max_pages=2)
        run = app.orchestrator.start(RunRequest(
            target_url="http://local.test/",
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            request_budget=30,
        ))
        self.assertEqual(run.phase, RunPhase.DONE)
        self.assertFalse(app.stores.findings.list_by_run(run.run_id))
        self.assertFalse(any(urlsplit(item.resolved_url).path.endswith(".map")
                             for item in runtime.requests))

    def test_only_explicit_same_origin_map_references_are_collected(self) -> None:
        urls = source_map_urls(
            "http://local.test/static/app.js",
            "//# sourceMappingURL=app.js.map\n"
            "//# sourceMappingURL=https://elsewhere.test/private.map\n"
            "//# sourceMappingURL=data:application/json;base64,AAAA\n"
            "//# sourceMappingURL=app.js.map?token=value",
        )
        self.assertEqual(urls, ("http://local.test/static/app.js.map",))

    def test_source_map_requires_embedded_original_code(self) -> None:
        response = {"status": 200, "body": json.dumps({
            "version": 3, "sources": ["webpack:///src/app.ts"],
            "sourcesContent": [_SOURCE],
        })}
        signature = exposed_source_map_signature(response)
        self.assertIsNotNone(signature)
        self.assertEqual(signature[1], 1)
        self.assertNotIn(_SOURCE, repr(signature))
        response["body"] = json.dumps({
            "version": 3, "sources": ["webpack:///src/app.ts"],
            "sourcesContent": [None],
        })
        self.assertIsNone(exposed_source_map_signature(response))

    def test_pipeline_confirms_only_reproducible_public_map(self) -> None:
        for exposed in (True, False):
            with self.subTest(exposed=exposed):
                runtime = _Runtime(exposed=exposed)
                app = build_local_application(
                    {}, runtime=runtime, router=standard_router(("Source Map Exposure",)),
                )
                register_standard_agents(app, recon_max_pages=2)
                run = app.orchestrator.start(RunRequest(
                    target_url="http://local.test/",
                    scope=RunScope(allowed_hosts=frozenset({"local.test"})),
                    request_budget=30,
                ))
                self.assertEqual(run.phase, RunPhase.DONE)
                findings = app.stores.findings.list_by_run(run.run_id)
                self.assertEqual(len(findings), int(exposed))
                if exposed:
                    self.assertEqual(findings[0].proof_type,
                                     ValidationProofType.SOURCE_MAP_EXPOSURE)
                    observations = [item.observation for item in app.stores.evidence.list_by_run(run.run_id)
                                    if item.created_by == "source_map_exposure_analyzer"]
                    self.assertEqual(len(observations), 1)
                    self.assertNotIn(_SOURCE, json.dumps(observations))
                    self.assertEqual(sum(urlsplit(item.resolved_url).path == "/static/app.js.map"
                                         for item in runtime.requests), 2)
                self.assertTrue(all(urlsplit(item.resolved_url).hostname == "local.test"
                                    for item in runtime.requests))
