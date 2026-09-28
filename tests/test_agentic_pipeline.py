"""Agentic Router 가설이 GET probe와 독립 Validation까지 이어지는지 검증."""

from __future__ import annotations

import re
import unittest
from urllib.parse import urlsplit

from hacklipse.bootstrap import build_local_application, register_standard_agents, standard_router
from hacklipse.domain import ExecutionResult, RunExecutionProfile, RunPhase, RunRequest, RunScope
from hacklipse.ports.llm import LlmResponse


class _Model:
    def __init__(self) -> None:
        self.roles: list[str] = []

    def complete(self, request):
        properties = request.response_schema["properties"]
        if "suggestions" in properties:
            self.roles.append("router")
            surface_id = re.search(
                r"surface_id=(\S+) method=GET path=/search ",
                request.messages[0].content,
            ).group(1)
            payload = {"suggestions": [{
                "surface_id": surface_id,
                "vulnerability_type": "SQLi",
                "basis_observation_ids": [],
                "reason_code": "query_interpreter_risk",
                "required_evidence_types": ["control_response", "server_error_delta"],
            }]}
        elif "parameters" in properties:
            self.roles.append("analysis")
            payload = {"parameters": ["q"], "reason": "observed input"}
        elif "action" in properties:
            self.roles.append("probe")
            payload = {"parameter": "q", "action": "syntax_quote"}
        else:
            self.roles.append("interpretation")
            payload = {"assessment": "supports", "reason_code": "server_error_delta"}
        return LlmResponse(payload=payload, model="fixture")


class _Runtime:
    def __init__(self) -> None:
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        path = urlsplit(request.resolved_url).path
        if path == "/":
            status = 200
            body = '<form method="GET" action="/search"><input name="q"></form>'
        else:
            injected = dict(request.query_parameters).get("q", "").endswith("'")
            status = 500 if injected else 200
            body = "You have an error in your SQL syntax" if injected else "normal"
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response", "status": status,
                "body": body, "content_type": "text/html",
                "requested_url": request.resolved_url,
            },
        )


class AgenticPipelineTests(unittest.TestCase):
    def test_router_probe_interpretation_and_validation_are_connected(self):
        model, runtime = _Model(), _Runtime()
        app = build_local_application(
            {}, runtime=runtime,
            router=standard_router(("SQLi",), mode="agentic", llm_client=model),
        )
        register_standard_agents(
            app, llm_client=model, agentic_probe_enabled=True, recon_max_pages=2,
        )
        run = app.orchestrator.start(RunRequest(
            target_url="http://local.test/",
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            request_budget=20,
            execution_profile=RunExecutionProfile(
                analysis_profile="llm", recon_entry_mode="base-url",
                router_mode="agentic", llm_provider="fixture", llm_model="fixture",
            ),
        ))

        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(model.roles, ["router", "analysis", "probe", "interpretation"])
        self.assertEqual(len(app.stores.findings.list_by_run(run.run_id)), 1)
        evidence = app.stores.evidence.list_by_run(run.run_id)
        kinds = {item.observation.get("type") for item in evidence}
        self.assertIn("agentic_probe_result", kinds)
        self.assertIn("agentic_evidence_interpretation", kinds)
        self.assertTrue(any(item.validation_id for item in evidence))
        self.assertTrue(all(request.method == "GET" for request in runtime.requests))


if __name__ == "__main__":
    unittest.main()
