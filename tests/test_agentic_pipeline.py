"""Agentic Router 가설이 GET probe와 독립 Validation까지 이어지는지 검증."""

from __future__ import annotations

import re
import unittest
from urllib.parse import urlsplit

from hacklipse.application.orchestrator import OrchestratorConfig
from hacklipse.bootstrap import build_local_application, register_standard_agents, standard_router
from hacklipse.domain import ExecutionResult, RunExecutionProfile, RunPhase, RunRequest, RunScope
from hacklipse.ports.llm import LlmResponse


class _Model:
    def __init__(self, *, explore=False, bad_parameter=False) -> None:
        self.roles: list[str] = []
        self.explore = explore
        self.bad_parameter = bad_parameter

    def complete(self, request):
        properties = request.response_schema["properties"]
        if "dispositions" in properties:
            self.roles.append("router")
            surface_id = re.search(
                r"surface_id=(\S+) method=GET path=/search ",
                request.messages[0].content,
            ).group(1)
            payload = {"dispositions": [{
                "surface_id": surface_id,
                "vulnerability_type": "SQLi",
                "decision": "route",
                "basis_observation_ids": [],
                "reason_code": "query_interpreter_risk",
                "required_evidence_types": [
                    "control_response",
                    "mutated_input_response" if self.explore else "server_error_delta",
                ],
            }]}
        elif "parameters" in properties:
            self.roles.append("analysis")
            payload = {"parameters": ["invented" if self.bad_parameter else "q"], "reason": "observed input"}
        elif "action" in properties:
            self.roles.append("probe")
            payload = {"parameter": "q", "action": "marker" if self.explore else "syntax_quote"}
        else:
            self.roles.append("interpretation")
            payload = (
                {"assessment": "inconclusive", "reason_code": "insufficient_evidence"}
                if self.explore and self.roles.count("interpretation") == 1
                else {"assessment": "supports", "reason_code": "server_error_delta"}
            )
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

    def test_inconclusive_evidence_triggers_one_extra_round_then_validation(self):
        model, runtime = _Model(explore=True), _Runtime()
        app = build_local_application(
            {}, runtime=runtime,
            router=standard_router(("SQLi",), mode="agentic", llm_client=model),
            config=OrchestratorConfig(max_evidence_rounds=2),
        )
        register_standard_agents(
            app, llm_client=model, agentic_probe_enabled=True, recon_max_pages=2,
        )
        run = app.orchestrator.start(RunRequest(
            target_url="http://local.test/",
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            request_budget=20,
        ))
        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(model.roles, [
            "router", "analysis", "probe", "interpretation", "interpretation",
        ])
        evidence = app.stores.evidence.list_by_run(run.run_id)
        follow_ups = [item for item in evidence if item.observation.get("follow_up_of")]
        self.assertEqual(len(follow_ups), 1)
        self.assertEqual(follow_ups[0].observation["action"], "syntax_quote")
        self.assertEqual(len(app.stores.findings.list_by_run(run.run_id)), 1)

    def test_invented_llm_parameter_recovers_to_heuristic_analysis(self):
        model, runtime = _Model(bad_parameter=True), _Runtime()
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
        ))
        self.assertIs(run.phase, RunPhase.DONE)
        evidence = app.stores.evidence.list_by_run(run.run_id)
        fallbacks = [item for item in evidence if item.observation.get("type") == "analysis_llm_fallback"]
        self.assertEqual(len(fallbacks), 1)
        self.assertEqual(fallbacks[0].observation["reason"], "LlmOutputContractError")
        self.assertEqual(len(app.stores.findings.list_by_run(run.run_id)), 1)


if __name__ == "__main__":
    unittest.main()
