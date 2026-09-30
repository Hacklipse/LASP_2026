"""Capability 등록만으로 Agentic Router를 확장할 수 있는지 검증."""

from __future__ import annotations

import unittest

from hacklipse.adapters.llm_router_advisor import LlmRouterAdvisor
from hacklipse.adapters.routing import RuleBasedVulnerabilityRouter
from hacklipse.domain import Run, RunScope, Surface
from hacklipse.ports import AnalyzerCapability, AnalyzerCapabilityRegistry
from hacklipse.ports.llm import LlmResponse


class _Planner:
    def __init__(self) -> None:
        self.requests = []

    def complete(self, request):
        self.requests.append(request)
        self.assert_new_contract(request.response_schema)
        return LlmResponse(
            payload={
                "hypotheses": [
                    {
                        "surface_id": "surface-1",
                        "capability_id": "custom.query.first",
                        "confidence": "high",
                        "priority": "high",
                        "basis_observation_ids": [],
                        "reason_code": "query_interpreter_risk",
                        "required_evidence_types": ["mutated_input_response"],
                        "analysis_strategy_id": "first_strategy",
                    },
                    {
                        "surface_id": "surface-1",
                        "capability_id": "custom.query.second",
                        "confidence": "medium",
                        "priority": "normal",
                        "basis_observation_ids": [],
                        "reason_code": "input_reflection_risk",
                        "required_evidence_types": ["control_response"],
                        "analysis_strategy_id": "second_strategy",
                    },
                ]
            },
            model="fixture",
        )

    @staticmethod
    def assert_new_contract(schema):
        properties = schema["properties"]
        assert "hypotheses" in properties
        assert "dispositions" not in properties
        assert "surface_dispositions" not in properties


class CapabilityDrivenRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.run = Run(
            run_id="run-1",
            target_url="http://localhost/",
            scope=RunScope(allowed_hosts=frozenset({"localhost"})),
            policy_profile="safe",
            request_budget=10,
        )
        self.surface = Surface(
            surface_id="surface-1",
            run_id=self.run.run_id,
            url="http://localhost/custom?q=1",
            method="GET",
            parameters=("q",),
        )

    def test_registry_rejects_duplicate_capability_ids(self) -> None:
        capability = AnalyzerCapability(
            capability_id="custom.query",
            agent_type="custom_analyzer",
            vulnerability_type="Custom",
        )
        registry = AnalyzerCapabilityRegistry((capability,))
        with self.assertRaises(ValueError):
            registry.register(capability)

    def test_same_vulnerability_can_keep_multiple_agent_capabilities(self) -> None:
        capabilities = (
            AnalyzerCapability(
                capability_id="custom.query.first",
                agent_type="first_analyzer",
                vulnerability_type="Custom",
                supported_evidence_types=("mutated_input_response",),
                strategy_ids=("first_strategy",),
            ),
            AnalyzerCapability(
                capability_id="custom.query.second",
                agent_type="second_analyzer",
                vulnerability_type="Custom",
                supported_evidence_types=("control_response",),
                strategy_ids=("second_strategy",),
            ),
        )
        planner = _Planner()
        advisor = LlmRouterAdvisor(
            llm_client=planner,
            capabilities=capabilities,
            hypothesis_mode=True,
        )
        router = RuleBasedVulnerabilityRouter(
            rules=(),
            surface_rules=(),
            capabilities=capabilities,
            advisor=advisor,
            advisor_mode="primary",
        )

        decisions = router.route(self.run, (self.surface,), ())

        self.assertEqual(len(decisions), 2)
        self.assertEqual(
            {item.candidate.assigned_agent for item in decisions},
            {"first_analyzer", "second_analyzer"},
        )
        by_capability = {
            item.candidate.routing_capability_id: item.candidate
            for item in decisions
        }
        self.assertEqual(
            by_capability["custom.query.first"].routing_confidence, "high"
        )
        self.assertEqual(
            by_capability["custom.query.second"].analysis_strategy_id,
            "second_strategy",
        )
        self.assertEqual(
            {item.status for item in advisor.last_trace.hypotheses}, {"planned"}
        )


if __name__ == "__main__":
    unittest.main()

