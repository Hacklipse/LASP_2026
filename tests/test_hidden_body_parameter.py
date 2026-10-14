"""Field names alone must never authorize a hidden POST probe."""

from __future__ import annotations

import unittest

from hacklipse.adapters import StaticApprovalGate
from hacklipse.adapters.analyzer_capabilities import (
    DEFAULT_ANALYZER_CAPABILITIES, capability_missing_requirements,
)
from hacklipse.adapters.llm_path_traversal_analysis import LlmPathTraversalAnalyzer
from hacklipse.adapters.path_traversal_analysis import (
    HIDDEN_BODY_CAPABILITY, PATH_TRAVERSAL_POST_APPROVAL_REF,
    PATH_TRAVERSAL_TOOL, build_hidden_body_requests,
)
from hacklipse.adapters.validation import ValidationAgent
from hacklipse.application.errors import AgentContractError
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    AgentResultStatus, Candidate, Evidence, Run, RunScope, Surface, TaskEnvelope,
    ValidationReasonCode, ValidationVerdict,
)


class _Llm:
    def __init__(self) -> None:
        self.calls = 0

    def complete(self, request):
        self.calls += 1
        raise AssertionError("LLM must not receive an unverified POST form")


class HiddenBodySafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = build_local_application(
            {}, approval_gate=StaticApprovalGate((PATH_TRAVERSAL_POST_APPROVAL_REF,))
        )
        self.surface = Surface(
            surface_id="post-form", run_id="run-hidden",
            url="http://local.test/submit", method="POST",
            parameters=("email", "securityAnswer"),
        )
        self.app.stores.runs.add(Run(
            run_id=self.surface.run_id, target_url=self.surface.url,
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            policy_profile="safe", request_budget=40,
        ))
        self.app.budget_manager.open_run(self.surface.run_id, 40)
        self.app.stores.surfaces.add(self.surface)
        self.candidate = Candidate(
            candidate_id="hidden-candidate", run_id=self.surface.run_id,
            surface_id=self.surface.surface_id, vulnerability_type="Path Traversal",
            hypothesis="hidden body", assigned_agent="path_traversal_analyzer",
            evidence_ids=(), routing_capability_id=HIDDEN_BODY_CAPABILITY,
        )
        self.app.stores.candidates.add(self.candidate)

    def test_unverified_form_is_not_routable(self) -> None:
        capability = next(item for item in DEFAULT_ANALYZER_CAPABILITIES
                          if item.capability_id == HIDDEN_BODY_CAPABILITY)
        form_shape = Evidence(
            evidence_id="form-shape", run_id=self.surface.run_id,
            surface_id=self.surface.surface_id, created_by="recon",
            evidence_type="observation",
            observation={"type": "post_form_body_structure", "source": "html_form",
                         "field_names": ["email", "securityAnswer"],
                         "observed_request": False},
        )
        self.assertIn(
            "required_observation",
            capability_missing_requirements(capability, self.surface, (form_shape,)),
        )

    def test_old_candidate_cannot_probe_even_with_post_approval(self) -> None:
        llm = _Llm()
        analyzer = LlmPathTraversalAnalyzer(
            llm_client=llm, candidate_store=self.app.stores.candidates,
            surface_store=self.app.stores.surfaces,
            evidence_store=self.app.stores.evidence,
        )
        result = analyzer.handle(TaskEnvelope(
            task_id="analysis", run_id=self.surface.run_id,
            agent_type="path_traversal_analyzer", target_url=self.surface.url,
            surface_id=self.surface.surface_id, candidate_id=self.candidate.candidate_id,
            allowed_tools=(PATH_TRAVERSAL_TOOL,), request_budget=30,
        ))
        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        self.assertEqual(result.evidence_requests, ())
        self.assertEqual(llm.calls, 0)

        validator = ValidationAgent(
            candidate_store=self.app.stores.candidates,
            evidence_store=self.app.stores.evidence,
            surface_store=self.app.stores.surfaces,
        )
        validation = validator.handle(TaskEnvelope(
            task_id="validation", run_id=self.surface.run_id,
            agent_type="validation", target_url=self.surface.url,
            surface_id=self.surface.surface_id, candidate_id=self.candidate.candidate_id,
            validation_id="validation-hidden",
            allowed_tools=(PATH_TRAVERSAL_TOOL,), request_budget=3,
        ))
        self.assertIs(validation.validation.verdict, ValidationVerdict.BLOCKED)
        self.assertIs(
            validation.validation.reason_code,
            ValidationReasonCode.POST_REQUEST_TEMPLATE_MISSING,
        )
        self.assertEqual(validation.evidence_requests, ())

    def test_blank_control_builder_is_disabled(self) -> None:
        with self.assertRaises(AgentContractError):
            build_hidden_body_requests(self.surface, ("layout",), purpose="test")


if __name__ == "__main__":
    unittest.main()
