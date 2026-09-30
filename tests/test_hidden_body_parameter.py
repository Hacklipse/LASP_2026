"""Hidden POST names remain hypotheses until approved differential reproduction."""

from __future__ import annotations

import unittest
from dataclasses import replace
from urllib.parse import parse_qsl

from hacklipse.adapters import StaticApprovalGate
from hacklipse.adapters.llm_path_traversal_analysis import LlmPathTraversalAnalyzer
from hacklipse.adapters.hidden_parameter_planner import HiddenParameterPlanner
from hacklipse.adapters.path_traversal_analysis import (
    HIDDEN_BODY_CAPABILITY,
    PATH_TRAVERSAL_FORM_PROOF_MARKERS,
    PATH_TRAVERSAL_POST_APPROVAL_REF,
    PATH_TRAVERSAL_TOOL,
)
from hacklipse.adapters.recon import RECON_TOOL, ReconAgent
from hacklipse.adapters.validation import ValidationAgent
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    AgentResultStatus, Candidate, Evidence, ExecutionRequest, ExecutionResult,
    Run, RunScope, Surface, TaskEnvelope, ValidationVerdict,
)
from hacklipse.ports.llm import LlmResponse


class _Runtime:
    def __init__(self, *, enctype: str = "") -> None:
        self.requests: list[ExecutionRequest] = []
        self.enctype = enctype

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        if request.method == "GET":
            body = (
                f'<form action="/dataerasure" method="POST" enctype="{self.enctype}">'
                '<input name="email"><input name="securityAnswer"></form>'
            )
        else:
            fields = dict(parse_qsl(request.body or "", keep_blank_values=True))
            if fields.get("layout") == "../package.json":
                body = "\n".join(PATH_TRAVERSAL_FORM_PROOF_MARKERS)
            elif any(value == "package.json" for value in fields.values()):
                body = "benign render selection"
            else:
                body = "ordinary form response"
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response", "status": 200, "body": body,
                "requested_url": request.resolved_url,
                "content_type": "text/html",
            },
        )


class _Llm:
    def __init__(self) -> None:
        self.requests = []

    def complete(self, request):
        self.requests.append(request)
        return LlmResponse(payload={"hypotheses": [
            {"name": "delete", "semantic_role": "file_path", "confidence": "high", "reason_code": "x"},
            {"name": "layout", "semantic_role": "render_layout", "confidence": "medium", "reason_code": "server_render_option"},
        ]})


class _UnrelatedLlm:
    def complete(self, request):
        return LlmResponse(payload={"hypotheses": [
            {"name": f"other{i}", "semantic_role": "resource_name",
             "confidence": "low", "reason_code": "x"}
            for i in range(12)
        ]})


class HiddenBodyParameterTests(unittest.TestCase):
    def test_multipart_form_is_not_claimed_as_urlencoded_template(self) -> None:
        runtime = _Runtime(enctype="multipart/form-data")
        app = build_local_application({}, runtime=runtime)
        run_id = "run-multipart"
        url = "http://local.test/dataerasure"
        app.stores.runs.add(Run(
            run_id=run_id, target_url=url,
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            policy_profile="safe", request_budget=2,
        ))
        app.budget_manager.open_run(run_id, 2)
        recon = ReconAgent(
            collector=app.collector, evidence_store=app.stores.evidence,
            surface_store=app.stores.surfaces, max_pages=1,
            infer_unlinked_render_parameters=False,
        )
        recon.handle(TaskEnvelope(
            task_id="recon-multipart", run_id=run_id, agent_type="recon",
            target_url=url, allowed_tools=(RECON_TOOL,), request_budget=1,
        ))
        self.assertFalse(any(
            item.observation.get("type") == "post_form_body_structure"
            for item in app.stores.evidence.list_by_run(run_id)
        ))

    def test_generic_corpus_survives_unrelated_llm_names(self) -> None:
        surface = Surface(
            surface_id="s", run_id="r", url="http://local.test/other",
            method="POST", parameters=("email", "securityAnswer"),
        )
        hypotheses = HiddenParameterPlanner(_UnrelatedLlm()).plan(
            surface, timeout_seconds=5,
        )
        self.assertEqual(len(hypotheses), 12)
        self.assertIn("layout", [item.name for item in hypotheses])
        self.assertEqual(hypotheses[-1].source, "generic_corpus")

    def test_negative_first_wave_expands_to_corpus_second_wave(self) -> None:
        runtime = _Runtime()
        app = build_local_application(
            {}, runtime=runtime,
            approval_gate=StaticApprovalGate((PATH_TRAVERSAL_POST_APPROVAL_REF,)),
        )
        run_id = "run-second-wave"
        url = "http://local.test/dataerasure"
        app.stores.runs.add(Run(
            run_id=run_id, target_url=url,
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            policy_profile="safe", request_budget=40,
        ))
        app.budget_manager.open_run(run_id, 40)
        surface = Surface(
            surface_id="surface-second-wave", run_id=run_id, url=url,
            method="POST", parameters=("email", "securityAnswer"),
        )
        app.stores.surfaces.add(surface)
        candidate = Candidate(
            candidate_id="candidate-second-wave", run_id=run_id,
            surface_id=surface.surface_id, vulnerability_type="Path Traversal",
            hypothesis="hidden body search", assigned_agent="path_traversal_analyzer",
            evidence_ids=(), routing_capability_id=HIDDEN_BODY_CAPABILITY,
        )
        app.stores.candidates.add(candidate)
        analyzer = LlmPathTraversalAnalyzer(
            llm_client=_UnrelatedLlm(), candidate_store=app.stores.candidates,
            surface_store=app.stores.surfaces,
            evidence_store=app.stores.evidence,
        )
        task = TaskEnvelope(
            task_id="analyze-second-wave", run_id=run_id,
            agent_type="path_traversal_analyzer", target_url=url,
            surface_id=surface.surface_id, candidate_id=candidate.candidate_id,
            allowed_tools=(PATH_TRAVERSAL_TOOL,), request_budget=30,
        )
        result = analyzer.handle(task)
        self.assertEqual(len(result.evidence_requests), 13)
        for wave in range(2):
            ids = list(task.evidence_ids) + list(result.new_evidence_ids)
            ids.extend(app.collector.collect(
                run_id, url, spec, task_id=task.task_id,
                approval_ref=spec.approval_ref,
            ) for spec in result.evidence_requests)
            task = replace(
                task, evidence_ids=tuple(ids),
                request_budget=app.budget_manager.remaining(run_id),
            )
            result = analyzer.handle(task)
            if wave == 0:
                self.assertIs(result.status, AgentResultStatus.NEEDS_EVIDENCE)
                self.assertEqual(len(result.evidence_requests), 12)
        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        signal = app.stores.evidence.get(run_id, result.new_evidence_ids[0])
        self.assertEqual(signal.observation["parameter"], "layout")
        self.assertEqual(signal.observation["hypothesis_source"], "generic_corpus")

    def test_form_to_hypothesis_to_independent_three_way_proof(self) -> None:
        runtime = _Runtime()
        llm = _Llm()
        app = build_local_application(
            {}, runtime=runtime,
            approval_gate=StaticApprovalGate((PATH_TRAVERSAL_POST_APPROVAL_REF,)),
        )
        run_id = "run-hidden"
        url = "http://local.test/dataerasure"
        app.stores.runs.add(Run(
            run_id=run_id, target_url=url,
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            policy_profile="safe", request_budget=40,
        ))
        app.budget_manager.open_run(run_id, 40)
        recon = ReconAgent(
            collector=app.collector,
            evidence_store=app.stores.evidence,
            surface_store=app.stores.surfaces,
            max_pages=1,
            infer_unlinked_render_parameters=False,
        )
        recon.handle(TaskEnvelope(
            task_id="recon-hidden", run_id=run_id, agent_type="recon",
            target_url=url, allowed_tools=(RECON_TOOL,), request_budget=1,
        ))
        surface = next(item for item in app.stores.surfaces.list_by_run(run_id)
                       if item.method == "POST")
        observations = app.stores.evidence.list_by_run(run_id)
        self.assertEqual(surface.parameters, ("email", "securityAnswer"))
        self.assertTrue(any(
            item.surface_id == surface.surface_id
            and item.observation.get("type") == "post_form_body_structure"
            and item.observation.get("observed_request") is False
            for item in observations
        ))
        self.assertFalse(any(item.observation.get("parameter") == "layout"
                             for item in observations))

        candidate = Candidate(
            candidate_id="candidate-hidden", run_id=run_id,
            surface_id=surface.surface_id,
            vulnerability_type="Path Traversal", hypothesis="hidden body search",
            assigned_agent="path_traversal_analyzer", evidence_ids=(),
            routing_capability_id=HIDDEN_BODY_CAPABILITY,
            analysis_strategy_id="hidden_parameter_differential_probe",
        )
        app.stores.candidates.add(candidate)
        analyzer = LlmPathTraversalAnalyzer(
            llm_client=llm, candidate_store=app.stores.candidates,
            surface_store=app.stores.surfaces,
            evidence_store=app.stores.evidence,
        )
        task = TaskEnvelope(
            task_id="analyze-hidden", run_id=run_id,
            agent_type="path_traversal_analyzer", target_url=url,
            surface_id=surface.surface_id, candidate_id=candidate.candidate_id,
            allowed_tools=(PATH_TRAVERSAL_TOOL,), request_budget=30,
        )
        first = analyzer.handle(task)
        self.assertIs(first.status, AgentResultStatus.NEEDS_EVIDENCE)
        plan = app.stores.evidence.get(run_id, first.new_evidence_ids[0])
        self.assertEqual(plan.observation["hypotheses"][0]["name"], "layout")
        self.assertEqual(plan.observation["hypotheses"][0]["source"], "llm_hypothesis")
        self.assertFalse(plan.observation["hypotheses"][0]["observed"])
        self.assertNotIn("delete", [item["name"] for item in plan.observation["hypotheses"]])
        self.assertTrue(all(req.http_request.method == "POST" and req.approval_ref
                            for req in first.evidence_requests))
        self.assertTrue(all(
            set(dict(parse_qsl(req.http_request.body or "", keep_blank_values=True)))
            >= {"email", "securityAnswer"}
            for req in first.evidence_requests
        ))
        ids = list(first.new_evidence_ids)
        ids.extend(app.collector.collect(
            run_id, url, spec, task_id=task.task_id,
            approval_ref=spec.approval_ref,
        ) for spec in first.evidence_requests)
        analyzed = analyzer.handle(replace(
            task, evidence_ids=tuple(ids),
            request_budget=app.budget_manager.remaining(run_id),
        ))
        self.assertIs(analyzed.status, AgentResultStatus.COMPLETED)
        signal = app.stores.evidence.get(run_id, analyzed.new_evidence_ids[0])
        self.assertEqual(signal.observation["parameter"], "layout")
        self.assertEqual(signal.observation["source"], "active_differential_probe")
        self.assertTrue(signal.observation["observed"])

        validator = ValidationAgent(
            candidate_store=app.stores.candidates,
            evidence_store=app.stores.evidence,
            surface_store=app.stores.surfaces,
        )
        validation_task = TaskEnvelope(
            task_id="validate-hidden", run_id=run_id, agent_type="validation",
            target_url=url, surface_id=surface.surface_id,
            candidate_id=candidate.candidate_id, validation_id="validation-hidden",
            evidence_ids=tuple((*ids, *analyzed.new_evidence_ids)),
            allowed_tools=(PATH_TRAVERSAL_TOOL,), request_budget=3,
        )
        needed = validator.handle(validation_task)
        self.assertEqual(len(needed.evidence_requests), 3)
        reproduced = tuple(app.collector.collect(
            run_id, url, spec, task_id=validation_task.task_id,
            validation_id=validation_task.validation_id,
            approval_ref=spec.approval_ref,
        ) for spec in needed.evidence_requests)
        final = validator.handle(replace(
            validation_task, evidence_ids=(*validation_task.evidence_ids, *reproduced),
        ))
        self.assertIs(final.validation.verdict, ValidationVerdict.CONFIRMED)
        self.assertEqual(len(final.validation.proof.evidence_ids), 3)


if __name__ == "__main__":
    unittest.main()
