"""Safe file-read probes, redacted evidence, and independent proof."""

from __future__ import annotations

import hashlib
import unittest
from dataclasses import replace

from hacklipse.adapters.arbitrary_file_read_analysis import (
    ArbitraryFileReadAnalyzer, FILE_READ_OBSERVATION, FILE_READ_TOOL,
    SafeFileTarget,
)
from hacklipse.adapters.validation import ValidationAgent
from hacklipse.bootstrap import build_local_application, standard_router
from hacklipse.domain import (
    AgentResultStatus, Candidate, ExecutionRequest, ExecutionResult, Evidence,
    HttpRequestKind, Run, RunScope, Surface, TaskEnvelope,
    ValidationProofType, ValidationVerdict,
    ValidationReasonCode,
)
from hacklipse.ports.errors import PolicyViolation


TARGET = SafeFileTarget("test-canary", "/var/afr-canary.txt", ("afr-canary-content",))
TARGET_TWO = SafeFileTarget(
    "second-canary", "/opt/afr-second.txt", ("afr-second-content",)
)
URL = "http://local.test/download"


class FakeRuntime:
    def __init__(self, *, vulnerable: bool = True, marker_in_control: bool = False,
                 public_file: bool = False,
                 readable_targets: tuple[SafeFileTarget, ...] = (TARGET,)):
        self.vulnerable = vulnerable
        self.marker_in_control = marker_in_control
        self.public_file = public_file
        self.readable_targets = {
            target.request_value: target.markers[0] for target in readable_targets
        }

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        value = dict(request.query_parameters).get("asset", "")
        body = "normal"
        if request.request_kind is HttpRequestKind.FILE_READ_PUBLIC_CHECK:
            body = "afr-canary-content\n" if self.public_file else "not found"
        elif self.marker_in_control:
            body = "afr-canary-content\n"
        elif self.vulnerable and value in self.readable_targets:
            body = self.readable_targets[value] + "\n"
        elif not value.startswith("hacklipse-file-read-control-"):
            body = value  # a path reflection is not a file read
        return ExecutionResult(
            execution_id=request.execution_id, evidence_type="http_response",
            observation={
                "type": "http_response", "status": 200, "body": body,
                "body_bytes": len(body), "truncated": False,
                "requested_url": request.resolved_url,
                "request_kind": request.request_kind.value,
            },
            content_hash=hashlib.sha256(body.encode()).hexdigest(),
        )


def fixture(*, vulnerable: bool = True, marker_in_control: bool = False,
            public_file: bool = False,
            targets: tuple[SafeFileTarget, ...] = (TARGET,),
            readable_targets: tuple[SafeFileTarget, ...] = (TARGET,),
            parameters: tuple[str, ...] = ("asset",),
            observed_query: tuple[tuple[str, str], ...] = (("asset", "sample"),)):
    app = build_local_application(
        {}, runtime=FakeRuntime(
            vulnerable=vulnerable, marker_in_control=marker_in_control,
            public_file=public_file, readable_targets=readable_targets,
        ), file_read_targets=targets,
    )
    app.stores.runs.add(Run(
        run_id="afr-run", target_url=URL,
        scope=RunScope(allowed_hosts=frozenset({"local.test"})),
        policy_profile="safe", request_budget=20,
    ))
    app.stores.surfaces.add(Surface(
        surface_id="afr-surface", run_id="afr-run", url=URL,
        method="GET", parameters=parameters, observed_query=observed_query,
    ))
    app.stores.candidates.add(Candidate(
        candidate_id="afr-candidate", run_id="afr-run",
        surface_id="afr-surface", vulnerability_type="Arbitrary File Read",
        hypothesis="file read", assigned_agent="arbitrary_file_read_analyzer",
        evidence_ids=(),
    ))
    app.budget_manager.open_run("afr-run", 20)
    analyzer = ArbitraryFileReadAnalyzer(
        candidate_store=app.stores.candidates,
        surface_store=app.stores.surfaces,
        evidence_store=app.stores.evidence, targets=targets,
    )
    task = TaskEnvelope(
        task_id="afr-analysis", run_id="afr-run",
        agent_type="arbitrary_file_read_analyzer", target_url=URL,
        surface_id="afr-surface", candidate_id="afr-candidate",
        allowed_tools=(FILE_READ_TOOL,), request_budget=10,
    )
    return app, analyzer, task


def collect(app, task, requests, *, validation_id=None):
    ids = tuple(app.collector.collect(
        task.run_id, request.target_url_override or URL, request, task_id=task.task_id,
        validation_id=validation_id,
    ) for request in requests)
    return replace(task, evidence_ids=task.evidence_ids + ids)


class ArbitraryFileReadTests(unittest.TestCase):
    def test_independent_file_read_proof_and_redacted_evidence(self):
        app, analyzer, task = fixture()
        first = analyzer.handle(task)
        self.assertEqual(first.status, AgentResultStatus.NEEDS_EVIDENCE)
        task = collect(app, task, first.evidence_requests)
        for item in app.stores.evidence.get_many(task.run_id, task.evidence_ids):
            self.assertNotIn("body", item.observation)
            self.assertNotIn("headers", item.observation)
        analyzed = analyzer.handle(task)
        self.assertEqual(len(analyzed.new_evidence_ids), 1)
        signal = app.stores.evidence.get_many(task.run_id, analyzed.new_evidence_ids)[0]
        self.assertEqual(signal.observation["type"], FILE_READ_OBSERVATION)
        validation_task = TaskEnvelope(
            task_id="afr-validation", run_id="afr-run", agent_type="validation",
            surface_id="afr-surface", candidate_id="afr-candidate",
            validation_id="validation-1", allowed_tools=(FILE_READ_TOOL,),
            evidence_ids=task.evidence_ids + analyzed.new_evidence_ids,
            request_budget=10,
        )
        validator = ValidationAgent(
            candidate_store=app.stores.candidates,
            evidence_store=app.stores.evidence,
            surface_store=app.stores.surfaces,
            file_read_targets=(TARGET,),
        )
        reproduce = validator.handle(validation_task)
        self.assertEqual(reproduce.status, AgentResultStatus.NEEDS_EVIDENCE)
        validation_task = collect(
            app, validation_task, reproduce.evidence_requests,
            validation_id="validation-1",
        )
        verified = validator.handle(validation_task).validation
        self.assertIsNotNone(verified)
        self.assertEqual(verified.verdict, ValidationVerdict.CONFIRMED)
        self.assertEqual(verified.proof.proof_type, ValidationProofType.ARBITRARY_FILE_READ)
        self.assertEqual(len(verified.proof.evidence_ids), 3)

    def test_directly_public_file_does_not_create_proof(self):
        app, analyzer, task = fixture(public_file=True)
        task = collect(app, task, analyzer.handle(task).evidence_requests)
        analyzed = analyzer.handle(task)
        validation_task = TaskEnvelope(
            task_id="afr-validation", run_id="afr-run", agent_type="validation",
            surface_id="afr-surface", candidate_id="afr-candidate",
            validation_id="validation-1", allowed_tools=(FILE_READ_TOOL,),
            evidence_ids=task.evidence_ids + analyzed.new_evidence_ids,
            request_budget=10,
        )
        validator = ValidationAgent(
            candidate_store=app.stores.candidates,
            evidence_store=app.stores.evidence,
            surface_store=app.stores.surfaces,
            file_read_targets=(TARGET,),
        )
        reproduce = validator.handle(validation_task)
        validation_task = collect(
            app, validation_task, reproduce.evidence_requests,
            validation_id="validation-1",
        )
        verified = validator.handle(validation_task).validation
        self.assertEqual(verified.verdict, ValidationVerdict.REJECTED)
        self.assertIsNone(verified.proof)

    def test_reflection_and_baseline_marker_are_not_file_reads(self):
        for vulnerable, baseline in ((False, False), (True, True)):
            with self.subTest(vulnerable=vulnerable, baseline=baseline):
                app, analyzer, task = fixture(
                    vulnerable=vulnerable, marker_in_control=baseline,
                )
                task = collect(app, task, analyzer.handle(task).evidence_requests)
                self.assertFalse(analyzer.handle(task).new_evidence_ids)

    def test_preserves_observed_query_and_reuses_one_control_per_parameter(self):
        app, analyzer, task = fixture(
            targets=(TARGET, TARGET_TWO),
            readable_targets=(TARGET, TARGET_TWO),
            parameters=("asset", "format"),
            observed_query=(("asset", "sample.txt"), ("format", "raw")),
        )
        task = replace(task, request_budget=6)

        result = analyzer.handle(task)
        self.assertEqual(len(result.evidence_requests), 6)
        asset_requests = [
            request for request in result.evidence_requests
            if request.http_request.file_read_parameter == "asset"
        ]
        self.assertEqual(
            sum(
                request.http_request.request_kind is HttpRequestKind.CONTROL
                for request in asset_requests
            ),
            1,
        )
        for request in asset_requests:
            self.assertEqual(dict(request.http_request.query_parameters)["format"], "raw")

    def test_policy_rejects_change_to_an_unselected_query_coordinate(self):
        app, _, task = fixture(
            parameters=("asset", "format"),
            observed_query=(("asset", "sample.txt"), ("format", "raw")),
        )
        from hacklipse.domain import EvidenceRequest, HttpRequestSpec
        request = EvidenceRequest(
            evidence_type="http_response", surface_id="afr-surface",
            reason="mutates two inputs", suggested_tool=FILE_READ_TOOL,
            http_request=HttpRequestSpec(
                query_parameters=(("asset", TARGET.request_value), ("format", "changed")),
                request_kind=HttpRequestKind.ARBITRARY_FILE_READ_PROBE,
                file_read_parameter="asset",
            ),
        )
        with self.assertRaises(PolicyViolation):
            app.collector.collect(task.run_id, URL, request, task_id=task.task_id)

    def test_policy_rejects_an_unknown_surface_before_runtime(self):
        app, _, task = fixture()
        from hacklipse.domain import EvidenceRequest, HttpRequestSpec
        request = EvidenceRequest(
            evidence_type="http_response", surface_id="missing-surface",
            reason="unknown surface", suggested_tool=FILE_READ_TOOL,
            http_request=HttpRequestSpec(
                query_parameters=(("asset", TARGET.request_value),),
                request_kind=HttpRequestKind.ARBITRARY_FILE_READ_PROBE,
                file_read_parameter="asset",
            ),
        )
        with self.assertRaises(PolicyViolation):
            app.collector.collect(task.run_id, URL, request, task_id=task.task_id)

    def test_validation_tries_later_signal_when_the_first_no_longer_reproduces(self):
        app, _, task = fixture(
            targets=(TARGET, TARGET_TWO), readable_targets=(TARGET_TWO,),
        )
        signal_ids = []
        for index, target in enumerate((TARGET, TARGET_TWO), start=1):
            evidence_id = f"afr-signal-{index}"
            app.stores.evidence.append(Evidence(
                evidence_id=evidence_id, run_id=task.run_id,
                surface_id="afr-surface", created_by="arbitrary_file_read_analyzer",
                evidence_type="observation",
                observation={
                    "type": FILE_READ_OBSERVATION, "parameter": "asset",
                    "target_key": target.key,
                    "target_fingerprint": target.configuration_fingerprint,
                },
            ))
            signal_ids.append(evidence_id)
        validation_task = TaskEnvelope(
            task_id="afr-validation", run_id=task.run_id, agent_type="validation",
            surface_id="afr-surface", candidate_id="afr-candidate",
            validation_id="validation-1", allowed_tools=(FILE_READ_TOOL,),
            evidence_ids=tuple(signal_ids), request_budget=10,
        )
        validator = ValidationAgent(
            candidate_store=app.stores.candidates,
            evidence_store=app.stores.evidence,
            surface_store=app.stores.surfaces,
            file_read_targets=(TARGET, TARGET_TWO),
        )
        reproduce = validator.handle(validation_task)
        validation_task = collect(
            app, validation_task, reproduce.evidence_requests,
            validation_id="validation-1",
        )

        verified = validator.handle(validation_task).validation
        self.assertEqual(verified.verdict, ValidationVerdict.CONFIRMED)
        self.assertIn(TARGET_TWO.key, verified.proof.summary)

    def test_validation_marks_changed_proof_target_configuration_blocked(self):
        app, _, task = fixture()
        signal_id = "afr-stale-signal"
        app.stores.evidence.append(Evidence(
            evidence_id=signal_id, run_id=task.run_id, surface_id="afr-surface",
            created_by="arbitrary_file_read_analyzer", evidence_type="observation",
            observation={
                "type": FILE_READ_OBSERVATION, "parameter": "asset",
                "target_key": TARGET.key, "target_fingerprint": "0" * 64,
            },
        ))
        validation_task = TaskEnvelope(
            task_id="afr-validation", run_id=task.run_id, agent_type="validation",
            surface_id="afr-surface", candidate_id="afr-candidate",
            validation_id="validation-1", allowed_tools=(FILE_READ_TOOL,),
            evidence_ids=(signal_id,), request_budget=10,
        )
        result = ValidationAgent(
            candidate_store=app.stores.candidates,
            evidence_store=app.stores.evidence,
            surface_store=app.stores.surfaces,
            file_read_targets=(TARGET,),
        ).handle(validation_task).validation
        self.assertEqual(result.verdict, ValidationVerdict.BLOCKED)
        self.assertEqual(
            result.reason_code,
            ValidationReasonCode.FILE_READ_CONFIGURATION_MISMATCH,
        )

    def test_validation_reports_insufficient_budget_as_inconclusive(self):
        app, _, task = fixture()
        signal_id = "afr-budget-signal"
        app.stores.evidence.append(Evidence(
            evidence_id=signal_id, run_id=task.run_id, surface_id="afr-surface",
            created_by="arbitrary_file_read_analyzer", evidence_type="observation",
            observation={
                "type": FILE_READ_OBSERVATION, "parameter": "asset",
                "target_key": TARGET.key,
                "target_fingerprint": TARGET.configuration_fingerprint,
            },
        ))
        validation_task = TaskEnvelope(
            task_id="afr-validation", run_id=task.run_id, agent_type="validation",
            surface_id="afr-surface", candidate_id="afr-candidate",
            validation_id="validation-1", allowed_tools=(FILE_READ_TOOL,),
            evidence_ids=(signal_id,), request_budget=2,
        )
        result = ValidationAgent(
            candidate_store=app.stores.candidates,
            evidence_store=app.stores.evidence,
            surface_store=app.stores.surfaces,
            file_read_targets=(TARGET,),
        ).handle(validation_task).validation
        self.assertEqual(result.verdict, ValidationVerdict.SUSPECTED)
        self.assertEqual(
            result.reason_code,
            ValidationReasonCode.FILE_READ_BUDGET_EXHAUSTED,
        )

    def test_unapproved_path_is_rejected_before_runtime(self):
        app, _, task = fixture()
        from hacklipse.domain import EvidenceRequest, HttpRequestSpec
        request = EvidenceRequest(
            evidence_type="http_response", surface_id="afr-surface",
            reason="unapproved path", suggested_tool=FILE_READ_TOOL,
            http_request=HttpRequestSpec(
                query_parameters=(("asset", "/etc/passwd"),),
                request_kind=HttpRequestKind.ARBITRARY_FILE_READ_PROBE,
            ),
        )
        with self.assertRaises(PolicyViolation):
            app.collector.collect(task.run_id, URL, request, task_id=task.task_id)

    def test_path_mutation_requires_the_dedicated_tool(self):
        app, _, task = fixture()
        from hacklipse.domain import EvidenceRequest, HttpRequestSpec
        request = EvidenceRequest(
            evidence_type="http_response", surface_id="afr-surface",
            reason="path mutation through generic HTTP", suggested_tool="http_get",
            http_request=HttpRequestSpec(
                file_read_path_index=1,
                file_read_path_value=TARGET.request_value,
                request_kind=HttpRequestKind.ARBITRARY_FILE_READ_PROBE,
            ),
        )
        with self.assertRaises(PolicyViolation):
            app.collector.collect(task.run_id, URL, request, task_id=task.task_id)

    def test_standard_router_creates_file_read_category_without_path_traversal(self):
        app, _, _ = fixture()
        router = standard_router()
        self.assertTrue(any(
            item.candidate.vulnerability_type == "Arbitrary File Read"
            for item in router.route(
                app.stores.runs.get("afr-run"),
                app.stores.surfaces.list_by_run("afr-run"), (),
            )
        ))


if __name__ == "__main__":
    unittest.main()
