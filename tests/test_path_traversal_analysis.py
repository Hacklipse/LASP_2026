"""고정 os-release Path Traversal baseline과 독립 proof를 검증한다."""

from __future__ import annotations

import unittest
from dataclasses import replace

from hacklipse.adapters import HeuristicPathTraversalAnalyzer
from hacklipse.adapters.path_traversal_analysis import (
    HEURISTIC_PATH_TRAVERSAL_ANALYZER,
    PATH_TRAVERSAL_PROBE_PATH,
    PATH_TRAVERSAL_PROOF_MARKERS,
    PATH_TRAVERSAL_TOOL,
)
from hacklipse.adapters.policy import AllowlistPolicyGate
from hacklipse.bootstrap import (
    build_local_application,
    register_standard_agents,
    standard_router,
)
from hacklipse.domain import (
    AgentResultStatus,
    Candidate,
    DomainInvariantError,
    Evidence,
    ExecutionRequest,
    ExecutionResult,
    HttpRequestKind,
    HttpRequestSpec,
    Run,
    RunPhase,
    RunRequest,
    RunScope,
    Surface,
    TaskEnvelope,
    ValidationProofType,
)
from hacklipse.ports.errors import PolicyViolation

_RUN_ID = "run-path"
_SURFACE_ID = "surface-fi"
_CANDIDATE_ID = "candidate-path"
_TARGET = "http://local.test/vulnerabilities/fi/?page=include.php"


class _SafeFileRuntime:
    def __init__(self, *, vulnerable: bool = True, marker_in_control: bool = False) -> None:
        self.vulnerable = vulnerable
        self.marker_in_control = marker_in_control
        self.requests: list[ExecutionRequest] = []

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        values = dict(request.query_parameters).values()
        traversed = PATH_TRAVERSAL_PROBE_PATH in values
        body = "normal include response"
        if self.marker_in_control or (self.vulnerable and traversed):
            body = "\n".join(PATH_TRAVERSAL_PROOF_MARKERS)
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response",
                "status": 200,
                "body": body,
                "requested_url": request.resolved_url,
            },
        )


def _fixture(*, vulnerable: bool = True, marker_in_control: bool = False):
    runtime = _SafeFileRuntime(
        vulnerable=vulnerable, marker_in_control=marker_in_control
    )
    app = build_local_application({}, runtime=runtime)
    app.stores.runs.add(
        Run(
            run_id=_RUN_ID,
            target_url=_TARGET,
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            policy_profile="safe",
            request_budget=20,
        )
    )
    app.stores.surfaces.add(
        Surface(
            surface_id=_SURFACE_ID,
            run_id=_RUN_ID,
            url=_TARGET,
            method="GET",
            parameters=("page",),
        )
    )
    app.stores.evidence.append(
        Evidence(
            evidence_id="evi-file-param",
            run_id=_RUN_ID,
            surface_id=_SURFACE_ID,
            created_by="recon",
            evidence_type="observation",
            observation={"type": "url_or_file_parameter", "parameter": "page"},
        )
    )
    app.stores.candidates.add(
        Candidate(
            candidate_id=_CANDIDATE_ID,
            run_id=_RUN_ID,
            surface_id=_SURFACE_ID,
            vulnerability_type="Path Traversal",
            hypothesis="file parameter",
            assigned_agent="path_traversal_analyzer",
            evidence_ids=("evi-file-param",),
        )
    )
    app.budget_manager.open_run(_RUN_ID, 20)
    agent = HeuristicPathTraversalAnalyzer(
        candidate_store=app.stores.candidates,
        surface_store=app.stores.surfaces,
        evidence_store=app.stores.evidence,
        id_factory=iter(str(index) for index in range(100)).__next__,
    )
    task = TaskEnvelope(
        task_id="task-path",
        run_id=_RUN_ID,
        agent_type="path_traversal_analyzer",
        target_url=_TARGET,
        surface_id=_SURFACE_ID,
        candidate_id=_CANDIDATE_ID,
        evidence_ids=("evi-file-param",),
        allowed_tools=(PATH_TRAVERSAL_TOOL,),
        request_budget=10,
    )
    return agent, app, runtime, task


def _collect(result, app, task: TaskEnvelope) -> TaskEnvelope:
    ids = list(task.evidence_ids) + list(result.new_evidence_ids)
    for request in result.evidence_requests:
        ids.append(
            app.collector.collect(
                task.run_id, task.target_url or "", request, task_id=task.task_id
            )
        )
    return replace(
        task,
        evidence_ids=tuple(ids),
        request_budget=app.budget_manager.remaining(task.run_id),
    )


class PathTraversalSafetyContractTests(unittest.TestCase):
    def test_domain_allows_only_fixed_safe_file_traversal(self) -> None:
        spec = HttpRequestSpec(
            query_parameters=(("page", PATH_TRAVERSAL_PROBE_PATH),),
            request_kind=HttpRequestKind.PATH_TRAVERSAL_PROBE,
        )
        self.assertEqual(spec.query_parameters[0][1], PATH_TRAVERSAL_PROBE_PATH)

        for value in (
            "../../../etc/passwd",
            "../../../../etc/os-release",
            "../../../../../../etc/os-release",
            "/etc/os-release",
        ):
            with self.subTest(value=value), self.assertRaises(DomainInvariantError):
                HttpRequestSpec(
                    query_parameters=(("page", value),),
                    request_kind=HttpRequestKind.PATH_TRAVERSAL_PROBE,
                )

    def test_policy_rejects_non_fixed_control_on_dedicated_tool(self) -> None:
        run = Run(
            run_id="run-policy",
            target_url=_TARGET,
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            policy_profile="safe",
            request_budget=5,
        )
        request = ExecutionRequest(
            execution_id="exec-policy",
            run_id=run.run_id,
            task_id="task-policy",
            tool=PATH_TRAVERSAL_TOOL,
            target_url=_TARGET,
            surface_id=_SURFACE_ID,
            purpose="invalid control",
            query_parameters=(("page", "unexpected-value"),),
            request_kind=HttpRequestKind.CONTROL,
        )

        with self.assertRaises(PolicyViolation):
            AllowlistPolicyGate().validate_execution(run, request)


class HeuristicPathTraversalAnalyzerTests(unittest.TestCase):
    def test_uses_central_fixed_safe_file_control_and_probe(self) -> None:
        agent, app, runtime, task = _fixture()

        requested = agent.handle(task)
        self.assertIs(requested.status, AgentResultStatus.NEEDS_EVIDENCE)
        _collect(requested, app, task)

        self.assertEqual(len(runtime.requests), 2)
        self.assertEqual(
            [request.request_kind for request in runtime.requests],
            [HttpRequestKind.CONTROL, HttpRequestKind.PATH_TRAVERSAL_PROBE],
        )
        self.assertEqual(
            dict(runtime.requests[1].query_parameters)["page"],
            PATH_TRAVERSAL_PROBE_PATH,
        )
        self.assertTrue(
            all(request.tool == PATH_TRAVERSAL_TOOL for request in runtime.requests)
        )

    def test_probe_only_safe_file_read_emits_observation(self) -> None:
        agent, app, _, task = _fixture()

        requested = agent.handle(task)
        result = agent.handle(_collect(requested, app, task))

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        signal = next(
            item
            for item in app.stores.evidence.list_by_run(_RUN_ID)
            if item.observation.get("type") == "path_traversal_file_read"
        )
        self.assertEqual(signal.created_by, HEURISTIC_PATH_TRAVERSAL_ANALYZER)
        self.assertEqual(signal.observation["parameter"], "page")
        self.assertIn("control_evidence_id", signal.observation)
        self.assertIn("probe_evidence_id", signal.observation)

    def test_safe_response_or_marker_in_control_produces_no_signal(self) -> None:
        for options in ({"vulnerable": False}, {"marker_in_control": True}):
            with self.subTest(options=options):
                agent, app, _, task = _fixture(**options)
                requested = agent.handle(task)
                agent.handle(_collect(requested, app, task))
                signals = [
                    item
                    for item in app.stores.evidence.list_by_run(_RUN_ID)
                    if item.observation.get("type") == "path_traversal_file_read"
                ]
                self.assertEqual(signals, [])


class PathTraversalFindingEndToEndTests(unittest.TestCase):
    def test_independent_safe_file_reproduction_promotes_finding(self) -> None:
        runtime = _SafeFileRuntime()
        app = build_local_application(
            {},
            runtime=runtime,
            router=standard_router(vulnerability_types=("Path Traversal",)),
        )
        register_standard_agents(app, recon_max_pages=1)

        run = app.orchestrator.start(
            RunRequest(
                target_url=_TARGET,
                scope=RunScope(allowed_hosts=frozenset({"local.test"})),
                request_budget=20,
            )
        )

        self.assertIs(run.phase, RunPhase.DONE)
        findings = app.stores.findings.list_by_run(run.run_id)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vulnerability_type, "Path Traversal")
        validation = app.stores.candidates.get(
            run.run_id, findings[0].candidate_id
        )
        self.assertEqual(validation.status, "confirmed")
        proof_evidence = app.stores.evidence.get_many(
            run.run_id, findings[0].evidence_ids
        )
        self.assertEqual(len(proof_evidence), 2)
        self.assertTrue(
            all(item.validation_id == findings[0].validation_id for item in proof_evidence)
        )
        self.assertEqual(
            {
                record.envelope.agent_type
                for record in app.stores.tasks.list_by_run(run.run_id)
            },
            {
                "recon",
                "path_traversal_analyzer",
                "evidence_collector",
                "validation",
                "report",
            },
        )

        # Finding 생성 자체가 proof type을 강제하므로 직접 증적 수도 함께 확인한다.
        self.assertEqual(
            ValidationProofType.PATH_TRAVERSAL_FILE_READ.value,
            "path_traversal_file_read",
        )


if __name__ == "__main__":
    unittest.main()
