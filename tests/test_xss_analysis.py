"""결정적 XSS baseline Analyzer의 control/probe와 워크플로 배선을 검증한다."""

from __future__ import annotations

import unittest
from dataclasses import replace

from hacklipse.adapters import (
    HeuristicXssAnalyzer,
    RuleBasedVulnerabilityRouter,
    SurfaceRoutingRule,
)
from hacklipse.application.errors import AgentContractError
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Candidate,
    ExecutionRequest,
    ExecutionResult,
    HttpRequestKind,
    Run,
    RunPhase,
    RunRequest,
    RunScope,
    Surface,
    TaskEnvelope,
    ValidationResult,
    ValidationVerdict,
)

_RUN_ID = "run-1"
_SURFACE_ID = "surface-search"
_CANDIDATE_ID = "candidate-xss"


class _ReflectionRuntime:
    """probe query 값을 응답에 반사하거나 제거하는 결정적 Runtime 대역."""

    def __init__(self, *, reflect: bool) -> None:
        self.reflect = reflect
        self.requests: list[ExecutionRequest] = []

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        values = " ".join(value for _, value in request.query_parameters)
        body = values if self.reflect else "static response"
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


def _task(*, parameters: tuple[str, ...], request_budget: int = 10) -> tuple:
    runtime = _ReflectionRuntime(reflect=True)
    app = build_local_application({}, runtime=runtime)
    run = Run(
        run_id=_RUN_ID,
        target_url="http://local.test/",
        scope=RunScope(allowed_hosts=frozenset({"local.test"})),
        policy_profile="safe",
        request_budget=10,
    )
    surface = Surface(
        surface_id=_SURFACE_ID,
        run_id=_RUN_ID,
        url="http://local.test/search",
        method="GET",
        parameters=parameters,
    )
    candidate = Candidate(
        candidate_id=_CANDIDATE_ID,
        run_id=_RUN_ID,
        surface_id=_SURFACE_ID,
        vulnerability_type="XSS",
        hypothesis="parameterized GET surface",
        assigned_agent="xss_analyzer",
        evidence_ids=(),
    )
    app.stores.runs.add(run)
    app.stores.surfaces.add(surface)
    app.stores.candidates.add(candidate)
    app.budget_manager.open_run(run.run_id, run.request_budget)
    agent = HeuristicXssAnalyzer(
        candidate_store=app.stores.candidates,
        surface_store=app.stores.surfaces,
        evidence_store=app.stores.evidence,
        id_factory=iter((str(index) for index in range(100))).__next__,
    )
    envelope = TaskEnvelope(
        task_id="task-xss",
        run_id=_RUN_ID,
        agent_type="xss_analyzer",
        target_url=surface.url,
        surface_id=surface.surface_id,
        candidate_id=candidate.candidate_id,
        allowed_tools=("http_get",),
        request_budget=request_budget,
    )
    return agent, app, runtime, envelope


def _collect_requested(agent_result, app, task: TaskEnvelope) -> TaskEnvelope:
    evidence_ids = []
    for request in agent_result.evidence_requests:
        evidence_ids.append(
            app.collector.collect(
                task.run_id,
                task.target_url or "",
                request,
                task_id=task.task_id,
            )
        )
    return replace(
        task,
        evidence_ids=tuple(evidence_ids),
        request_budget=app.budget_manager.remaining(task.run_id),
    )


class HeuristicXssAnalyzerTests(unittest.TestCase):
    def test_reflected_marker_creates_observation(self) -> None:
        agent, app, runtime, task = _task(parameters=("name",))

        requested = agent.handle(task)
        self.assertIs(requested.status, AgentResultStatus.NEEDS_EVIDENCE)
        self.assertEqual(runtime.requests, [])

        result = agent.handle(_collect_requested(requested, app, task))

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        self.assertEqual(
            [request.request_kind for request in runtime.requests],
            [HttpRequestKind.CONTROL, HttpRequestKind.PROBE],
        )
        self.assertEqual(
            runtime.requests[1].query_parameters,
            (("name", "hacklipse7331"),),
        )
        observations = [
            item
            for item in app.stores.evidence.list_by_run(_RUN_ID)
            if item.created_by == "heuristic_xss_analyzer"
        ]
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].observation["type"], "reflection")
        self.assertEqual(observations[0].observation["parameter"], "name")
        self.assertEqual(app.budget_manager.remaining(_RUN_ID), 8)

    def test_non_reflected_marker_keeps_only_http_evidence(self) -> None:
        agent, app, runtime, task = _task(parameters=("name",))
        runtime.reflect = False

        requested = agent.handle(task)
        result = agent.handle(_collect_requested(requested, app, task))

        self.assertEqual(result.new_evidence_ids, ())
        self.assertFalse(
            any(
                item.created_by == "heuristic_xss_analyzer"
                for item in app.stores.evidence.list_by_run(_RUN_ID)
            )
        )

    def test_each_parameter_gets_one_probe_after_shared_control(self) -> None:
        agent, app, runtime, task = _task(parameters=("first", "second"))

        requested = agent.handle(task)
        result = agent.handle(_collect_requested(requested, app, task))

        self.assertEqual(len(runtime.requests), 3)
        self.assertEqual(len(result.new_evidence_ids), 2)
        probes = runtime.requests[1:]
        self.assertEqual(
            probes[0].query_parameters,
            (("first", "hacklipse7331"), ("second", "hacklipse-control")),
        )
        self.assertEqual(
            probes[1].query_parameters,
            (("first", "hacklipse-control"), ("second", "hacklipse7331")),
        )
        observations = [
            item.observation["parameter"]
            for item in app.stores.evidence.list_by_run(_RUN_ID)
            if item.created_by == "heuristic_xss_analyzer"
        ]
        self.assertEqual(observations, ["first", "second"])

    def test_rejects_missing_tool_and_insufficient_task_budget_before_requests(self) -> None:
        agent, _, runtime, task = _task(parameters=("name",), request_budget=1)
        with self.assertRaises(AgentContractError):
            agent.handle(task)
        self.assertEqual(runtime.requests, [])

        task = TaskEnvelope(
            task_id=task.task_id,
            run_id=task.run_id,
            agent_type=task.agent_type,
            target_url=task.target_url,
            surface_id=task.surface_id,
            candidate_id=task.candidate_id,
            allowed_tools=(),
            request_budget=10,
        )
        with self.assertRaises(AgentContractError):
            agent.handle(task)
        self.assertEqual(runtime.requests, [])


class _SurfaceOnlyRecon:
    def __init__(self, surface_store) -> None:
        self._surfaces = surface_store

    def handle(self, task: TaskEnvelope) -> AgentResult:
        surface = Surface(
            surface_id=_SURFACE_ID,
            run_id=task.run_id,
            url="http://local.test/search",
            method="GET",
            parameters=("name",),
        )
        self._surfaces.add(surface)
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            surface_ids=(surface.surface_id,),
        )


class _RejectingValidator:
    def handle(self, task: TaskEnvelope) -> AgentResult:
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            validation=ValidationResult(
                validation_id=task.validation_id or "",
                run_id=task.run_id,
                candidate_id=task.candidate_id or "",
                verdict=ValidationVerdict.REJECTED,
                evidence_ids=(),
                reason="fixture stops before independent validation",
            ),
        )


class HeuristicXssWorkflowTests(unittest.TestCase):
    def test_surface_candidate_runs_through_baseline_analyzer(self) -> None:
        runtime = _ReflectionRuntime(reflect=True)
        router = RuleBasedVulnerabilityRouter(
            rules=(),
            surface_rules=(SurfaceRoutingRule("XSS", "xss_analyzer", priority=0.3),),
        )
        app = build_local_application({}, runtime=runtime, router=router)
        app.dispatcher.register("recon", _SurfaceOnlyRecon(app.stores.surfaces))
        app.dispatcher.register(
            "xss_analyzer",
            HeuristicXssAnalyzer(
                candidate_store=app.stores.candidates,
                surface_store=app.stores.surfaces,
                evidence_store=app.stores.evidence,
            ),
        )
        app.dispatcher.register("validation", _RejectingValidator())

        run = app.orchestrator.start(
            RunRequest(
                target_url="http://local.test/",
                scope=RunScope(allowed_hosts=frozenset({"local.test"})),
                request_budget=10,
            )
        )

        self.assertIs(run.phase, RunPhase.DONE)
        candidate = app.stores.candidates.list_by_run(run.run_id)[0]
        self.assertEqual(candidate.status, "rejected")
        self.assertTrue(
            any(
                item.observation.get("type") == "reflection"
                for item in app.stores.evidence.list_by_run(run.run_id)
            )
        )
        self.assertEqual(
            [item.envelope.agent_type for item in app.stores.tasks.list_by_run(run.run_id)],
            [
                "recon",
                "xss_analyzer",
                "evidence_collector",
                "evidence_collector",
                "xss_analyzer",
                "validation",
                "report",
            ],
        )


if __name__ == "__main__":
    unittest.main()
