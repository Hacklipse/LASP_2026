"""Router가 Surface와 Evidence를 함께 사용해 Analysis 대상을 만드는지 검증."""

from __future__ import annotations

import unittest

from hacklipse.adapters import RuleBasedVulnerabilityRouter
from hacklipse.application.errors import WorkflowExecutionError
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Evidence,
    Run,
    RunRequest,
    RunScope,
    Surface,
    TaskEnvelope,
)


def _run() -> Run:
    return Run(
        run_id="run-1",
        target_url="http://localhost/",
        scope=RunScope(allowed_hosts=frozenset({"localhost"})),
        policy_profile="safe",
        request_budget=10,
    )


def _surface(*, method: str = "GET", parameters: tuple[str, ...] = ("q",)) -> Surface:
    return Surface(
        surface_id="surface-search",
        run_id="run-1",
        url="http://localhost/search",
        method=method,
        parameters=parameters,
    )


class SurfaceRoutingTests(unittest.TestCase):
    def test_parameterized_get_surface_reaches_analysis_without_observation(self) -> None:
        router = RuleBasedVulnerabilityRouter(id_factory=iter(("1", "2", "3")).__next__)

        decisions = router.route(_run(), (_surface(),), ())

        self.assertEqual(
            [decision.candidate.vulnerability_type for decision in decisions],
            ["XSS", "SQLi", "SSTI"],
        )
        self.assertEqual(
            [decision.candidate.assigned_agent for decision in decisions],
            ["xss_analyzer", "sqli_analyzer", "ssti_analyzer"],
        )
        self.assertTrue(all(not decision.candidate.evidence_ids for decision in decisions))

    def test_evidence_rule_wins_over_surface_rule_for_same_candidate(self) -> None:
        router = RuleBasedVulnerabilityRouter(id_factory=iter(("1", "2", "3")).__next__)
        evidence = Evidence(
            evidence_id="evi-reflection",
            run_id="run-1",
            surface_id="surface-search",
            created_by="fixture",
            evidence_type="observation",
            observation={"type": "reflection", "parameter": "q"},
        )

        decisions = router.route(_run(), (_surface(),), (evidence,))

        xss = next(
            decision for decision in decisions if decision.candidate.vulnerability_type == "XSS"
        )
        self.assertEqual(xss.candidate.evidence_ids, ("evi-reflection",))
        self.assertEqual(xss.priority, 0.8)
        self.assertEqual(
            [decision.candidate.vulnerability_type for decision in decisions],
            ["XSS", "SQLi", "SSTI"],
        )

    def test_surface_rule_requires_parameterized_get(self) -> None:
        router = RuleBasedVulnerabilityRouter()

        post = router.route(_run(), (_surface(method="POST"),), ())
        no_parameters = router.route(_run(), (_surface(parameters=()),), ())

        self.assertEqual(post, ())
        self.assertEqual(no_parameters, ())


class _SurfaceOnlyReconAgent:
    """Observation 없이 입력 가능한 Surface 하나만 반환하는 Recon 대역."""

    def __init__(self, surface_store) -> None:
        self._surfaces = surface_store

    def handle(self, task: TaskEnvelope) -> AgentResult:
        surface = Surface(
            surface_id="surface-search",
            run_id=task.run_id,
            url="http://localhost/search",
            method="GET",
            parameters=("q",),
        )
        self._surfaces.add(surface)
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            surface_ids=(surface.surface_id,),
        )


class SurfaceRoutingWorkflowTests(unittest.TestCase):
    def test_surface_without_observation_reaches_analyze_phase(self) -> None:
        app = build_local_application({})
        app.dispatcher.register(
            "recon",
            _SurfaceOnlyReconAgent(app.stores.surfaces),
            allowed_tools=("http_get",),
        )

        with self.assertRaises(WorkflowExecutionError) as context:
            app.orchestrator.start(
                RunRequest(
                    target_url="http://localhost/",
                    scope=RunScope(allowed_hosts=frozenset({"localhost"})),
                )
            )

        self.assertEqual(context.exception.phase, "analyze")
        run = app.stores.runs.get(context.exception.run_id)
        candidates = app.stores.candidates.list_by_run(run.run_id)
        self.assertEqual(
            [candidate.vulnerability_type for candidate in candidates],
            ["XSS", "SQLi", "SSTI"],
        )
        tasks = app.stores.tasks.list_by_run(run.run_id)
        analysis_task = tasks[-1].envelope
        self.assertEqual(analysis_task.agent_type, "xss_analyzer")
        self.assertEqual(analysis_task.surface_id, "surface-search")
        self.assertEqual(analysis_task.target_url, "http://localhost/search")
        self.assertEqual(analysis_task.allowed_tools, ("http_get",))


if __name__ == "__main__":
    unittest.main()
