"""Answer-blind iterative Recon contract and execution tests."""

from __future__ import annotations

import json
import unittest

from hacklipse.adapters.llm_iterative_recon import LlmIterativeReconPlanner
from hacklipse.adapters.memory import InMemoryEvidenceStore, InMemorySurfaceStore
from hacklipse.adapters.recon import ReconAgent
from hacklipse.domain import Evidence, TaskEnvelope
from hacklipse.ports import ReconAction, ReconObservation
from hacklipse.ports.errors import LlmTimeout
from hacklipse.ports.llm import LlmRequest, LlmResponse


_TASK = TaskEnvelope(
    task_id="task-agentic-recon",
    run_id="run-agentic-recon",
    agent_type="recon",
    target_url="http://localhost/",
    allowed_tools=("http_get",),
    request_budget=10,
    timeout_seconds=30,
)

_OBSERVATIONS = (
    ReconObservation(
        observation_id="observation-a",
        surface_id="surface-a",
        path="/a",
        method="GET",
        parameter_names=("parameter_1",),
        discovery_types=("html_link",),
        state="discovered",
    ),
    ReconObservation(
        observation_id="observation-root",
        surface_id="surface-root",
        path="/",
        method="GET",
        parameter_names=(),
        discovery_types=("seed",),
        state="fetched",
        status_code=200,
        content_type="text/html",
    ),
)


class _FakeLlm:
    def __init__(self, payload=None, error=None) -> None:
        self.payload = payload
        self.error = error
        self.requests: list[LlmRequest] = []

    def complete(self, request: LlmRequest) -> LlmResponse:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return LlmResponse(payload=self.payload, model="fake")


class AgenticPlannerContractTests(unittest.TestCase):
    def test_prompt_contains_only_the_answer_blind_observation_contract(self) -> None:
        llm = _FakeLlm(
            {
                "action": "visit_surface",
                "surface_id": "surface-a",
                "basis_observation_ids": ["observation-a"],
                "reason_code": "inspect_input_surface",
            }
        )
        planner = LlmIterativeReconPlanner(llm_client=llm)

        action = planner.decide(
            task=_TASK,
            observations=_OBSERVATIONS,
            selectable_surface_ids=("surface-a",),
            remaining_budget=3,
            round_index=0,
        )

        self.assertEqual(action.surface_id, "surface-a")
        prompt = json.loads(llm.requests[0].messages[0].content)
        self.assertEqual(prompt["selectable_surface_ids"], ["surface-a"])
        self.assertEqual(prompt["observations"][0]["parameter_names"], ["parameter_1"])
        serialized = json.dumps(prompt).casefold()
        for forbidden in (
            "response_body",
            "headers",
            "cookies",
            "credential",
            "payload",
            "ground_truth",
            "expected_finding",
            "vulnerability_type",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_unknown_surface_falls_back_to_the_first_offered_surface(self) -> None:
        planner = LlmIterativeReconPlanner(
            llm_client=_FakeLlm(
                {
                    "action": "visit_surface",
                    "surface_id": "surface-outside-run",
                    "basis_observation_ids": ["observation-a"],
                    "reason_code": "inspect_document",
                }
            )
        )

        action = planner.decide(
            task=_TASK,
            observations=_OBSERVATIONS,
            selectable_surface_ids=("surface-a",),
            remaining_budget=3,
            round_index=0,
        )

        self.assertEqual(action.surface_id, "surface-a")
        self.assertEqual(action.source, "deterministic_fallback")
        self.assertEqual(action.status, "fallback:invalid_response")
        self.assertEqual(action.rejected_surface_ids, ("surface-outside-run",))

    def test_timeout_falls_back_without_exposing_the_exception(self) -> None:
        planner = LlmIterativeReconPlanner(
            llm_client=_FakeLlm(error=LlmTimeout("secret provider text"))
        )

        action = planner.decide(
            task=_TASK,
            observations=_OBSERVATIONS,
            selectable_surface_ids=("surface-a",),
            remaining_budget=3,
            round_index=0,
        )

        self.assertEqual(action.surface_id, "surface-a")
        self.assertEqual(action.status, "fallback:timeout")
        self.assertNotIn("secret", action.status)


class _Collector:
    def __init__(self, evidence_store, bodies: dict[str, str]) -> None:
        self._evidence = evidence_store
        self._bodies = bodies
        self.calls: list[str] = []
        self._next_id = 0

    def collect(
        self,
        run_id,
        target_url,
        spec,
        *,
        task_id,
        timeout_seconds=120.0,
        credential_ref=None,
    ):
        del task_id, timeout_seconds, credential_ref
        self.calls.append(target_url)
        self._next_id += 1
        evidence_id = f"http-{self._next_id}"
        self._evidence.append(
            Evidence(
                evidence_id=evidence_id,
                run_id=run_id,
                surface_id=spec.surface_id,
                created_by="execution_runtime:http_get",
                evidence_type="http_response",
                observation={
                    "type": "http_response",
                    "status": 200,
                    "content_type": "text/html; charset=utf-8",
                    "headers": (("set-cookie", "must-not-reach-the-planner"),),
                    "body": self._bodies[target_url],
                },
            )
        )
        return evidence_id


class _PathPlanner:
    def __init__(self) -> None:
        self.calls: list[tuple[ReconObservation, ...]] = []

    def decide(
        self,
        *,
        task,
        observations,
        selectable_surface_ids,
        remaining_budget,
        round_index,
    ):
        del task, remaining_budget, round_index
        self.calls.append(observations)
        by_path = {
            item.path: item.surface_id
            for item in observations
            if item.surface_id in selectable_surface_ids
        }
        for path in ("/b", "/new"):
            if path in by_path:
                surface_id = by_path[path]
                return ReconAction(
                    action="visit_surface",
                    surface_id=surface_id,
                    basis_observation_ids=(f"recon-observation:{surface_id}",),
                    reason_code="expand_coverage",
                    source="llm",
                    status="llm_success",
                )
        return ReconAction(
            action="stop",
            surface_id=None,
            basis_observation_ids=(),
            reason_code="insufficient_signal",
            source="llm",
            status="llm_success",
        )


class _ForeignSurfacePlanner:
    def decide(self, **kwargs):
        del kwargs
        return ReconAction(
            action="visit_surface",
            surface_id="surface-outside-current-run",
            basis_observation_ids=(),
            reason_code="inspect_document",
            source="llm",
            status="llm_success",
        )


class AgenticReconIntegrationTests(unittest.TestCase):
    def test_recon_agent_independently_blocks_a_foreign_surface_id(self) -> None:
        bodies = {
            "http://localhost/": '<a href="/a">a</a>',
            "http://localhost/a": "<p>a</p>",
        }
        evidence_store = InMemoryEvidenceStore()
        surface_store = InMemorySurfaceStore()
        collector = _Collector(evidence_store, bodies)
        ids = iter(range(1000))
        agent = ReconAgent(
            collector=collector,
            evidence_store=evidence_store,
            surface_store=surface_store,
            iterative_planner=_ForeignSurfacePlanner(),
            max_pages=2,
            id_factory=lambda: str(next(ids)),
        )
        task = TaskEnvelope(
            task_id="task-agentic-policy",
            run_id="run-agentic-policy",
            agent_type="recon",
            target_url="http://localhost/",
            allowed_tools=("http_get",),
            request_budget=10,
        )

        result = agent.handle(task)

        self.assertEqual(collector.calls, ["http://localhost/", "http://localhost/a"])
        self.assertEqual(result.message, "agentic_recon:fallback:invalid_response")
        trace = next(
            item.observation
            for item in evidence_store.list_by_run(task.run_id)
            if item.observation.get("type") == "recon_action"
        )
        self.assertNotEqual(trace["executed_surface_id"], "surface-outside-current-run")
        self.assertEqual(
            trace["rejected_surface_ids"], ["surface-outside-current-run"]
        )

    def test_new_observation_can_change_the_next_round_and_is_traced(self) -> None:
        bodies = {
            "http://localhost/": (
                '<a href="/a">a</a><a href="/b">b</a>'
                '<form action="/submit" method="post"><input name="query"></form>'
            ),
            "http://localhost/a": "<p>a</p>",
            "http://localhost/b": (
                '<a href="/new">new</a><p>TOP_SECRET_RESPONSE_BODY</p>'
            ),
            "http://localhost/new": "<p>new</p>",
        }
        evidence_store = InMemoryEvidenceStore()
        surface_store = InMemorySurfaceStore()
        collector = _Collector(evidence_store, bodies)
        planner = _PathPlanner()
        ids = iter(range(1000))
        agent = ReconAgent(
            collector=collector,
            evidence_store=evidence_store,
            surface_store=surface_store,
            iterative_planner=planner,
            max_pages=5,
            id_factory=lambda: str(next(ids)),
        )
        task = TaskEnvelope(
            task_id="task-agentic-loop",
            run_id="run-agentic-loop",
            agent_type="recon",
            target_url="http://localhost/",
            allowed_tools=("http_get",),
            request_budget=10,
        )

        result = agent.handle(task)

        self.assertEqual(
            collector.calls,
            ["http://localhost/", "http://localhost/b", "http://localhost/new"],
        )
        self.assertEqual(len(planner.calls), 3)
        self.assertIn("/new", {item.path for item in planner.calls[1]})
        traces = [
            item.observation
            for item in evidence_store.list_by_run(task.run_id)
            if item.observation.get("type") == "recon_action"
        ]
        self.assertEqual([item["round_index"] for item in traces], [0, 1, 2])
        self.assertEqual(traces[-1]["action"], "stop")
        self.assertEqual(result.message, "agentic_recon:llm_success")
        serialized = json.dumps(traces)
        self.assertNotIn("TOP_SECRET_RESPONSE_BODY", serialized)
        self.assertNotIn("must-not-reach-the-planner", serialized)
        self.assertNotIn("headers", serialized)
        self.assertTrue(all(len(item["observation_fingerprint"]) == 64 for item in traces))

        # Replaying the same run restores each decision from its exact observation
        # fingerprint. Surfaces found in a later old round must not leak into round zero.
        agent.handle(task)
        self.assertEqual(len(planner.calls), 3)
        self.assertEqual(
            collector.calls[-3:],
            ["http://localhost/", "http://localhost/b", "http://localhost/new"],
        )
        replayed_traces = [
            item
            for item in evidence_store.list_by_run(task.run_id)
            if item.observation.get("type") == "recon_action"
        ]
        self.assertEqual(len(replayed_traces), 3)


if __name__ == "__main__":
    unittest.main()
