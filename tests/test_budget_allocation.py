"""Budget reservation is enforced at the collector and survives Run restart."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from hacklipse.adapters import SQLiteBudgetManager, SQLiteStoreBundle
from hacklipse.adapters.llm_budget_allocation_advisor import LlmBudgetAllocationAdvisor
from hacklipse.application import OrchestratorConfig
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Candidate,
    CandidateStatus,
    EvidenceRequest,
    ExecutionResult,
    HttpRequestSpec,
    ProgressEventKind,
    Run,
    RunPhase,
    RunScope,
    Surface,
    ValidationResult,
    ValidationVerdict,
)
from hacklipse.ports import BudgetAllocationDecision
from hacklipse.ports.llm import LlmResponse
from hacklipse.ports.errors import LlmTimeout


class _Runtime:
    def __init__(self) -> None:
        self.calls = 0

    def execute(self, request):
        self.calls += 1
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={"type": "http_response", "status": 200, "body": "<html/>"},
        )


class _Agent:
    def __init__(self, app, *, stage: str, request_counts: dict[str, int], calls: list):
        self._app = app
        self._stage = stage
        self._counts = request_counts
        self._calls = calls

    def handle(self, task):
        self._calls.append((self._stage, task.candidate_id))
        surface = self._app.stores.surfaces.get(task.run_id, task.surface_id)
        for _ in range(self._counts.get(task.candidate_id, 0)):
            self._app.collector.collect(
                task.run_id,
                surface.url,
                EvidenceRequest(
                    evidence_type="http_response",
                    surface_id=surface.surface_id,
                    reason="budget test request",
                    suggested_tool="http_get",
                    http_request=HttpRequestSpec(method="GET"),
                ),
                task_id=task.task_id,
                validation_id=task.validation_id,
            )
        if self._stage == "analysis":
            return AgentResult(task_id=task.task_id, status=AgentResultStatus.COMPLETED)
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            validation=ValidationResult(
                validation_id=task.validation_id or "",
                run_id=task.run_id,
                candidate_id=task.candidate_id or "",
                verdict=ValidationVerdict.REJECTED,
                evidence_ids=(),
                reason="test rejected",
            ),
        )


def _app(*, stores=None, budget=None, advisor=None, analysis=None, validation=None):
    runtime = _Runtime()
    app = build_local_application(
        {},
        stores=stores,
        budget_manager=budget,
        runtime=runtime,
        config=OrchestratorConfig(budget_allocation_enabled=True),
        budget_allocation_advisor=advisor,
    )
    calls: list[tuple[str, str]] = []
    app.dispatcher.register(
        "test_analyzer",
        _Agent(app, stage="analysis", request_counts=analysis or {}, calls=calls),
        allowed_tools=("http_get",),
    )
    app.dispatcher.register(
        "validation",
        _Agent(app, stage="validation", request_counts=validation or {}, calls=calls),
        allowed_tools=("http_get",),
    )
    return app, runtime, calls


def _seed(app, *, budget: int = 7, planned_order=(), planned_weights=(), reserve=0,
          active_candidate=None, active_phase=None, active_floor=None):
    run = Run(
        run_id="run-budget",
        target_url="http://localhost/",
        scope=RunScope(allowed_hosts=frozenset({"localhost"})),
        policy_profile="safe",
        request_budget=budget,
        phase=RunPhase.ANALYZE,
        surface_ids=("surface-a", "surface-b"),
        candidate_ids=("candidate-a", "candidate-b"),
        budget_candidate_order=planned_order,
        budget_candidate_weights=planned_weights or ((1,) * len(planned_order)),
        budget_validation_reserve=reserve,
        budget_allocation_source="heuristic" if planned_order else "",
        budget_active_candidate_id=active_candidate,
        budget_active_phase=active_phase,
        budget_active_floor=active_floor,
    )
    app.stores.runs.add(run)
    app.budget_manager.open_run(run.run_id, budget)
    for name in ("a", "b"):
        app.stores.surfaces.add(
            Surface(
                surface_id=f"surface-{name}",
                run_id=run.run_id,
                url=f"http://localhost/{name}",
                method="GET",
            )
        )
        app.stores.candidates.add(
            Candidate(
                candidate_id=f"candidate-{name}",
                run_id=run.run_id,
                surface_id=f"surface-{name}",
                vulnerability_type="XSS",
                hypothesis="untrusted hypothesis text",
                assigned_agent="test_analyzer",
                evidence_ids=(),
            )
        )
    return run


class _Advisor:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = 0

    def decide(self, run, candidates, remaining_budget):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.result


class _Llm:
    def __init__(self, payload):
        self.payload = payload
        self.requests = []

    def complete(self, request):
        self.requests.append(request)
        return LlmResponse(payload=self.payload)


class BudgetAllocationTests(unittest.TestCase):
    def test_hybrid_allocation_loads_llm_independently_of_other_modes(self):
        from scripts.routing_options import needs_llm

        args = SimpleNamespace(
            profile="heuristic", recon="heuristic", router="heuristic",
            orchestrator="heuristic", compare_routers=False,
            budget_allocation="hybrid",
        )
        self.assertTrue(needs_llm(args))

    def test_collector_cannot_spend_units_reserved_for_other_validation(self):
        app, runtime, _ = _app(
            analysis={"candidate-a": 2, "candidate-b": 1},
            validation={"candidate-a": 4, "candidate-b": 1},
        )
        run = _seed(app)

        completed = app.orchestrator.resume(run.run_id)

        self.assertIs(completed.phase, RunPhase.DONE)
        self.assertEqual(completed.budget_candidate_order, run.candidate_ids)
        self.assertEqual(completed.budget_validation_reserve, 1)
        self.assertEqual(runtime.calls, 6)
        self.assertEqual(app.budget_manager.global_remaining(run.run_id), 1)
        first = app.stores.candidates.get(run.run_id, "candidate-a")
        second = app.stores.candidates.get(run.run_id, "candidate-b")
        self.assertIs(first.status, CandidateStatus.SKIPPED_BUDGET)
        self.assertIs(first.resume_status, CandidateStatus.ANALYZED)
        self.assertIs(second.status, CandidateStatus.REJECTED)

    def test_weighted_share_caps_first_analysis_and_leaves_second_a_turn(self):
        advisor = _Advisor(result=BudgetAllocationDecision(
            ("candidate-a", "candidate-b"), 1, "llm", (3, 1)
        ))
        app, runtime, _ = _app(
            advisor=advisor,
            analysis={"candidate-a": 7, "candidate-b": 1},
        )
        run = _seed(app, budget=10)

        completed = app.orchestrator.resume(run.run_id)

        self.assertEqual(completed.budget_candidate_weights, (3, 1))
        self.assertEqual(runtime.calls, 7)
        self.assertIs(
            app.stores.candidates.get(run.run_id, "candidate-a").status,
            CandidateStatus.SKIPPED_BUDGET,
        )
        self.assertIs(
            app.stores.candidates.get(run.run_id, "candidate-b").status,
            CandidateStatus.REJECTED,
        )

    def test_advisor_order_is_used_and_invalid_advice_falls_back(self):
        for result, expected in (
            (BudgetAllocationDecision(("candidate-b", "candidate-a"), 2, "llm"),
             ("candidate-b", "candidate-a")),
            (BudgetAllocationDecision(("foreign", "candidate-a"), 2, "llm"),
             ("candidate-a", "candidate-b")),
        ):
            with self.subTest(result=result):
                advisor = _Advisor(result=result)
                app, _, calls = _app(advisor=advisor)
                run = _seed(app, budget=8)
                completed = app.orchestrator.resume(run.run_id)
                self.assertEqual(completed.budget_candidate_order, expected)
                if result.candidate_ids[0] == "foreign":
                    self.assertEqual(completed.budget_candidate_weights, (1, 1))
                    self.assertEqual(completed.budget_validation_reserve, 1)
                    self.assertEqual(completed.budget_allocation_source, "deterministic_fallback")
                self.assertEqual(
                    tuple(candidate_id for stage, candidate_id in calls if stage == "analysis"),
                    expected,
                )
                self.assertEqual(advisor.calls, 1)
                events = [
                    event for event in app.progress_log.list_by_run(run.run_id)
                    if event.kind is ProgressEventKind.BUDGET_ALLOCATED
                ]
                self.assertEqual(len(events), 1)

        advisor = _Advisor(error=LlmTimeout("test timeout"))
        app, _, calls = _app(advisor=advisor)
        run = _seed(app, budget=8)
        completed = app.orchestrator.resume(run.run_id)
        self.assertEqual(completed.budget_candidate_order, run.candidate_ids)
        self.assertEqual(advisor.calls, 1)
        self.assertEqual(calls[0], ("analysis", "candidate-a"))
        events = [
            event for event in app.progress_log.list_by_run(run.run_id)
            if event.kind is ProgressEventKind.BUDGET_ALLOCATED
        ]
        self.assertEqual(events[0].detail, "deterministic_fallback:reserve_1")

    def test_saved_order_survives_sqlite_restart_without_asking_again(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "allocation.sqlite3"
            stores = SQLiteStoreBundle(path)
            budget = SQLiteBudgetManager(path)
            app, _, _ = _app(stores=stores, budget=budget)
            run = _seed(
                app, budget=8,
                planned_order=("candidate-b", "candidate-a"), reserve=1,
            )
            stores.close()
            budget.close()

            stores = SQLiteStoreBundle(path)
            budget = SQLiteBudgetManager(path)
            advisor = _Advisor(error=AssertionError("advisor must not be called"))
            app, _, calls = _app(stores=stores, budget=budget, advisor=advisor)
            completed = app.orchestrator.resume(run.run_id)
            self.assertEqual(completed.budget_candidate_order, ("candidate-b", "candidate-a"))
            self.assertEqual(advisor.calls, 0)
            self.assertEqual(
                [candidate_id for stage, candidate_id in calls if stage == "analysis"],
                ["candidate-b", "candidate-a"],
            )
            stores.close()
            budget.close()

    def test_active_candidate_keeps_its_spending_floor_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "active-allocation.sqlite3"
            stores = SQLiteStoreBundle(path)
            budget = SQLiteBudgetManager(path)
            app, _, _ = _app(stores=stores, budget=budget)
            run = _seed(
                app, budget=10,
                planned_order=("candidate-a", "candidate-b"), reserve=1,
                active_candidate="candidate-a", active_phase="analyze", active_floor=7,
            )
            budget.consume(run.run_id, 2)
            stores.close()
            budget.close()

            stores = SQLiteStoreBundle(path)
            budget = SQLiteBudgetManager(path)
            app, runtime, _ = _app(
                stores=stores, budget=budget,
                analysis={"candidate-a": 3},
            )
            completed = app.orchestrator.resume(run.run_id)
            self.assertIs(completed.phase, RunPhase.DONE)
            self.assertEqual(runtime.calls, 1)
            self.assertEqual(app.budget_manager.global_remaining(run.run_id), 7)
            self.assertIsNone(completed.budget_active_candidate_id)
            stores.close()
            budget.close()

    def test_active_validation_floor_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "active-validation.sqlite3"
            stores = SQLiteStoreBundle(path)
            budget = SQLiteBudgetManager(path)
            app, _, _ = _app(stores=stores, budget=budget)
            run = _seed(
                app, budget=10,
                planned_order=("candidate-a", "candidate-b"), reserve=1,
                active_candidate="candidate-a", active_phase="validate", active_floor=7,
            ).with_updates(phase=RunPhase.VALIDATE)
            stores.runs.save(run)
            for candidate_id in run.candidate_ids:
                candidate = stores.candidates.get(run.run_id, candidate_id)
                stores.candidates.save(candidate.set_status(CandidateStatus.ANALYZED))
            budget.consume(run.run_id, 2)
            stores.close()
            budget.close()

            stores = SQLiteStoreBundle(path)
            budget = SQLiteBudgetManager(path)
            app, runtime, _ = _app(
                stores=stores, budget=budget,
                validation={"candidate-a": 3},
            )
            completed = app.orchestrator.resume(run.run_id)
            self.assertIs(completed.phase, RunPhase.DONE)
            self.assertEqual(runtime.calls, 1)
            self.assertEqual(app.budget_manager.global_remaining(run.run_id), 7)
            self.assertIsNone(completed.budget_active_candidate_id)
            self.assertIs(
                stores.candidates.get(run.run_id, "candidate-b").status,
                CandidateStatus.REJECTED,
            )
            stores.close()
            budget.close()

    def test_llm_prompt_contains_only_offered_structured_candidate_facts(self):
        model = _Llm({
            "candidate_ids": ["candidate-b", "candidate-a"],
            "candidate_weights": [2, 1],
            "validation_reserve_per_candidate": 1,
        })
        advisor = LlmBudgetAllocationAdvisor(llm_client=model)
        app, _, _ = _app()
        run = _seed(app)
        candidates = tuple(app.stores.candidates.list_by_run(run.run_id))

        decision = advisor.decide(run, candidates, 7)

        self.assertEqual(decision.candidate_ids, ("candidate-b", "candidate-a"))
        self.assertEqual(decision.candidate_weights, (2, 1))
        prompt = json.loads(model.requests[0].messages[0].content)
        self.assertEqual(len(prompt["candidates"]), 2)
        self.assertNotIn("untrusted hypothesis text", model.requests[0].messages[0].content)
        self.assertNotIn("http://", model.requests[0].messages[0].content)

    def test_malformed_llm_response_keeps_deterministic_allocation(self):
        model = _Llm({
            "candidate_ids": ["candidate-a", "foreign"],
            "candidate_weights": [3, 1],
            "validation_reserve_per_candidate": 2,
        })
        advisor = LlmBudgetAllocationAdvisor(llm_client=model)
        app, _, _ = _app(advisor=advisor)
        run = _seed(app, budget=8)

        completed = app.orchestrator.resume(run.run_id)

        self.assertEqual(completed.budget_candidate_order, run.candidate_ids)
        self.assertEqual(completed.budget_candidate_weights, (1, 1))
        self.assertEqual(completed.budget_validation_reserve, 1)
        self.assertEqual(completed.budget_allocation_source, "deterministic_fallback")
