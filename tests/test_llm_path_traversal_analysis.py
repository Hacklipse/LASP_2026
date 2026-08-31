"""Gemini 대역을 사용해 Path Traversal LLM Agent 경계를 검증한다."""

from __future__ import annotations

import unittest
from dataclasses import replace

from hacklipse.adapters import LlmPathTraversalAnalyzer
from hacklipse.adapters.llm_path_traversal_analysis import (
    LLM_PATH_TRAVERSAL_ANALYZER,
)
from hacklipse.adapters.path_traversal_analysis import (
    PATH_TRAVERSAL_PROBE_PATH,
    PATH_TRAVERSAL_PROOF_MARKERS,
    PATH_TRAVERSAL_TOOL,
)
from hacklipse.application.errors import AgentContractError
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    AgentResultStatus,
    Candidate,
    Evidence,
    ExecutionRequest,
    ExecutionResult,
    Run,
    RunScope,
    Surface,
    TaskEnvelope,
)
from hacklipse.ports.llm import LlmRequest, LlmResponse

_RUN_ID = "run-llm-path"
_SURFACE_ID = "surface-llm-path"
_CANDIDATE_ID = "candidate-llm-path"
_TARGET = "http://local.test/vulnerabilities/fi/?page=include.php"


class _FakeLlmClient:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload
        self.requests: list[LlmRequest] = []

    def complete(self, request: LlmRequest) -> LlmResponse:
        self.requests.append(request)
        return LlmResponse(payload=self.payload, model="fake")


class _Runtime:
    def __init__(self, *, vulnerable: bool = True) -> None:
        self.vulnerable = vulnerable
        self.requests: list[ExecutionRequest] = []

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        values = dict(request.query_parameters).values()
        body = (
            "\n".join(PATH_TRAVERSAL_PROOF_MARKERS)
            if self.vulnerable and PATH_TRAVERSAL_PROBE_PATH in values
            else "normal"
        )
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={"type": "http_response", "status": 200, "body": body},
        )


def _fixture(payload: dict[str, object], *, vulnerable: bool = True):
    llm = _FakeLlmClient(payload)
    runtime = _Runtime(vulnerable=vulnerable)
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
            parameters=("page", "Submit"),
        )
    )
    app.stores.evidence.append(
        Evidence(
            evidence_id="evi-hint",
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
            evidence_ids=("evi-hint",),
        )
    )
    app.budget_manager.open_run(_RUN_ID, 20)
    agent = LlmPathTraversalAnalyzer(
        llm_client=llm,
        candidate_store=app.stores.candidates,
        surface_store=app.stores.surfaces,
        evidence_store=app.stores.evidence,
        id_factory=iter(str(index) for index in range(100)).__next__,
    )
    task = TaskEnvelope(
        task_id="task-llm-path",
        run_id=_RUN_ID,
        agent_type="path_traversal_analyzer",
        target_url=_TARGET,
        surface_id=_SURFACE_ID,
        candidate_id=_CANDIDATE_ID,
        evidence_ids=("evi-hint",),
        allowed_tools=(PATH_TRAVERSAL_TOOL,),
        request_budget=10,
    )
    return agent, app, llm, runtime, task


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


class LlmPathTraversalAnalyzerTests(unittest.TestCase):
    def test_llm_selects_only_name_and_python_owns_path(self) -> None:
        agent, app, llm, runtime, task = _fixture(
            {
                "parameters": ["page"],
                "reason": "file include input",
                "path": "../../../../etc/passwd",
            }
        )

        requested = agent.handle(task)
        _collect(requested, app, task)

        self.assertEqual(len(llm.requests), 1)
        self.assertEqual(len(runtime.requests), 2)
        sent_values = {
            value for request in runtime.requests for _, value in request.query_parameters
        }
        self.assertIn(PATH_TRAVERSAL_PROBE_PATH, sent_values)
        self.assertNotIn("../../../../etc/passwd", sent_values)

    def test_python_safe_file_comparison_emits_shared_observation(self) -> None:
        agent, app, _, _, task = _fixture(
            {"parameters": ["page"], "reason": "file include input"}
        )

        requested = agent.handle(task)
        result = agent.handle(_collect(requested, app, task))

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        signal = next(
            item
            for item in app.stores.evidence.list_by_run(_RUN_ID)
            if item.observation.get("type") == "path_traversal_file_read"
        )
        self.assertEqual(signal.created_by, LLM_PATH_TRAVERSAL_ANALYZER)
        self.assertEqual(signal.observation["selection_source"], "llm")
        self.assertIn("plan_evidence_id", signal.observation)

    def test_llm_claim_cannot_create_signal_without_safe_file_markers(self) -> None:
        agent, app, _, _, task = _fixture(
            {"parameters": ["page"], "reason": "definitely vulnerable"},
            vulnerable=False,
        )

        requested = agent.handle(task)
        agent.handle(_collect(requested, app, task))

        self.assertFalse(
            any(
                item.observation.get("type") == "path_traversal_file_read"
                for item in app.stores.evidence.list_by_run(_RUN_ID)
            )
        )

    def test_invented_parameter_is_contract_error_before_http(self) -> None:
        agent, _, _, runtime, task = _fixture(
            {"parameters": ["filename"], "reason": "invented"}
        )

        with self.assertRaises(AgentContractError):
            agent.handle(task)
        self.assertEqual(runtime.requests, [])

    def test_plan_is_reused_without_second_llm_call(self) -> None:
        agent, app, llm, _, task = _fixture(
            {"parameters": ["page"], "reason": "file include input"}
        )

        requested = agent.handle(task)
        agent.handle(_collect(requested, app, task))

        self.assertEqual(len(llm.requests), 1)

    def test_empty_selection_spends_no_http_requests(self) -> None:
        agent, _, llm, runtime, task = _fixture(
            {"parameters": [], "reason": "no file input"}
        )

        result = agent.handle(task)

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        self.assertEqual(len(llm.requests), 1)
        self.assertEqual(runtime.requests, [])


if __name__ == "__main__":
    unittest.main()
