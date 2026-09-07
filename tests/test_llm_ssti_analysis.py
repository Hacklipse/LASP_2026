"""LLM SSTI Agent가 필드만 선택하고 고정 산술 계약을 유지하는지 검증한다."""

from __future__ import annotations

import unittest
from dataclasses import replace
from urllib.parse import parse_qs

from hacklipse.adapters import LlmSstiAnalyzer, StaticApprovalGate
from hacklipse.adapters.llm_ssti_analysis import LLM_SSTI_ANALYZER
from hacklipse.adapters.ssti_analysis import (
    SSTI_APPROVAL_REF,
    SSTI_SAFE_EXPRESSION,
    SSTI_TOOL,
)
from hacklipse.application.errors import AgentContractError
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    Candidate,
    ExecutionRequest,
    ExecutionResult,
    Run,
    RunScope,
    Surface,
    TaskEnvelope,
)
from hacklipse.ports.llm import LlmRequest, LlmResponse

_RUN_ID = "run-llm-ssti"
_SURFACE_ID = "surface-llm-ssti"
_CANDIDATE_ID = "candidate-llm-ssti"
_TARGET = "http://local.test/profile"


class _FakeLlmClient:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload
        self.requests: list[LlmRequest] = []

    def complete(self, request: LlmRequest) -> LlmResponse:
        self.requests.append(request)
        return LlmResponse(payload=self.payload, model="fake")


class _ProfileRuntime:
    def __init__(self, *, vulnerable: bool = True) -> None:
        self.vulnerable = vulnerable
        self.username = "initial-user"
        self.requests: list[ExecutionRequest] = []

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        if request.method.upper() == "POST":
            fields = parse_qs(request.body or "", keep_blank_values=True)
            self.username = fields.get("username", [""])[0]
            return ExecutionResult(
                execution_id=request.execution_id,
                evidence_type="http_redirect",
                observation={"type": "http_redirect", "status": 302, "body": ""},
            )
        rendered = (
            "12121"
            if self.vulnerable and self.username == SSTI_SAFE_EXPRESSION
            else self.username
        )
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response",
                "status": 200,
                "body": (
                    f"<p>{rendered}</p>"
                    f'<input name="username" value="{self.username}">'
                ),
            },
        )


def _fixture(payload: dict[str, object], *, vulnerable: bool = True):
    llm = _FakeLlmClient(payload)
    runtime = _ProfileRuntime(vulnerable=vulnerable)
    app = build_local_application(
        {},
        runtime=runtime,
        approval_gate=StaticApprovalGate((SSTI_APPROVAL_REF,)),
    )
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
            method="POST",
            parameters=("email", "role", "username"),
        )
    )
    app.stores.candidates.add(
        Candidate(
            candidate_id=_CANDIDATE_ID,
            run_id=_RUN_ID,
            surface_id=_SURFACE_ID,
            vulnerability_type="SSTI",
            hypothesis="server-rendered username",
            assigned_agent="ssti_analyzer",
            evidence_ids=(),
        )
    )
    app.budget_manager.open_run(_RUN_ID, 20)
    agent = LlmSstiAnalyzer(
        llm_client=llm,
        candidate_store=app.stores.candidates,
        surface_store=app.stores.surfaces,
        evidence_store=app.stores.evidence,
        id_factory=iter(str(index) for index in range(100)).__next__,
    )
    task = TaskEnvelope(
        task_id="task-llm-ssti",
        run_id=_RUN_ID,
        agent_type="ssti_analyzer",
        target_url=_TARGET,
        surface_id=_SURFACE_ID,
        candidate_id=_CANDIDATE_ID,
        allowed_tools=(SSTI_TOOL,),
        request_budget=10,
    )
    return agent, app, llm, runtime, task


def _collect(result, app, task: TaskEnvelope) -> TaskEnvelope:
    ids = list(task.evidence_ids) + list(result.new_evidence_ids)
    for request in result.evidence_requests:
        ids.append(
            app.collector.collect(
                task.run_id,
                task.target_url or "",
                request,
                task_id=task.task_id,
                approval_ref=request.approval_ref,
            )
        )
    return replace(
        task,
        evidence_ids=tuple(ids),
        request_budget=app.budget_manager.remaining(task.run_id),
    )


class LlmSstiAnalyzerTests(unittest.TestCase):
    def test_llm_selects_only_field_and_python_owns_expression(self) -> None:
        agent, app, llm, runtime, task = _fixture(
            {
                "parameters": ["username"],
                "reason": "display name is rendered",
                "payload": "#{process.env}",
            }
        )

        requested = agent.handle(task)
        _collect(requested, app, task)

        self.assertEqual(len(llm.requests), 1)
        self.assertEqual(len(runtime.requests), 5)
        bodies = [request.body or "" for request in runtime.requests]
        self.assertTrue(any("%23%7B713%2A17%7D" in body for body in bodies))
        self.assertFalse(any("process.env" in body for body in bodies))

    def test_python_comparison_emits_shared_observation(self) -> None:
        agent, app, _, _, task = _fixture(
            {"parameters": ["username"], "reason": "rendered profile field"}
        )

        requested = agent.handle(task)
        result = agent.handle(_collect(requested, app, task))

        self.assertTrue(result.new_evidence_ids)
        signal = next(
            item
            for item in app.stores.evidence.list_by_run(_RUN_ID)
            if item.observation.get("type") == "template_execution"
        )
        self.assertEqual(signal.created_by, LLM_SSTI_ANALYZER)
        self.assertEqual(signal.observation["selection_source"], "llm")

    def test_llm_claim_cannot_create_signal_without_evaluation(self) -> None:
        agent, app, _, _, task = _fixture(
            {"parameters": ["username"], "reason": "definitely vulnerable"},
            vulnerable=False,
        )

        requested = agent.handle(task)
        agent.handle(_collect(requested, app, task))

        self.assertFalse(
            any(
                item.observation.get("type") == "template_execution"
                for item in app.stores.evidence.list_by_run(_RUN_ID)
            )
        )

    def test_invented_parameter_is_rejected_before_http(self) -> None:
        agent, _, _, runtime, task = _fixture(
            {"parameters": ["templateSource"], "reason": "invented"}
        )

        with self.assertRaises(AgentContractError):
            agent.handle(task)
        self.assertEqual(runtime.requests, [])

    def test_empty_selection_spends_no_requests(self) -> None:
        agent, _, llm, runtime, task = _fixture(
            {"parameters": [], "reason": "no template field"}
        )

        result = agent.handle(task)

        self.assertEqual(result.evidence_requests, ())
        self.assertEqual(len(llm.requests), 1)
        self.assertEqual(runtime.requests, [])


if __name__ == "__main__":
    unittest.main()
