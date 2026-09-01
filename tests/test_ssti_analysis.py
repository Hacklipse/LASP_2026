"""고정 산술식 SSTI baseline과 전용 Policy 경계를 검증한다."""

from __future__ import annotations

import unittest
from dataclasses import replace
from urllib.parse import parse_qs

from hacklipse.adapters import HeuristicSstiAnalyzer, StaticApprovalGate
from hacklipse.adapters.policy import AllowlistPolicyGate
from hacklipse.adapters.ssti_analysis import (
    HEURISTIC_SSTI_ANALYZER,
    SSTI_APPROVAL_REF,
    SSTI_CLEANUP_VALUE,
    SSTI_CONTROL_VALUE,
    SSTI_EXPECTED_RESULT,
    SSTI_SAFE_EXPRESSION,
    SSTI_TOOL,
)
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    AgentResultStatus,
    Candidate,
    ExecutionRequest,
    ExecutionResult,
    HttpRequestKind,
    Run,
    RunScope,
    Surface,
    TaskEnvelope,
)
from hacklipse.ports.errors import ApprovalRequired, PolicyViolation

_RUN_ID = "run-ssti"
_SURFACE_ID = "surface-profile"
_CANDIDATE_ID = "candidate-ssti"
_TARGET = "http://local.test/profile"


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
                observation={
                    "type": "http_redirect",
                    "status": 302,
                    "body": "",
                },
            )
        rendered = self.username
        if self.vulnerable and self.username == SSTI_SAFE_EXPRESSION:
            rendered = SSTI_EXPECTED_RESULT
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response",
                "status": 200,
                # 실제 Juice Shop처럼 표시 영역은 평가 결과를 쓰지만 편집 input에는
                # 저장된 원본 username을 유지한다.
                "body": (
                    f"<p>{rendered}</p>"
                    f'<input name="username" value="{self.username}">'
                ),
            },
        )


def _fixture(*, vulnerable: bool = True, approved: bool = True):
    runtime = _ProfileRuntime(vulnerable=vulnerable)
    app = build_local_application(
        {},
        runtime=runtime,
        approval_gate=(
            StaticApprovalGate((SSTI_APPROVAL_REF,)) if approved else None
        ),
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
    agent = HeuristicSstiAnalyzer(
        candidate_store=app.stores.candidates,
        surface_store=app.stores.surfaces,
        evidence_store=app.stores.evidence,
        id_factory=iter(str(index) for index in range(100)).__next__,
    )
    task = TaskEnvelope(
        task_id="task-ssti",
        run_id=_RUN_ID,
        agent_type="ssti_analyzer",
        target_url=_TARGET,
        surface_id=_SURFACE_ID,
        candidate_id=_CANDIDATE_ID,
        allowed_tools=(SSTI_TOOL,),
        request_budget=10,
    )
    return agent, app, runtime, task


def _collect(result, app, task: TaskEnvelope) -> TaskEnvelope:
    evidence_ids = list(task.evidence_ids) + list(result.new_evidence_ids)
    for request in result.evidence_requests:
        evidence_ids.append(
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
        evidence_ids=tuple(evidence_ids),
        request_budget=app.budget_manager.remaining(task.run_id),
    )


class SstiSafetyContractTests(unittest.TestCase):
    def test_fixed_sequence_uses_only_arithmetic_and_finishes_with_cleanup(self) -> None:
        agent, app, runtime, task = _fixture()

        requested = agent.handle(task)
        _collect(requested, app, task)

        self.assertEqual(len(runtime.requests), 5)
        self.assertEqual(
            [request.method for request in runtime.requests],
            ["POST", "GET", "POST", "GET", "POST"],
        )
        self.assertIn(SSTI_CONTROL_VALUE, runtime.requests[0].body or "")
        self.assertIn("%23%7B713%2A17%7D", runtime.requests[2].body or "")
        self.assertNotIn("child_process", repr(runtime.requests))
        self.assertEqual(runtime.username, SSTI_CLEANUP_VALUE)
        self.assertIs(
            runtime.requests[-1].request_kind, HttpRequestKind.SSTI_CLEANUP
        )

    def test_probe_only_arithmetic_evaluation_emits_observation(self) -> None:
        agent, app, _, task = _fixture()

        requested = agent.handle(task)
        result = agent.handle(_collect(requested, app, task))

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        signal = next(
            item
            for item in app.stores.evidence.list_by_run(_RUN_ID)
            if item.observation.get("type") == "template_execution"
        )
        self.assertEqual(signal.created_by, HEURISTIC_SSTI_ANALYZER)
        self.assertEqual(signal.observation["parameter"], "username")
        self.assertEqual(signal.observation["expected_result"], SSTI_EXPECTED_RESULT)
        self.assertIn("cleanup_evidence_id", signal.observation)

    def test_literal_rendering_does_not_emit_signal(self) -> None:
        agent, app, _, task = _fixture(vulnerable=False)

        requested = agent.handle(task)
        agent.handle(_collect(requested, app, task))

        self.assertFalse(
            any(
                item.observation.get("type") == "template_execution"
                for item in app.stores.evidence.list_by_run(_RUN_ID)
            )
        )

    def test_state_change_is_blocked_without_user_approval(self) -> None:
        agent, app, _, task = _fixture(approved=False)
        request = agent.handle(task).evidence_requests[0]

        with self.assertRaises(ApprovalRequired):
            app.collector.collect(
                task.run_id,
                task.target_url or "",
                request,
                task_id=task.task_id,
                approval_ref=request.approval_ref,
            )

    def test_policy_rejects_non_fixed_expression(self) -> None:
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
            tool=SSTI_TOOL,
            target_url=_TARGET,
            surface_id=_SURFACE_ID,
            purpose="unsafe SSTI expression",
            method="POST",
            headers=(("Content-Type", "application/x-www-form-urlencoded"),),
            body="username=%23%7Bprocess.env%7D",
            request_kind=HttpRequestKind.SSTI_PROBE,
            approval_ref=SSTI_APPROVAL_REF,
            scope=run.scope,
        )

        with self.assertRaises(PolicyViolation):
            AllowlistPolicyGate(
                StaticApprovalGate((SSTI_APPROVAL_REF,))
            ).validate_execution(run, request)


if __name__ == "__main__":
    unittest.main()
