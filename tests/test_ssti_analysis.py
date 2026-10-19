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
    SSTI_QUERY_PROBES,
    SSTI_SAFE_EXPRESSION,
    SSTI_TOOL,
    build_ssti_form_requests,
    validate_ssti_request,
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


def _form_request(
    parameters: tuple[tuple[str, str], ...],
    kind: HttpRequestKind = HttpRequestKind.SSTI_PROBE,
    **overrides,
) -> ExecutionRequest:
    defaults: dict = {
        "execution_id": "exe-form",
        "run_id": _RUN_ID,
        "task_id": "task-form",
        "tool": SSTI_TOOL,
        "target_url": "http://local.test/search",
        "surface_id": _SURFACE_ID,
        "purpose": "unit",
        "method": "POST",
        "form_parameters": parameters,
        "request_kind": kind,
    }
    defaults.update(overrides)
    return ExecutionRequest(**defaults)


class SstiStatelessFormContractTests(unittest.TestCase):
    """응답에만 렌더링되는 POST 폼 경로. /profile 저장 계약과 제약이 다르다."""

    def test_builds_one_control_and_one_probe_per_dialect(self) -> None:
        surface = Surface(
            surface_id=_SURFACE_ID, run_id=_RUN_ID, url="http://local.test/search",
            method="POST", parameters=("name", "submit"),
            observed_query=(("submit", "Search"),),
        )
        requests = build_ssti_form_requests(surface, "name", purpose="unit")

        self.assertEqual(len(requests), 1 + len(SSTI_QUERY_PROBES))
        kinds = [item.http_request.request_kind for item in requests]
        self.assertEqual(kinds[0], HttpRequestKind.CONTROL)
        self.assertTrue(all(kind is HttpRequestKind.SSTI_PROBE for kind in kinds[1:]))
        for item in requests:
            fields = dict(item.http_request.form_parameters)
            # 버튼 이름이 빠지면 분기 자체에 닿지 못하는 폼이 흔하다. 관측된 값을 싣는다.
            self.assertEqual(fields["submit"], "Search")
            self.assertEqual(item.http_request.method, "POST")
            self.assertIsNone(item.http_request.body)
        self.assertEqual(
            [dict(item.http_request.form_parameters)["name"] for item in requests],
            [SSTI_CONTROL_VALUE, *(expression for _, expression in SSTI_QUERY_PROBES)],
        )

    def test_only_a_post_surface_can_use_the_form_path(self) -> None:
        surface = Surface(
            surface_id=_SURFACE_ID, run_id=_RUN_ID, url="http://local.test/search",
            method="GET", parameters=("name",),
        )
        with self.assertRaises(Exception):
            build_ssti_form_requests(surface, "name", purpose="unit")

    def test_accepts_exactly_one_fixed_expression(self) -> None:
        validate_ssti_request(_form_request(
            (("name", SSTI_SAFE_EXPRESSION), ("submit", "Search")),
        ))
        validate_ssti_request(_form_request(
            (("name", SSTI_CONTROL_VALUE),), HttpRequestKind.CONTROL,
        ))

    def test_rejects_a_value_outside_the_fixed_set(self) -> None:
        for value in ("{{7*7}}", "{{config}}", SSTI_SAFE_EXPRESSION + "x"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_ssti_request(_form_request((("name", value),)))

    def test_rejects_two_changed_coordinates(self) -> None:
        with self.assertRaises(ValueError):
            validate_ssti_request(_form_request(
                (("name", SSTI_SAFE_EXPRESSION), ("note", SSTI_SAFE_EXPRESSION)),
            ))

    def test_control_cannot_carry_a_probe_expression(self) -> None:
        with self.assertRaises(ValueError):
            validate_ssti_request(_form_request(
                (("name", SSTI_SAFE_EXPRESSION),), HttpRequestKind.CONTROL,
            ))

    def test_rejects_template_syntax_smuggled_through_another_field(self) -> None:
        for value in ("{{7*7}}", "${7*7}", "#{7*7}", "<%=7*7%>"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_ssti_request(_form_request(
                        (("name", SSTI_SAFE_EXPRESSION), ("note", value)),
                    ))

    def test_rejects_a_raw_body_header_or_query_coordinate(self) -> None:
        for overrides in (
            {"body": "name=x"},
            {"headers": (("X-Test", "1"),)},
            {"query_parameters": (("name", SSTI_CONTROL_VALUE),)},
            {"method": "PUT"},
        ):
            with self.subTest(overrides=tuple(overrides)):
                with self.assertRaises(ValueError):
                    validate_ssti_request(_form_request(
                        (("name", SSTI_SAFE_EXPRESSION),), **overrides,
                    ))

    def test_the_form_path_needs_no_profile_endpoint(self) -> None:
        # /profile 계약은 저장된 프로필을 바꾸므로 엔드포인트를 묶지만, 이 경로는
        # 보낸 값이 그 응답에만 렌더링되므로 묶을 이유가 없다.
        validate_ssti_request(_form_request(
            (("name", SSTI_SAFE_EXPRESSION),),
            target_url="http://local.test/shop/index.php",
        ))


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
