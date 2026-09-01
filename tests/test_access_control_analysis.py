"""Access Control 탐침이 인증 주체를 섞지 않고 객체 노출만 신호로 만드는지 검증한다.

지키려는 계약은 다섯 가지다.
1. Agent는 자격증명을 고를 수 없다 — 역할만 지정하고 해석은 중앙에서 한다.
2. 두 주체의 세션이 섞이지 않는다.
3. 탐침은 식별자 값 하나만 바꾼다 — 헤더·본문·메서드·다른 파라미터는 못 건드린다.
4. 거부·로그인 리다이렉트를 정상 객체 접근으로 오인하지 않는다.
5. LLM은 파라미터 이름만 고를 수 있고 잘못된 선택은 차단된다.
"""

from __future__ import annotations

import unittest
from dataclasses import replace
from urllib.parse import urlsplit

from hacklipse.adapters import HeuristicAccessControlAnalyzer, LlmAccessControlAnalyzer
from hacklipse.adapters.access_control_analysis import (
    ACCESS_CONTROL_TOOL,
    build_access_control_requests,
    validate_access_control_request,
)
from hacklipse.adapters.routing import RuleBasedVulnerabilityRouter
from hacklipse.application.errors import AgentContractError
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    AccessPrincipalRole,
    AccessIdentifierLocation,
    AgentResultStatus,
    Candidate,
    DomainInvariantError,
    ExecutionRequest,
    ExecutionResult,
    HttpRequestKind,
    HttpRequestSpec,
    Run,
    RunScope,
    Surface,
    TaskEnvelope,
)
from hacklipse.ports.errors import PolicyViolation
from hacklipse.ports.llm import LlmResponse

_RUN_ID = "run-ac"
_SURFACE_ID = "surface-profile"
_CANDIDATE_ID = "candidate-ac"
_URL = "http://local.test/profile"

_ACTOR_CRED = "cred-actor"
_OWNER_CRED = "cred-owner"


def _profile(user_id: str) -> str:
    return f'<div id="profile-info"><p>User ID: {user_id}</p><p>Name: someone</p></div>'


class _PrincipalRuntime:
    """세션 주체별로 다른 응답을 돌려주는 대역. 소유권 검사 유무를 모드로 바꾼다."""

    def __init__(self, *, enforces_ownership: bool) -> None:
        self.enforces_ownership = enforces_ownership
        self.requests: list[ExecutionRequest] = []

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        # 세션 주체는 자격증명 참조로만 결정된다. 요청 본문이나 헤더로는 바꿀 수 없다.
        session_user = {"cred-actor": "2", "cred-owner": "1"}.get(
            request.credential_ref or ""
        )
        requested = dict(request.query_parameters).get("user_id", "")
        if request.identifier_location is AccessIdentifierLocation.PATH:
            requested = urlsplit(request.resolved_url).path.rstrip("/").rsplit("/", 1)[-1]
        if session_user is None:
            body, status = "<form><input type='password'></form>", 200
        elif self.enforces_ownership and requested != session_user:
            body, status = "<p>Access denied.</p>", 403
        else:
            body, status = _profile(requested), 200
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response",
                "status": status,
                "body": body,
                "requested_url": request.resolved_url,
            },
        )


def _fixture(
    *, enforces_ownership: bool, parameters=("user_id", "action"), path=False
):
    runtime = _PrincipalRuntime(enforces_ownership=enforces_ownership)
    app = build_local_application({}, runtime=runtime)
    url = "http://local.test/users/2" if path else _URL
    app.stores.runs.add(
        Run(
            run_id=_RUN_ID,
            target_url=url,
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            policy_profile="safe",
            request_budget=40,
            credential_ref=_ACTOR_CRED,
            principal_credentials=(("actor", _ACTOR_CRED), ("owner", _OWNER_CRED)),
        )
    )
    app.stores.surfaces.add(
        Surface(
            surface_id=_SURFACE_ID,
            run_id=_RUN_ID,
            url=url,
            method="GET",
            parameters=() if path else parameters,
            observed_query=() if path else (("user_id", "1"), ("action", "view")),
            path_identifier="user_id" if path else None,
            path_identifier_index=2 if path else None,
            observed_path_identifier="2" if path else None,
        )
    )
    app.stores.candidates.add(
        Candidate(
            candidate_id=_CANDIDATE_ID,
            run_id=_RUN_ID,
            surface_id=_SURFACE_ID,
            vulnerability_type="Access Control",
            hypothesis="identifier surface",
            assigned_agent="access_control_analyzer",
            evidence_ids=(),
        )
    )
    app.budget_manager.open_run(_RUN_ID, 40)
    task = TaskEnvelope(
        task_id="task-ac",
        run_id=_RUN_ID,
        agent_type="access_control_analyzer",
        target_url=url,
        surface_id=_SURFACE_ID,
        candidate_id=_CANDIDATE_ID,
        allowed_tools=(ACCESS_CONTROL_TOOL,),
        request_budget=20,
    )
    return app, runtime, task


def _analyzer(app, **kwargs):
    return HeuristicAccessControlAnalyzer(
        candidate_store=app.stores.candidates,
        surface_store=app.stores.surfaces,
        evidence_store=app.stores.evidence,
        actor_object_id="2",
        owner_object_id="1",
        id_factory=iter(str(index) for index in range(100)).__next__,
        **kwargs,
    )


def _collect(result, app, task):
    ids = list(task.evidence_ids)
    for request in result.evidence_requests:
        ids.append(
            app.collector.collect(
                task.run_id, task.target_url, request, task_id=task.task_id
            )
        )
    return replace(
        task,
        evidence_ids=tuple(ids),
        request_budget=app.budget_manager.remaining(task.run_id),
    )


def _signals(app):
    return [
        item.observation
        for item in app.stores.evidence.list_by_run(_RUN_ID)
        if item.observation.get("type") == "object_id_auth"
    ]


class AccessControlAnalysisTests(unittest.TestCase):
    # --- 1. 신호 판정 ---

    def test_exposed_owner_object_creates_the_observation(self) -> None:
        app, _, task = _fixture(enforces_ownership=False)
        agent = _analyzer(app)

        requested = agent.handle(task)
        self.assertIs(requested.status, AgentResultStatus.NEEDS_EVIDENCE)
        agent.handle(_collect(requested, app, task))

        signals = _signals(app)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["identifier_parameter"], "user_id")
        self.assertEqual(signals[0]["actor_object_id"], "2")
        self.assertEqual(signals[0]["owner_object_id"], "1")
        self.assertEqual(signals[0]["signal"], "unauthorized_owner_object_exposed")
        for key in (
            "actor_control_evidence_id",
            "owner_control_evidence_id",
            "probe_evidence_id",
        ):
            self.assertIn(key, signals[0])

    def test_access_denied_produces_no_observation(self) -> None:
        app, _, task = _fixture(enforces_ownership=True)
        agent = _analyzer(app)

        requested = agent.handle(task)
        agent.handle(_collect(requested, app, task))

        self.assertEqual(_signals(app), [])

    def test_path_segment_identifier_produces_the_same_observation(self) -> None:
        app, runtime, task = _fixture(enforces_ownership=False, path=True)
        agent = _analyzer(app)

        requested = agent.handle(task)
        agent.handle(_collect(requested, app, task))

        self.assertEqual(
            [urlsplit(item.resolved_url).path for item in runtime.requests],
            ["/users/2", "/users/1", "/users/1"],
        )
        signals = _signals(app)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["identifier_parameter"], "user_id")
        self.assertEqual(signals[0]["identifier_location"], "path")

    def test_path_segment_ownership_denial_produces_no_observation(self) -> None:
        app, _, task = _fixture(enforces_ownership=True, path=True)
        agent = _analyzer(app)

        requested = agent.handle(task)
        agent.handle(_collect(requested, app, task))

        self.assertEqual(_signals(app), [])

    def test_surface_without_an_identifier_spends_no_request(self) -> None:
        app, runtime, task = _fixture(
            enforces_ownership=False, parameters=("action", "token")
        )
        agent = _analyzer(app)

        result = agent.handle(task)

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        self.assertEqual(runtime.requests, [])
        self.assertEqual(_signals(app), [])

    # --- 2. 인증 주체 분리 ---

    def test_three_requests_use_the_declared_roles(self) -> None:
        app, runtime, task = _fixture(enforces_ownership=False)
        agent = _analyzer(app)

        requested = agent.handle(task)
        roles = [request.principal_role for request in requested.evidence_requests]
        self.assertEqual(
            roles,
            [
                AccessPrincipalRole.ACTOR,
                AccessPrincipalRole.OWNER,
                AccessPrincipalRole.ACTOR,
            ],
        )

        _collect(requested, app, task)
        # 역할이 중앙에서 각기 다른 자격증명으로 해석돼야 세션이 섞이지 않는다.
        self.assertEqual(
            [request.credential_ref for request in runtime.requests],
            [_ACTOR_CRED, _OWNER_CRED, _ACTOR_CRED],
        )

    def test_unregistered_role_is_rejected_by_the_central_resolver(self) -> None:
        app, _, task = _fixture(enforces_ownership=False)
        run = app.stores.runs.get(_RUN_ID)
        # owner 역할을 등록하지 않은 Run에서는 owner 요청이 실행되지 않아야 한다.
        app.stores.runs.save(replace(run, principal_credentials=(("actor", _ACTOR_CRED),)))
        agent = _analyzer(app)

        requested = agent.handle(task)
        with self.assertRaises(PolicyViolation):
            _collect(requested, app, task)

    def test_agent_cannot_name_a_credential_directly(self) -> None:
        """EvidenceRequest에는 credential_ref 필드 자체가 없다."""

        request = build_access_control_requests(
            app_surface := Surface(
                surface_id=_SURFACE_ID,
                run_id=_RUN_ID,
                url=_URL,
                method="GET",
                parameters=("user_id",),
            ),
            "user_id",
            actor_object_id="2",
            owner_object_id="1",
            purpose="test",
        )[0]
        self.assertFalse(hasattr(request, "credential_ref"))
        self.assertIs(request.principal_role, AccessPrincipalRole.ACTOR)
        del app_surface

    # --- 3. 탐침 표면 제한 ---

    def test_probe_preserves_non_identifier_parameters(self) -> None:
        app, runtime, task = _fixture(enforces_ownership=False)
        agent = _analyzer(app)

        _collect(agent.handle(task), app, task)

        for request in runtime.requests:
            values = dict(request.query_parameters)
            self.assertEqual(values["action"], "view", "관측된 원본 값이 유지된다")
            self.assertEqual(request.method.upper(), "GET")
            self.assertEqual(request.headers, ())
            self.assertIsNone(request.body)

    def test_domain_rejects_unsafe_probe_shapes(self) -> None:
        base = dict(
            query_parameters=(("user_id", "1"),),
            request_kind=HttpRequestKind.ACCESS_CONTROL_PROBE,
            identifier_parameter="user_id",
        )
        for description, override in (
            ("숫자 아닌 객체 ID", {"query_parameters": (("user_id", "1 OR 1=1"),)}),
            ("경로 값", {"query_parameters": (("user_id", "../../etc/passwd"),)}),
            ("헤더 주입", {"headers": (("X-Forwarded-For", "1.2.3.4"),)}),
            ("본문", {"body": "x=1"}),
            ("POST", {"method": "POST"}),
            ("식별자 미지정", {"identifier_parameter": None}),
        ):
            with self.subTest(description), self.assertRaises(DomainInvariantError):
                HttpRequestSpec(**{**base, **override})

    def test_path_probe_replaces_only_the_declared_numeric_segment(self) -> None:
        request = ExecutionRequest(
            execution_id="e-path",
            run_id=_RUN_ID,
            task_id="t-path",
            tool=ACCESS_CONTROL_TOOL,
            target_url="http://local.test/api/users/2?view=full",
            surface_id=_SURFACE_ID,
            purpose="path probe",
            request_kind=HttpRequestKind.ACCESS_CONTROL_PROBE,
            identifier_parameter="user_id",
            identifier_location=AccessIdentifierLocation.PATH,
            path_identifier_index=3,
            path_identifier_value="1",
        )

        self.assertEqual(
            request.resolved_url, "http://local.test/api/users/1?view=full"
        )
        validate_access_control_request(request)

        for value in ("../admin", "1 OR 1=1", ""):
            with self.subTest(value), self.assertRaises(DomainInvariantError):
                replace(request, path_identifier_value=value)

        with self.assertRaises(ValueError):
            validate_access_control_request(
                replace(request, target_url="http://local.test/api/users/current")
            )

    def test_policy_repeats_the_same_checks_at_the_execution_boundary(self) -> None:
        """도메인을 우회해 ExecutionRequest를 직접 만들어도 같은 제약을 받는다."""

        request = ExecutionRequest(
            execution_id="e1",
            run_id=_RUN_ID,
            task_id="t1",
            tool=ACCESS_CONTROL_TOOL,
            target_url=_URL,
            surface_id=_SURFACE_ID,
            purpose="probe",
            query_parameters=(("user_id", "1"),),
            request_kind=HttpRequestKind.ACCESS_CONTROL_PROBE,
            identifier_parameter="user_id",
        )
        validate_access_control_request(request)  # 정상 요청은 통과한다

        with self.assertRaises(ValueError):
            validate_access_control_request(
                replace(request, request_kind=HttpRequestKind.CONTROL)
            )

    # --- 4. 거부 응답 오인 방지 ---

    def test_login_redirect_is_not_treated_as_object_access(self) -> None:
        app, _, task = _fixture(enforces_ownership=False)
        run = app.stores.runs.get(_RUN_ID)
        # 자격증명을 지우면 대역이 로그인 폼을 200으로 돌려준다.
        app.stores.runs.save(
            replace(
                run,
                credential_ref=None,
                principal_credentials=(("actor", ""), ("owner", "")),
            )
        )
        agent = _analyzer(app)

        requested = agent.handle(task)
        with self.assertRaises(PolicyViolation):
            _collect(requested, app, task)
        self.assertEqual(_signals(app), [])


class _FakeLlm:
    def __init__(self, parameters) -> None:
        self.parameters = parameters
        self.calls = 0

    def complete(self, request):
        self.calls += 1
        return LlmResponse(
            payload={"parameters": self.parameters, "reason": "identifies the object"},
            model="fake",
        )


class LlmAccessControlAnalysisTests(unittest.TestCase):
    def _agent(self, app, llm):
        return LlmAccessControlAnalyzer(
            llm_client=llm,
            candidate_store=app.stores.candidates,
            surface_store=app.stores.surfaces,
            evidence_store=app.stores.evidence,
            actor_object_id="2",
            owner_object_id="1",
            id_factory=iter(str(index) for index in range(100)).__next__,
        )

    def test_llm_selection_produces_the_same_observation_shape(self) -> None:
        app, _, task = _fixture(enforces_ownership=False)
        llm = _FakeLlm(["user_id"])
        agent = self._agent(app, llm)

        requested = agent.handle(task)
        agent.handle(_collect(requested, app, task))

        signals = _signals(app)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["identifier_parameter"], "user_id")

    def test_llm_can_select_a_path_identifier(self) -> None:
        app, _, task = _fixture(enforces_ownership=False, path=True)
        prompts: list[str] = []

        class _CapturingPathLlm(_FakeLlm):
            def complete(self, request):
                prompts.append(request.messages[0].content)
                return super().complete(request)

        llm = _CapturingPathLlm(["path:user_id"])
        agent = self._agent(app, llm)

        requested = agent.handle(task)
        result = agent.handle(_collect(requested, app, task))

        self.assertEqual(llm.calls, 1)
        self.assertTrue(result.new_evidence_ids)
        self.assertEqual(_signals(app)[0]["identifier_location"], "path")
        self.assertIn("/users/{user_id}", prompts[0])
        self.assertNotIn("/users/2", prompts[0])

    def test_prompt_carries_no_secrets_or_object_ids(self) -> None:
        app, _, task = _fixture(enforces_ownership=False)
        llm = _FakeLlm(["user_id"])
        captured: list[str] = []

        class _Capturing(_FakeLlm):
            def complete(self, request):
                captured.append(request.messages[0].content)
                return super().complete(request)

        agent = self._agent(app, _Capturing(["user_id"]))
        agent.handle(task)

        prompt = "\n".join(captured)
        for secret in (_ACTOR_CRED, _OWNER_CRED, "cred-", "Cookie", "password"):
            self.assertNotIn(secret, prompt)
        # 실제 객체 ID는 Python이 정한다. LLM은 이름만 본다.
        self.assertNotIn("actor_object_id", prompt)
        self.assertIn("user_id", prompt)
        del llm

    def test_invalid_llm_selection_is_rejected(self) -> None:
        for description, parameters in (
            ("없는 파라미터", ["admin_flag"]),
            ("식별자가 아닌 이름", ["action"]),
            ("CSRF 토큰", ["token"]),
            ("문자열이 아님", [1]),
        ):
            with self.subTest(description):
                app, _, task = _fixture(
                    enforces_ownership=False, parameters=("user_id", "action", "token")
                )
                agent = self._agent(app, _FakeLlm(parameters))
                with self.assertRaises(AgentContractError):
                    agent.handle(task)

    def test_empty_llm_selection_spends_no_request(self) -> None:
        app, runtime, task = _fixture(enforces_ownership=False)
        agent = self._agent(app, _FakeLlm([]))

        result = agent.handle(task)

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        self.assertEqual(runtime.requests, [])


class AccessControlRoutingTests(unittest.TestCase):
    def _run(self):
        return Run(
            run_id=_RUN_ID,
            target_url=_URL,
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            policy_profile="safe",
            request_budget=10,
        )

    def _surface(self, parameters, method="GET"):
        return Surface(
            surface_id=_SURFACE_ID,
            run_id=_RUN_ID,
            url=_URL,
            method=method,
            parameters=parameters,
        )

    def _access_candidates(self, parameters, method="GET"):
        decisions = RuleBasedVulnerabilityRouter().route(
            self._run(), [self._surface(parameters, method)], []
        )
        return [
            decision
            for decision in decisions
            if decision.candidate.vulnerability_type == "Access Control"
        ]

    def test_identifier_surface_creates_a_candidate(self) -> None:
        self.assertEqual(len(self._access_candidates(("user_id", "action", "token"))), 1)

    def test_surface_without_identifier_creates_none(self) -> None:
        self.assertEqual(self._access_candidates(("action", "token")), [])

    def test_state_changing_surface_creates_none(self) -> None:
        self.assertEqual(self._access_candidates(("user_id", "password_new")), [])

    def test_post_surface_creates_none(self) -> None:
        self.assertEqual(self._access_candidates(("user_id",), method="POST"), [])


if __name__ == "__main__":
    unittest.main()
