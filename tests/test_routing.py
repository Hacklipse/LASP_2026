"""Router가 Surface와 Evidence를 함께 사용해 Analysis 대상을 만드는지 검증."""

from __future__ import annotations

import unittest

from hacklipse.adapters import RuleBasedVulnerabilityRouter
from hacklipse.adapters.routing import (
    ADVISOR_PRIORITY,
    DEFAULT_RULES,
    OPTIONAL_RESTRICTED_FILE_BYPASS_RULES,
    RouteSuggestion,
    RoutingRule,
    SurfaceRoutingRule,
)
from hacklipse.adapters.llm_router_advisor import LlmRouterAdvisor
from hacklipse.application.errors import WorkflowExecutionError
from hacklipse.bootstrap import (
    IMPLEMENTED_ANALYZERS,
    build_local_application,
    standard_router,
)
from hacklipse.ports.errors import LlmCredentialsMissing
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
            ["XSS", "SQLi"],
        )
        self.assertEqual(
            [decision.candidate.assigned_agent for decision in decisions],
            ["xss_analyzer", "sqli_analyzer"],
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
            ["XSS", "SQLi"],
        )

    def test_surface_rules_require_their_supported_method_and_parameters(self) -> None:
        router = RuleBasedVulnerabilityRouter()

        post = router.route(_run(), (_surface(method="POST"),), ())
        no_parameters = router.route(_run(), (_surface(parameters=()),), ())

        self.assertEqual(post, ())
        self.assertEqual(no_parameters, ())

    def test_username_post_surface_routes_only_to_ssti(self) -> None:
        router = RuleBasedVulnerabilityRouter()

        decisions = router.route(
            _run(),
            (_surface(method="POST", parameters=("email", "role", "username")),),
            (),
        )

        self.assertEqual(
            [decision.candidate.vulnerability_type for decision in decisions],
            ["SSTI"],
        )
        self.assertEqual(decisions[0].candidate.assigned_agent, "ssti_analyzer")

    def test_surface_rule_skips_state_changing_get_form(self) -> None:
        router = RuleBasedVulnerabilityRouter()

        decisions = router.route(
            _run(),
            (_surface(parameters=("password_new", "password_conf", "Change")),),
            (),
        )

        self.assertEqual(decisions, ())

    def test_path_traversal_observation_does_not_route_a_post_upload_surface(self) -> None:
        """파일명 파라미터가 있어도 POST 업로드는 GET 전용 Agent로 보내지 않는다."""

        router = RuleBasedVulnerabilityRouter()
        evidence = Evidence(
            evidence_id="evi-file-upload",
            run_id="run-1",
            surface_id="surface-search",
            created_by="recon",
            evidence_type="observation",
            observation={
                "type": "url_or_file_parameter",
                "parameter": "file",
            },
        )

        decisions = router.route(
            _run(),
            (_surface(method="POST", parameters=("file",)),),
            (evidence,),
        )

        self.assertEqual(decisions, ())

    def test_restricted_file_bypass_is_disabled_by_default_but_remains_opt_in(self) -> None:
        surface = Surface(
            surface_id="surface-ftp-file",
            run_id="run-1",
            url="http://localhost/ftp/package.json.bak",
            method="GET",
        )
        evidence = Evidence(
            evidence_id="evi-restricted-file",
            run_id="run-1",
            surface_id=surface.surface_id,
            created_by="recon",
            evidence_type="observation",
            observation={
                "type": "restricted_file_path",
                "parameter": "package.json.bak",
            },
        )

        default_decisions = RuleBasedVulnerabilityRouter().route(
            _run(), (surface,), (evidence,)
        )
        self.assertEqual(default_decisions, ())

        opt_in_router = RuleBasedVulnerabilityRouter(
            rules=(*DEFAULT_RULES, *OPTIONAL_RESTRICTED_FILE_BYPASS_RULES),
            surface_rules=(),
        )
        opt_in_decisions = opt_in_router.route(_run(), (surface,), (evidence,))

        self.assertEqual(len(opt_in_decisions), 1)
        candidate = opt_in_decisions[0].candidate
        self.assertEqual(candidate.vulnerability_type, "Path Traversal")
        self.assertEqual(candidate.assigned_agent, "path_traversal_analyzer")
        self.assertEqual(candidate.evidence_ids, (evidence.evidence_id,))


class _StubAdvisor:
    """정해진 제안을 그대로 돌려주는 Advisor 대역."""

    def __init__(self, *suggestions: RouteSuggestion) -> None:
        self._suggestions = suggestions
        self.calls: list[frozenset[tuple[str, str]]] = []
        self.surface_calls: list[tuple[Surface, ...]] = []

    def advise(self, run, surfaces, evidence, routed):
        self.calls.append(routed)
        self.surface_calls.append(tuple(surfaces))
        return self._suggestions


class _RaisingAdvisor:
    """호출되면 반드시 실패하는 Advisor 대역."""

    def advise(self, run, surfaces, evidence, routed):
        raise RuntimeError("advisor transport failed")


class AdvisorRoutingTests(unittest.TestCase):
    """Advisor를 붙여도 규칙 판정이 보존되는지 검증한다."""

    def test_absent_advisor_produces_the_same_result_as_before(self) -> None:
        """advisor=None이면 규칙만 쓰던 기존 동작과 완전히 같아야 한다."""

        surfaces = (_surface(),)
        baseline = RuleBasedVulnerabilityRouter(
            id_factory=iter(("1", "2", "3")).__next__
        ).route(_run(), surfaces, ())
        with_default = RuleBasedVulnerabilityRouter(
            id_factory=iter(("1", "2", "3")).__next__, advisor=None
        ).route(_run(), surfaces, ())

        self.assertEqual(baseline, with_default)

    def test_advisor_fills_only_the_type_rules_left_empty(self) -> None:
        # 규칙은 이 Surface를 XSS와 SQLi로만 보낸다. Path Traversal 자리는 비어 있다.
        advisor = _StubAdvisor(
            RouteSuggestion(
                surface_id="surface-search",
                vulnerability_type="Path Traversal",
                agent_type="path_traversal_analyzer",
                reason="파일 경로처럼 보이는 파라미터",
            )
        )
        router = RuleBasedVulnerabilityRouter(
            id_factory=iter(("1", "2", "3")).__next__, advisor=advisor
        )

        decisions = router.route(_run(), (_surface(),), ())

        self.assertEqual(
            [decision.candidate.vulnerability_type for decision in decisions],
            ["XSS", "SQLi", "Path Traversal"],
        )
        advised = decisions[-1]
        self.assertEqual(advised.priority, ADVISOR_PRIORITY)
        # Advisor 판단은 Claim이므로 관측 Evidence를 근거로 달지 않는다.
        self.assertEqual(advised.candidate.evidence_ids, ())
        # 규칙이 이미 채운 조합을 Advisor에게 알려 준다.
        self.assertEqual(
            advisor.calls[0],
            frozenset({("surface-search", "XSS"), ("surface-search", "SQLi")}),
        )

    def test_review_policy_changes_single_weak_surface_selection(self) -> None:
        weak_rule = SurfaceRoutingRule("XSS", "xss_analyzer", priority=0.30)
        weak_advisor = _StubAdvisor()
        ambiguous_advisor = _StubAdvisor()

        RuleBasedVulnerabilityRouter(
            rules=(), surface_rules=(weak_rule,), advisor=weak_advisor,
            review_policy="weak",
        ).route(_run(), (_surface(),), ())
        RuleBasedVulnerabilityRouter(
            rules=(), surface_rules=(weak_rule,), advisor=ambiguous_advisor,
            review_policy="ambiguous",
        ).route(_run(), (_surface(),), ())

        self.assertEqual(weak_advisor.surface_calls[0], (_surface(),))
        self.assertEqual(ambiguous_advisor.surface_calls[0], ())

    def test_single_strong_surface_is_not_reviewed_under_either_policy(self) -> None:
        strong_rule = RoutingRule("reflection", "XSS", "xss_analyzer", 0.8)
        evidence = Evidence(
            evidence_id="evi-reflection",
            run_id="run-1",
            surface_id="surface-search",
            created_by="fixture",
            evidence_type="observation",
            observation={"type": "reflection"},
        )

        for policy in ("weak", "ambiguous"):
            with self.subTest(policy=policy):
                advisor = _StubAdvisor()
                RuleBasedVulnerabilityRouter(
                    rules=(strong_rule,), surface_rules=(), advisor=advisor,
                    review_policy=policy,
                ).route(_run(), (_surface(),), (evidence,))
                self.assertEqual(advisor.surface_calls[0], ())

    def test_invalid_review_policy_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            RuleBasedVulnerabilityRouter(review_policy="unknown")

    def test_advisor_cannot_overwrite_a_rule_decision(self) -> None:
        evidence = Evidence(
            evidence_id="evi-reflection",
            run_id="run-1",
            surface_id="surface-search",
            created_by="fixture",
            evidence_type="observation",
            observation={"type": "reflection", "parameter": "q"},
        )
        advisor = _StubAdvisor(
            RouteSuggestion(
                surface_id="surface-search",
                vulnerability_type="XSS",
                agent_type="browser_xss_analyzer",
            )
        )
        router = RuleBasedVulnerabilityRouter(
            id_factory=iter(("1", "2", "3")).__next__, advisor=advisor
        )

        decisions = router.route(_run(), (_surface(),), (evidence,))

        xss = next(
            decision
            for decision in decisions
            if decision.candidate.vulnerability_type == "XSS"
        )
        # 규칙이 만든 Evidence 근거와 priority가 그대로 남는다.
        self.assertEqual(xss.candidate.assigned_agent, "xss_analyzer")
        self.assertEqual(xss.candidate.evidence_ids, ("evi-reflection",))
        self.assertEqual(xss.priority, 0.8)

    def test_advisor_failure_still_returns_the_rule_decisions(self) -> None:
        router = RuleBasedVulnerabilityRouter(
            id_factory=iter(("1", "2", "3")).__next__, advisor=_RaisingAdvisor()
        )

        decisions = router.route(_run(), (_surface(),), ())

        self.assertEqual(
            [decision.candidate.vulnerability_type for decision in decisions],
            ["XSS", "SQLi"],
        )

    def test_unregistered_agent_suggestion_is_dropped_item_by_item(self) -> None:
        """미등록 Agent 제안만 버리고 같은 응답의 유효한 제안은 살린다."""

        advisor = _StubAdvisor(
            RouteSuggestion(
                surface_id="surface-search",
                vulnerability_type="SSRF",
                agent_type="ssrf_analyzer",
            ),
            RouteSuggestion(
                surface_id="surface-search",
                vulnerability_type="Path Traversal",
                agent_type="path_traversal_analyzer",
            ),
        )
        router = RuleBasedVulnerabilityRouter(
            id_factory=iter(("1", "2", "3")).__next__, advisor=advisor
        )

        decisions = router.route(_run(), (_surface(),), ())

        self.assertEqual(
            sorted(
                decision.candidate.vulnerability_type for decision in decisions
            ),
            ["Path Traversal", "SQLi", "XSS"],
        )

    def test_suggestion_for_another_run_surface_is_dropped(self) -> None:
        advisor = _StubAdvisor(
            RouteSuggestion(
                surface_id="surface-from-another-run",
                vulnerability_type="Path Traversal",
                agent_type="path_traversal_analyzer",
            )
        )
        router = RuleBasedVulnerabilityRouter(
            id_factory=iter(("1", "2", "3")).__next__, advisor=advisor
        )

        decisions = router.route(_run(), (_surface(),), ())

        self.assertEqual(
            [decision.candidate.vulnerability_type for decision in decisions],
            ["XSS", "SQLi"],
        )

    def test_advisor_cannot_bypass_the_state_changing_form_guard(self) -> None:
        advisor = _StubAdvisor(
            RouteSuggestion(
                surface_id="surface-search",
                vulnerability_type="XSS",
                agent_type="xss_analyzer",
            )
        )
        router = RuleBasedVulnerabilityRouter(
            id_factory=iter(("1", "2", "3")).__next__, advisor=advisor
        )

        decisions = router.route(
            _run(),
            (_surface(parameters=("password_new", "password_conf", "Change")),),
            (),
        )

        self.assertEqual(decisions, ())

    def test_advisor_cannot_turn_a_generic_post_into_path_traversal_probe(self) -> None:
        advisor = _StubAdvisor(
            RouteSuggestion(
                surface_id="surface-search",
                vulnerability_type="Path Traversal",
                agent_type="path_traversal_analyzer",
            )
        )
        router = RuleBasedVulnerabilityRouter(advisor=advisor)

        decisions = router.route(
            _run(),
            (_surface(method="POST", parameters=("comment", "rating")),),
            (),
        )

        self.assertEqual(decisions, ())
        self.assertEqual(router.last_advisor_outcomes, ((0, "incompatible_surface"),))

    def test_http_agent_is_not_given_a_client_route_surface(self) -> None:
        """fragment 표면을 HTTP Analyzer로 보내면 같은 루트 문서만 받고 예산을 쓴다."""

        spa = Surface(
            surface_id="surface-spa",
            run_id="run-1",
            url="http://localhost/#/search?q=1",
            method="GET",
            parameters=("q",),
        )
        advisor = _StubAdvisor(
            RouteSuggestion(
                surface_id="surface-spa",
                vulnerability_type="SQLi",
                agent_type="sqli_analyzer",
            )
        )
        router = RuleBasedVulnerabilityRouter(
            id_factory=iter(("1", "2", "3")).__next__, advisor=advisor
        )

        decisions = router.route(_run(), (spa,), ())

        self.assertNotIn(
            "SQLi",
            [decision.candidate.vulnerability_type for decision in decisions],
        )


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
            ["XSS", "SQLi"],
        )
        tasks = app.stores.tasks.list_by_run(run.run_id)
        analysis_task = tasks[-1].envelope
        self.assertEqual(analysis_task.agent_type, "xss_analyzer")
        self.assertEqual(analysis_task.surface_id, "surface-search")
        self.assertEqual(analysis_task.target_url, "http://localhost/search")
        self.assertEqual(analysis_task.allowed_tools, ("http_get",))


class _StubLlmClient:
    """호출되지 않아야 하는 자리에도 안전하게 넣을 수 있는 LlmClient 대역."""

    def complete(self, request):  # pragma: no cover - 배선 테스트는 호출하지 않는다
        raise AssertionError("bootstrap wiring test must not call the llm")


class StandardRouterWiringTests(unittest.TestCase):
    """bootstrap이 Advisor를 규칙과 같은 필터 아래에서 배선하는지 검증한다."""

    def test_router_has_no_advisor_unless_requested(self) -> None:
        self.assertIsNone(standard_router()._advisor)
        self.assertIsNone(standard_router(llm_client=_StubLlmClient())._advisor)

    def test_requesting_an_advisor_without_a_client_fails_at_wiring_time(self) -> None:
        """키가 없는데 조용히 규칙만 도는 경로를 Run 시작 전에 막는다."""

        with self.assertRaises(LlmCredentialsMissing):
            standard_router(router_advisor=True)

    def test_advisor_is_built_when_a_client_is_available(self) -> None:
        router = standard_router(llm_client=_StubLlmClient(), router_advisor=True)

        self.assertIsInstance(router._advisor, LlmRouterAdvisor)

    def test_advisor_inherits_the_vulnerability_type_filter(self) -> None:
        """--vuln xss로 만든 Router의 Advisor는 SQLi를 제안할 수 없어야 한다."""

        router = standard_router(
            ("XSS",), llm_client=_StubLlmClient(), router_advisor=True
        )

        offered = {choice.vulnerability_type for choice in router._advisor._analyzers}
        self.assertEqual(offered, {"XSS"})

    def test_advisor_only_offers_implemented_analyzers(self) -> None:
        router = standard_router(llm_client=_StubLlmClient(), router_advisor=True)

        agents = {choice.agent_type for choice in router._advisor._analyzers}
        self.assertTrue(agents.issubset(set(IMPLEMENTED_ANALYZERS)))

    def test_client_route_flag_is_carried_from_the_surface_rules(self) -> None:
        """XSS는 담당 Analyzer가 둘이므로 표면 모양 구분이 함께 넘어가야 한다."""

        router = standard_router(
            ("XSS",), llm_client=_StubLlmClient(), router_advisor=True
        )

        by_agent = {
            choice.agent_type: choice.client_route
            for choice in router._advisor._analyzers
        }
        self.assertIs(by_agent["xss_analyzer"], False)
        self.assertIs(by_agent["browser_xss_analyzer"], True)

    def test_no_advisor_when_the_filter_removes_every_rule(self) -> None:
        """제안할 유형이 없으면 Advisor를 만들지 않는다. 구성 오류가 아니라 선택의 결과다."""

        router = standard_router(
            ("Nonexistent",), llm_client=_StubLlmClient(), router_advisor=True
        )

        self.assertIsNone(router._advisor)


if __name__ == "__main__":
    unittest.main()
