"""LLM Router Advisor가 제안을 안전한 범위로만 좁히는지 검증."""

from __future__ import annotations

import unittest

from hacklipse.adapters.llm_router_advisor import (
    AnalyzerChoice,
    LlmRouterAdvisor,
)
from hacklipse.adapters.routing import RouteSuggestion, RuleBasedVulnerabilityRouter
from hacklipse.domain import Evidence, Run, RunScope, Surface
from hacklipse.ports.errors import (
    LlmCredentialsMissing,
    LlmRefused,
    LlmResponseFormatError,
    LlmTimeout,
    LlmTransportError,
)
from hacklipse.ports.llm import LlmResponse

ANALYZERS = (
    AnalyzerChoice("XSS", "xss_analyzer"),
    AnalyzerChoice("XSS", "browser_xss_analyzer", client_route=True),
    AnalyzerChoice("SQLi", "sqli_analyzer"),
    AnalyzerChoice("Path Traversal", "path_traversal_analyzer"),
)


class _FakeLlmClient:
    """정해진 payload를 돌려주고 받은 요청을 기록하는 LlmClient 대역."""

    def __init__(self, payload: object) -> None:
        self._payload = payload
        self.requests: list = []

    def complete(self, request):
        self.requests.append(request)
        return LlmResponse(payload=self._payload)


class _RaisingLlmClient:
    def __init__(self, error: Exception) -> None:
        self._error = error
        self.requests: list = []

    def complete(self, request):
        self.requests.append(request)
        raise self._error


def _run() -> Run:
    return Run(
        run_id="run-1",
        target_url="http://localhost/",
        scope=RunScope(allowed_hosts=frozenset({"localhost"})),
        policy_profile="safe",
        request_budget=10,
    )


def _surface(
    surface_id: str = "surface-import",
    *,
    url: str = "http://localhost/api/import",
    method: str = "POST",
    parameters: tuple[str, ...] = ("source",),
) -> Surface:
    return Surface(
        surface_id=surface_id,
        run_id="run-1",
        url=url,
        method=method,
        parameters=parameters,
    )


def _advise(llm, surfaces=None, evidence=(), routed=frozenset(), **kwargs):
    advisor = LlmRouterAdvisor(llm_client=llm, analyzers=ANALYZERS, **kwargs)
    return advisor.advise(
        _run(), surfaces if surfaces is not None else (_surface(),), evidence, routed
    )


class ValidSuggestionTests(unittest.TestCase):
    def test_offered_pairing_becomes_a_route_suggestion(self) -> None:
        llm = _FakeLlmClient(
            {
                "suggestions": [
                    {
                        "surface_id": "surface-import",
                        "vulnerability_type": "Path Traversal",
                        "reason": "서버가 외부 자원을 가져오는 기능으로 보인다",
                    }
                ]
            }
        )

        suggestions = _advise(llm)

        self.assertEqual(
            suggestions,
            (
                RouteSuggestion(
                    surface_id="surface-import",
                    vulnerability_type="Path Traversal",
                    agent_type="path_traversal_analyzer",
                    reason="서버가 외부 자원을 가져오는 기능으로 보인다",
                ),
            ),
        )

    def test_agent_type_is_resolved_from_the_surface_shape_not_the_llm(self) -> None:
        """XSS는 담당 Analyzer가 둘이므로 표면 모양이 Agent를 정한다."""

        spa = _surface(
            "surface-spa", url="http://localhost/#/search", method="GET", parameters=("q",)
        )
        llm = _FakeLlmClient(
            {
                "suggestions": [
                    {
                        "surface_id": "surface-spa",
                        "vulnerability_type": "XSS",
                        "reason": "DOM sink 가능성",
                    }
                ]
            }
        )

        suggestions = _advise(llm, surfaces=(spa,))

        self.assertEqual(suggestions[0].agent_type, "browser_xss_analyzer")

    def test_no_llm_call_when_rules_already_covered_every_type(self) -> None:
        llm = _FakeLlmClient({"suggestions": []})
        routed = frozenset(
            {
                ("surface-import", "XSS"),
                ("surface-import", "SQLi"),
                ("surface-import", "Path Traversal"),
            }
        )

        suggestions = _advise(llm, routed=routed)

        self.assertEqual(suggestions, ())
        self.assertEqual(llm.requests, [])


class ItemViolationTests(unittest.TestCase):
    """항목 하나가 잘못돼도 같은 응답의 유효한 제안은 살아남아야 한다."""

    def test_unknown_surface_id_is_dropped_but_valid_pairing_survives(self) -> None:
        llm = _FakeLlmClient(
            {
                "suggestions": [
                    {
                        "surface_id": "surface-not-offered",
                        "vulnerability_type": "SQLi",
                        "reason": "x",
                    },
                    {
                        "surface_id": "surface-import",
                        "vulnerability_type": "SQLi",
                        "reason": "y",
                    },
                ]
            }
        )

        suggestions = _advise(llm)

        self.assertEqual(
            [item.surface_id for item in suggestions], ["surface-import"]
        )

    def test_unknown_vulnerability_type_is_dropped(self) -> None:
        llm = _FakeLlmClient(
            {
                "suggestions": [
                    {
                        "surface_id": "surface-import",
                        "vulnerability_type": "SSRF",
                        "reason": "x",
                    }
                ]
            }
        )

        self.assertEqual(_advise(llm), ())

    def test_already_routed_pairing_is_not_suggested_again(self) -> None:
        llm = _FakeLlmClient(
            {
                "suggestions": [
                    {
                        "surface_id": "surface-import",
                        "vulnerability_type": "SQLi",
                        "reason": "x",
                    }
                ]
            }
        )

        suggestions = _advise(
            llm, routed=frozenset({("surface-import", "SQLi")})
        )

        self.assertEqual(suggestions, ())

    def test_duplicate_pairing_in_one_response_is_kept_once(self) -> None:
        llm = _FakeLlmClient(
            {
                "suggestions": [
                    {
                        "surface_id": "surface-import",
                        "vulnerability_type": "SQLi",
                        "reason": "first",
                    },
                    {
                        "surface_id": "surface-import",
                        "vulnerability_type": "SQLi",
                        "reason": "second",
                    },
                ]
            }
        )

        suggestions = _advise(llm)

        self.assertEqual(len(suggestions), 1)
        self.assertEqual(suggestions[0].reason, "first")

    def test_malformed_entry_is_dropped(self) -> None:
        llm = _FakeLlmClient(
            {
                "suggestions": [
                    "not-an-object",
                    {"surface_id": 7, "vulnerability_type": "SQLi", "reason": "x"},
                    {
                        "surface_id": "surface-import",
                        "vulnerability_type": "SQLi",
                        "reason": "ok",
                    },
                ]
            }
        )

        suggestions = _advise(llm)

        self.assertEqual([item.reason for item in suggestions], ["ok"])

    def test_server_agent_is_not_resolved_for_a_client_route_surface(self) -> None:
        spa = _surface(
            "surface-spa", url="http://localhost/#/search", method="GET", parameters=("q",)
        )
        llm = _FakeLlmClient(
            {
                "suggestions": [
                    {
                        "surface_id": "surface-spa",
                        "vulnerability_type": "SQLi",
                        "reason": "x",
                    }
                ]
            }
        )

        # SQLi를 맡는 Agent 중 fragment 표면을 다루는 것이 없으므로 해석되지 않는다.
        self.assertEqual(_advise(llm, surfaces=(spa,)), ())


class StructuralViolationTests(unittest.TestCase):
    """응답의 구조 자체가 깨지면 제안 전체를 버린다."""

    def test_non_object_payload_yields_no_suggestion(self) -> None:
        self.assertEqual(_advise(_FakeLlmClient(["nope"])), ())

    def test_missing_suggestions_key_yields_no_suggestion(self) -> None:
        self.assertEqual(_advise(_FakeLlmClient({"result": []})), ())

    def test_suggestions_that_are_not_a_list_yield_no_suggestion(self) -> None:
        self.assertEqual(_advise(_FakeLlmClient({"suggestions": {}})), ())


class TransportFailureTests(unittest.TestCase):
    def test_recoverable_llm_failures_yield_no_suggestion(self) -> None:
        for error in (
            LlmTimeout("timeout"),
            LlmTransportError("transport"),
            LlmResponseFormatError("format"),
            LlmRefused("refused"),
        ):
            with self.subTest(error=type(error).__name__):
                self.assertEqual(_advise(_RaisingLlmClient(error)), ())

    def test_missing_credentials_are_not_swallowed(self) -> None:
        """키 없이 배선한 것은 실행 중 장애가 아니라 구성 오류다."""

        with self.assertRaises(LlmCredentialsMissing):
            _advise(_RaisingLlmClient(LlmCredentialsMissing("no api key")))


class OfferSelectionTests(unittest.TestCase):
    def test_state_changing_form_is_never_offered(self) -> None:
        llm = _FakeLlmClient({"suggestions": []})

        _advise(
            llm,
            surfaces=(
                _surface(parameters=("password_new", "password_conf", "Change")),
            ),
        )

        self.assertEqual(llm.requests, [])

    def test_uncovered_surfaces_are_offered_before_partially_covered_ones(self) -> None:
        llm = _FakeLlmClient({"suggestions": []})
        surfaces = (
            _surface("surface-covered"),
            _surface("surface-bare"),
        )

        _advise(
            llm,
            surfaces=surfaces,
            routed=frozenset({("surface-covered", "SQLi")}),
            max_surfaces=1,
        )

        prompt = llm.requests[0].messages[0].content
        self.assertIn("surface-bare", prompt)
        self.assertNotIn("surface-covered", prompt)

    def test_offer_is_capped_to_bound_prompt_cost(self) -> None:
        llm = _FakeLlmClient({"suggestions": []})
        surfaces = tuple(_surface(f"surface-{index}") for index in range(10))

        _advise(llm, surfaces=surfaces, max_surfaces=3)

        prompt = llm.requests[0].messages[0].content
        self.assertEqual(prompt.count("surface_id=surface-"), 3)


class PromptHygieneTests(unittest.TestCase):
    def test_prompt_carries_only_sanitized_surface_metadata(self) -> None:
        llm = _FakeLlmClient({"suggestions": []})
        evidence = Evidence(
            evidence_id="evi-1",
            run_id="run-1",
            surface_id="surface-import",
            created_by="recon",
            evidence_type="observation",
            observation={"type": "url_or_file_parameter", "parameter": "source"},
        )

        _advise(llm, evidence=(evidence,))

        prompt = llm.requests[0].messages[0].content
        self.assertIn("surface-import", prompt)
        self.assertIn("/api/import", prompt)
        self.assertIn("POST", prompt)
        self.assertIn("source", prompt)
        self.assertIn("url_or_file_parameter", prompt)
        self.assertIn("Path Traversal", prompt)

    def test_prompt_never_carries_observed_query_values_or_secrets(self) -> None:
        llm = _FakeLlmClient({"suggestions": []})
        surface = Surface(
            surface_id="surface-profile",
            run_id="run-1",
            url="http://localhost/profile",
            method="GET",
            parameters=("token", "action"),
            observed_query=(("token", "s3cr3t-session-value"), ("action", "View Profile")),
        )

        _advise(llm, surfaces=(surface,))

        prompt = llm.requests[0].messages[0].content
        # 파라미터 이름은 판단에 필요하므로 남는다.
        self.assertIn("token", prompt)
        # 관측된 값은 어느 것도 실리지 않는다.
        for forbidden in ("s3cr3t-session-value", "View Profile", "Cookie", "Authorization"):
            self.assertNotIn(forbidden, prompt)


class RouterIntegrationTests(unittest.TestCase):
    """Advisor를 실제 Router에 꽂았을 때 규칙 판정이 보존되는지 확인한다."""

    def test_advisor_output_survives_the_router_guards(self) -> None:
        llm = _FakeLlmClient(
            {
                "suggestions": [
                    {
                        "surface_id": "surface-search",
                        "vulnerability_type": "Path Traversal",
                        "reason": "파일 경로처럼 보이는 파라미터",
                    }
                ]
            }
        )
        advisor = LlmRouterAdvisor(llm_client=llm, analyzers=ANALYZERS)
        router = RuleBasedVulnerabilityRouter(
            id_factory=iter(("1", "2", "3")).__next__, advisor=advisor
        )
        surface = Surface(
            surface_id="surface-search",
            run_id="run-1",
            url="http://localhost/search",
            method="GET",
            parameters=("q",),
        )

        decisions = router.route(_run(), (surface,), ())

        self.assertEqual(
            [decision.candidate.vulnerability_type for decision in decisions],
            ["XSS", "SQLi", "Path Traversal"],
        )
        advised = decisions[-1]
        self.assertEqual(advised.candidate.assigned_agent, "path_traversal_analyzer")
        self.assertEqual(advised.candidate.evidence_ids, ())


if __name__ == "__main__":
    unittest.main()
