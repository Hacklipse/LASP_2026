"""ReconAgent + Planner 통합 — 실제 pending 반영, 방문 순서, fallback, 재사용을 검증한다.

`tests/test_recon.py`는 `planner=None`일 때의 결정적 동작만 다룬다(회귀 없음, 이번
작업으로 수정하지 않았다). 여기서는 `planner`가 주어졌을 때 실제로 어떤 URL을 방문하고
어떤 URL을 건너뛰는지, Evidence에 무엇이 남는지를 검증한다.
"""

from __future__ import annotations

import unittest
from dataclasses import replace
from uuid import uuid4

from hacklipse.adapters.llm_recon_planner import LlmReconPlanner, ReconPlan
from hacklipse.adapters.memory import InMemoryEvidenceStore, InMemorySurfaceStore
from hacklipse.adapters.path_traversal_analysis import (
    UNLINKED_RENDER_PARAMETER_OBSERVATION,
)
from hacklipse.adapters.recon import ReconAgent
from hacklipse.domain import AgentResultStatus, Evidence, TaskEnvelope
from hacklipse.ports.errors import LlmTimeout
from hacklipse.ports.llm import LlmRequest, LlmResponse

_SPA_ROOT = '<html><body><div id="app"></div><script src="/main.js"></script></body></html>'
_NAV_BUNDLE = (
    "class Nav {\n"
    "  toA(){ window.location.assign('/a') }\n"
    "  toB(){ window.location.assign('/b') }\n"
    "  toC(){ window.location.assign('/c') }\n"
    "}\n"
)
_EMPTY_PAGE = "<html></html>"

_BODIES = {
    "http://localhost/": _SPA_ROOT,
    "http://localhost/main.js": _NAV_BUNDLE,
    "http://localhost/a": _EMPTY_PAGE,
    "http://localhost/b": _EMPTY_PAGE,
    "http://localhost/c": _EMPTY_PAGE,
}


class _RoutingCollector:
    """URL별로 다른 응답을 돌려주는 대역. tests/test_recon.py의 것과 동일한 모양."""

    def __init__(self, evidence_store, bodies: dict[str, str]) -> None:
        self._evidence = evidence_store
        self._bodies = bodies
        self.calls: list[str] = []

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
        del timeout_seconds, credential_ref
        self.calls.append(target_url)
        # 여러 Collector 인스턴스가 같은 evidence_store를 공유하는 재개 테스트에서도
        # ID가 안 겹치게 uuid를 쓴다(len(self.calls) 기준이면 인스턴스마다 1부터 다시
        # 세어 충돌한다).
        evidence_id = f"evi-page-{uuid4()}"
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
                    "body": self._bodies.get(target_url, "<html></html>"),
                },
            )
        )
        return evidence_id


class _FakeLlmClient:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload
        self.requests: list[LlmRequest] = []

    def complete(self, request: LlmRequest) -> LlmResponse:
        self.requests.append(request)
        return LlmResponse(payload=self.payload, model="fake")


class _RaisingLlmClient:
    def __init__(self, error: Exception) -> None:
        self._error = error

    def complete(self, request: LlmRequest) -> LlmResponse:
        raise self._error


class _OrderingPlanner:
    """실제 LLM 없이 path로 지정한 순서를 그대로 ReconPlan으로 만드는 대역."""

    def __init__(self, order_by_path: tuple[str, ...], *, action: str = "continue") -> None:
        self._order_by_path = order_by_path
        self._action = action
        self.calls: list[tuple[tuple, int]] = []

    def plan(self, *, task, candidates, remaining_budget):
        self.calls.append((candidates, remaining_budget))
        by_path = {candidate.path: candidate.surface_id for candidate in candidates}
        ranked = tuple(by_path[path] for path in self._order_by_path if path in by_path)
        return ReconPlan(
            ranked_surface_ids=ranked,
            action=self._action,
            reason="test ordering",
            dropped_for_budget=(),
            rejected_surface_ids=(),
            source="llm",
        )


class _ForeignIdPlanner:
    """pending에 없는 surface_id를 반환하는 대역 — 외부 ID 차단을 검증한다."""

    def plan(self, *, task, candidates, remaining_budget):
        return ReconPlan(
            ranked_surface_ids=("surface-does-not-exist",),
            action="continue",
            reason="hallucinated id",
            dropped_for_budget=(),
            rejected_surface_ids=(),
            source="llm",
        )


def _task(run_id: str, target_url: str, *, request_budget: int = 20) -> TaskEnvelope:
    return TaskEnvelope(
        task_id=f"task-{run_id}",
        run_id=run_id,
        agent_type="recon",
        target_url=target_url,
        allowed_tools=("http_get",),
        request_budget=request_budget,
    )


def _agent(evidence_store, surface_store, *, planner=None, max_pages: int = 6):
    collector = _RoutingCollector(evidence_store, _BODIES)
    counter = iter(range(10_000))
    agent = ReconAgent(
        collector=collector,
        evidence_store=evidence_store,
        surface_store=surface_store,
        id_factory=lambda: str(next(counter)),
        planner=planner,
        max_pages=max_pages,
    )
    return agent, collector


def _plan_evidence(evidence_store, run_id: str):
    return next(
        item
        for item in evidence_store.list_by_run(run_id)
        if item.observation.get("type") == "recon_plan"
    )


class HybridReconOrderingTests(unittest.TestCase):
    def test_planner_reorders_the_second_round_of_visits(self) -> None:
        evidence_store = InMemoryEvidenceStore()
        surface_store = InMemorySurfaceStore()
        planner = _OrderingPlanner(order_by_path=("/c", "/a", "/b"))
        agent, collector = _agent(evidence_store, surface_store, planner=planner)

        agent.handle(_task("run-order", "http://localhost/"))

        # 첫 두 요청(root, main.js)은 결정적이고, 그 뒤 Planner가 고른 순서로 이어진다.
        self.assertEqual(
            collector.calls,
            [
                "http://localhost/",
                "http://localhost/main.js",
                "http://localhost/c",
                "http://localhost/a",
                "http://localhost/b",
            ],
        )

    def test_a_document_surface_the_planner_omitted_is_still_visited(self) -> None:
        """Planner는 서버 문서 표면의 순서만 바꿀 수 있고 제외하지는 못한다.

        제외를 허용하면 그 URL의 HTML 폼이 파싱되지 않아 POST Surface와 렌더 파라미터
        신호가 사라진다. 실제로 /dataerasure가 순위에서 빠져 Path Traversal을 통째로
        놓친 적이 있다.
        """

        evidence_store = InMemoryEvidenceStore()
        surface_store = InMemorySurfaceStore()
        planner = _OrderingPlanner(order_by_path=("/c", "/a"))
        agent, collector = _agent(evidence_store, surface_store, planner=planner)

        agent.handle(_task("run-skip-b", "http://localhost/"))

        self.assertIn("http://localhost/b", collector.calls)
        urls = {surface.url for surface in surface_store.list_by_run("run-skip-b")}
        self.assertIn("http://localhost/b", urls)

    def test_stop_action_still_visits_protected_document_surfaces(self) -> None:
        """stop은 새 탐색만 멈추고 이미 확보한 문서 표면까지 버리지는 않는다."""

        evidence_store = InMemoryEvidenceStore()
        surface_store = InMemorySurfaceStore()
        planner = _OrderingPlanner(order_by_path=("/a", "/b", "/c"), action="stop")
        agent, collector = _agent(evidence_store, surface_store, planner=planner)

        agent.handle(_task("run-stop", "http://localhost/"))

        self.assertEqual(
            collector.calls,
            [
                "http://localhost/",
                "http://localhost/main.js",
                "http://localhost/a",
                "http://localhost/b",
                "http://localhost/c",
            ],
        )

    def test_a_surface_id_the_planner_never_received_is_never_visited(self) -> None:
        evidence_store = InMemoryEvidenceStore()
        surface_store = InMemorySurfaceStore()
        agent, collector = _agent(
            evidence_store, surface_store, planner=_ForeignIdPlanner()
        )

        agent.handle(_task("run-foreign-id", "http://localhost/"))

        # 지어낸 ID는 새 URL을 만들지 못한다. 방문한 것은 코드가 이미 알고 있던
        # 표면뿐이고, 그중 보호 대상은 순위에서 빠졌어도 그대로 남는다.
        self.assertEqual(
            set(collector.calls),
            {
                "http://localhost/",
                "http://localhost/main.js",
                "http://localhost/a",
                "http://localhost/b",
                "http://localhost/c",
            },
        )

    def test_llm_failure_falls_back_to_the_original_fifo_visit_order(self) -> None:
        evidence_store = InMemoryEvidenceStore()
        surface_store = InMemorySurfaceStore()
        planner = LlmReconPlanner(llm_client=_RaisingLlmClient(LlmTimeout("slow")))
        agent, collector = _agent(evidence_store, surface_store, planner=planner)

        result = agent.handle(_task("run-llm-timeout", "http://localhost/"))

        self.assertEqual(
            collector.calls,
            [
                "http://localhost/",
                "http://localhost/main.js",
                "http://localhost/a",
                "http://localhost/b",
                "http://localhost/c",
            ],
        )
        self.assertEqual(result.message, "recon_planner:fallback:timeout")

    def test_visits_never_exceed_the_recon_page_budget(self) -> None:
        evidence_store = InMemoryEvidenceStore()
        surface_store = InMemorySurfaceStore()
        # max_pages=3: root + main.js가 이미 2를 쓰므로 세 번째만 더 방문할 수 있다.
        planner = _OrderingPlanner(order_by_path=("/a", "/b", "/c"))
        agent, collector = _agent(
            evidence_store, surface_store, planner=planner, max_pages=3
        )

        agent.handle(_task("run-budget", "http://localhost/"))

        self.assertEqual(len(collector.calls), 3)


class HybridReconProtectedSurfaceTests(unittest.TestCase):
    """Planner가 문서 표면을 빠뜨려도 POST Surface와 렌더 파라미터 신호가 남는지 본다.

    순서 검증만으로는 부족하다. 실제 회귀는 `/dataerasure`가 순위에서 빠지면서 HTML 폼이
    파싱되지 않아 `POST /dataerasure`와 `layout` 신호가 통째로 사라진 것이었고, 그 결과
    Path Traversal이 Analyzer까지 가지도 못했다.
    """

    _FORM_PAGE = (
        "<html><body><form method='post' action='/erase'>"
        "<input name='email'><input name='securityAnswer'>"
        "</form></body></html>"
    )
    _BUNDLE = (
        "class Nav {\n"
        "  toErase(){ window.location.assign('/erase') }\n"
        "  toOther(){ window.location.assign('/other') }\n"
        "}\n"
    )
    _BODIES = {
        "http://localhost/": _SPA_ROOT,
        "http://localhost/main.js": _BUNDLE,
        "http://localhost/erase": _FORM_PAGE,
        "http://localhost/other": _EMPTY_PAGE,
    }

    def _run(self, planner):
        evidence_store = InMemoryEvidenceStore()
        surface_store = InMemorySurfaceStore()
        collector = _RoutingCollector(evidence_store, self._BODIES)
        counter = iter(range(10_000))
        agent = ReconAgent(
            collector=collector,
            evidence_store=evidence_store,
            surface_store=surface_store,
            id_factory=lambda: str(next(counter)),
            planner=planner,
            max_pages=6,
        )
        agent.handle(_task("run-protected", "http://localhost/"))
        return evidence_store, surface_store, collector

    def test_omitted_document_surface_still_yields_its_post_form_and_signal(
        self,
    ) -> None:
        # Planner가 /erase를 순위에서 빼도 방문·파싱돼야 한다.
        planner = _OrderingPlanner(order_by_path=("/other",))

        evidence_store, surface_store, collector = self._run(planner)

        self.assertIn("http://localhost/erase", collector.calls)
        post_surfaces = [
            surface
            for surface in surface_store.list_by_run("run-protected")
            if surface.method.upper() == "POST"
        ]
        self.assertEqual(
            [surface.url for surface in post_surfaces], ["http://localhost/erase"]
        )
        self.assertEqual(post_surfaces[0].parameters, ("email", "securityAnswer"))
        signals = [
            item
            for item in evidence_store.list_by_run("run-protected")
            if item.observation.get("type") == UNLINKED_RENDER_PARAMETER_OBSERVATION
        ]
        self.assertTrue(signals, "layout 신호가 남아야 Router가 Candidate를 만든다")

    def test_stop_action_does_not_discard_the_form_signal(self) -> None:
        planner = _OrderingPlanner(order_by_path=("/other",), action="stop")

        evidence_store, _, collector = self._run(planner)

        self.assertIn("http://localhost/erase", collector.calls)
        signals = [
            item
            for item in evidence_store.list_by_run("run-protected")
            if item.observation.get("type") == UNLINKED_RENDER_PARAMETER_OBSERVATION
        ]
        self.assertTrue(signals)


class HybridReconEvidenceTests(unittest.TestCase):
    def test_plan_evidence_records_every_required_field(self) -> None:
        evidence_store = InMemoryEvidenceStore()
        surface_store = InMemorySurfaceStore()
        planner = _OrderingPlanner(order_by_path=("/c",))
        agent, _ = _agent(evidence_store, surface_store, planner=planner)

        result = agent.handle(_task("run-plan-evidence", "http://localhost/"))

        plan_evidence = _plan_evidence(evidence_store, "run-plan-evidence")
        observation = plan_evidence.observation
        self.assertEqual(observation["action"], "continue")
        self.assertEqual(observation["selection_source"], "llm")
        self.assertIn("ranked_surface_ids", observation)
        self.assertIn("offered_surface_ids", observation)
        self.assertIn("dropped_for_budget", observation)
        self.assertIn("rejected_surface_ids", observation)
        self.assertEqual(len(observation["offered_surface_ids"]), 3)
        self.assertIn(plan_evidence.evidence_id, result.new_evidence_ids)
        self.assertEqual(result.message, "recon_planner:llm_success")


class HybridReconPlanReuseTests(unittest.TestCase):
    def test_a_matching_stored_plan_is_reused_without_calling_the_llm_again(
        self,
    ) -> None:
        llm = _FakeLlmClient(
            {"ranked_surface_ids": [], "action": "continue", "reason": "seed"}
        )

        evidence_store_1 = InMemoryEvidenceStore()
        surface_store_1 = InMemorySurfaceStore()
        agent1, _ = _agent(
            evidence_store_1, surface_store_1, planner=LlmReconPlanner(llm_client=llm)
        )
        agent1.handle(_task("run-reuse", "http://localhost/"))
        self.assertEqual(len(llm.requests), 1)
        stored_plan = _plan_evidence(evidence_store_1, "run-reuse")

        # 재개를 흉내낸다: 같은 run_id, 새 프로세스(=새 store 인스턴스)지만 결정적
        # crawl과 id_factory가 재실행되면 같은 순서로 같은 surface_id를 다시 만든다.
        # 그래서 이전에 만든 recon_plan Evidence를 같은 offered_surface_ids로 복사해
        # 두면, 실제 재개 상황에서 저장소가 그 Evidence를 이미 갖고 있는 것과 같다.
        evidence_store_2 = InMemoryEvidenceStore()
        surface_store_2 = InMemorySurfaceStore()
        evidence_store_2.append(replace(stored_plan, evidence_id="evi-seeded-plan"))
        agent2, _ = _agent(
            evidence_store_2, surface_store_2, planner=LlmReconPlanner(llm_client=llm)
        )
        agent2.handle(_task("run-reuse", "http://localhost/"))

        self.assertEqual(len(llm.requests), 1)

    def test_a_different_candidate_set_does_not_reuse_the_old_plan(self) -> None:
        llm = _FakeLlmClient(
            {"ranked_surface_ids": [], "action": "continue", "reason": "seed"}
        )

        evidence_store_1 = InMemoryEvidenceStore()
        surface_store_1 = InMemorySurfaceStore()
        agent1, _ = _agent(
            evidence_store_1, surface_store_1, planner=LlmReconPlanner(llm_client=llm)
        )
        agent1.handle(_task("run-stale-plan", "http://localhost/"))
        self.assertEqual(len(llm.requests), 1)
        stored_plan = _plan_evidence(evidence_store_1, "run-stale-plan")

        stale_observation = dict(stored_plan.observation)
        stale_observation["offered_surface_ids"] = ["surface-from-a-previous-crawl"]
        evidence_store_2 = InMemoryEvidenceStore()
        surface_store_2 = InMemorySurfaceStore()
        evidence_store_2.append(
            replace(
                stored_plan,
                evidence_id="evi-seeded-stale-plan",
                observation=stale_observation,
            )
        )
        agent2, _ = _agent(
            evidence_store_2, surface_store_2, planner=LlmReconPlanner(llm_client=llm)
        )
        agent2.handle(_task("run-stale-plan", "http://localhost/"))

        self.assertEqual(len(llm.requests), 2)

    def test_reuse_survives_a_real_restart_with_a_non_resetting_id_sequence(
        self,
    ) -> None:
        """실제 재시작을 흉내낸다: store는 그대로 남고, id_factory는 리셋되지 않는다.

        위 두 테스트는 같은 offered_surface_ids를 만들려고 두 Agent가 매번 0부터
        시작하는 독립된 counter를 썼다 — 실제로는 uuid4처럼 호출마다 다른 값이 나오는
        id_factory를 쓴다. surface_id가 URL마다 안정적으로 재사용되지 않으면, 카운터를
        이어 써도 offered_surface_ids가 재개 때마다 달라져 재사용이 절대 안 걸린다.
        """

        llm = _FakeLlmClient(
            {"ranked_surface_ids": [], "action": "continue", "reason": "seed"}
        )
        evidence_store = InMemoryEvidenceStore()
        surface_store = InMemorySurfaceStore()
        # 두 Agent가 같은 store를 공유하고, counter는 첫 번째 handle() 이후에도
        # 이어서 증가한다 — 재시작 후 다시 0부터 세는 것보다 훨씬 현실적이다.
        counter = iter(range(10_000))

        def make_agent():
            collector = _RoutingCollector(evidence_store, _BODIES)
            return (
                ReconAgent(
                    collector=collector,
                    evidence_store=evidence_store,
                    surface_store=surface_store,
                    id_factory=lambda: str(next(counter)),
                    planner=LlmReconPlanner(llm_client=llm),
                    max_pages=6,
                ),
                collector,
            )

        agent1, _ = make_agent()
        agent1.handle(_task("run-real-restart", "http://localhost/"))
        self.assertEqual(len(llm.requests), 1)

        agent2, _ = make_agent()  # 새 프로세스: 새 Agent 인스턴스, 같은 영속 store
        agent2.handle(_task("run-real-restart", "http://localhost/"))

        self.assertEqual(len(llm.requests), 1)


class HybridReconRegressionTests(unittest.TestCase):
    def test_planner_none_visits_in_the_original_fifo_order(self) -> None:
        evidence_store = InMemoryEvidenceStore()
        surface_store = InMemorySurfaceStore()
        agent, collector = _agent(evidence_store, surface_store, planner=None)

        result = agent.handle(_task("run-no-planner", "http://localhost/"))

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        self.assertEqual(
            collector.calls,
            [
                "http://localhost/",
                "http://localhost/main.js",
                "http://localhost/a",
                "http://localhost/b",
                "http://localhost/c",
            ],
        )
        self.assertFalse(
            [
                item
                for item in evidence_store.list_by_run("run-no-planner")
                if item.observation.get("type") == "recon_plan"
            ]
        )


if __name__ == "__main__":
    unittest.main()
