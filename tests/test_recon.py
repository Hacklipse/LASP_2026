"""ReconAgent가 HTML 응답에서 Surface와 라우팅용 Observation을 추출하는지 검증."""

from __future__ import annotations

import unittest

from hacklipse.adapters.memory import InMemoryEvidenceStore, InMemorySurfaceStore
from hacklipse.adapters.recon import ReconAgent
from hacklipse.adapters.routing import RuleBasedVulnerabilityRouter
from hacklipse.application.errors import AgentContractError, WorkflowExecutionError
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    AgentResultStatus,
    Evidence,
    ExecutionRequest,
    ExecutionResult,
    RunRequest,
    Run,
    RunScope,
    TaskEnvelope,
)

_SAMPLE_HTML = """
<html><body>
<form action="/login.php" method="POST">
  <input type="text" name="username">
  <input type="password" name="password">
</form>
<a href="/vulnerabilities/fi/?page=include.php">file inclusion</a>
<a href="/about.php">about</a>
</body></html>
"""


class _FakeCollector:
    """RuntimeEvidenceCollector.collect()를 흉내 내는 결정적 테스트 대역."""

    def __init__(self, evidence_store, *, body: str | None = _SAMPLE_HTML) -> None:
        self._evidence = evidence_store
        self._body = body
        self.calls: list[tuple[str, str]] = []
        self.credential_refs: list[str | None] = []

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
        del timeout_seconds
        self.calls.append((run_id, target_url))
        self.credential_refs.append(credential_ref)
        evidence_id = f"evi-fetch-{task_id}-{len(self.calls)}"
        self._evidence.append(
            Evidence(
                evidence_id=evidence_id,
                run_id=run_id,
                surface_id=spec.surface_id,
                created_by="http_execution_runtime:http_get",
                evidence_type="http_response",
                observation={"type": "http_response", "status": 200, "body": self._body},
            )
        )
        return evidence_id


def _make_agent(*, body: str | None = _SAMPLE_HTML):
    evidence_store = InMemoryEvidenceStore()
    surface_store = InMemorySurfaceStore()
    collector = _FakeCollector(evidence_store, body=body)
    counter = iter(range(10_000))
    agent = ReconAgent(
        collector=collector,
        evidence_store=evidence_store,
        surface_store=surface_store,
        id_factory=lambda: str(next(counter)),
    )
    return agent, evidence_store, surface_store


def _task(
    run_id: str,
    target_url: str,
    *,
    allowed_tools=("http_get",),
    credential_ref: str | None = None,
) -> TaskEnvelope:
    return TaskEnvelope(
        task_id=f"task-{run_id}",
        run_id=run_id,
        agent_type="recon",
        target_url=target_url,
        allowed_tools=allowed_tools,
        request_budget=5,
        credential_ref=credential_ref,
    )


class ReconAgentTests(unittest.TestCase):
    def test_extracts_form_and_link_surfaces(self) -> None:
        agent, _, surfaces = _make_agent()
        result = agent.handle(_task("run-1", "http://localhost/index.php"))

        self.assertEqual(result.status, AgentResultStatus.COMPLETED)
        stored = surfaces.list_by_run("run-1")
        urls = {surface.url for surface in stored}
        self.assertIn("http://localhost/login.php", urls)
        self.assertIn("http://localhost/vulnerabilities/fi/", urls)
        self.assertIn("http://localhost/about.php", urls)

        login = next(surface for surface in stored if surface.url == "http://localhost/login.php")
        self.assertEqual(login.method, "POST")
        self.assertEqual(set(login.parameters), {"username", "password"})
        self.assertEqual(set(result.surface_ids), {surface.surface_id for surface in stored})

    def test_flags_file_like_parameter_found_in_a_link(self) -> None:
        agent, evidence, _ = _make_agent()
        result = agent.handle(_task("run-2", "http://localhost/index.php"))

        observations = [item.observation for item in evidence.list_by_run("run-2")]
        self.assertTrue(
            any(
                observation.get("type") == "url_or_file_parameter"
                and observation.get("parameter") == "page"
                for observation in observations
            )
        )
        self.assertEqual(set(result.new_evidence_ids), {item.evidence_id for item in evidence.list_by_run("run-2")})

    def test_flags_file_like_parameter_on_the_fetched_url_itself(self) -> None:
        # DVWA류 타겟은 링크가 아니라 요청한 URL 자체에 취약 파라미터가 있다.
        agent, evidence, surfaces = _make_agent(body="<html><body>no links here</body></html>")
        agent.handle(_task("run-3", "http://localhost/vulnerabilities/fi/?page=include.php"))

        root = next(
            surface
            for surface in surfaces.list_by_run("run-3")
            if surface.url == "http://localhost/vulnerabilities/fi/"
        )
        self.assertEqual(root.parameters, ("page",))
        observations = [item.observation for item in evidence.list_by_run("run-3")]
        self.assertTrue(any(o.get("type") == "url_or_file_parameter" for o in observations))

    def test_extracts_numeric_rest_path_as_an_object_identifier(self) -> None:
        body = '<html><body><a href="/users/17">profile</a></body></html>'
        agent, _, surfaces = _make_agent(body=body)

        agent.handle(_task("run-path", "http://localhost/index.php"))

        profile = next(
            surface
            for surface in surfaces.list_by_run("run-path")
            if surface.url == "http://localhost/users/17"
        )
        self.assertEqual(profile.path_identifier, "user_id")
        self.assertEqual(profile.path_identifier_index, 2)
        self.assertEqual(profile.observed_path_identifier, "17")

        decisions = RuleBasedVulnerabilityRouter(
            id_factory=iter(str(index) for index in range(100)).__next__
        ).route(
            Run(
                run_id="run-path",
                target_url="http://localhost/index.php",
                scope=RunScope(allowed_hosts=frozenset({"localhost"})),
                policy_profile="safe",
                request_budget=10,
            ),
            (profile,),
            (),
        )
        self.assertEqual(
            [item.candidate.vulnerability_type for item in decisions],
            ["Access Control"],
        )

    def test_extracts_juice_shop_singular_basket_path_identifier(self) -> None:
        agent, _, surfaces = _make_agent(body="<html><body>basket</body></html>")

        agent.handle(_task("run-basket", "http://localhost/rest/basket/7"))

        basket = surfaces.list_by_run("run-basket")[0]
        self.assertEqual(basket.url, "http://localhost/rest/basket/7")
        self.assertEqual(basket.path_identifier, "basket_id")
        self.assertEqual(basket.path_identifier_index, 3)
        self.assertEqual(basket.observed_path_identifier, "7")

    def test_missing_target_url_is_a_contract_error(self) -> None:
        agent, *_ = _make_agent()
        task = TaskEnvelope(
            task_id="task-4",
            run_id="run-4",
            agent_type="recon",
            allowed_tools=("http_get",),
            request_budget=5,
        )
        with self.assertRaises(AgentContractError):
            agent.handle(task)

    def test_disallowed_tool_is_a_contract_error(self) -> None:
        agent, *_ = _make_agent()
        with self.assertRaises(AgentContractError):
            agent.handle(_task("run-5", "http://localhost/index.php", allowed_tools=()))

    def test_non_textual_or_empty_body_yields_only_the_root_surface(self) -> None:
        agent, _, surfaces = _make_agent(body=None)
        result = agent.handle(_task("run-6", "http://localhost/index.php"))

        self.assertEqual(len(surfaces.list_by_run("run-6")), 1)
        self.assertEqual(len(result.surface_ids), 1)


class _StaticHtmlRuntime:
    """실제 네트워크 없이 고정된 HTML을 http_response로 반환하는 Runtime 대역."""

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={"type": "http_response", "status": 200, "body": _SAMPLE_HTML},
        )


class ReconDrivesRoutingTests(unittest.TestCase):
    """완료 기준: orchestrator.start()가 RECON -> ROUTE를 통과하고 candidate_ids가 채워진다."""

    def test_recon_alone_produces_routable_candidates(self) -> None:
        # Analysis Agent(Phase 6)는 아직 없으므로 ANALYZE에서 AgentUnavailable로 멈춘다.
        # 완료 기준은 그 앞 단계 — RECON -> ROUTE가 candidate_ids를 채우는지만 확인한다.
        app = build_local_application(agents={}, runtime=_StaticHtmlRuntime())
        app.dispatcher.register(
            "recon",
            ReconAgent(
                collector=app.collector,
                evidence_store=app.stores.evidence,
                surface_store=app.stores.surfaces,
            ),
            allowed_tools=("http_get",),
        )

        with self.assertRaises(WorkflowExecutionError) as ctx:
            app.orchestrator.start(
                RunRequest(
                    target_url="http://localhost/vulnerabilities/fi/?page=include.php",
                    scope=RunScope(allowed_hosts=frozenset({"localhost"})),
                )
            )

        self.assertEqual(ctx.exception.phase, "analyze")
        run = app.stores.runs.get(ctx.exception.run_id)
        self.assertTrue(run.candidate_ids)
        self.assertTrue(run.surface_ids)


if __name__ == "__main__":
    unittest.main()


_SPA_HTML = """
<html><body><div id="app"></div>
<script src="/main.js"></script>
<script src="https://cdn.example.com/vendor.js"></script>
</body></html>
"""

_BUNDLE = """
class Api{
  search(e){ return this.http.get(`${this.host}/rest/products/search?q=${e}`) }
  question(e){ return fetch(`${this.host}/rest/user/security-question?email=${e}`) }
  list(){ return fetch("/api/Products") }
  share(){ return "https://twitter.com/intent/tweet?text=hi" }
}
"""

_PAGE_TWO = """
<html><body>
<a href="/deep.php?file=secret.txt">deep</a>
<a href="https://evil.example.com/out">external</a>
</body></html>
"""


class _RoutingCollector:
    """URL별로 다른 응답을 돌려주는 대역. 크롤링 동작 검증에 쓴다."""

    def __init__(self, evidence_store, bodies: dict[str, str]) -> None:
        self._evidence = evidence_store
        self._bodies = bodies
        self.calls: list[str] = []
        self.credential_refs: list[str | None] = []

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
        del timeout_seconds
        self.calls.append(target_url)
        self.credential_refs.append(credential_ref)
        evidence_id = f"evi-page-{len(self.calls)}"
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


def _crawling_agent(bodies: dict[str, str], **kwargs):
    evidence_store = InMemoryEvidenceStore()
    surface_store = InMemorySurfaceStore()
    collector = _RoutingCollector(evidence_store, bodies)
    counter = iter(range(10_000))
    agent = ReconAgent(
        collector=collector,
        evidence_store=evidence_store,
        surface_store=surface_store,
        id_factory=lambda: str(next(counter)),
        **kwargs,
    )
    return agent, collector, surface_store


class ReconCrawlTests(unittest.TestCase):
    def test_fetches_an_authenticated_additional_seed_with_the_recon_credential(
        self,
    ) -> None:
        agent, collector, surfaces = _crawling_agent(
            {
                "http://localhost/": "<html><body>spa</body></html>",
                "http://localhost/profile": (
                    '<form action="/profile" method="post">'
                    '<input name="username"></form>'
                ),
            },
            max_pages=2,
            seed_urls=("http://localhost/profile",),
        )

        agent.handle(
            _task(
                "run-seeds",
                "http://localhost/",
                credential_ref="juice-ssti-session",
            )
        )

        self.assertEqual(
            collector.calls,
            ["http://localhost/", "http://localhost/profile"],
        )
        self.assertEqual(
            collector.credential_refs,
            ["juice-ssti-session", "juice-ssti-session"],
        )
        profile = next(
            item
            for item in surfaces.list_by_run("run-seeds")
            if item.url == "http://localhost/profile" and item.method == "POST"
        )
        self.assertEqual(profile.parameters, ("username",))

    def test_follows_links_and_finds_surfaces_on_later_pages(self) -> None:
        agent, collector, surfaces = _crawling_agent(
            {
                "http://localhost/": '<html><a href="/two.php">two</a></html>',
                "http://localhost/two.php": _PAGE_TWO,
            }
        )
        agent.handle(_task("run-c1", "http://localhost/"))

        self.assertIn("http://localhost/two.php", collector.calls)
        urls = {surface.url for surface in surfaces.list_by_run("run-c1")}
        # 2단계 페이지에서만 발견되는 표면이다.
        self.assertIn("http://localhost/deep.php", urls)

    def test_does_not_crawl_other_origins(self) -> None:
        agent, collector, surfaces = _crawling_agent(
            {"http://localhost/": _PAGE_TWO}
        )
        agent.handle(_task("run-c2", "http://localhost/"))

        self.assertTrue(all("evil.example.com" not in url for url in collector.calls))
        urls = {surface.url for surface in surfaces.list_by_run("run-c2")}
        self.assertTrue(all("evil.example.com" not in url for url in urls))

    def test_discovers_endpoints_from_a_javascript_bundle(self) -> None:
        """SPA는 초기 HTML이 비어 있고 엔드포인트는 번들에 문자열로 남는다."""

        agent, collector, surfaces = _crawling_agent(
            {"http://localhost/": _SPA_HTML, "http://localhost/main.js": _BUNDLE}
        )
        agent.handle(_task("run-c3", "http://localhost/"))

        self.assertIn("http://localhost/main.js", collector.calls)
        # 다른 출처의 스크립트는 받지 않는다.
        self.assertTrue(all("cdn.example.com" not in url for url in collector.calls))

        found = {
            surface.url: surface.parameters
            for surface in surfaces.list_by_run("run-c3")
        }
        self.assertEqual(found.get("http://localhost/rest/products/search"), ("q",))
        self.assertEqual(
            found.get("http://localhost/rest/user/security-question"), ("email",)
        )
        self.assertIn("http://localhost/api/Products", found)
        # 외부 URL의 경로 조각이 표면으로 새어 들어오면 안 된다.
        self.assertTrue(all("twitter.com" not in url for url in found))

    def test_leaves_request_budget_for_later_phases(self) -> None:
        chain = {
            f"http://localhost/p{index}.php": f'<html><a href="/p{index + 1}.php">n</a></html>'
            for index in range(30)
        }
        chain["http://localhost/"] = '<html><a href="/p0.php">n</a></html>'
        agent, collector, _ = _crawling_agent(chain)

        task = _task("run-c4", "http://localhost/")  # request_budget=5
        agent.handle(task)

        # 정찰이 예산을 다 먹으면 Analysis가 아무 요청도 못 한다.
        self.assertLessEqual(len(collector.calls), task.request_budget // 2)

    def test_discovered_links_become_surfaces_even_when_not_crawled(self) -> None:
        agent, collector, surfaces = _crawling_agent(
            {"http://localhost/": _PAGE_TWO}, max_pages=1
        )
        agent.handle(_task("run-c5", "http://localhost/"))

        self.assertEqual(len(collector.calls), 1)
        urls = {surface.url for surface in surfaces.list_by_run("run-c5")}
        self.assertIn("http://localhost/deep.php", urls)
