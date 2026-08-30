"""ReconAgent가 HTML 응답에서 Surface와 라우팅용 Observation을 추출하는지 검증."""

from __future__ import annotations

import unittest

from hacklipse.adapters.memory import InMemoryEvidenceStore, InMemorySurfaceStore
from hacklipse.adapters.recon import ReconAgent
from hacklipse.application.errors import AgentContractError, WorkflowExecutionError
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    AgentResultStatus,
    Evidence,
    ExecutionRequest,
    ExecutionResult,
    RunRequest,
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

    def collect(self, run_id, target_url, spec, *, task_id, timeout_seconds=120.0):
        del timeout_seconds
        self.calls.append((run_id, target_url))
        evidence_id = f"evi-fetch-{task_id}"
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


def _task(run_id: str, target_url: str, *, allowed_tools=("http_get",)) -> TaskEnvelope:
    return TaskEnvelope(
        task_id=f"task-{run_id}",
        run_id=run_id,
        agent_type="recon",
        target_url=target_url,
        allowed_tools=allowed_tools,
        request_budget=5,
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
