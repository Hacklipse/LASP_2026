"""ReconAgent가 HTML 응답에서 Surface와 라우팅용 Observation을 추출하는지 검증."""

from __future__ import annotations

import hashlib
import json
import threading
import unittest
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from hacklipse.adapters import HttpExecutionRuntime
from hacklipse.adapters.browser_recon import BrowserReconResult
from hacklipse.adapters.memory import InMemoryEvidenceStore, InMemorySurfaceStore
from hacklipse.adapters.recon import (
    ReconAgent, _data_navigation_links, _json_links_from_response, _parse_page,
    _openapi_html_document_urls, _script_ssrf_json_shapes,
    sanitize_url_reference, ssrf_destination_hints,
)
from hacklipse.adapters.routing import RuleBasedVulnerabilityRouter
from hacklipse.application.errors import AgentContractError, WorkflowExecutionError
from hacklipse.bootstrap import build_local_application, standard_router
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Evidence,
    ExecutionRequest,
    ExecutionResult,
    ProgressEventKind,
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


class SsrfJsonShapeTests(unittest.TestCase):
    def test_data_navigation_accepts_only_local_nonmutating_get(self) -> None:
        body = (
            '<button data-url="/articles/new">New</button>'
            '<button data-url="/articles/delete/1">Delete</button>'
            '<button data-url="https://elsewhere.example/collect">Elsewhere</button>'
            '<button data-url="/articles/edit" data-method="POST">Post</button>'
        )
        self.assertEqual(
            _data_navigation_links(body, "https://target.example/articles"),
            ("https://target.example/articles/new",),
        )

    def test_inline_fetch_shape_keeps_only_single_url_field(self) -> None:
        script = (
            "fetch('/api/preview',{method:'POST',headers:{'Content-Type':'application/json'},"
            "body:JSON.stringify({url:u})});"
            "fetch('/api/ping',{method:'POST',headers:{'Content-Type':'application/json'},"
            "body:JSON.stringify({target:h})});"
        )
        self.assertEqual(
            _script_ssrf_json_shapes(script, urlsplit("http://localhost/")),
            (("http://localhost/api/preview", "url"),),
        )

    def test_openapi_html_sampling_ignores_mutations_and_malformed_entries(self) -> None:
        document = {"openapi": "3.0.0", "paths": {
            "/console": {"get": {"responses": {
                "200": {"content": {"text/html": {}}},
            }}},
            "/write": {"post": {"responses": {
                "200": {"content": {"text/html": {}}},
            }}},
            "/broken": {"get": {"responses": ["bad"]}},
        }}
        evidence = Evidence(
            evidence_id="schema", run_id="run-1", surface_id=None,
            created_by="recon", evidence_type="http_response",
            observation={"status": 200, "content_type": "application/json",
                         "body": json.dumps(document)},
        )
        self.assertEqual(
            _openapi_html_document_urls(evidence, urlsplit("http://localhost/")),
            ("http://localhost/console",),
        )


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


class _RedirectCollector:
    """첫 URL은 redirect, 두 번째 URL은 HTML로 반환하는 테스트 대역."""

    def __init__(self, evidence_store) -> None:
        self._evidence = evidence_store
        self.calls: list[str] = []

    def collect(self, run_id, target_url, spec, *, task_id, **_kwargs):
        self.calls.append(target_url)
        evidence_id = f"evi-redirect-{len(self.calls)}"
        redirected = len(self.calls) == 1
        self._evidence.append(
            Evidence(
                evidence_id=evidence_id,
                run_id=run_id,
                surface_id=spec.surface_id,
                created_by="http_execution_runtime:http_get",
                evidence_type="http_redirect" if redirected else "http_response",
                observation=(
                    {
                        "type": "http_redirect",
                        "status": 302,
                        "location": "/landing?category=all",
                        "body": "",
                    }
                    if redirected
                    else {
                        "type": "http_response",
                        "status": 200,
                        "content_type": "text/html",
                        "body": "<html><body>landing</body></html>",
                    }
                ),
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
    def test_internal_destination_hints_store_only_origin_and_redacted_path(self) -> None:
        run_key = b"r" * 32
        body = (
            '"http://mailpit:8025/private/token/DEMO-SECRET?token=secret#fragment" '
            '"http://10.0.0.7:8080/health" "https://public.example/api" '
            '"mailpit:8025" "https://user:pass@localhost/api/status?key=hidden"'
        )
        hints = ssrf_destination_hints(body, run_key=run_key)
        self.assertEqual(
            {(item.destination_origin, item.path_hint) for item in hints},
            {
                ("http://10.0.0.7:8080", "/health"),
                ("http://mailpit:8025", "/private/token/{redacted}"),
                ("https://localhost", "/api/status"),
            },
        )
        serialized = json.dumps([
            {
                "destination_origin": item.destination_origin,
                "path_hint": item.path_hint,
                "destination_fingerprint": item.destination_fingerprint,
            }
            for item in hints
        ])
        for secret in ("DEMO-SECRET", "user", "pass", "hidden", "token=secret"):
            self.assertNotIn(secret, serialized)
        self.assertNotIn("destination_url", serialized)
        self.assertEqual(hints, ssrf_destination_hints(body, run_key=run_key))

    def test_destination_fingerprint_is_stable_only_for_the_same_run_key(self) -> None:
        raw_url = "http://mailpit:8025/private/token/DEMO-SECRET"
        first_key = b"a" * 32
        second_key = b"b" * 32

        first = sanitize_url_reference(raw_url, run_key=first_key)
        same_run = sanitize_url_reference(raw_url, run_key=first_key)
        another_run = sanitize_url_reference(raw_url, run_key=second_key)
        assert first is not None and same_run is not None and another_run is not None

        self.assertEqual(
            first.destination_fingerprint, same_run.destination_fingerprint,
        )
        self.assertNotEqual(
            first.destination_fingerprint, another_run.destination_fingerprint,
        )
        self.assertNotEqual(
            first.destination_fingerprint, hashlib.sha256(raw_url.encode()).hexdigest(),
        )
        self.assertNotIn("DEMO-SECRET", first.destination_fingerprint)

    def test_url_reference_sanitizer_returns_only_persistence_safe_fields(self) -> None:
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        jwt = (
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        raw_url = (
            "https://user:password@service.local/private/token/"
            f"{uuid}/{jwt}/%41%50%49%2d%4b%45%59"
            "?api_key=DEMO-SECRET#session-value"
        )

        hint = sanitize_url_reference(raw_url, run_key=b"k" * 32)

        self.assertIsNotNone(hint)
        assert hint is not None
        self.assertEqual(
            set(hint.__dataclass_fields__),
            {"destination_origin", "path_hint", "destination_fingerprint"},
        )
        self.assertEqual(hint.destination_origin, "https://service.local")
        self.assertEqual(
            hint.path_hint,
            "/private/token/{redacted}/{redacted}/{redacted}",
        )
        serialized = repr(hint)
        for secret in (
            "user", "password", uuid, jwt, "%41", "api_key", "DEMO-SECRET",
            "session-value",
        ):
            self.assertNotIn(secret, serialized)

    def test_url_reference_sanitizer_rejects_invalid_input_and_short_key(self) -> None:
        self.assertIsNone(
            sanitize_url_reference("file:///etc/passwd", run_key=b"k" * 32),
        )
        with self.assertRaises(ValueError):
            sanitize_url_reference("https://service.local/path", run_key=b"short")

    def test_url_reference_sanitizer_masks_secret_shaped_hostname_labels(self) -> None:
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        random_label = "QWxhZGRpbjpvcGVuU2VzYW1lMTIzNA"
        raw_url = f"https://{uuid}.{random_label}.internal/health"

        hint = sanitize_url_reference(raw_url, run_key=b"k" * 32)

        self.assertIsNotNone(hint)
        assert hint is not None
        self.assertEqual(
            hint.destination_origin,
            "https://redacted.redacted.internal",
        )
        self.assertEqual(hint.path_hint, "/health")
        self.assertNotIn(uuid, repr(hint))
        self.assertNotIn(random_label, repr(hint))

    def test_internal_destination_path_masks_secret_shaped_segments(self) -> None:
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        jwt = (
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        base64url = "QWxhZGRpbjpvcGVuU2VzYW1lMTIzNA"
        api_key = "AKIAIOSFODNN7EXAMPLE"
        encoded = "%44%45%4D%4F%2D%53%45%43%52%45%54"
        body = " ".join((
            f'"http://service.local/id/{uuid}"',
            f'"http://service.local/session/{jwt}"',
            f'"http://service.local/blob/{base64url}"',
            f'"http://service.local/key/{api_key}"',
            f'"http://service.local/encoded/{encoded}"',
            '"http://service.local/api/status"',
        ))

        hints = ssrf_destination_hints(body, run_key=b"r" * 32)

        self.assertEqual(
            {item.path_hint for item in hints},
            {
                "/id/{redacted}", "/session/{redacted}",
                "/blob/{redacted}", "/key/{redacted}",
                "/encoded/{redacted}", "/api/status",
            },
        )
        serialized = repr(hints)
        for secret in (uuid, jwt, base64url, api_key, encoded):
            self.assertNotIn(secret, serialized)

    def test_html_preloaded_script_chunks_enter_existing_script_frontier(self) -> None:
        _, _, sources, _ = _parse_page(
            '<script src="/app.js"></script>'
            '<link rel="modulepreload" href="/route.mjs">'
            '<link rel="preload" as="script" href="/lazy.js">'
            '<link rel="preload" as="style" href="/styles.css">'
            '<link rel="stylesheet" href="/other.js">'
            '<link rel="modulepreload" href="/route.mjs">',
            "http://localhost/",
        )
        self.assertEqual(sources, [
            "http://localhost/app.js", "http://localhost/route.mjs",
            "http://localhost/lazy.js",
        ])

    def test_browser_only_search_page_can_confirm_query_surface(self) -> None:
        base = "http://localhost"
        marker = "hacklipse-search-control"
        evidence_store = InMemoryEvidenceStore()
        surface_store = InMemorySurfaceStore()
        collector = _RoutingCollector(evidence_store, {
            base + "/": "<html></html>",
            base + "/search?q=" + marker: "<html>Results for: " + marker + "</html>",
        })

        class BrowserSearch:
            def discover(self, task, **kwargs):
                evidence_store.append(Evidence(
                    evidence_id="browser-search-response", run_id=task.run_id,
                    surface_id=None, created_by="execution_runtime:http_get",
                    evidence_type="http_response", observation={
                        "requested_url": base + "/search", "status": 200,
                        "content_type": "text/html", "body": "<html>Results for: </html>",
                    },
                ))
                return BrowserReconResult(("browser-search-response",), ())

        agent = ReconAgent(
            collector=collector, evidence_store=evidence_store,
            surface_store=surface_store, browser_recon=BrowserSearch(),
            max_pages=8,
        )
        agent.handle(replace(_task("browser-search", base + "/"), request_budget=30))
        self.assertIn(base + "/search?q=" + marker, collector.calls)
        self.assertTrue(any(
            surface.url == base + "/search" and surface.parameters == ("q",)
            for surface in surface_store.list_by_run("browser-search")
        ))

    def test_reuses_browser_fetched_javascript_without_another_request(self) -> None:
        evidence_store = InMemoryEvidenceStore()
        surface_store = InMemorySurfaceStore()
        collector = _FakeCollector(evidence_store, body="<html></html>")

        class BrowserScripts:
            def discover(self, task, **kwargs):
                del kwargs
                for suffix, media, body in (
                    ("/lazy.js", "application/javascript", 'fetch("/api/search?q=")'),
                    ("/data.json", "application/json", '{"html":"/false?q=","navigation":["/api/linked?q=one"]}'),
                ):
                    evidence_store.append(Evidence(
                        evidence_id="browser" + suffix,
                        run_id=task.run_id,
                        surface_id=None,
                        created_by="execution_runtime:http_get",
                        evidence_type="http_response",
                        observation={
                            "requested_url": "http://localhost" + suffix,
                            "content_type": media,
                            "status": 200,
                            "body": body,
                        },
                    ))
                return BrowserReconResult(
                    ("browser/lazy.js", "browser/data.json"),
                    ((None, {"type": "browser_recon_summary", "status": "completed"}),),
                )

        agent = ReconAgent(
            collector=collector,
            evidence_store=evidence_store,
            surface_store=surface_store,
            browser_recon=BrowserScripts(),
        )
        task = replace(_task("browser-script", "http://localhost/"), request_budget=80)
        agent.handle(task)

        self.assertEqual(
            [url for _, url in collector.calls[:4]],
            ["http://localhost/", "http://localhost/openapi.json",
             "http://localhost/swagger.json", "http://localhost/swagger/v1/swagger.json"],
        )
        self.assertEqual(len(collector.calls), 5)
        self.assertTrue(collector.calls[4][1].startswith("http://localhost/graphql?query="))
        surfaces = surface_store.list_by_run(task.run_id)
        self.assertTrue(any(
            surface.url == "http://localhost/api/search"
            and surface.parameters == ("q",)
            for surface in surfaces
        ))
        self.assertFalse(any(surface.url == "http://localhost/false" for surface in surfaces))
        self.assertTrue(any(
            surface.url == "http://localhost/api/linked"
            and surface.parameters == ("q",)
            for surface in surfaces
        ))
        summary = next(
            item.observation for item in evidence_store.list_by_run(task.run_id)
            if item.observation.get("type") == "browser_recon_summary"
        )
        self.assertEqual(summary["parsed_script_count"], 1)
        self.assertEqual(summary["parsed_json_link_response_count"], 1)

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

    def test_follows_same_origin_redirect_as_a_separate_scoped_request(self) -> None:
        evidence_store = InMemoryEvidenceStore()
        surface_store = InMemorySurfaceStore()
        collector = _RedirectCollector(evidence_store)
        counter = iter(range(100))
        agent = ReconAgent(
            collector=collector,
            evidence_store=evidence_store,
            surface_store=surface_store,
            id_factory=lambda: str(next(counter)),
        )

        agent.handle(_task("run-redirect", "http://localhost/start"))

        self.assertEqual(
            collector.calls,
            ["http://localhost/start", "http://localhost/landing?category=all"],
        )
        landing = next(
            surface
            for surface in surface_store.list_by_run("run-redirect")
            if surface.url == "http://localhost/landing"
        )
        self.assertEqual(landing.parameters, ("category",))
        self.assertIn("http_redirect", landing.discovery_types)

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

    def test_file_serving_route_identifies_generic_filename_field(self) -> None:
        body = (
            '<a href="/api/attachments/download?name=report.pdf">file</a>'
            '<a href="/api/profile?name=someone">profile</a>'
        )
        agent, evidence, surfaces = _make_agent(body=body)
        agent.handle(_task("file-serving", "http://localhost/"))

        observations = evidence.list_by_run("file-serving")
        file_surface = next(surface for surface in surfaces.list_by_run("file-serving")
                            if surface.url.endswith("/api/attachments/download"))
        profile_surface = next(surface for surface in surfaces.list_by_run("file-serving")
                               if surface.url.endswith("/api/profile"))
        self.assertTrue(any(item.surface_id == file_surface.surface_id
                            and item.observation.get("type") == "file_serving_parameter"
                            and item.observation.get("parameter") == "name"
                            for item in observations))
        self.assertFalse(any(item.surface_id == profile_surface.surface_id
                             and item.observation.get("type") == "file_serving_parameter"
                             for item in observations))

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

    def test_recon_planner_status_is_forwarded_as_a_progress_event(self) -> None:
        class _StatusOnlyRecon:
            def handle(self, task):
                return AgentResult(
                    task_id=task.task_id,
                    status=AgentResultStatus.COMPLETED,
                    message="recon_planner:fallback:timeout",
                )

        app = build_local_application(agents={})
        app.dispatcher.register(
            "recon", _StatusOnlyRecon(), allowed_tools=("http_get",)
        )

        run = app.orchestrator.start(
            RunRequest(
                target_url="http://localhost/",
                scope=RunScope(allowed_hosts=frozenset({"localhost"})),
            )
        )

        planner_events = [
            event
            for event in app.progress_log.list_by_run(run.run_id)
            if event.agent_type == "recon"
            and event.detail == "recon_planner:fallback:timeout"
        ]
        self.assertEqual(len(planner_events), 1)
        self.assertIs(planner_events[0].kind, ProgressEventKind.AGENT_COMPLETED)


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

_DOCUMENT_NAVIGATION_BUNDLE = """
class AccountMenu {
  openExport(){ window.location.replace(environment.hostServer + `/account/export`) }
}
"""

_SERVER_RENDERED_FORM = """
<html><body>
<form action="/account/export" method="POST">
  <input name="email"><input name="securityAnswer">
</form>
</body></html>
"""

_PAGE_TWO = """
<html><body>
<a href="/deep.php?file=secret.txt">deep</a>
<a href="https://evil.example.com/out">external</a>
</body></html>
"""


class _RoutingCollector:
    """URL별로 다른 응답을 돌려주는 대역. 크롤링 동작 검증에 쓴다."""

    def __init__(
        self,
        evidence_store,
        bodies: dict[str, str],
        content_types: dict[str, str] | None = None,
    ) -> None:
        self._evidence = evidence_store
        self._bodies = bodies
        self._content_types = content_types or {}
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
                    "requested_url": target_url,
                    "body": self._bodies.get(target_url, "<html></html>"),
                    **(
                        {"content_type": self._content_types[target_url]}
                        if target_url in self._content_types
                        else {}
                    ),
                },
            )
        )
        return evidence_id


def _crawling_agent(bodies: dict[str, str], **kwargs):
    evidence_store = InMemoryEvidenceStore()
    surface_store = InMemorySurfaceStore()
    content_types = kwargs.pop("content_types", None)
    collector = _RoutingCollector(evidence_store, bodies, content_types)
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
    def test_authenticated_form_does_not_create_unobserved_csv_workflow(self) -> None:
        base = "http://localhost"
        page = base + "/admin-dev/index.php?controller=AdminImport"
        form = (
            '<html><body>AdminImport Categories'
            '<input name="file"><input name="csv"><select name="entity"></select>'
        )
        route = (
            '/admin-dev/index.php/configure/advanced/import/file/upload'
            '?_token=opaque'
        )
        for include_route in (False, True):
            body = form + (f'<a href="{route}">Upload</a>' if include_route else "")
            agent, collector, surfaces = _crawling_agent(
                {page: body + "</body></html>"}, max_pages=1,
            )
            run_id = f"presta-csv-{include_route}"
            agent.handle(replace(
                _task(run_id, page, credential_ref="presta-admin"),
                request_budget=10,
            ))
            workflow = [
                item for item in collector._evidence.list_by_run(run_id)
                if item.observation.get("type") == "admin_csv_image_import_workflow"
            ]
            self.assertEqual(workflow, [])

    def test_script_does_not_invent_model_download_workflow(self) -> None:
        base = "http://localhost"
        list_url = base + "/externalmodel/getlist?mode=cache"
        model_script = (
            "const data = item.originalData;"
            "fetchApi('/manager/queue/install_model',"
            "{method:'POST',body:JSON.stringify(data)});"
            "fetchApi('/manager/queue/start');"
            "fetchData(`/externalmodel/getlist?mode=${mode}`);"
        )
        agent, collector, surfaces = _crawling_agent(
            {
                base + "/": (
                    '<script src="/model-manager.js"></script>'
                    '<script src="/main.js"></script>'
                ),
                base + "/model-manager.js": model_script,
                base + "/main.js": "const option = {value:'cache'};",
                list_url: json.dumps({"models": [{
                    "filename": "sample.safetensors", "type": "clip",
                    "base": "clip", "save_path": "default",
                }]}),
            },
            content_types={
                base + "/model-manager.js": "application/javascript",
                base + "/main.js": "application/javascript",
                list_url: "application/json",
            },
            max_pages=6, max_scripts=3,
        )
        agent.handle(replace(_task("model-flow", base + "/"), request_budget=30))
        self.assertNotIn(list_url, collector.calls)
        evidence = collector._evidence.list_by_run("model-flow")
        workflow = [
            item for item in evidence
            if item.observation.get("type") == "javascript_model_download_workflow"
        ]
        self.assertEqual(workflow, [])

    def test_observed_ueditor_config_declares_ssrf_coordinate(self) -> None:
        base = "http://localhost"
        upload = base + "/admin/upload/index.html"
        config_url = upload + "?from=ueditor&action=config"
        agent, collector, surfaces = _crawling_agent(
            {
                base + "/": f'<a href="{upload}">Upload</a>',
                upload: "<html></html>",
                config_url: json.dumps({
                    "catcherActionName": "catch_image",
                    "catcherFieldName": "remote_image",
                }),
            },
            content_types={config_url: "application/json"},
            max_pages=3,
        )
        agent.handle(replace(_task("ueditor", base + "/"), request_budget=20))
        self.assertIn(config_url, collector.calls)
        found = surfaces.list_by_run("ueditor")
        editor = next(item for item in found if "remote_image[]" in item.parameters)
        self.assertEqual(editor.observed_query, (
            ("from", "ueditor"), ("action", "catch_image"),
        ))
        evidence = collector._evidence.list_by_run("ueditor")
        self.assertTrue(any(
            item.surface_id == editor.surface_id
            and item.observation.get("type") == "editor_catcher_request_structure"
            for item in evidence
        ))
        run = Run(
            run_id="ueditor", target_url=base + "/",
            scope=RunScope(allowed_hosts=frozenset({"localhost"})),
            policy_profile="safe", request_budget=20,
        )
        decisions = standard_router(
            ("SSRF",), ssrf_owned_receiver_enabled=True,
        ).route(run, found, evidence)
        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0].candidate.surface_id, editor.surface_id)

    def test_unrelated_upload_response_does_not_declare_catcher(self) -> None:
        base = "http://localhost"
        upload = base + "/admin/upload/index.html"
        config_url = upload + "?from=ueditor&action=config"
        agent, collector, surfaces = _crawling_agent(
            {
                base + "/": f'<a href="{upload}">Upload</a>',
                config_url: json.dumps({"catcherFieldName": "file"}),
            },
            content_types={config_url: "application/json"},
            max_pages=2,
        )
        agent.handle(replace(_task("not-ueditor", base + "/"), request_budget=20))
        self.assertIn(config_url, collector.calls)
        self.assertFalse(any(
            "file[]" in item.parameters
            for item in surfaces.list_by_run("not-ueditor")
        ))

    def test_search_query_surface_requires_observed_echo(self) -> None:
        base = "http://localhost"
        marker = "hacklipse-search-control"
        agent, collector, surfaces = _crawling_agent({
            base + "/": '<a href="/search">Search</a><a href="/lookup">Lookup</a>',
            base + "/search": "<html>Results for: </html>",
            base + "/search?q=" + marker: "<html>Results for: " + marker + "</html>",
            base + "/lookup": "<html>Lookup</html>",
            base + "/lookup?q=" + marker: "<html>Lookup</html>",
        }, max_pages=8)
        agent.handle(replace(_task("search-echo", base + "/"), request_budget=30))

        self.assertIn(base + "/search?q=" + marker, collector.calls)
        self.assertIn(base + "/lookup?q=" + marker, collector.calls)
        self.assertTrue(any(
            surface.url == base + "/search"
            and surface.parameters == ("q",)
            and "observed_search_parameter" in surface.discovery_types
            for surface in surfaces.list_by_run("search-echo")
        ))
        self.assertFalse(any(
            surface.url == base + "/lookup" and surface.parameters
            for surface in surfaces.list_by_run("search-echo")
        ))

    def test_sparse_root_records_public_graphql_schema_without_executing_mutations(self) -> None:
        base = "http://localhost"
        schema = {"data": {"__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [
                {"kind": "OBJECT", "name": "Query", "fields": [{"name": "posts"}]},
                {"kind": "OBJECT", "name": "Mutation", "fields": [{"name": "login"}]},
                {"kind": "OBJECT", "name": "User", "fields": [{"name": "displayName"}]},
            ],
        }}}
        agent, collector, surfaces = _crawling_agent(
            {base + "/": "<html><body>Welcome</body></html>"},
        )
        original_collect = collector.collect

        def collect(run_id, target_url, spec, **kwargs):
            if target_url.startswith(base + "/graphql?query="):
                collector._bodies[target_url] = json.dumps(schema)
                collector._content_types[target_url] = "application/json"
            return original_collect(run_id, target_url, spec, **kwargs)

        collector.collect = collect
        agent.handle(replace(_task("graphql-schema", base + "/"), request_budget=30))
        discovered = surfaces.list_by_run("graphql-schema")
        self.assertTrue(any(
            item.url == base + "/graphql" and item.discovery_types == ("graphql_introspection",)
            for item in discovered
        ))
        observations = [
            item.observation for item in collector._evidence.list_by_run("graphql-schema")
            if item.observation.get("type") == "graphql_schema_operation"
        ]
        self.assertEqual(
            {(item["graphql_kind"], item["operation"]) for item in observations},
            {("query", "__schema"), ("query", "posts"),
             ("mutation", "login")},
        )
        self.assertEqual(len([url for url in collector.calls if "/graphql?" in url]), 1)

    def test_sparse_root_stops_schema_probe_at_first_valid_description(self) -> None:
        base = "http://localhost"
        schema = {"openapi": "3.0.0", "paths": {
            "/api/search": {"get": {"parameters": [
                {"name": "q", "in": "query", "schema": {"type": "string"}}
            ]}},
        }}
        agent, collector, surfaces = _crawling_agent(
            {base + "/": "<html><body>Welcome</body></html>",
             base + "/swagger.json": json.dumps(schema)},
            content_types={base + "/swagger.json": "application/json"},
        )
        agent.handle(replace(_task("sparse-schema", base + "/"), request_budget=30))
        self.assertEqual(collector.calls, [
            base + "/", base + "/openapi.json", base + "/swagger.json",
        ])
        self.assertTrue(any(
            item.url == base + "/api/search" and item.parameters == ("q",)
            for item in surfaces.list_by_run("sparse-schema")
        ))

    def test_openapi_declared_ssrf_get_is_routed_only_with_callback(self) -> None:
        base = "http://localhost"
        schema = {"openapi": "3.0.0", "paths": {
            "/api/fetch": {"get": {"parameters": [
                {"name": "url", "in": "query", "schema": {"type": "string"}},
            ]}},
            "/api/submit": {"post": {"requestBody": {"content": {
                "application/json": {"schema": {"properties": {"url": {"type": "string"}}}}
            }}}},
        }}
        agent, collector, surfaces = _crawling_agent(
            {base + "/": "<html><body>Welcome</body></html>",
             base + "/openapi.json": json.dumps(schema)},
            content_types={base + "/openapi.json": "application/json"},
        )
        agent.handle(replace(_task("ssrf-openapi", base + "/"), request_budget=20))
        run = Run(
            run_id="ssrf-openapi", target_url=base + "/",
            scope=RunScope(allowed_hosts=frozenset({"localhost"})),
            policy_profile="safe", request_budget=20,
        )
        found = surfaces.list_by_run(run.run_id)
        evidence = collector._evidence.list_by_run(run.run_id)
        self.assertEqual(
            standard_router(("SSRF",)).route(run, found, evidence), (),
        )
        reviews = [
            item.observation for item in evidence
            if item.observation.get("type") == "ssrf_url_fetch_review"
        ]
        self.assertEqual(len(reviews), 1)
        self.assertEqual(reviews[0]["parameter_names"], ["url"])
        self.assertEqual(
            reviews[0]["parameter_sources"],
            [{"name": "url", "source": "openapi_declaration"}],
        )
        self.assertFalse(reviews[0]["verification_performed"])
        decisions = standard_router(
            ("SSRF",), ssrf_callback_service=object(),
        ).route(run, found, evidence)
        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0].candidate.surface_id, next(
            item.surface_id for item in found if item.url == base + "/api/fetch"
        ))

    def test_observed_url_input_gets_one_passive_review_on_resume(self) -> None:
        base = "http://localhost"
        target = base + "/preview?url=https%3A%2F%2Fexample.com%2Fpublic"
        agent, collector, _ = _crawling_agent({
            base + "/": f'<a href="{target}">Preview</a>',
            target: "ok",
        })
        task = replace(_task("ssrf-passive", base + "/"), request_budget=20)
        agent.handle(task)
        agent.handle(task)
        reviews = [
            item.observation
            for item in collector._evidence.list_by_run("ssrf-passive")
            if item.observation.get("type") == "ssrf_url_fetch_review"
        ]
        self.assertEqual(len(reviews), 1)
        self.assertEqual(reviews[0]["parameter_names"], ["url"])
        self.assertEqual(
            reviews[0]["parameter_sources"],
            [{"name": "url", "source": "observed_query"}],
        )
        self.assertNotIn("example.com", str(reviews[0]))

    def test_openapi_and_javascript_record_internal_destinations_without_probing(self) -> None:
        base = "http://localhost"
        schema = {"openapi": "3.0.0", "paths": {
            "/api/fetch": {"get": {
                "description": (
                    "forwards to http://mailpit:8025/private/token/DEMO-SECRET"
                    "?key=hidden"
                ),
                "parameters": [{"name": "url", "in": "query"}],
            }},
        }}
        agent, collector, surfaces = _crawling_agent(
            {
                base + "/": '<script src="/app.js"></script>',
                base + "/app.js": 'const health = "http://10.0.0.8:9000/health";',
                base + "/openapi.json": json.dumps(schema),
            },
            content_types={
                base + "/app.js": "application/javascript",
                base + "/openapi.json": "application/json",
            },
            max_pages=8,
        )
        agent.handle(replace(_task("ssrf-hints", base + "/"), request_budget=30))

        # A process restart intentionally creates a new HMAC key. Dedupe must
        # therefore use only the already-sanitized origin/path pair rather than
        # a fingerprint that cannot remain stable across restarts.
        resumed_ids = iter(range(10_000, 20_000))
        resumed = ReconAgent(
            collector=collector,
            evidence_store=collector._evidence,
            surface_store=surfaces,
            id_factory=lambda: str(next(resumed_ids)),
            max_pages=8,
        )
        resumed.handle(replace(_task("ssrf-hints", base + "/"), request_budget=30))

        hints = [
            item.observation for item in collector._evidence.list_by_run("ssrf-hints")
            if item.observation.get("type") == "ssrf_destination_hint"
        ]
        self.assertEqual(
            {
                (item["destination_origin"], item["path_hint"], item["source"])
                for item in hints
            },
            {
                ("http://10.0.0.8:9000", "/health", "delivered_javascript"),
                (
                    "http://mailpit:8025", "/private/token/{redacted}",
                    "openapi_document",
                ),
            },
        )
        self.assertTrue(all(item["observed"] for item in hints))
        self.assertTrue(all(item["probe_authorized"] is False for item in hints))
        serialized = json.dumps(hints, sort_keys=True)
        self.assertNotIn("destination_url", serialized)
        self.assertNotIn("DEMO-SECRET", serialized)
        self.assertNotIn("key=hidden", serialized)
        self.assertFalse(any("mailpit" in url or "10.0.0.8" in url
                             for url in collector.calls))

    def test_openapi_get_sampling_follows_response_links_without_mutation(self) -> None:
        base = "http://localhost"
        schema = {"openapi": "3.0.0", "paths": {
            "/api/config": {"get": {}},
            "/api/info": {"get": {}},
            "/api/logout": {"get": {}},
            "/api/items": {"post": {}},
        }}
        agent, collector, surfaces = _crawling_agent(
            {base + "/": "<html><body>Welcome</body></html>",
             base + "/openapi.json": json.dumps(schema),
             base + "/api/info": '{"navigation":["/api/linked?term=ok"]}'},
            content_types={
                base + "/openapi.json": "application/json",
                base + "/api/info": "application/json",
            },
        )
        agent.handle(replace(_task("schema-get-sample", base + "/"), request_budget=30))
        self.assertIn(base + "/api/info", collector.calls)
        self.assertIn(base + "/api/linked?term=ok", collector.calls)
        self.assertNotIn(base + "/api/logout", collector.calls)
        self.assertNotIn(base + "/api/items", collector.calls)
        self.assertNotIn(base + "/api/config", collector.calls)
        self.assertTrue(any(
            item.url == base + "/api/linked" and item.parameters == ("term",)
            for item in surfaces.list_by_run("schema-get-sample")
        ))

    def test_html_navigation_records_but_does_not_fetch_mutating_get(self) -> None:
        base = "http://localhost"
        agent, collector, surfaces = _crawling_agent({
            base + "/": '<a href="/admin/logout">Exit</a>'
                        '<a href="/admin/dashboard">Dashboard</a>',
            base + "/admin/dashboard": "<html>Dashboard</html>",
        })
        agent.handle(replace(_task("admin-navigation", base + "/"), request_budget=10))
        self.assertNotIn(base + "/admin/logout", collector.calls)
        self.assertIn(base + "/admin/dashboard", collector.calls)
        self.assertTrue(any(
            item.url == base + "/admin/logout"
            for item in surfaces.list_by_run("admin-navigation")
        ))

    def test_template_only_openapi_is_recorded_without_guessing_another_schema_url(self) -> None:
        base = "http://localhost"
        schema = {"openapi": "3.0.0", "paths": {
            "/api/items/{item_id}": {"get": {}},
        }}
        agent, collector, surfaces = _crawling_agent(
            {base + "/": '<a href="/api/schema/">schema</a>',
             base + "/api/schema/": json.dumps(schema)},
            content_types={base + "/api/schema/": "application/json"},
        )
        agent.handle(replace(_task("template-only", base + "/"), request_budget=20))
        self.assertEqual(collector.calls, [base + "/", base + "/api/schema/"])
        self.assertFalse(any(
            "item_id" in item.url for item in surfaces.list_by_run("template-only")
        ))

    def test_heuristic_frontier_summary_names_unvisited_surfaces_and_stop_reason(self) -> None:
        base = "http://localhost"
        agent, collector, _ = _crawling_agent(
            {base + "/": '<a href="/first">one</a><a href="/second">two</a>'},
            max_pages=1,
        )
        agent.handle(replace(_task("frontier", base + "/"), request_budget=20))
        summary = next(
            item.observation for item in collector._evidence.list_by_run("frontier")
            if item.observation.get("type") == "recon_frontier_summary"
        )
        self.assertEqual(summary["attempted_url_count"], 1)
        self.assertEqual(summary["response_url_count"], 1)
        self.assertEqual(summary["parsed_url_count"], 1)
        self.assertEqual(summary["unvisited_count"], 2)
        self.assertEqual(len(summary["unvisited_surface_ids"]), 2)
        self.assertEqual(summary["discovered_without_response_surface_count"], 2)
        self.assertEqual(
            set(summary["discovered_without_response_surface_ids"]),
            set(summary["unvisited_surface_ids"]),
        )
        self.assertEqual(summary["stop_reason"], "request_budget")
        self.assertNotIn("/first", str(summary))

    def test_crawled_openapi_link_is_parsed_without_guessing_a_second_location(self) -> None:
        base = "http://localhost"
        schema = {"openapi": "3.0.0", "paths": {
            "/api/items": {"get": {"parameters": [{"in": "query", "name": "filter"}]}},
            "/api/items/{item_id}": {"get": {}},
            "/api/create": {"post": {
                "parameters": [{"in": "query", "name": "mode"}],
                "requestBody": {"content": {"application/json": {"schema": {
                    "type": "object", "properties": {
                        "email": {"type": "string", "example": "private@example.invalid"},
                        "csrf_token": {"type": "string", "example": "secret-token-value"},
                    },
                }}}},
            }},
        }}
        agent, collector, surfaces = _crawling_agent(
            {base + "/": '<a href="/api/schema/">API</a>',
             base + "/api/schema/": json.dumps(schema),
             base + "/api/items": json.dumps({"results": [
                 {"id": 7, "name": "observed item"},
                 {"id": "../../outside", "name": "ignored"},
             ]}),
             base + "/api/items/7": json.dumps({"id": 7})},
            content_types={
                base + "/api/schema/": "application/json",
                base + "/api/items": "application/json",
                base + "/api/items/7": "application/json",
            },
        )
        agent.handle(replace(_task("linked-openapi", base + "/"), request_budget=20))
        self.assertEqual(collector.calls, [
            base + "/", base + "/api/schema/", base + "/api/items",
            base + "/api/items/7",
        ])
        self.assertTrue(any(
            item.url == base + "/api/items" and item.parameters == ("filter",)
            for item in surfaces.list_by_run("linked-openapi")
        ))
        post = next(
            item for item in surfaces.list_by_run("linked-openapi")
            if item.url == base + "/api/create" and item.method == "POST"
        )
        self.assertEqual(post.parameters, ("mode", "email", "csrf_token"))
        shape = next(
            item.observation for item in collector._evidence.list_by_run("linked-openapi")
            if item.surface_id == post.surface_id
            and item.observation.get("type") == "openapi_request_structure"
        )
        self.assertEqual(shape["body_parameter_names"], ["email", "csrf_token"])
        self.assertEqual(shape["query_parameter_names"], ["mode"])
        self.assertFalse(shape["request_template_available"])
        self.assertNotIn("secret-token-value", str(shape))
        self.assertNotIn("private@example.invalid", str(shape))
        self.assertTrue(any(
            item.url == base + "/api/items/7"
            and item.path_identifier == "item_id"
            for item in surfaces.list_by_run("linked-openapi")
        ))
        self.assertFalse(any("outside" in item.url for item in surfaces.list_by_run("linked-openapi")))

    def test_public_openapi_adds_literal_request_shapes_without_mutations(self) -> None:
        base = "http://localhost"
        schema = {
            "openapi": "3.0.0",
            "paths": {
                "/api/search": {
                    "get": {"parameters": [
                        {"in": "query", "name": "q"},
                        {"in": "header", "name": "Authorization"},
                    ]},
                    "post": {"parameters": [{"in": "query", "name": "unsafe"}]},
                },
                "/api/items/{item_id}": {"get": {"parameters": []}},
                "//outside.example/steal": {"get": {}},
            },
        }
        agent, collector, surfaces = _crawling_agent(
            {base + "/": "<html></html>",
             base + "/openapi.json": json.dumps(schema)},
            content_types={base + "/openapi.json": "application/json"},
        )

        agent.handle(replace(_task("openapi", base + "/"), request_budget=20))

        self.assertEqual(collector.calls, [base + "/", base + "/openapi.json"])
        discovered = surfaces.list_by_run("openapi")
        self.assertTrue(any(
            item.url == base + "/api/search" and item.method == "GET"
            and item.parameters == ("q",)
            for item in discovered
        ))
        self.assertTrue(any(
            item.url == base + "/api/search" and item.method == "POST"
            and item.parameters == ("unsafe",)
            for item in discovered
        ))
        self.assertFalse(any("item_id" in item.url or "outside.example" in item.url
                             for item in discovered))

    def test_openapi_like_json_without_schema_contract_is_ignored(self) -> None:
        base = "http://localhost"
        agent, _, surfaces = _crawling_agent(
            {base + "/": "<html></html>",
             base + "/openapi.json": '{"paths":{"/api/private":{"get":{}}}}'},
            content_types={base + "/openapi.json": "application/json"},
        )
        agent.handle(replace(_task("not-openapi", base + "/"), request_budget=20))
        self.assertFalse(any(item.url == base + "/api/private"
                             for item in surfaces.list_by_run("not-openapi")))

    def test_application_chunk_is_not_starved_by_framework_scripts(self) -> None:
        base = "http://localhost"
        agent, collector, surfaces = _crawling_agent({
            base + "/": ''.join(f'<script src="{p}"></script>' for p in (
                "/runtime.js", "/vendor.js", "/framework.js", "/chunks/app/page-feature.js")),
            base + "/chunks/app/page-feature.js": 'fetch("/api/find?q=")',
        }, max_scripts=1)
        agent.handle(replace(_task("script-priority", base + "/"), request_budget=20))
        self.assertIn(base + "/chunks/app/page-feature.js", collector.calls)
        self.assertNotIn(base + "/runtime.js", collector.calls)
        self.assertTrue(any(s.url == base + "/api/find" and s.parameters == ("q",)
                            for s in surfaces.list_by_run("script-priority")))

    def test_does_not_parse_html_looking_strings_inside_json_as_surfaces(self) -> None:
        api_url = "http://localhost/api/items"
        agent, collector, surfaces = _crawling_agent(
            {
                "http://localhost/": '<a href="/api/items">items</a>',
                api_url: (
                    '{"description":"<a href=\\"/not-a-page\\">x</a>'
                    '<form action=\\"/not-a-form\\" method=\\"post\\">"}'
                ),
            },
            content_types={
                "http://localhost/": "text/html; charset=utf-8",
                api_url: "application/json; charset=utf-8",
            },
            max_pages=3,
        )

        agent.handle(
            replace(_task("run-json-data", "http://localhost/"), request_budget=10)
        )

        self.assertIn(api_url, collector.calls)
        urls = {item.url for item in surfaces.list_by_run("run-json-data")}
        self.assertNotIn("http://localhost/not-a-page", urls)
        self.assertNotIn("http://localhost/not-a-form", urls)

    def test_json_navigation_links_are_bounded_and_same_origin(self) -> None:
        base = "http://localhost"
        document = {
            "items": [
                {"href": "/posts/7?view=full", "description": "<a href='/fake'>fake</a>"},
                {"url": "https://elsewhere.invalid/private"},
                {"path": "//elsewhere.invalid/private"},
            ],
            "navigation": ["/search?q=one", "/posts/7?view=full"],
            "data": ["/not-a-link"],
        }
        evidence = Evidence(
            evidence_id="evi-json-links", run_id="json-links", surface_id=None,
            created_by="test", evidence_type="http_response",
            observation={"status": 200, "content_type": "application/json",
                         "body": json.dumps(document)},
        )
        self.assertEqual(_json_links_from_response(evidence, base + "/api/nav"), (
            base + "/posts/7?view=full", base + "/search?q=one",
        ))

        agent, collector, surfaces = _crawling_agent(
            {base + "/": '<a href="/api/nav">nav</a>',
             base + "/api/nav": json.dumps(document),
             base + "/posts/7?view=full": "<html></html>",
             base + "/search?q=one": "<html></html>"},
            content_types={base + "/api/nav": "application/json"},
            max_pages=5,
        )
        agent.handle(replace(_task("json-links", base + "/"), request_budget=20))
        urls = {item.url for item in surfaces.list_by_run("json-links")}
        self.assertIn(base + "/posts/7", urls)
        self.assertIn(base + "/search", urls)
        self.assertNotIn(base + "/not-a-link", urls)
        self.assertNotIn(base + "/fake", urls)
        self.assertNotIn("https://elsewhere.invalid/private", collector.calls)

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

    def test_discovers_only_constant_concatenated_javascript_paths(self) -> None:
        bundle = (
            'fetch("/api/" + "items?term=" + "");'
            'const dynamic = "/api/" + itemId;'
            'const external = "//evil.example" + "/collect";'
        )
        agent, _, surfaces = _crawling_agent(
            {"http://localhost/": _SPA_HTML, "http://localhost/main.js": bundle}
        )
        agent.handle(_task("run-constant-js", "http://localhost/"))
        found = {
            surface.url: surface.parameters
            for surface in surfaces.list_by_run("run-constant-js")
        }
        self.assertEqual(found["http://localhost/api/items"], ("term",))
        self.assertNotIn("http://localhost/api/itemId", found)
        self.assertNotIn("http://localhost//evil.example/collect", found)

    def test_discovers_all_fields_in_literal_javascript_query(self) -> None:
        bundle = (
            'fetch("/api/items?term=hello&sort=recent&limit=10");'
            'fetch("//outside.example/items?token=secret");'
            'fetch("/api/" + itemId + "?unknown=value");'
        )
        agent, collector, surfaces = _crawling_agent(
            {"http://localhost/": _SPA_HTML, "http://localhost/main.js": bundle}
        )
        agent.handle(_task("run-literal-query", "http://localhost/"))
        found = {
            surface.url: surface.parameters
            for surface in surfaces.list_by_run("run-literal-query")
        }
        self.assertEqual(
            found["http://localhost/api/items"], ("limit", "sort", "term")
        )
        self.assertNotIn("http://localhost/api/itemId", found)
        self.assertFalse(any("outside.example" in url for url in collector.calls))

    def test_discovers_inline_script_routes_without_parsing_json_data_as_code(self) -> None:
        html = (
            '<script type="application/json">{"path":"/api/not-code?secret=x"}</script>'
            '<script>fetch("/api/inline?term=a&sort=recent");'
            'location.assign("/account")</script>'
            '<script src="/main.js"></script>'
        )
        agent, collector, surfaces = _crawling_agent(
            {
                "http://localhost/": html,
                "http://localhost/main.js": 'fetch("/api/external?q=")',
                "http://localhost/account": "<html>account</html>",
            }, max_pages=4,
        )
        agent.handle(replace(
            _task("run-inline-js", "http://localhost/"), request_budget=20
        ))
        found = {
            surface.url: surface.parameters
            for surface in surfaces.list_by_run("run-inline-js")
        }
        self.assertEqual(found["http://localhost/api/inline"], ("sort", "term"))
        self.assertEqual(found["http://localhost/api/external"], ("q",))
        self.assertNotIn("http://localhost/api/not-code", found)
        self.assertIn("http://localhost/main.js", collector.calls)
        self.assertIn("http://localhost/account", collector.calls)
        self.assertNotIn("http://localhost/openapi.json", collector.calls)
        self.assertLess(
            collector.calls.index("http://localhost/main.js"),
            collector.calls.index("http://localhost/account"),
        )

    def test_inline_scripts_keep_distinct_query_shapes_for_one_route(self) -> None:
        html = (
            '<script>fetch("/api/search?q=")</script>'
            '<script>fetch("/api/search?sort=")</script>'
        )
        agent, _, surfaces = _crawling_agent(
            {"http://localhost/": html}, max_pages=3,
        )
        agent.handle(replace(
            _task("run-inline-shapes", "http://localhost/"), request_budget=20
        ))
        shapes = {
            surface.parameters
            for surface in surfaces.list_by_run("run-inline-shapes")
            if surface.url == "http://localhost/api/search"
        }
        self.assertEqual(shapes, {("q",), ("sort",)})

    def test_inline_script_cap_preserves_input_bearing_routes(self) -> None:
        bundle = "".join(f'const p{i}="/asset{i}";' for i in range(110))
        bundle += 'fetch("/api/search?q=")'
        agent, _, surfaces = _crawling_agent(
            {"http://localhost/": f"<script>{bundle}</script>"}, max_pages=2,
        )
        agent.handle(replace(
            _task("run-inline-cap", "http://localhost/"), request_budget=20
        ))
        found = {
            surface.url: surface.parameters
            for surface in surfaces.list_by_run("run-inline-cap")
        }
        self.assertEqual(found["http://localhost/api/search"], ("q",))
        self.assertNotIn("http://localhost/asset90", found)

    def test_client_script_records_literal_mutation_methods_without_sending_them(self) -> None:
        bundle = (
            'fetch("/api/messages?view=short", {method: "POST", '
            'body: JSON.stringify({message: secretValue})});'
            'axios.patch("/api/profile/7", {name: "private"});'
            'fetch("//evil.example/collect", {method: "POST"});'
            'fetch(dynamicPath, {method: "POST"});'
        )
        agent, collector, surfaces = _crawling_agent(
            {"http://localhost/": _SPA_HTML, "http://localhost/main.js": bundle}
        )
        agent.handle(_task("script-methods", "http://localhost/"))
        found = {(surface.url, surface.method): surface
                 for surface in surfaces.list_by_run("script-methods")}
        post = found[("http://localhost/api/messages", "POST")]
        self.assertEqual(post.parameters, ())
        self.assertIn("script_request_shape", post.discovery_types)
        shape = next(
            item.observation for item in collector._evidence.list_by_run("script-methods")
            if item.surface_id == post.surface_id
            and item.observation.get("type") == "script_request_structure"
        )
        self.assertEqual(shape["query_parameter_names"], ["view"])
        self.assertFalse(shape["request_template_available"])
        self.assertIn(("http://localhost/api/profile/7", "PATCH"), found)
        self.assertFalse(any("evil.example" in surface.url for surface in found.values()))
        self.assertFalse(any("dynamicPath" in surface.url for surface in found.values()))
        self.assertFalse(any(url.endswith("/api/messages") for url in collector.calls))

    def test_json_module_manifest_reveals_fetchapi_post_shape(self) -> None:
        base = "http://localhost"
        main = (
            'async function modules() { return await(await '
            'api.fetchApi("/extensions", {cache:"no-store"})).json() }'
        )
        extension = (
            'await api.fetchApi("/api/install", {'
            'method: "POST", body: JSON.stringify(item)});'
        )
        agent, collector, surfaces = _crawling_agent(
            {
                base + "/": '<script src="/main.js"></script>',
                base + "/main.js": main,
                base + "/extensions": json.dumps(["/extensions/model.js"]),
                base + "/extensions/model.js": extension,
            },
            content_types={
                base + "/main.js": "application/javascript",
                base + "/extensions": "application/json",
                base + "/extensions/model.js": "application/javascript",
            },
            max_pages=8,
        )
        agent.handle(replace(
            _task("json-module-manifest", base + "/"), request_budget=40
        ))
        found = {(item.url, item.method): item
                 for item in surfaces.list_by_run("json-module-manifest")}
        self.assertIn((base + "/api/install", "POST"), found)
        self.assertIn(base + "/extensions/model.js", collector.calls)
        self.assertNotIn(base + "/api/install", collector.calls)

    def test_discovers_post_ajax_shape_and_localized_runtime_values(self) -> None:
        html = """
        <html><body>
        <script>
          var appConfig = {"ajax_url":"/wp-admin/admin-ajax.php","nonce":"abc123"};
        </script>
        <script src="/plugin.js"></script>
        </body></html>
        """
        bundle = """
        jQuery.ajax({
          url: appConfig.ajax_url,
          method: 'POST',
          data: {action: 'lookup_states', nonce_ajax: appConfig.nonce, cnt: selected}
        });
        """
        agent, _, surfaces = _crawling_agent(
            {
                "http://localhost/": html,
                "http://localhost/plugin.js": bundle,
            }
        )

        agent.handle(_task("run-js-ajax", "http://localhost/"))

        ajax = next(
            surface
            for surface in surfaces.list_by_run("run-js-ajax")
            if surface.url == "http://localhost/wp-admin/admin-ajax.php"
            and surface.method == "POST"
        )
        self.assertEqual(ajax.parameters, ("action", "nonce_ajax", "cnt"))
        self.assertEqual(
            dict(ajax.observed_query),
            {"action": "lookup_states", "nonce_ajax": "abc123", "cnt": "1"},
        )
        self.assertEqual(ajax.discovery_types, ("javascript_request",))

    def test_preserves_javascript_array_form_shape(self) -> None:
        html = """
        <script>var cfg = {"ajaxurl":"/admin-ajax.php"};</script>
        <script src="/map.js"></script>
        """
        bundle = """
        var post_data = {
          'locations_ids': [location.id],
          'action': 'get_marker'
        };
        $.ajax({type: 'POST', url: cfg.ajaxurl, data: post_data});
        """
        agent, _, surfaces = _crawling_agent(
            {"http://localhost/": html, "http://localhost/map.js": bundle}
        )

        agent.handle(_task("run-js-array", "http://localhost/"))

        ajax = next(
            surface
            for surface in surfaces.list_by_run("run-js-array")
            if surface.url == "http://localhost/admin-ajax.php"
            and surface.method == "POST"
        )
        self.assertEqual(ajax.parameters, ("locations_ids[]", "action"))
        self.assertEqual(dict(ajax.observed_query)["action"], "get_marker")

    def test_ignores_numeric_character_counters_but_keeps_real_numeric_routes(self) -> None:
        bundle = (
            "render(`${value.length || 0}/160`);"
            "const objectRoute = '/users/10';"
            "const numericQueryEndpoint = '/10?q=';"
            "location.assign('/20');"
        )
        agent, _, surfaces = _crawling_agent(
            {"http://localhost/": _SPA_HTML, "http://localhost/main.js": bundle}
        )

        agent.handle(_task("run-numeric-js", "http://localhost/"))

        found = {
            surface.url: surface
            for surface in surfaces.list_by_run("run-numeric-js")
        }
        self.assertNotIn("http://localhost/160", found)
        self.assertIn("http://localhost/users/10", found)
        self.assertEqual(found["http://localhost/10"].parameters, ("q",))
        self.assertIn("http://localhost/20", found)
        self.assertEqual(
            found["http://localhost/users/10"].discovery_types,
            ("script_literal",),
        )
        self.assertEqual(
            found["http://localhost/20"].discovery_types,
            ("browser_navigation",),
        )

    def test_discovers_a_spa_route_navigated_with_backtick_quotes(self) -> None:
        """실제 Juice Shop 빌드는 navigate 배열 리터럴을 백틱으로 내보낸다.

        큰따옴표만 매칭하던 정규식으로는 `/search?q=` 같은 반사 XSS SPA 라우트 자체가
        Surface로 안 잡혀서, XSS 후보가 하나도 안 만들어지는 채로 조용히 넘어갔다.
        """

        bundle = (
            "class SearchComponent {\n"
            "  applyFilter(e){ return this.router.navigate([`/search`],"
            "{queryParams:{q:e}}) }\n"
            "}\n"
        )
        agent, collector, surfaces = _crawling_agent(
            {"http://localhost/": _SPA_HTML, "http://localhost/main.js": bundle}
        )
        agent.handle(_task("run-backtick-route", "http://localhost/"))

        found = {
            surface.url: surface.parameters
            for surface in surfaces.list_by_run("run-backtick-route")
        }
        self.assertEqual(found.get("http://localhost/#/search"), ("q",))

    def test_crawls_document_navigation_and_flags_unlinked_render_option(self) -> None:
        """제품별 URL seed 없이 SPA 밖의 서버 렌더링 POST 폼까지 이어간다."""

        agent, collector, surfaces = _crawling_agent(
            {
                "http://localhost/": _SPA_HTML,
                "http://localhost/main.js": _DOCUMENT_NAVIGATION_BUNDLE,
                "http://localhost/account/export": _SERVER_RENDERED_FORM,
            },
            max_pages=4,
        )

        agent.handle(
            replace(
                _task("run-document-navigation", "http://localhost/"),
                request_budget=10,
            )
        )

        self.assertIn("http://localhost/account/export", collector.calls)
        form = next(
            surface
            for surface in surfaces.list_by_run("run-document-navigation")
            if surface.url == "http://localhost/account/export"
            and surface.method == "POST"
        )
        self.assertEqual(form.parameters, ("email", "securityAnswer"))
        inferred = [
            item.observation
            for item in collector._evidence.list_by_run("run-document-navigation")
            if item.surface_id == form.surface_id
            and item.observation.get("type")
            == "unlinked_render_parameter_candidate"
        ]
        self.assertEqual(
            inferred,
            [
                {
                    "type": "unlinked_render_parameter_candidate",
                    "parameter": "layout",
                    "source": "bounded_unlinked_render_parameter",
                }
            ],
        )

    def test_answer_blind_recon_does_not_inject_unobserved_layout_parameter(self) -> None:
        agent, collector, surfaces = _crawling_agent(
            {
                "http://localhost/": _SPA_HTML,
                "http://localhost/main.js": _DOCUMENT_NAVIGATION_BUNDLE,
                "http://localhost/account/export": _SERVER_RENDERED_FORM,
            },
            max_pages=4,
            infer_unlinked_render_parameters=False,
        )

        agent.handle(
            replace(
                _task("run-answer-blind", "http://localhost/"),
                request_budget=10,
            )
        )

        form = next(
            surface
            for surface in surfaces.list_by_run("run-answer-blind")
            if surface.url == "http://localhost/account/export"
            and surface.method == "POST"
        )
        inferred = [
            item
            for item in collector._evidence.list_by_run("run-answer-blind")
            if item.surface_id == form.surface_id
            and item.observation.get("type")
            == "unlinked_render_parameter_candidate"
        ]
        self.assertEqual(inferred, [])

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


# 512KiB를 넘긴 뒤에야 검색 엔드포인트가 나오는 번들. 실제 Juice Shop의 main.js 가 이
# 모양이라 응답 본문 상한이 낮으면 후반부 경로가 통째로 사라진다.
_LARGE_BUNDLE_SPA = (
    b'<html><body><div id="app"></div>'
    b'<script src="/main.js"></script></body></html>'
)
_LARGE_BUNDLE = (
    b"// " + b"x" * (512 * 1024) + b"\n"
    b"search(e){ return this.http.get(`${this.host}/rest/products/search?q=${e}`) }\n"
)


class _LargeBundleHandler(BaseHTTPRequestHandler):
    """루트 HTML과 대형 JS 번들만 돌려주는 최소 서버."""

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/main.js":
            body, content_type = _LARGE_BUNDLE, "application/javascript"
        else:
            body, content_type = _LARGE_BUNDLE_SPA, "text/html"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass


class ReconReadsLargeBundlesTests(unittest.TestCase):
    """대역이 아닌 실제 HttpExecutionRuntime 으로 응답 본문 상한까지 함께 검증한다.

    다른 Recon 테스트는 본문을 그대로 넘겨주는 대역을 쓰므로 상한 회귀를 잡지 못한다.
    여기서는 기본 생성자로 만든 Runtime 을 그대로 써서 전역 기본값이 512KiB 로 되돌아가면
    실패하게 한다.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _LargeBundleHandler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()

    def test_endpoint_after_512kib_becomes_a_surface(self) -> None:
        # 기본 생성자. 여기에 max_body_bytes 를 넘기면 회귀를 가리게 된다.
        app = build_local_application({}, runtime=HttpExecutionRuntime(timeout_seconds=5.0))
        app.dispatcher.register(
            "recon",
            ReconAgent(
                collector=app.collector,
                evidence_store=app.stores.evidence,
                surface_store=app.stores.surfaces,
            ),
            allowed_tools=("http_get",),
        )

        # Analysis Agent를 등록하지 않았으므로 ROUTE 까지만 진행하고 ANALYZE 에서 멈춘다.
        with self.assertRaises(WorkflowExecutionError) as ctx:
            app.orchestrator.start(
                RunRequest(
                    target_url=f"http://127.0.0.1:{self.port}/",
                    scope=RunScope(allowed_hosts=frozenset({"127.0.0.1"})),
                    request_budget=10,
                )
            )

        found = {
            surface.url: surface.parameters
            for surface in app.stores.surfaces.list_by_run(ctx.exception.run_id)
        }
        self.assertEqual(
            found.get(f"http://127.0.0.1:{self.port}/rest/products/search"), ("q",)
        )


if __name__ == "__main__":
    unittest.main()
