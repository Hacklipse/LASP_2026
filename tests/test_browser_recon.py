"""실제 렌더링 발견과 브라우저 개별 요청의 공용 통제 경계를 검증한다."""

from __future__ import annotations

import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

from hacklipse.adapters.browser_recon import PlaywrightRecon, _CollectorTransport, request_structure
from hacklipse.adapters.browser_runtime import PlaywrightBrowserRuntime
from hacklipse.adapters.http_runtime import HttpExecutionRuntime
from hacklipse.adapters.recon import ReconAgent
from hacklipse.adapters.xss_execution import (
    BROWSER_XSS_TOOL, RAW_HASH_CANARY, RAW_HASH_PARAMETER,
    XSS_EXECUTION_MARKER_PREFIX, XSS_REFLECTION_MARKER_PREFIX,
    browser_navigation_url,
)
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    EvidenceRequest, ExecutionRequest, HttpRequestKind, HttpRequestSpec,
    Run, RunScope, TaskEnvelope,
)
from hacklipse.ports import ReconAction


def _fixture(budget=30, allowed_path="/", runtime=None):
    app = build_local_application({}, runtime=runtime or HttpExecutionRuntime())
    scope = RunScope(allowed_hosts=frozenset({"127.0.0.1"}), allowed_path_prefixes=(allowed_path,))
    app.stores.runs.add(Run(run_id="browser-run", target_url="http://127.0.0.1/", scope=scope, request_budget=budget, policy_profile="safe"))
    app.budget_manager.open_run("browser-run", budget)
    task = TaskEnvelope(task_id="browser-task", run_id="browser-run", agent_type="recon",
                        target_url="http://127.0.0.1/", allowed_tools=("http_get",), request_budget=budget)
    return app, task


class _Route:
    def __init__(self, url, *, method="GET", body=None, headers=None, resource_type="fetch"):
        self.request = SimpleNamespace(url=url, method=method, post_data=body,
                                       headers=headers or {}, resource_type=resource_type)
        self.outcome = None

    def abort(self, reason):
        self.outcome = ("abort", reason)

    def fulfill(self, **kwargs):
        self.outcome = ("fulfill", kwargs)


class BrowserRequestBoundaryTests(unittest.TestCase):
    def test_body_shapes_do_not_contain_values(self):
        shape = request_structure("http://127.0.0.1/a?q=hello&token=secret", "POST", "application/json", '{"name":"private","csrfToken":"secret"}')
        self.assertEqual(shape["body_parameter_names"], ["name", "csrfToken"])
        self.assertEqual(shape["query_parameter_names"], ["q", "token"])
        self.assertNotIn("private", json.dumps(shape))
        self.assertNotIn("secret", json.dumps(shape))
        form = request_structure("http://127.0.0.1/", "POST", "application/x-www-form-urlencoded", "q=x&empty=&q=y")
        self.assertEqual(form["body_parameter_names"], ["q", "empty"])
        spa = request_structure("http://127.0.0.1/#/search?q=hello", "GET", "", None)
        self.assertEqual(spa["query_parameter_names"], ["q"])

    def test_cross_origin_encoded_escape_and_mutations_do_not_reach_collector(self):
        app, task = _fixture(allowed_path="/scope/")
        class NeverCollector:
            def collect_with_result(self, *args, **kwargs):
                raise AssertionError("blocked browser request reached network")
        transport = _CollectorTransport(collector=NeverCollector(), task=task,
                                        scope=app.stores.runs.get(task.run_id).scope,
                                        remember=lambda *a: "surface", limit=10, deadline=time.monotonic()+10)
        for url in ("http://127.0.0.1:9999/scope/", "https://example.invalid/scope/", "http://127.0.0.1/scope/%2e%2e/private"):
            route = _Route(url)
            transport.handle(route)
            self.assertEqual(route.outcome[0], "abort")
        route = _Route("http://127.0.0.1/scope/new", method="POST", body='{"title":"private"}', headers={"content-type":"application/json"})
        transport.handle(route)
        self.assertEqual(route.outcome[0], "abort")
        self.assertEqual(transport.observations[-1][1]["body_parameter_names"], ["title"])
        self.assertFalse(transport.observations[-1][1]["sent"])
        self.assertEqual(transport.attempts, 0)


class _App(BaseHTTPRequestHandler):
    requests = []
    other_origin = ""

    def log_message(self, *args):
        pass

    def do_POST(self):
        self.requests.append(("POST", self.path))
        self.send_error(500, "browser discovery must not mutate")

    def do_PATCH(self):
        self.requests.append(("PATCH", self.path))
        self.send_error(500, "browser discovery must not mutate")

    def do_GET(self):
        self.requests.append(("GET", self.path))
        media = "text/html"
        if self.path == "/":
            body = '''<html><body><nav id="nav"></nav>
              <button id="menu" aria-expanded="false" onclick="this.insertAdjacentHTML('afterend','<a href=/menu>Menu entry</a>')">Menu</button>
              <button role="tab" onclick="document.querySelector('nav').insertAdjacentHTML('beforeend','<a href=/tabbed>Tab page</a>');let x=new XMLHttpRequest();x.open('GET','/api/tab?view=detail');x.send()">Details</button>
              <script src="/runtime.js"></script><script src="/vendor.js"></script><script src="/framework.js"></script>
              <script src="/app/layout.js"></script></body></html>'''
        elif self.path == "/app/layout.js":
            media = "application/javascript"
            body = 'fetch(["","api","nav"].join("/")).then(r=>r.json()).then(d=>{document.querySelector("nav").innerHTML=d.map(x=>`<a href="${x}">${x}</a>`).join("")});' + f'fetch("{self.other_origin}/outside").catch(()=>{{}});' + 'setTimeout(()=>document.body.insertAdjacentHTML("beforeend", "<a href=/late>Late link</a>"),50);'
        elif self.path == "/api/nav":
            media, body = "application/json", '["/board","/spa"]'
        elif self.path == "/spa":
            body = '''<html><body><button role="tab" onclick="history.pushState({},'', '/spa#/results?q=hello')">Results</button></body></html>'''
        elif self.path == "/board":
            body = '''<html><body><table><tr><td>row</td><td><button onclick="location.href='/item/7'">Details</button></td></tr></table>
              <button type="button" onclick="document.getElementById('editor').hidden=false">Edit</button>
              <button type="button" onclick="document.getElementById('filters').hidden=false">Advanced filters</button>
              <div id="filters" hidden><input type="search" placeholder="search" oninput="fetch('/api/search?q='+encodeURIComponent(this.value))"></div>
              <form id="editor" hidden onsubmit="event.preventDefault();fetch('/api/items/7',{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({title:this.querySelector('input').value,csrfToken:this.querySelector('[type=hidden]').value})})">
              <input placeholder="title"><input type="hidden" name="csrf_token" value="private-fixture-csrf"><button type="submit">Save</button></form></body></html>'''
        elif self.path == "/hash":
            body = '''<html><body><div id="out"></div><script>
              function render(){document.getElementById('out').innerHTML=decodeURIComponent(location.hash.slice(1))}
              addEventListener('hashchange',render);render();</script></body></html>'''
        elif self.path == "/hash-safe":
            body = '''<html><body><div id="out"></div><script>
              function render(){document.getElementById('out').textContent=decodeURIComponent(location.hash.slice(1))}
              addEventListener('hashchange',render);render();
              fetch('/mutation',{method:'POST',body:'blocked'}).catch(()=>{});
              </script></body></html>'''
        else:
            body = "<html><body>Page</body></html>"
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", media)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class LiveBrowserReconTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from playwright.sync_api import sync_playwright, Error
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch()
                browser.close()
            except Error as error:
                raise unittest.SkipTest("Chromium not installed") from error
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _App)
        cls.other = ThreadingHTTPServer(("127.0.0.1", 0), _App)
        _App.other_origin = f"http://127.0.0.1:{cls.other.server_port}"
        for server in (cls.server, cls.other):
            threading.Thread(target=server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        for server in (cls.server, cls.other):
            server.shutdown()
            server.server_close()

    def setUp(self):
        _App.requests = []

    def test_agentic_recon_selects_observed_browser_page(self):
        base = f"http://127.0.0.1:{self.server.server_port}"
        app, task = _fixture(budget=80)
        from dataclasses import replace
        task = replace(task, target_url=base + "/")

        class SelectSpa:
            calls = []

            def decide(self, *, observations, selectable_surface_ids, **kwargs):
                self.calls.append(observations)
                selected = next(
                    item for item in observations
                    if item.path == "/spa" and item.surface_id in selectable_surface_ids
                )
                return ReconAction(
                    action="visit_surface", surface_id=selected.surface_id,
                    basis_observation_ids=(selected.observation_id,),
                    reason_code="inspect_document", source="llm", status="llm_success",
                )

        planner = SelectSpa()
        agent = ReconAgent(
            collector=app.collector, evidence_store=app.stores.evidence,
            surface_store=app.stores.surfaces, max_pages=1,
            iterative_planner=planner,
            browser_recon=PlaywrightRecon(
                collector=app.collector, run_store=app.stores.runs, max_pages=2,
            ),
        )
        agent.handle(task)
        self.assertEqual(len(planner.calls), 1)
        self.assertTrue(any(
            item.path == "/spa" and "browser_dom" in item.discovery_types
            for item in planner.calls[0]
        ))
        self.assertIn(("GET", "/spa"), _App.requests)
        self.assertNotIn(("GET", "/board"), _App.requests)
        summary = next(
            item.observation for item in app.stores.evidence.list_by_run(task.run_id)
            if item.observation.get("type") == "browser_recon_summary"
        )
        self.assertEqual(summary["planner_selection_count"], 1)
        self.assertEqual(summary["planner_llm_call_count"], 1)
        self.assertFalse(any(method != "GET" for method, _ in _App.requests))

    def test_browser_recon_rejects_unoffered_page_choice(self):
        base = f"http://127.0.0.1:{self.server.server_port}"
        app, task = _fixture(budget=80)
        from dataclasses import replace
        task = replace(task, target_url=base + "/")
        browser = PlaywrightRecon(
            collector=app.collector, run_store=app.stores.runs, max_pages=2,
        )
        result = browser.discover(
            task, remember=lambda *args: "surface-observed",
            request_budget=30, timeout_seconds=30,
            select_next=lambda options, budget, seconds: base + "/not-offered",
        )
        summary = next(
            observation for _, observation in result.observations
            if observation.get("type") == "browser_recon_summary"
        )
        self.assertEqual(summary["planner_selection_count"], 0)
        self.assertNotIn(("GET", "/not-offered"), _App.requests)

    def test_dynamic_menu_tab_form_and_network_structure_use_shared_collector(self):
        base = f"http://127.0.0.1:{self.server.server_port}"
        app, task = _fixture(budget=80)
        from dataclasses import replace
        task = replace(task, target_url=base + "/")
        agent = ReconAgent(collector=app.collector, evidence_store=app.stores.evidence,
                           surface_store=app.stores.surfaces, max_pages=10,
                           browser_recon=PlaywrightRecon(collector=app.collector, run_store=app.stores.runs, max_pages=6))
        result = agent.handle(task)
        surfaces = app.stores.surfaces.list_by_run(task.run_id)
        urls = {s.url for s in surfaces}
        for path in ("/board", "/menu", "/tabbed", "/late", "/item/7"):
            self.assertIn(base + path, urls)
        self.assertTrue(any(s.url == base + "/api/tab" and "view" in s.parameters for s in surfaces))
        self.assertTrue(any(s.url == base + "/api/search" and "q" in s.parameters for s in surfaces))
        self.assertTrue(any(s.url == base + "/spa#/results" and "q" in s.parameters for s in surfaces))
        self.assertTrue(any(s.url == base + "/api/items/7" and s.method == "PATCH" and "title" in s.parameters for s in surfaces))
        self.assertFalse(any(method != "GET" for method, _ in _App.requests))
        self.assertNotIn(("GET", "/outside"), _App.requests)
        used = 80 - app.budget_manager.remaining(task.run_id)
        self.assertEqual(used, len(_App.requests))
        self.assertLessEqual(used, 40)
        self.assertEqual(used, len(app.audit_log.list_by_run(task.run_id)))
        observations = [e for e in app.stores.evidence.list_by_run(task.run_id) if e.created_by == "browser_recon"]
        serialized = json.dumps([e.observation for e in observations])
        self.assertNotIn("private-fixture-csrf", serialized)
        self.assertTrue(any(e.observation.get("body_parameter_names") == ["title", "csrfToken"] and e.observation.get("sent") is False for e in observations))
        self.assertTrue(any(e.observation.get("type") == "browser_recon_summary" for e in observations))
        self.assertTrue(set(e.evidence_id for e in observations).issubset(result.new_evidence_ids))

    def test_inert_hash_reflection_creates_observed_client_surface(self):
        base = f"http://127.0.0.1:{self.server.server_port}"
        app, task = _fixture(budget=20)
        from dataclasses import replace
        task = replace(task, target_url=base + "/hash")
        agent = ReconAgent(
            collector=app.collector, evidence_store=app.stores.evidence,
            surface_store=app.stores.surfaces, max_pages=1,
            browser_recon=PlaywrightRecon(
                collector=app.collector, run_store=app.stores.runs, max_pages=1
            ),
        )
        agent.handle(task)
        surfaces = app.stores.surfaces.list_by_run(task.run_id)
        hash_surface = next(
            s for s in surfaces if s.url == base + "/hash#" + RAW_HASH_CANARY
        )
        self.assertEqual(hash_surface.parameters, (RAW_HASH_PARAMETER,))
        self.assertIn("browser_hash_probe", hash_surface.discovery_types)
        observations = app.stores.evidence.list_by_run(task.run_id)
        self.assertTrue(any(
            e.surface_id == hash_surface.surface_id
            and e.observation.get("type") == "browser_hash_reflection"
            for e in observations
        ))
        self.assertFalse(any(method != "GET" for method, _ in _App.requests))

    def test_safe_hash_renderer_does_not_execute_validation_payload(self):
        base = f"http://127.0.0.1:{self.server.server_port}"
        marker = XSS_EXECUTION_MARKER_PREFIX + "safecontrol"
        request = ExecutionRequest(
            execution_id="safe-hash", run_id="browser-run", task_id="validation",
            tool=BROWSER_XSS_TOOL, target_url=base + "/hash-safe#" + RAW_HASH_CANARY,
            surface_id="safe-hash", purpose="independent execution check",
            request_kind=HttpRequestKind.PROBE,
            query_parameters=((RAW_HASH_PARAMETER, marker),),
            scope=RunScope(allowed_hosts=frozenset({"127.0.0.1"})),
            timeout_seconds=2,
        )
        navigation_url, expected = browser_navigation_url(request)
        result = PlaywrightBrowserRuntime._run_playwright(
            request, navigation_url, expected, ()
        )
        self.assertEqual(result.evidence_type, "browser_execution")
        self.assertFalse(result.observation["script_executed"])
        self.assertGreaterEqual(result.observation["blocked_request_count"], 1)
        self.assertFalse(any(method != "GET" for method, _ in _App.requests))

    def test_browser_xss_page_dependencies_use_the_shared_request_budget(self):
        base = f"http://127.0.0.1:{self.server.server_port}"
        for budget in (1, 2):
            with self.subTest(budget=budget):
                _App.requests = []
                app, task = _fixture(
                    budget=budget,
                    runtime=PlaywrightBrowserRuntime(http_runtime=HttpExecutionRuntime()),
                )
                _, result = app.collector.collect_with_result(
                    task.run_id, base + "/hash#" + RAW_HASH_CANARY,
                    EvidenceRequest(
                        evidence_type="browser_execution", surface_id="hash-surface",
                        reason="bounded browser XSS reflection",
                        suggested_tool=BROWSER_XSS_TOOL,
                        http_request=HttpRequestSpec(
                            query_parameters=((RAW_HASH_PARAMETER, XSS_REFLECTION_MARKER_PREFIX + "budget"),),
                            request_kind=HttpRequestKind.PROBE,
                        ),
                    ),
                    task_id=task.task_id,
                )
                self.assertEqual(app.budget_manager.remaining(task.run_id), 0)
                audited = app.audit_log.list_by_run(task.run_id)
                self.assertEqual(len(audited), 2)
                self.assertEqual(sum(item.outcome == "completed" for item in audited), budget)
                self.assertEqual(len(_App.requests), budget - 1)
                self.assertEqual(
                    result.evidence_type,
                    "browser_execution" if budget == 2 else "browser_error",
                )

    def test_subresource_stops_at_shared_budget(self):
        app, task = _fixture(budget=1)
        base = f"http://127.0.0.1:{self.server.server_port}"
        from dataclasses import replace
        task = replace(task, target_url=base + "/")
        transport = _CollectorTransport(collector=app.collector, task=task,
                                        scope=app.stores.runs.get(task.run_id).scope,
                                        remember=lambda *a: "surface", limit=5, deadline=time.monotonic()+5)
        first = _Route(base + "/api/nav")
        second = _Route(base + "/board")
        transport.handle(first)
        transport.handle(second)
        self.assertEqual(first.outcome[0], "fulfill")
        self.assertEqual(second.outcome[0], "abort")
        self.assertEqual(app.budget_manager.remaining(task.run_id), 0)
        self.assertNotIn(("GET", "/board"), _App.requests)


if __name__ == "__main__":
    unittest.main()
