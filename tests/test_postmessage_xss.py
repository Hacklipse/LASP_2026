"""PostMessage candidate parsing and real foreign-origin browser proof."""

from __future__ import annotations

import json
import os
import threading
import unittest
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from hacklipse.adapters.browser_runtime import PlaywrightBrowserRuntime
from hacklipse.adapters.memory import (
    InMemoryCandidateStore, InMemoryEvidenceStore, InMemorySurfaceStore,
)
from hacklipse.adapters.postmessage_plan import (
    POSTMESSAGE_ANALYZER, POSTMESSAGE_PLAN, postmessage_html_plans,
)
from hacklipse.adapters.postmessage_xss_analysis import PostMessageXssAnalyzer
from hacklipse.adapters.xss_execution import (
    BROWSER_XSS_TOOL, browser_navigation_url, validate_browser_xss_request,
)
from hacklipse.domain import (
    AgentResultStatus, Candidate, Evidence, ExecutionRequest, HttpRequestKind,
    RunScope, Surface, TaskEnvelope,
)


_REFLECTION = "hacklipsreflectionabc123"
_EXECUTION = "hacklipsexecutionabc123"
_SCRIPT = """<script>
window.addEventListener('message', function(event) {
  const data = event.data || {};
  if (GUARD) return;
  if (data.type === 'notice:show') {
    document.querySelector('#notice').innerHTML = String(data.html || '');
  }
});
</script><div id=notice></div>"""


class _Target(BaseHTTPRequestHandler):
    def do_GET(self):
        guard = "event.origin !== location.origin" if self.path == "/safe" else "false"
        body = _SCRIPT.replace("GUARD", guard).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _request(base: str, path: str, kind: HttpRequestKind, marker: str = "") -> ExecutionRequest:
    body = None if kind is HttpRequestKind.POSTMESSAGE_CONTROL else json.dumps({
        "type": "notice:show", "field": "html", "marker": marker,
    })
    return ExecutionRequest(
        execution_id="exec", run_id="run", task_id="task", tool=BROWSER_XSS_TOOL,
        target_url=base + path, surface_id="surface", purpose="foreign origin probe",
        method="GET", body=body, request_kind=kind, timeout_seconds=8,
        scope=RunScope(allowed_hosts=frozenset({"127.0.0.1"})),
    )


class PostMessageContractTests(unittest.TestCase):
    def test_script_parser_keeps_only_bounded_message_shape(self):
        plans = postmessage_html_plans(_SCRIPT.replace("GUARD", "false"))
        self.assertEqual(plans, (("notice:show", "html"),))
        self.assertEqual(postmessage_html_plans("window.addEventListener('message', fn)"), ())

    def test_probe_contract_rejects_arbitrary_fields_and_payloads(self):
        valid = _request("http://127.0.0.1", "/vuln", HttpRequestKind.POSTMESSAGE_EXECUTION, _EXECUTION)
        validate_browser_xss_request(valid)
        self.assertEqual(browser_navigation_url(valid), (valid.target_url, _EXECUTION))
        for unsafe in (
            {"type": "notice:show", "field": "html", "marker": "<script>"},
            {"type": "notice:show", "field": "__proto__", "marker": _EXECUTION},
            {"type": "notice:show", "field": "html", "marker": _EXECUTION, "extra": "x"},
        ):
            request = ExecutionRequest(
                execution_id="exec", run_id="run", task_id="task", tool=BROWSER_XSS_TOOL,
                target_url=valid.target_url, surface_id="surface", purpose="probe",
                body=json.dumps(unsafe), request_kind=HttpRequestKind.POSTMESSAGE_EXECUTION,
            )
            with self.assertRaises(ValueError):
                validate_browser_xss_request(request)

    def test_analysis_reuses_collected_probe_when_task_id_changes(self):
        surfaces = InMemorySurfaceStore()
        candidates = InMemoryCandidateStore()
        evidence = InMemoryEvidenceStore()
        url = "http://127.0.0.1/profile"
        surfaces.add(Surface(
            surface_id="surface", run_id="run", url=url, method="GET",
        ))
        candidates.add(Candidate(
            candidate_id="candidate", run_id="run", surface_id="surface",
            vulnerability_type="XSS", hypothesis="message HTML sink",
            assigned_agent=POSTMESSAGE_ANALYZER, evidence_ids=("plan",),
        ))
        evidence.append(Evidence(
            evidence_id="plan", run_id="run", surface_id="surface",
            created_by="recon", evidence_type="observation",
            observation={
                "type": POSTMESSAGE_PLAN, "message_type": "notice:show",
                "html_field": "html",
            },
        ))
        analyzer = PostMessageXssAnalyzer(
            candidate_store=candidates, surface_store=surfaces,
            evidence_store=evidence, id_factory=lambda: "reflection",
        )
        task = TaskEnvelope(
            task_id="first", run_id="run", agent_type=POSTMESSAGE_ANALYZER,
            target_url=url, surface_id="surface", candidate_id="candidate",
            evidence_ids=("plan",), allowed_tools=(BROWSER_XSS_TOOL,),
            request_budget=3,
        )
        first = analyzer.handle(task)
        self.assertIs(first.status, AgentResultStatus.NEEDS_EVIDENCE)
        request = first.evidence_requests[0]
        marker = json.loads(request.http_request.body)["marker"]
        evidence.append(Evidence(
            evidence_id="probe", run_id="run", surface_id="surface",
            created_by="execution_runtime:browser_xss",
            evidence_type="browser_execution", observation={
                "type": "browser_execution",
                "request_kind": HttpRequestKind.POSTMESSAGE_REFLECTION.value,
                "method": "GET", "request_fingerprint": request.request_fingerprint(url),
                "foreign_origin_message": True, "dom_reflected": True,
                "reflection_marker": marker,
            },
        ))
        second = analyzer.handle(replace(
            task, task_id="second", evidence_ids=("plan", "probe"),
        ))
        self.assertIs(second.status, AgentResultStatus.COMPLETED)
        self.assertEqual(len(second.new_evidence_ids), 1)


class PostMessageBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.executable = os.environ.get("HACKLIPSE_TEST_CHROMIUM")
        if not cls.executable or not Path(cls.executable).is_file():
            raise unittest.SkipTest("local Chromium executable is unavailable")
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Target)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def _execute(self, path: str, kind: HttpRequestKind, marker: str = ""):
        request = _request(self.base, path, kind, marker)
        navigation, expected = browser_navigation_url(request)
        return PlaywrightBrowserRuntime._run_playwright(
            request, navigation, expected, (), executable_path=self.executable,
        )

    def test_foreign_origin_message_executes_only_in_vulnerable_page(self):
        control = self._execute("/vuln", HttpRequestKind.POSTMESSAGE_CONTROL)
        vulnerable = self._execute("/vuln", HttpRequestKind.POSTMESSAGE_EXECUTION, _EXECUTION)
        safe = self._execute("/safe", HttpRequestKind.POSTMESSAGE_EXECUTION, _EXECUTION)
        self.assertIs(control.observation.get("script_executed"), False)
        self.assertIs(vulnerable.observation.get("foreign_origin_message"), True)
        self.assertIs(vulnerable.observation.get("script_executed"), True)
        self.assertEqual(vulnerable.observation.get("execution_marker"), _EXECUTION)
        self.assertIs(safe.observation.get("script_executed"), False)

    def test_benign_message_reaches_only_vulnerable_dom(self):
        vulnerable = self._execute("/vuln", HttpRequestKind.POSTMESSAGE_REFLECTION, _REFLECTION)
        safe = self._execute("/safe", HttpRequestKind.POSTMESSAGE_REFLECTION, _REFLECTION)
        self.assertIs(vulnerable.observation.get("dom_reflected"), True)
        self.assertIs(safe.observation.get("dom_reflected"), False)


if __name__ == "__main__":
    unittest.main()
