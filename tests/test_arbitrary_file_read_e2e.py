"""End-to-end local HTTP fixture for the standard file-read workflow."""

from __future__ import annotations

import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from hacklipse.adapters import HttpExecutionRuntime, InMemoryKnowledgeBase
from hacklipse.adapters.arbitrary_file_read_analysis import SafeFileTarget
from hacklipse.bootstrap import (
    build_local_application, register_standard_agents, standard_router,
)
from hacklipse.domain import KnowledgeQuery, RunRequest, RunScope, ValidationProofType


class FileReadHandler(BaseHTTPRequestHandler):
    canary_path: str = ""
    accepted_value: str = ""
    link: str = "/download?asset=sample"
    public_canary: bool = False

    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/":
            body = f'<a href="{self.link}">download</a>'.encode()
            status = 200
            content_type = "text/html"
        elif parsed.path == "/download":
            value = parse_qs(parsed.query).get("asset", [""])[0]
            mode = parse_qs(parsed.query).get("mode", [""])[0]
            if value == self.accepted_value and mode in {"", "raw"}:
                body = Path(self.canary_path).read_bytes()
                status = 200
            else:
                body = b"not found"
                status = 404
            content_type = "application/octet-stream"
        elif parsed.path == "/reflect":
            value = parse_qs(parsed.query).get("asset", [""])[0]
            body = value.encode()
            status = 200
            content_type = "text/plain"
        elif self.public_canary and parsed.path == self.canary_path:
            body = Path(self.canary_path).read_bytes()
            status = 200
            content_type = "text/plain"
        elif parsed.path.startswith("/files/"):
            value = unquote(parsed.path[len("/files/"):])
            if value == self.accepted_value:
                body = Path(self.canary_path).read_bytes()
                status = 200
            else:
                body = b"not found"
                status = 404
            content_type = "application/octet-stream"
        else:
            body = b"not found"
            status = 404
            content_type = "text/plain"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class FileReadWorkflowTests(unittest.TestCase):
    def test_local_http_run_reaches_a_confirmed_finding(self):
        self._run_fixture("/download?asset=sample")

    def test_path_input_reaches_a_confirmed_finding(self):
        self._run_fixture("/files/sample")

    def test_query_probe_preserves_a_required_observed_option(self):
        self._run_fixture("/download?asset=sample&mode=raw")

    def test_reflected_path_does_not_create_a_finding(self):
        self._run_fixture("/reflect?asset=sample", expected_findings=0)

    def test_directly_public_canary_does_not_create_a_finding(self):
        self._run_fixture(
            "/download?asset=sample", expected_findings=0, public_canary=True
        )

    def test_relative_path_strategy_reaches_a_confirmed_finding(self):
        self._run_fixture(
            "/download?asset=sample", proof_request="../../../safe/canary.txt"
        )

    def test_double_encoded_strategy_reaches_a_confirmed_finding(self):
        self._run_fixture(
            "/download?asset=sample",
            proof_request="..%2f..%2f..%2fsafe%2fcanary.txt",
        )

    def _run_fixture(
        self, link: str, *, expected_findings: int = 1,
        public_canary: bool = False, proof_request: str | None = None,
    ):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "canary.txt"
            path.write_text("afr unique canary contents\n", encoding="utf-8")
            FileReadHandler.canary_path = str(path)
            FileReadHandler.accepted_value = proof_request or str(path)
            FileReadHandler.link = link
            FileReadHandler.public_canary = public_canary
            server = ThreadingHTTPServer(("127.0.0.1", 0), FileReadHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                target = SafeFileTarget(
                    "local-canary", FileReadHandler.accepted_value,
                    ("afr unique canary contents",), public_path=str(path),
                )
                knowledge = InMemoryKnowledgeBase()
                app = build_local_application(
                    {}, runtime=HttpExecutionRuntime(),
                    router=standard_router(),
                    file_read_targets=(target,),
                    knowledge_base=knowledge,
                    report_format_version="v2",
                )
                register_standard_agents(app)
                run = app.orchestrator.start(RunRequest(
                    target_url=f"http://127.0.0.1:{server.server_port}/",
                    scope=RunScope(allowed_hosts=frozenset({"127.0.0.1"})),
                    request_budget=60,
                ))
                findings = app.stores.findings.list_by_run(run.run_id)
                candidates = [
                    candidate
                    for candidate in app.stores.candidates.list_by_run(run.run_id)
                    if candidate.vulnerability_type == "Arbitrary File Read"
                ]
                self.assertEqual(len(findings), expected_findings, (
                    run.phase,
                    [(s.url, s.parameters) for s in app.stores.surfaces.list_by_run(run.run_id)],
                    [(c.vulnerability_type, c.status.value) for c in app.stores.candidates.list_by_run(run.run_id)],
                    [(e.created_by, e.observation.get("type"), e.observation.get("status"), e.observation.get("file_read_marker_match")) for e in app.stores.evidence.list_by_run(run.run_id)],
                ))
                if expected_findings:
                    self.assertEqual(
                        findings[0].proof_type, ValidationProofType.ARBITRARY_FILE_READ
                    )
                    self.assertTrue(knowledge.search(KnowledgeQuery(
                        category="Arbitrary File Read", text="file read",
                    )))
                else:
                    self.assertTrue(candidates)
                    self.assertTrue(all(
                        candidate.validation_reason_code is not None
                        for candidate in candidates
                    ))
                report = app.stores.reports.list_by_run(run.run_id)[0]
                if expected_findings:
                    self.assertIn("arbitrary_file_read", report.content)
                for evidence in app.stores.evidence.list_by_run(run.run_id):
                    if evidence.created_by == "execution_runtime:file_read_probe":
                        self.assertNotIn("body", evidence.observation)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
