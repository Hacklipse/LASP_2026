"""Real loopback HTTP callback transport, without treating a fetch as a finding."""

from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import urlopen

from hacklipse.adapters import HttpExecutionRuntime
from hacklipse.adapters.local_ssrf_callback import LocalSsrfCallbackService
from hacklipse.adapters.policy import AllowlistPolicyGate
from hacklipse.bootstrap import build_local_application, register_standard_agents, standard_router
from hacklipse.domain import (
    CandidateStatus, ExecutionRequest, HttpRequestKind, Run, RunRequest, RunScope,
)
from hacklipse.ports.errors import PolicyViolation


class LocalSsrfCallbackTests(unittest.TestCase):
    def test_docker_host_origin_keeps_listener_on_loopback(self) -> None:
        with LocalSsrfCallbackService(advertised_host="host.docker.internal") as service:
            self.assertFalse(service.public_oast)
            ticket = service.issue("docker-target")
            self.assertTrue(ticket.url.startswith("http://host.docker.internal:"))
            with urlopen(ticket.url.replace("host.docker.internal", "127.0.0.1"), timeout=2) as response:
                self.assertEqual(response.status, 204)
            self.assertEqual(len(service.poll(ticket.token, timeout_seconds=0.1)), 1)

            scope = RunScope(allowed_hosts=frozenset({"127.0.0.1"}))
            run = Run(
                run_id="docker-run", target_url="http://127.0.0.1:13311/",
                scope=scope, policy_profile="safe", request_budget=8,
            )
            request = ExecutionRequest(
                execution_id="docker-probe", run_id=run.run_id, task_id="task-1",
                tool="http_get", target_url=run.target_url, surface_id="surface-1",
                purpose="Docker Desktop callback", request_kind=HttpRequestKind.SSRF_PROBE,
                query_parameters=(("url", ticket.url),), scope=scope,
            )
            AllowlistPolicyGate(
                ssrf_callback_origin=service.origin, ssrf_local_test_mode=True,
            ).validate_execution(run, request)
            with self.assertRaises(ValueError):
                AllowlistPolicyGate(ssrf_callback_origin=service.origin)

    def test_listener_issues_stable_ticket_and_records_only_known_http_requests(self) -> None:
        with LocalSsrfCallbackService() as service:
            ticket = service.issue("run:candidate:A")
            self.assertEqual(ticket, service.issue("run:candidate:A"))
            with urlopen(ticket.url, timeout=2) as response:
                self.assertEqual(response.status, 204)
            hits = service.poll(ticket.token, timeout_seconds=0.1)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].method, "GET")
            self.assertEqual(hits[0].source, "127.0.0.1")
            with self.assertRaises(HTTPError) as error:
                urlopen(f"{service.origin}/ssrf/unknown", timeout=2)
            self.assertEqual(error.exception.code, 404)
            self.assertEqual(len(service.poll(ticket.token, timeout_seconds=0.1)), 1)

            service.discard(ticket.token)
            with self.assertRaisesRegex(TimeoutError, "unavailable"):
                service.poll(ticket.token, timeout_seconds=0.1)
            self.assertNotIn(ticket.token, repr((service._tickets, service._tokens, service._hits)))

    def test_local_http_requires_explicit_mode_and_loopback_target(self) -> None:
        with LocalSsrfCallbackService() as service:
            with self.assertRaises(ValueError):
                AllowlistPolicyGate(ssrf_callback_origin=service.origin)
            policy = AllowlistPolicyGate(
                ssrf_callback_origin=service.origin, ssrf_local_test_mode=True,
            )
            ticket = service.issue("policy")
            scope = RunScope(allowed_hosts=frozenset({"target.example"}))
            run = Run(
                run_id="remote", target_url="https://target.example/", scope=scope,
                policy_profile="safe", request_budget=8,
            )
            request = ExecutionRequest(
                execution_id="exec-1", run_id=run.run_id, task_id="task-1",
                tool="http_get", target_url=run.target_url, surface_id="surface-1",
                purpose="local callback guard", request_kind=HttpRequestKind.SSRF_PROBE,
                query_parameters=(("url", ticket.url),), scope=scope,
            )
            with self.assertRaisesRegex(PolicyViolation, "loopback targets"):
                policy.validate_execution(run, request)

    def test_local_target_fetch_is_suspected_and_negative_target_has_no_hit(self) -> None:
        for fetch in (True, False):
            with self.subTest(fetch=fetch), LocalSsrfCallbackService() as service:
                callback_origin = service.origin

                class Target(BaseHTTPRequestHandler):
                    def do_GET(self) -> None:
                        parsed = urlsplit(self.path)
                        if parsed.path == "/":
                            body = b'<a href="/preview?url=old">preview</a>'
                        else:
                            url = parse_qs(parsed.query).get("url", [""])[0]
                            if fetch and url.startswith(callback_origin):
                                with urlopen(url, timeout=2):
                                    pass
                            body = b"ok"
                        self.send_response(200)
                        self.send_header("Content-Type", "text/html")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)

                    def log_message(self, format: str, *args: object) -> None:
                        pass

                server = ThreadingHTTPServer(("127.0.0.1", 0), Target)
                server.daemon_threads = True
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    app = build_local_application(
                        {}, runtime=HttpExecutionRuntime(),
                        ssrf_callback_service=service, ssrf_local_test_mode=True,
                        router=standard_router(("SSRF",), ssrf_callback_service=service),
                    )
                    register_standard_agents(app, recon_max_pages=4)
                    run = app.orchestrator.start(RunRequest(
                        target_url=f"http://127.0.0.1:{server.server_port}/",
                        scope=RunScope(allowed_hosts=frozenset({"127.0.0.1"})),
                        request_budget=20,
                    ))
                    candidates = app.stores.candidates.list_by_run(run.run_id)
                    self.assertEqual(len(candidates), 1)
                    self.assertEqual(candidates[0].status, CandidateStatus.SUSPECTED)
                    self.assertEqual(run.finding_ids, ())
                    hits = [item for item in app.stores.evidence.list_by_run(run.run_id)
                            if item.observation.get("type") == "ssrf_callback_http"]
                    self.assertEqual(len(hits), 2 if fetch else 0)
                    self.assertTrue(all(item.observation["attribution"] == "unverified"
                                        for item in hits))
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
