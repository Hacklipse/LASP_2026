"""Phase 8 인증·승인·마스킹·감사 경계를 로컬 DVWA 유사 서버로 검증한다."""

from __future__ import annotations

import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from hacklipse.adapters import (
    BoundedRetryPolicy,
    HttpExecutionRuntime,
    InMemoryBudgetManager,
    InMemoryCredentialResolver,
    InMemoryExecutionAuditLog,
    LocalTaskDispatcher,
    MemoryStoreBundle,
    SQLiteExecutionAuditLog,
    StaticApprovalGate,
)
from hacklipse.application import TaskExecutor
from hacklipse.application.errors import WorkflowExecutionError
from hacklipse.bootstrap import (
    build_local_application,
    register_standard_agents,
    standard_router,
)
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    RunPhase,
    RunRequest,
    RunScope,
    TaskEnvelope,
    TaskStatus,
)
from hacklipse.ports import FormLoginSpec, ResolvedHttpCredential
from hacklipse.ports.errors import AgentToolNotAllowed, TaskTimeout

_USERNAME = "dvwa-user"
_PASSWORD = "dvwa-password-secret"
_CSRF = "dvwa-csrf-secret"
_SESSION = "dvwa-session-secret"
_APPROVAL = "approve-local-dvwa-login"


class _DvwaLikeHandler(BaseHTTPRequestHandler):
    """CSRF form 로그인 뒤 세션 Cookie가 있어야 반사 페이지를 보여준다."""

    login_posts = 0
    authenticated_gets = 0

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path == "/login.php":
            body = (
                '<form method="post">'
                f'<input value="{_CSRF}" type="hidden" name="user_token">'
                '<input name="username"><input name="password">'
                "</form>"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", "bootstrap=dvwa-bootstrap-secret; Path=/")
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/vulnerabilities/xss_r/":
            cookie = self.headers.get("Cookie", "")
            if (
                f"PHPSESSID={_SESSION}" not in cookie
                or "security=low" not in cookie
            ):
                self.send_response(302)
                self.send_header("Location", "/login.php")
                self.end_headers()
                return
            type(self).authenticated_gets += 1
            name = parse_qs(parsed.query, keep_blank_values=True).get("name", [""])[0]
            self._html(
                200,
                f'<html><input value="{name}">victim@example.test</html>'.encode(),
            )
            return

        self._html(404, b"not found")

    def do_POST(self) -> None:  # noqa: N802
        if urlsplit(self.path).path != "/login.php":
            self._html(404, b"not found")
            return
        type(self).login_posts += 1
        length = int(self.headers.get("Content-Length", "0"))
        fields = parse_qs(self.rfile.read(length).decode(), keep_blank_values=True)
        cookie = self.headers.get("Cookie", "")
        valid = (
            "bootstrap=dvwa-bootstrap-secret" in cookie
            and fields.get("user_token") == [_CSRF]
            and fields.get("username") == [_USERNAME]
            and fields.get("password") == [_PASSWORD]
            and fields.get("Login") == ["Login"]
        )
        if not valid:
            self._html(200, b"Login failed")
            return
        self.send_response(302)
        self.send_header("Location", "/vulnerabilities/xss_r/")
        self.send_header("Set-Cookie", f"PHPSESSID={_SESSION}; Path=/; HttpOnly")
        self.end_headers()

    def _html(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass


class Phase8AuthenticatedWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _DvwaLikeHandler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()

    def setUp(self) -> None:
        _DvwaLikeHandler.login_posts = 0
        _DvwaLikeHandler.authenticated_gets = 0

    def _resolver(self) -> InMemoryCredentialResolver:
        base = f"http://127.0.0.1:{self.port}"
        return InMemoryCredentialResolver(
            {
                "local-dvwa": ResolvedHttpCredential(
                    cookies=(("security", "low"),),
                    form_login=FormLoginSpec(
                        login_url=f"{base}/login.php",
                        username=_USERNAME,
                        password=_PASSWORD,
                        csrf_field="user_token",
                        extra_fields=(("Login", "Login"),),
                        failure_marker="Login failed",
                        approval_ref=_APPROVAL,
                    ),
                )
            }
        )

    def _request(self) -> RunRequest:
        return RunRequest(
            target_url=(
                f"http://127.0.0.1:{self.port}/vulnerabilities/xss_r/?name=seed"
            ),
            scope=RunScope(allowed_hosts=frozenset({"127.0.0.1"})),
            request_budget=20,
            credential_ref="local-dvwa",
        )

    def test_form_login_session_is_reused_and_secrets_are_not_stored(self) -> None:
        resolver = self._resolver()
        runtime = HttpExecutionRuntime(credential_resolver=resolver)
        audit = InMemoryExecutionAuditLog()
        app = build_local_application(
            {},
            runtime=runtime,
            router=standard_router(),
            credential_resolver=resolver,
            approval_gate=StaticApprovalGate((_APPROVAL,)),
            audit_log=audit,
        )
        register_standard_agents(app)

        run = app.orchestrator.start(self._request())

        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(_DvwaLikeHandler.login_posts, 1)
        # Recon + control + probe + Validation 재현 요청이 같은 인증 세션을 쓴다.
        self.assertGreaterEqual(_DvwaLikeHandler.authenticated_gets, 4)
        self.assertEqual(
            app.stores.tasks.list_by_run(run.run_id)[0].envelope.agent_type,
            "session_authenticator",
        )

        stored = repr(app.stores.evidence.list_by_run(run.run_id))
        for secret in (
            _USERNAME,
            _PASSWORD,
            _CSRF,
            _SESSION,
            "dvwa-bootstrap-secret",
            "victim@example.test",
        ):
            self.assertNotIn(secret, stored)
        self.assertIn("<redacted>", stored)

        events = audit.list_by_run(run.run_id)
        self.assertTrue(any(event.method == "POST" for event in events))
        self.assertTrue(all("?" not in event.target for event in events))
        self.assertTrue(all(event.outcome == "completed" for event in events))

    def test_login_post_is_blocked_without_explicit_approval(self) -> None:
        resolver = self._resolver()
        audit = InMemoryExecutionAuditLog()
        app = build_local_application(
            {},
            runtime=HttpExecutionRuntime(credential_resolver=resolver),
            router=standard_router(),
            credential_resolver=resolver,
            audit_log=audit,
        )
        register_standard_agents(app)

        with self.assertRaises(WorkflowExecutionError) as context:
            app.orchestrator.start(self._request())

        self.assertEqual(_DvwaLikeHandler.login_posts, 0)
        events = audit.list_by_run(context.exception.run_id)
        self.assertEqual(events[-1].method, "POST")
        self.assertEqual(events[-1].outcome, "blocked_or_failed")
        self.assertEqual(events[-1].detail, "ApprovalRequired")


class Phase8PersistentAuditTests(unittest.TestCase):
    def test_sqlite_audit_is_append_only_across_reopen(self) -> None:
        from hacklipse.ports import ExecutionAuditEvent

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.sqlite3"
            first = SQLiteExecutionAuditLog(path)
            first.append(
                ExecutionAuditEvent(
                    execution_id="exec-1",
                    run_id="run-1",
                    task_id="task-1",
                    tool="http_get",
                    method="GET",
                    target="http://local.test/protected",
                    request_kind="control",
                    outcome="completed",
                    status_code=200,
                )
            )
            first.close()

            reopened = SQLiteExecutionAuditLog(path)
            try:
                events = reopened.list_by_run("run-1")
            finally:
                reopened.close()

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].execution_id, "exec-1")
        self.assertEqual(events[0].status_code, 200)


class _CompletingAgent:
    def handle(self, task: TaskEnvelope) -> AgentResult:
        return AgentResult(task_id=task.task_id, status=AgentResultStatus.COMPLETED)


class _SlowAgent:
    def handle(self, task: TaskEnvelope) -> AgentResult:
        time.sleep(0.5)
        return AgentResult(task_id=task.task_id, status=AgentResultStatus.COMPLETED)


class Phase8TaskBoundaryTests(unittest.TestCase):
    def test_dispatcher_rejects_tools_not_granted_at_registration(self) -> None:
        dispatcher = LocalTaskDispatcher()
        dispatcher.register("restricted", _CompletingAgent(), allowed_tools=())

        with self.assertRaises(AgentToolNotAllowed):
            dispatcher.dispatch(
                TaskEnvelope(
                    task_id="task-tool",
                    run_id="run-tool",
                    agent_type="restricted",
                    allowed_tools=("http_get",),
                )
            )

    def test_task_timeout_interrupts_and_records_failure(self) -> None:
        stores = MemoryStoreBundle()
        budget = InMemoryBudgetManager()
        budget.open_run("run-timeout", 1)
        dispatcher = LocalTaskDispatcher()
        dispatcher.register("slow", _SlowAgent(), allowed_tools=())
        executor = TaskExecutor(
            dispatcher=dispatcher,
            task_store=stores.tasks,
            budget_manager=budget,
            retry_policy=BoundedRetryPolicy(),
        )
        task = TaskEnvelope(
            task_id="task-timeout",
            run_id="run-timeout",
            agent_type="slow",
            timeout_seconds=0.05,
        )

        started = time.monotonic()
        with self.assertRaises(TaskTimeout):
            executor.execute(task)

        self.assertLess(time.monotonic() - started, 0.25)
        record = stores.tasks.get("task-timeout")
        self.assertIs(record.status, TaskStatus.FAILED)
        self.assertEqual(record.attempts, 1)


if __name__ == "__main__":
    unittest.main()
