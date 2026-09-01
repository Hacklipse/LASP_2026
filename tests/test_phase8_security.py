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
    SensitiveDataSanitizer,
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
    ExecutionRequest,
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

    def _localhost_domain(self) -> str:
        host = self.headers.get("Host", "").partition(":")[0].casefold()
        return "; Domain=localhost" if host == "localhost" else ""

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
            self.send_header(
                "Set-Cookie",
                f"bootstrap=dvwa-bootstrap-secret; Path=/{self._localhost_domain()}",
            )
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
            # 실제 DVWA처럼 로그인 성공과 실패 모두 302다. 보호 페이지를 확인하지
            # 않으면 상태 코드만으로 실패를 성공으로 오판한다.
            self.send_response(302)
            self.send_header("Location", "/login.php")
            self.end_headers()
            return
        self.send_response(302)
        self.send_header("Location", "/vulnerabilities/xss_r/")
        self.send_header(
            "Set-Cookie",
            f"PHPSESSID={_SESSION}; Path=/{self._localhost_domain()}; HttpOnly",
        )
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

    def _resolver(
        self, *, host: str = "127.0.0.1", password: str = _PASSWORD
    ) -> InMemoryCredentialResolver:
        base = f"http://{host}:{self.port}"
        target = f"{base}/vulnerabilities/xss_r/?name=seed"
        return InMemoryCredentialResolver(
            {
                "local-dvwa": ResolvedHttpCredential(
                    cookies=(("security", "low"),),
                    form_login=FormLoginSpec(
                        login_url=f"{base}/login.php",
                        username=_USERNAME,
                        password=password,
                        csrf_field="user_token",
                        extra_fields=(("Login", "Login"),),
                        failure_marker="Login failed",
                        verification_url=target,
                        approval_ref=_APPROVAL,
                    ),
                )
            }
        )

    def _request(self, *, host: str = "127.0.0.1") -> RunRequest:
        return RunRequest(
            target_url=(
                f"http://{host}:{self.port}/vulnerabilities/xss_r/?name=seed"
            ),
            scope=RunScope(allowed_hosts=frozenset({host})),
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
        # 인증 검증 + Recon + control + probe + Validation이 같은 세션을 쓴다.
        self.assertGreaterEqual(_DvwaLikeHandler.authenticated_gets, 5)
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

        # Browser Runtime에는 현재 Run에서 실제 전송 가능한 Cookie만 메모리로 넘긴다.
        browser_cookies = dict(
            runtime.session_cookies(
                ExecutionRequest(
                    execution_id="exec-browser-cookie-check",
                    run_id=run.run_id,
                    task_id="task-browser-cookie-check",
                    tool="browser_xss",
                    target_url=self._request().target_url,
                    surface_id=None,
                    purpose="test authenticated browser cookie handoff",
                    credential_ref="local-dvwa",
                    scope=run.scope,
                )
            )
        )
        self.assertEqual(browser_cookies["security"], "low")
        self.assertEqual(browser_cookies["PHPSESSID"], _SESSION)

    def test_domain_localhost_cookies_are_reused_for_exact_localhost(self) -> None:
        resolver = self._resolver(host="localhost")
        app = build_local_application(
            {},
            runtime=HttpExecutionRuntime(credential_resolver=resolver),
            router=standard_router(),
            credential_resolver=resolver,
            approval_gate=StaticApprovalGate((_APPROVAL,)),
        )
        register_standard_agents(app)

        run = app.orchestrator.start(self._request(host="localhost"))

        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(_DvwaLikeHandler.login_posts, 1)
        self.assertGreaterEqual(_DvwaLikeHandler.authenticated_gets, 5)

    def test_login_redirect_is_rejected_when_protected_page_redirects(self) -> None:
        resolver = self._resolver(password="incorrect-test-password")
        app = build_local_application(
            {},
            runtime=HttpExecutionRuntime(credential_resolver=resolver),
            router=standard_router(),
            credential_resolver=resolver,
            approval_gate=StaticApprovalGate((_APPROVAL,)),
        )
        register_standard_agents(app)

        with self.assertRaises(WorkflowExecutionError) as context:
            app.orchestrator.start(self._request())

        self.assertIn("protected resource verification", str(context.exception))
        self.assertEqual(_DvwaLikeHandler.authenticated_gets, 0)

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
    def test_task_progress_callback_observes_start_and_completion(self) -> None:
        stores = MemoryStoreBundle()
        budget = InMemoryBudgetManager()
        budget.open_run("run-progress", 1)
        dispatcher = LocalTaskDispatcher()
        dispatcher.register("worker", _CompletingAgent(), allowed_tools=())
        events: list[tuple[str, str, int, float]] = []
        executor = TaskExecutor(
            dispatcher=dispatcher,
            task_store=stores.tasks,
            budget_manager=budget,
            retry_policy=BoundedRetryPolicy(),
            progress_callback=lambda event, task, attempt, elapsed: events.append(
                (event, task.task_id, attempt, elapsed)
            ),
        )

        executor.execute(
            TaskEnvelope(
                task_id="task-progress",
                run_id="run-progress",
                agent_type="worker",
            )
        )

        self.assertEqual([event[0] for event in events], ["started", "succeeded"])
        self.assertTrue(all(event[1] == "task-progress" for event in events))
        self.assertTrue(all(event[2] == 1 for event in events))
        self.assertGreaterEqual(events[-1][3], 0.0)

    def test_task_progress_callback_failure_does_not_change_task_result(self) -> None:
        stores = MemoryStoreBundle()
        budget = InMemoryBudgetManager()
        budget.open_run("run-progress-error", 1)
        dispatcher = LocalTaskDispatcher()
        dispatcher.register("worker", _CompletingAgent(), allowed_tools=())

        def broken_callback(*args) -> None:
            del args
            raise RuntimeError("debug output unavailable")

        executor = TaskExecutor(
            dispatcher=dispatcher,
            task_store=stores.tasks,
            budget_manager=budget,
            retry_policy=BoundedRetryPolicy(),
            progress_callback=broken_callback,
        )

        result = executor.execute(
            TaskEnvelope(
                task_id="task-progress-error",
                run_id="run-progress-error",
                agent_type="worker",
            )
        )

        self.assertIs(result.status, AgentResultStatus.COMPLETED)

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


class PhoneMaskingPrecisionTests(unittest.TestCase):
    """마스킹은 개인정보만 지워야 한다. 관측을 훼손하면 탐지 누락으로 이어진다."""

    def test_masks_real_korean_mobile_numbers(self) -> None:
        for number in (
            "010-1234-5678",
            "01012345678",
            "+82 10-1234-5678",
            "+821012345678",
            "019-123-4567",
        ):
            with self.subTest(number=number):
                masked = SensitiveDataSanitizer._sanitize_text(f"연락처 {number}", ())
                self.assertNotIn(number, masked)

    def test_keeps_digit_runs_that_are_not_phone_numbers(self) -> None:
        # 앞자리 0 없이 1로 시작하는 숫자열은 전화번호가 아니다. UUID·주문번호·오류
        # 메시지에 흔하며, 지워지면 반사·SQL 오류 신호가 함께 사라진다.
        for text in (
            "182698169",
            "114098404",
            "order-1234567890",
            "hacklipsed3cdc8ab-018c-4d91-864c-182698169bc0",
        ):
            with self.subTest(text=text):
                self.assertEqual(
                    SensitiveDataSanitizer._sanitize_text(text, ()), text
                )


class SanitizerStructurePreservationTests(unittest.TestCase):
    """마스킹이 Recon 구조와 Evidence 재연결 메타데이터를 훼손하지 않아야 한다."""

    def test_preserves_html_field_names_while_masking_sensitive_values(self) -> None:
        html = (
            '<form><input type="password" name="password_new">'
            '<input name="password" value="password">'
            '<p>password</p></form>'
        )

        sanitized = SensitiveDataSanitizer._sanitize_text(html, ("password",))

        self.assertIn('type="password"', sanitized)
        self.assertIn('name="password_new"', sanitized)
        self.assertIn('name="password"', sanitized)
        self.assertIn('value="<redacted>"', sanitized)
        self.assertNotIn("<p>password</p>", sanitized)

    def test_csrf_path_does_not_redact_unrelated_query_value(self) -> None:
        url = "http://local.test/vulnerabilities/csrf/?q=hacklipse-control"

        sanitized = SensitiveDataSanitizer._sanitize_text(url, ())

        self.assertEqual(sanitized, url)

    def test_sensitive_query_value_is_redacted_without_renaming_parameter(self) -> None:
        url = "http://local.test/search?csrf_token=marker"

        sanitized = SensitiveDataSanitizer._sanitize_text(url, ())
        parsed = urlsplit(sanitized)

        self.assertEqual(parsed.path, "/search")
        self.assertEqual(parse_qs(parsed.query), {"csrf_token": ["<redacted>"]})


class InMemoryCredentialResolverRegistrationTests(unittest.TestCase):
    """자동 인증 Worker가 발급한 단기 자격증명은 중복 없이 메모리에만 등록한다."""

    def test_adds_a_provisioned_credential(self) -> None:
        resolver = InMemoryCredentialResolver({})
        credential = ResolvedHttpCredential(authorization="Bearer temporary-token")

        resolver.add("temporary-actor", credential)

        self.assertEqual(resolver.resolve("temporary-actor"), credential)

    def test_rejects_blank_or_duplicate_references(self) -> None:
        resolver = InMemoryCredentialResolver({})
        credential = ResolvedHttpCredential(authorization="Bearer temporary-token")

        with self.assertRaises(ValueError):
            resolver.add("", credential)
        resolver.add("temporary-actor", credential)
        with self.assertRaises(ValueError):
            resolver.add("temporary-actor", credential)


if __name__ == "__main__":
    unittest.main()
