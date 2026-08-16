"""HttpExecutionRuntime을 로컬 stdlib 서버로 검증한다 (외부 네트워크·Docker 불필요)."""

from __future__ import annotations

import socket
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from hacklipse.adapters import HttpExecutionRuntime
from hacklipse.domain import ExecutionRequest
from hacklipse.ports.errors import ExternalExecutionDisabled

# 리다이렉트 대상 서버가 실제로 요청을 받았는지 세는 카운터.
REDIRECT_TARGET_HITS = 0
BIG_BODY = b"A" * (512 * 1024 + 100)  # 512KB 초과


class _Handler(BaseHTTPRequestHandler):
    """테스트 라우팅."""

    def do_HEAD(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        path = self.path
        if path == "/ok":
            self._text(200, b"hello REFLECTED_MARKER")
        elif path == "/redirect":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{TARGET_PORT}/landed")
            self.end_headers()
        elif path == "/notmodified":
            self.send_response(304)
            self.end_headers()
        elif path == "/missing":
            self._text(404, b"not found")
        elif path == "/error":
            self._text(500, b"boom")
        elif path == "/big":
            self._text(200, BIG_BODY)
        elif path == "/dupcookie":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "a=1")
            self.send_header("Set-Cookie", "b=2")
            self.end_headers()
            self.wfile.write(b"ok")
        elif path == "/binary":
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.end_headers()
            self.wfile.write(b"\x89PNG\r\n\x00\xff\xfe")
        elif path == "/echo-accept-encoding":
            # 클라이언트가 보낸 Accept-Encoding을 본문에 되돌려준다.
            ae = self.headers.get("Accept-Encoding", "(none)")
            self._text(200, f"AE={ae}".encode())
        elif path == "/delay":
            time.sleep(0.2)
            self._text(200, b"delayed")
        elif path == "/slow":
            time.sleep(1.0)
            self._text(200, b"late")
        else:
            self._text(404, b"?")

    def _text(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:  # 테스트 출력 소음 제거
        pass


class _TargetHandler(BaseHTTPRequestHandler):
    """리다이렉트 대상. 요청을 받으면 카운터를 올린다 (따라갔는지 검증용)."""

    def do_GET(self) -> None:  # noqa: N802
        global REDIRECT_TARGET_HITS
        REDIRECT_TARGET_HITS += 1
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args) -> None:
        pass


TARGET_PORT = 0


class HttpExecutionRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        global TARGET_PORT
        cls.target = ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
        TARGET_PORT = cls.target.server_address[1]
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        for srv in (cls.target, cls.server):
            threading.Thread(target=srv.serve_forever, daemon=True).start()
        cls.runtime = HttpExecutionRuntime(timeout_seconds=5.0)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.target.shutdown()

    def _req(self, path: str, *, method: str = "GET", host: str | None = None) -> ExecutionRequest:
        base = host or f"http://127.0.0.1:{self.port}"
        return ExecutionRequest(
            execution_id="exec-1",
            run_id="run-1",
            task_id="task-1",
            tool="http_get",
            target_url=f"{base}{path}",
            surface_id=None,
            purpose="test",
            method=method,
        )

    # 1
    def test_200_captured_as_response(self) -> None:
        r = self.runtime.execute(self._req("/ok"))
        self.assertEqual(r.evidence_type, "http_response")
        self.assertEqual(r.observation["status"], 200)
        self.assertIn("REFLECTED_MARKER", r.observation["body"])
        self.assertTrue(r.observation["headers"])
        self.assertIsNotNone(r.content_hash)

    # 2 + 3
    def test_302_not_followed_and_target_untouched(self) -> None:
        before = REDIRECT_TARGET_HITS
        r = self.runtime.execute(self._req("/redirect"))
        self.assertEqual(r.evidence_type, "http_redirect")
        self.assertEqual(r.observation["status"], 302)
        self.assertEqual(r.observation["location"], f"http://127.0.0.1:{TARGET_PORT}/landed")
        # 리다이렉트 대상 서버는 요청을 한 번도 받지 않아야 한다.
        self.assertEqual(REDIRECT_TARGET_HITS, before)

    # 4
    def test_304_is_response_not_redirect(self) -> None:
        r = self.runtime.execute(self._req("/notmodified"))
        self.assertEqual(r.evidence_type, "http_response")
        self.assertEqual(r.observation["status"], 304)

    # 5
    def test_404_and_500_are_responses(self) -> None:
        self.assertEqual(self.runtime.execute(self._req("/missing")).observation["status"], 404)
        r = self.runtime.execute(self._req("/error"))
        self.assertEqual(r.evidence_type, "http_response")
        self.assertEqual(r.observation["status"], 500)

    # 6
    def test_connection_refused_is_http_error(self) -> None:
        # 빈 포트를 확보한 뒤 닫아 연결 거부를 유도한다.
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        dead_port = s.getsockname()[1]
        s.close()
        r = self.runtime.execute(self._req("/x", host=f"http://127.0.0.1:{dead_port}"))
        self.assertEqual(r.evidence_type, "http_error")
        self.assertIn(r.observation["error_kind"], {"connection_refused", "connection"})

    def test_timeout_is_http_error(self) -> None:
        fast = HttpExecutionRuntime(timeout_seconds=0.3)
        r = fast.execute(self._req("/slow"))
        self.assertEqual(r.evidence_type, "http_error")
        self.assertEqual(r.observation["error_kind"], "timeout")

    # 7
    def test_body_truncated_at_limit(self) -> None:
        r = self.runtime.execute(self._req("/big"))
        self.assertTrue(r.observation["truncated"])
        self.assertEqual(r.observation["body_bytes"], 512 * 1024)

    # 8
    def test_head_does_not_read_body(self) -> None:
        r = self.runtime.execute(self._req("/ok", method="HEAD"))
        self.assertEqual(r.observation["status"], 200)
        self.assertEqual(r.observation["body_bytes"], 0)
        self.assertIsNone(r.observation["body"])

    # 9
    def test_duplicate_headers_preserved(self) -> None:
        r = self.runtime.execute(self._req("/dupcookie"))
        cookies = [v for k, v in r.observation["headers"] if k == "set-cookie"]
        self.assertEqual(sorted(cookies), ["a=1", "b=2"])

    # 10
    def test_binary_not_forced_to_string(self) -> None:
        r = self.runtime.execute(self._req("/binary"))
        self.assertIsNone(r.observation["body"])  # 강제 디코딩하지 않음
        self.assertGreater(r.observation["body_bytes"], 0)
        self.assertIsNotNone(r.content_hash)

    # 11
    def test_disallowed_scheme_refused(self) -> None:
        req = self._req("/etc/passwd", host="file://")
        with self.assertRaises(ExternalExecutionDisabled):
            self.runtime.execute(req)

    # 추가: 응답 지연시간을 기록하는지 (time-based 탐지 신호)
    def test_elapsed_ms_recorded(self) -> None:
        fast = self.runtime.execute(self._req("/ok"))
        slow = self.runtime.execute(self._req("/delay"))
        self.assertIn("elapsed_ms", fast.observation)
        # 0.2초 지연 엔드포인트가 즉시 응답보다 확실히 느려야 한다.
        self.assertGreaterEqual(slow.observation["elapsed_ms"], 150.0)
        self.assertGreater(slow.observation["elapsed_ms"], fast.observation["elapsed_ms"])

    # 추가: 압축을 끄는 Accept-Encoding: identity를 보내는지
    def test_accept_encoding_identity(self) -> None:
        r = self.runtime.execute(self._req("/echo-accept-encoding"))
        self.assertEqual(r.observation["body"], "AE=identity")

    # 추가: 환경변수 프록시를 무시하는지
    def test_env_proxy_ignored(self) -> None:
        import os

        os.environ["http_proxy"] = "http://127.0.0.1:9"  # 죽은 프록시
        try:
            runtime = HttpExecutionRuntime(timeout_seconds=5.0)
            r = runtime.execute(self._req("/ok"))
            # 프록시를 탔다면 실패했을 것 — 200이면 프록시를 무시한 것.
            self.assertEqual(r.observation["status"], 200)
        finally:
            os.environ.pop("http_proxy", None)


if __name__ == "__main__":
    unittest.main()
