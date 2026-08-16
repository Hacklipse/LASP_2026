"""표준 라이브러리 기반 실제 HTTP 실행 Runtime.

Safety Boundary의 바깥 끝. PolicyGate·Budget 검사를 통과한 ExecutionRequest만
여기 도달하며, 이 클래스 뒤부터가 통제 불가능한 외부 세계다.

`DisabledExecutionRuntime`을 이 구현으로 교체하는 순간 시스템이 처음으로 실제
네트워크를 친다. 초기 대상은 로컬 컨테이너로 한정한다.

설계 노트 — 응답 헤더는 마스킹하지 않고 원문 그대로(중복 포함) 캡처한다.
관측은 사실의 원천이어야 하며, Auth state 채널(쿠키 리플레이로 IDOR 검증 등)이
실제 Set-Cookie/Authorization 값을 필요로 하기 때문이다. 민감정보 비노출은
LLM 프롬프트 직렬화·리포트 export 지점에서 처리한다(캡처 계층의 책임이 아님).
"""

from __future__ import annotations

import hashlib
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

from hacklipse.domain import ExecutionRequest, ExecutionResult
from hacklipse.ports.errors import ExternalExecutionDisabled

# http(s)만 허용한다. file:·ftp: 등은 SSRF 표면이므로 Runtime 진입 전에 차단한다.
_ALLOWED_SCHEMES = frozenset({"http", "https"})
# 실제 리다이렉트 상태만 리다이렉트로 분류한다. 300/304/305/306은 리다이렉트가 아니다.
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_DEFAULT_TIMEOUT = 15.0
_DEFAULT_MAX_BODY_BYTES = 512 * 1024
_DEFAULT_USER_AGENT = "hacklipse-runtime/0.1"

# 본문을 텍스트로 디코딩할 Content-Type 힌트. 그 외(이미지 등)는 바이너리로 간주한다.
_TEXTUAL_HINTS = ("text/", "json", "xml", "javascript", "html", "x-www-form-urlencoded")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """3xx 응답을 따라가지 않고 HTTPError로 올려보낸다.

    PolicyGate는 원래 URL만 검증하므로, urlopen이 302를 자동으로 따라가면
    allowlist 밖 도메인으로 요청이 새어 나갈 수 있다. 리다이렉트를 막고
    그 사실 자체를 증적으로 남긴다.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # None을 반환하면 urllib이 리다이렉트를 따라가지 않고 HTTPError를 발생시킨다.
        return None


class HttpExecutionRuntime:
    """urllib.request 기반 실제 HTTP 실행 구현.

    - 리다이렉트를 따라가지 않는다 (Scope 우회 방지).
    - 환경변수 프록시를 무시한다 (로컬 요청이 외부 프록시로 새는 것 방지).
    - 응답 본문은 상한까지만 읽고, 바이너리는 강제 디코딩하지 않는다.
    - 리다이렉트·네트워크 오류도 예외로 터뜨리지 않고 관측 결과로 기록한다.
    """

    def __init__(
        self,
        *,
        timeout_seconds: float = _DEFAULT_TIMEOUT,
        max_body_bytes: int = _DEFAULT_MAX_BODY_BYTES,
        user_agent: str = _DEFAULT_USER_AGENT,
    ) -> None:
        self._timeout = timeout_seconds
        self._max_body = max_body_bytes
        self._user_agent = user_agent
        # _NoRedirect: 리다이렉트로 allowlist 밖으로 나가는 것을 막는다.
        # ProxyHandler({}): 환경변수(http_proxy 등) 프록시를 무시해 요청이 외부로 새지 않게 한다.
        self._opener = urllib.request.build_opener(
            _NoRedirect, urllib.request.ProxyHandler({})
        )

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        """정책 검사를 통과한 요청을 실제로 전송하고 응답을 Evidence로 변환한다."""

        scheme = urllib.parse.urlsplit(request.target_url).scheme.lower()
        method = request.method.upper()
        if scheme not in _ALLOWED_SCHEMES:
            # 마지막 방어선: 정책 게이트를 통과했더라도 위험 스킴은 여기서 거부한다.
            raise ExternalExecutionDisabled(
                f"unsupported url scheme for http runtime: {scheme or '(none)'}"
            )

        http_request = urllib.request.Request(
            request.target_url,
            method=method,
            headers={
                "User-Agent": self._user_agent,
                # 서버 압축을 끈다. urllib은 gzip을 자동 해제하지 않으므로, 압축 응답을
                # 그대로 받으면 텍스트 분석(reflection·secret 탐지)이 깨진다.
                "Accept-Encoding": "identity",
            },
        )

        # 응답 지연 측정 시작. time-based blind 탐지(예: SQLi SLEEP)의 유일한 신호원이다.
        started = time.perf_counter()
        try:
            with self._opener.open(http_request, timeout=self._timeout) as response:
                return self._response_result(request, method, response, started, redirect=False)
        except urllib.error.HTTPError as error:
            # HTTPError도 응답 유사 객체다 — 실제 리다이렉트(301/302/303/307/308)만
            # http_redirect로, 나머지(304·4xx·5xx)는 정상 응답으로 기록한다.
            try:
                redirect = error.code in _REDIRECT_STATUSES
                return self._response_result(request, method, error, started, redirect=redirect)
            finally:
                error.close()
        except (urllib.error.URLError, TimeoutError) as error:
            # DNS 실패·연결 거부·타임아웃 등 — 예상한 네트워크 예외만 관측 사실로 남긴다.
            return self._error_result(request, method, error, started)

    def _response_result(
        self, request: ExecutionRequest, method: str, response, started: float, *, redirect: bool
    ) -> ExecutionResult:
        """응답 유사 객체(정상 응답 또는 HTTPError)를 ExecutionResult로 변환한다."""

        # HEAD는 본문이 없다. 상한+1을 읽어 잘림 여부를 판별한다.
        raw = b"" if method == "HEAD" else response.read(self._max_body + 1)
        truncated = len(raw) > self._max_body
        raw = raw[: self._max_body]

        status = getattr(response, "status", None)
        if status is None:  # HTTPError는 .status 대신 .code를 갖는 버전이 있다.
            status = getattr(response, "code", None)

        content_type = response.headers.get("Content-Type", "")
        # 중복 헤더(Set-Cookie 등)를 보존하기 위해 dict가 아닌 [이름, 값] 목록으로 담는다.
        headers = [[key.lower(), value] for key, value in response.headers.items()]

        observation: dict[str, object] = {
            "type": "http_redirect" if redirect else "http_response",
            "status": status,
            "method": method,
            "requested_url": request.target_url,
            "content_type": content_type,
            "headers": headers,
            "body_bytes": len(raw),
            "truncated": truncated,
            # 요청 시작부터 본문 수신 완료까지의 총 소요(ms). 서버 지연을 담는다.
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        }

        # 텍스트만 디코딩한다. 바이너리는 강제 문자열화하지 않고 크기·해시만 남긴다.
        if method != "HEAD" and _is_textual(content_type):
            observation["body"] = raw.decode(_charset(content_type), errors="replace")
        else:
            observation["body"] = None

        if redirect:
            # 어디로 보내려 했는지 남긴다 — Scope 우회 시도 분석의 근거.
            observation["location"] = response.headers.get("Location")

        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type=str(observation["type"]),
            observation=observation,
            # 본문 무결성·중복 판별용. 원문 바이트 기준으로 계산한다.
            content_hash=hashlib.sha256(raw).hexdigest(),
        )

    def _error_result(
        self, request: ExecutionRequest, method: str, error: BaseException, started: float
    ) -> ExecutionResult:
        """네트워크 오류를 예외 대신 http_error 증적으로 변환한다."""

        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_error",
            observation={
                "type": "http_error",
                "method": method,
                "requested_url": request.target_url,
                "error_kind": _classify_error(error),
                "message": str(getattr(error, "reason", error)),
                # timeout까지 실제로 걸린 시간 — 지연 기반 판단에도 참고된다.
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
            },
        )


def _classify_error(error: BaseException) -> str:
    """네트워크 예외를 timeout / connection_refused / dns / connection으로 분류한다."""

    reason = getattr(error, "reason", error)
    if isinstance(error, TimeoutError) or isinstance(reason, TimeoutError):
        return "timeout"
    if isinstance(reason, ConnectionRefusedError):
        return "connection_refused"
    if isinstance(reason, socket.gaierror):
        return "dns"
    return "connection"


def _is_textual(content_type: str) -> bool:
    """Content-Type이 텍스트 계열인지 판단한다. 헤더가 없으면 텍스트로 간주한다."""

    if not content_type:
        return True
    lowered = content_type.lower()
    return any(hint in lowered for hint in _TEXTUAL_HINTS)


def _charset(content_type: str) -> str:
    """"text/html; charset=euc-kr" 형태에서 charset을 뽑는다. 없으면 utf-8."""

    for part in content_type.split(";"):
        part = part.strip().lower()
        if part.startswith("charset="):
            return part[len("charset=") :] or "utf-8"
    return "utf-8"
