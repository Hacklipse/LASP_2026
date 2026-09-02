"""표준 라이브러리 기반 실제 HTTP 실행 Runtime.

Safety Boundary의 바깥 끝. PolicyGate·Budget 검사를 통과한 ExecutionRequest만
여기 도달하며, 이 클래스 뒤부터가 통제 불가능한 외부 세계다.

`DisabledExecutionRuntime`을 이 구현으로 교체하는 순간 시스템이 처음으로 실제
네트워크를 친다. 초기 대상은 로컬 컨테이너로 한정한다.

설계 노트 — Runtime은 세션 갱신을 위해 응답 헤더를 원문 그대로 캡처하지만, 중앙
RuntimeEvidenceCollector가 Evidence Store에 쓰기 전에 Cookie·Authorization·토큰을
마스킹한다. Agent에는 마스킹된 저장본만 전달되고 원문 응답은 인증 Worker의 현재
호출 스택 밖으로 나가지 않는다.
"""

from __future__ import annotations

import hashlib
import http.cookiejar
import http.cookies
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

from hacklipse.domain import ExecutionRequest, ExecutionResult
from hacklipse.ports import CredentialResolver
from hacklipse.ports.errors import CredentialNotFound, ExternalExecutionDisabled

# http(s)만 허용한다. file:·ftp: 등은 SSRF 표면이므로 Runtime 진입 전에 차단한다.
_ALLOWED_SCHEMES = frozenset({"http", "https"})
_HTTP_TOOLS = frozenset(
    {
        "http_get",
        "http_post",
        "path_traversal_probe",
        "access_control_probe",
        "ssti_probe",
    }
)
# 실제 리다이렉트 상태만 리다이렉트로 분류한다. 300/304/305/306은 리다이렉트가 아니다.
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_DEFAULT_TIMEOUT = 15.0
# 현대 SPA 번들은 1MiB를 넘는다. 상한이 번들 중간을 자르면 후반부에만 등장하는
# API 경로가 Recon에서 통째로 사라진다. Recon의 스크립트 분석 상한(4MiB)보다는
# 낮게 두어 무제한 수집으로 번지지 않게 한다.
_DEFAULT_MAX_BODY_BYTES = 2 * 1024 * 1024
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


class _LocalhostCookiePolicy(http.cookiejar.DefaultCookiePolicy):
    """정확한 localhost Domain 쿠키만 단일 호스트 예외로 허용한다.

    Python CookieJar는 점이 없는 ``Domain=localhost``를 기본적으로 거부한다. 로컬
    실습 서버가 이 속성을 명시하는 경우에만 받아들이되, 다른 단일 라벨 호스트나
    서브도메인에는 예외를 확장하지 않는다.
    """

    @staticmethod
    def _is_exact_localhost(cookie, request) -> bool:
        request_host = http.cookiejar.request_host(request).casefold()
        cookie_domain = cookie.domain.lstrip(".").casefold()
        return request_host == "localhost" and cookie_domain == "localhost"

    def set_ok_domain(self, cookie, request) -> bool:
        if self._is_exact_localhost(cookie, request):
            return not self.is_blocked(cookie.domain) and not self.is_not_allowed(
                cookie.domain
            )
        return super().set_ok_domain(cookie, request)

    def return_ok_domain(self, cookie, request) -> bool:
        if self._is_exact_localhost(cookie, request):
            return True
        return super().return_ok_domain(cookie, request)


class _RotatingSessionCookieJar(http.cookiejar.CookieJar):
    """같은 이름의 Cookie는 Domain 속성이 달라져도 최신 값 하나만 남긴다.

    RFC 6265는 Cookie를 (name, domain, path)로 구분한다. 그래서 서버가 로그인
    직후 세션 Cookie를 재발급하면서 Domain 속성만 새로 붙이면, 인증 이전의
    Cookie가 별개 항목으로 남아 두 값이 함께 전송된다. 서버가 그중 낡은 쪽을
    집으면 방금 성공한 로그인이 다음 요청에서 사라진다.

    이 Runtime의 CookieJar는 (run_id, credential_ref) 하나에만 묶인 단일 세션이라
    같은 호스트에 같은 이름의 Cookie를 여러 벌 들고 있을 이유가 없다. 이름과
    호스트가 같으면 이전 값을 지우고 새 값으로 대체한다.
    """

    def set_cookie(self, cookie) -> None:
        host = cookie.domain.lstrip(".").casefold()
        stale = [
            existing
            for existing in self
            if existing.name == cookie.name
            and existing.domain.lstrip(".").casefold() == host
        ]
        for existing in stale:
            self.clear(existing.domain, existing.path, existing.name)
        super().set_cookie(cookie)


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
        credential_resolver: CredentialResolver | None = None,
    ) -> None:
        self._timeout = timeout_seconds
        self._max_body = max_body_bytes
        self._user_agent = user_agent
        self._credentials = credential_resolver
        # CookieJar와 opener는 Run별로 격리한다. 다른 Run의 세션이 섞이면 인증 경계와
        # 검증 provenance가 동시에 깨진다.
        self._sessions: dict[tuple[str, str | None], urllib.request.OpenerDirector] = {}
        self._session_jars: dict[tuple[str, str | None], http.cookiejar.CookieJar] = {}
        self._seeded_sessions: set[tuple[str, str | None]] = set()

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        """정책 검사를 통과한 요청을 실제로 전송하고 응답을 Evidence로 변환한다."""

        if request.tool not in _HTTP_TOOLS:
            raise ExternalExecutionDisabled(
                f"http runtime does not implement tool: {request.tool}"
            )
        requested_url = request.resolved_url
        scheme = urllib.parse.urlsplit(requested_url).scheme.lower()
        method = request.method.upper()
        if scheme not in _ALLOWED_SCHEMES:
            # 마지막 방어선: 정책 게이트를 통과했더라도 위험 스킴은 여기서 거부한다.
            raise ExternalExecutionDisabled(
                f"unsupported url scheme for http runtime: {scheme or '(none)'}"
            )

        headers = dict(request.headers)
        opener = self._opener_for(request)
        if request.credential_ref is not None:
            if self._credentials is None:
                raise CredentialNotFound(
                    "execution references credentials but no resolver is configured"
                )
            credential = self._credentials.resolve(request.credential_ref)
            if credential.authorization:
                # Agent는 Authorization을 만들 수 없고 중앙 Resolver만 이 위치에 주입한다.
                headers["Authorization"] = credential.authorization
        # 이 두 헤더는 Runtime의 안전·식별 경계이므로 Agent 명세로 덮어쓸 수 없다.
        headers.update(
            {
                "User-Agent": self._user_agent,
                # 서버 압축을 끈다. urllib은 gzip을 자동 해제하지 않으므로, 압축 응답을
                # 그대로 받으면 텍스트 분석(reflection·secret 탐지)이 깨진다.
                "Accept-Encoding": "identity",
            }
        )
        body = request.body.encode("utf-8") if request.body is not None else None
        http_request = urllib.request.Request(
            requested_url,
            data=body,
            method=method,
            headers=headers,
        )

        # 응답 지연 측정 시작. time-based blind 탐지(예: SQLi SLEEP)의 유일한 신호원이다.
        started = time.perf_counter()
        try:
            with opener.open(
                http_request, timeout=min(self._timeout, request.timeout_seconds)
            ) as response:
                return self._response_result(
                    request, requested_url, method, response, started, redirect=False
                )
        except urllib.error.HTTPError as error:
            # HTTPError도 응답 유사 객체다 — 실제 리다이렉트(301/302/303/307/308)만
            # http_redirect로, 나머지(304·4xx·5xx)는 정상 응답으로 기록한다.
            try:
                redirect = error.code in _REDIRECT_STATUSES
                return self._response_result(
                    request, requested_url, method, error, started, redirect=redirect
                )
            finally:
                error.close()
        except (urllib.error.URLError, TimeoutError) as error:
            # DNS 실패·연결 거부·타임아웃 등 — 예상한 네트워크 예외만 관측 사실로 남긴다.
            return self._error_result(request, requested_url, method, error, started)

    def close_session(self, run_id: str) -> None:
        """Run 종료·폐기 시 메모리 CookieJar 참조를 제거한다."""

        keys = [key for key in self._sessions if key[0] == run_id]
        for key in keys:
            self._sessions.pop(key, None)
            self._session_jars.pop(key, None)
            self._seeded_sessions.discard(key)

    def session_cookies(self, request: ExecutionRequest) -> tuple[tuple[str, str], ...]:
        """현재 Run에서 이 URL로 실제 전송될 Cookie만 브라우저 경계에 전달한다.

        반환값은 메모리 안에서 Browser Runtime으로만 이동해야 하며 Evidence나 감사
        이벤트에 넣지 않는다. CookieJar의 domain/path/secure 정책을 그대로 적용하기
        위해 임시 urllib Request에 Cookie 헤더를 계산한 뒤 이름·값만 추출한다.
        """

        self._opener_for(request)
        jar = self._session_jars[(request.run_id, request.credential_ref)]
        cookie_request = urllib.request.Request(request.resolved_url)
        jar.add_cookie_header(cookie_request)
        header = cookie_request.get_header("Cookie")
        if not header:
            return ()
        parsed = http.cookies.SimpleCookie()
        parsed.load(header)
        return tuple((name, morsel.value) for name, morsel in parsed.items())

    def _opener_for(self, request: ExecutionRequest) -> urllib.request.OpenerDirector:
        """Run/credential 조합별 CookieJar를 만들고 초기 쿠키를 한 번만 주입한다."""

        key = (request.run_id, request.credential_ref)
        opener = self._sessions.get(key)
        if opener is None:
            jar = _RotatingSessionCookieJar(policy=_LocalhostCookiePolicy())
            opener = urllib.request.build_opener(
                _NoRedirect,
                urllib.request.ProxyHandler({}),
                urllib.request.HTTPCookieProcessor(jar),
            )
            self._sessions[key] = opener
            self._session_jars[key] = jar

        if request.credential_ref is not None and key not in self._seeded_sessions:
            if self._credentials is None:
                raise CredentialNotFound(
                    "execution references credentials but no resolver is configured"
                )
            credential = self._credentials.resolve(request.credential_ref)
            jar = self._session_jars[key]
            parsed = urllib.parse.urlsplit(request.resolved_url)
            hostname = parsed.hostname or ""
            for name, value in credential.cookies:
                jar.set_cookie(_session_cookie(name, value, hostname, parsed.scheme == "https"))
            self._seeded_sessions.add(key)
        return opener

    def _response_result(
        self,
        request: ExecutionRequest,
        requested_url: str,
        method: str,
        response,
        started: float,
        *,
        redirect: bool,
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
            "requested_url": requested_url,
            "request_kind": request.request_kind.value,
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
        self,
        request: ExecutionRequest,
        requested_url: str,
        method: str,
        error: BaseException,
        started: float,
    ) -> ExecutionResult:
        """네트워크 오류를 예외 대신 http_error 증적으로 변환한다."""

        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_error",
            observation={
                "type": "http_error",
                "method": method,
                "requested_url": requested_url,
                "request_kind": request.request_kind.value,
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


def _session_cookie(
    name: str, value: str, domain: str, secure: bool
) -> http.cookiejar.Cookie:
    """Resolver의 초기 쿠키를 현재 대상 host에만 한정된 세션 쿠키로 만든다."""

    if not name or not domain:
        raise ValueError("session cookie requires a name and target domain")
    return http.cookiejar.Cookie(
        version=0,
        name=name,
        value=value,
        port=None,
        port_specified=False,
        domain=domain,
        domain_specified=False,
        domain_initial_dot=False,
        path="/",
        path_specified=True,
        secure=secure,
        expires=None,
        discard=True,
        comment=None,
        comment_url=None,
        rest={"HttpOnly": None},
        rfc2109=False,
    )
