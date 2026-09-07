"""연구용 반사 실험 대상. 정답(ground truth)을 함께 정의한다.

왜 자체 대상이 필요한가 — juice-shop과 DVWA는 인터넷에서 가장 유명한 취약 앱이라
엔드포인트와 취약점이 학습 데이터에 들어있다. 거기서 LLM이 높은 점수를 받아도
"관측해서 찾았다"인지 "외운 걸 읊었다"인지 구분할 수 없다. 내적 타당성이 무너진다.

이 대상은 학습 데이터에 없으므로 암기가 불가능하고, 정답을 우리가 알고 있으므로
정밀도·재현율을 정확히 계산할 수 있다.

    python3 targets/reflection_lab.py          # 127.0.0.1:8000
    python3 targets/reflection_lab.py 8123     # 포트 지정

경고 — 의도적으로 입력을 반사한다. 127.0.0.1에만 바인딩하며 외부에 노출하지 않는다.
"""

from __future__ import annotations

import html
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

BIND_HOST = "127.0.0.1"  # 외부 인터페이스에 바인딩하지 않는다.
DEFAULT_PORT = 8000

# 정답. (경로, 파라미터) -> 기대 결과.
#   reflected  응답 본문에 입력이 그대로 나타나는가
#   context    나타난다면 어떤 구문 위치인가 (LlmXssAnalyzer의 분류 축과 같은 어휘)
#   encoded    출력 인코딩이 적용됐는가
GROUND_TRUTH: dict[tuple[str, str], dict[str, object]] = {
    ("/text", "q"): {"reflected": True, "context": "html_text", "encoded": False},
    ("/attr-quoted", "q"): {"reflected": True, "context": "html_attribute", "encoded": False},
    ("/attr-unquoted", "q"): {"reflected": True, "context": "html_attribute", "encoded": False},
    ("/script", "q"): {"reflected": True, "context": "script_block", "encoded": False},
    ("/comment", "q"): {"reflected": True, "context": "html_comment", "encoded": False},
    ("/href", "q"): {"reflected": True, "context": "url_context", "encoded": False},
    # 반사되지만 인코딩된다. 문자열 일치로는 구분되지 않고 맥락 분류만이 구분한다.
    ("/encoded", "q"): {"reflected": True, "context": "html_text", "encoded": True},
    # 아래 넷은 반사되지 않는다. 여기서 신호를 만들면 오탐이다.
    ("/filtered", "q"): {"reflected": False},
    ("/static", "q"): {"reflected": False},
    ("/json", "q"): {"reflected": False},
    ("/multi", "b"): {"reflected": False},
    # 같은 Surface의 다른 파라미터는 반사된다 — 파라미터 단위 분해 능력을 본다.
    ("/multi", "a"): {"reflected": True, "context": "html_text", "encoded": False},
}

# SQLi 신호 정답. 값 뒤 작은따옴표가 SQL 파서에 닿는지를 세 가지 방식으로 나눈다.
SQL_GROUND_TRUTH: dict[tuple[str, str], dict[str, object]] = {
    # 오류 메시지를 그대로 노출한다(개발 설정에서 흔하다).
    ("/sqli-error", "id"): {"vulnerable": True, "signal": "error_message", "engine": "sqlite"},
    # 오류를 감추지만 500으로 갈린다(운영 설정에서 흔하다).
    ("/sqli-status", "id"): {"vulnerable": True, "signal": "status_differential"},
    # 파라미터 바인딩을 써서 따옴표가 값으로만 취급된다.
    ("/sqli-safe", "id"): {"vulnerable": False},
}

# Access Control 정답. 두 계정이 각자 프로필 객체를 소유하고, 한 엔드포인트만 소유권을
# 검사한다. 실제 앱(DVWA bac)과 같은 구조를 정답을 아는 상태로 재현한 것이다.
ACCESS_CONTROL_GROUND_TRUTH: dict[tuple[str, str], dict[str, object]] = {
    # 소유권 검사가 없다. 로그인만 했으면 남의 프로필도 읽힌다.
    ("/profile-vuln", "user_id"): {"vulnerable": True},
    # 세션 주체와 요청한 객체가 다르면 거부한다.
    ("/profile-safe", "user_id"): {"vulnerable": False},
}

# 실험용 계정. 이 파일은 127.0.0.1에만 바인딩되며 실제 자격증명이 아니다.
_ACCOUNTS = {"alice": ("lab-alice-secret", "1"), "bob": ("lab-bob-secret", "2")}
_SESSIONS: dict[str, str] = {}  # session id -> user_id
_ACCESS_LOG: list[tuple[str, str, str]] = []  # (session user_id, path, requested user_id)

_PATHS = tuple(
    dict.fromkeys(
        [path for path, _ in GROUND_TRUTH]
        + [path for path, _ in SQL_GROUND_TRUTH]
        + [path for path, _ in ACCESS_CONTROL_GROUND_TRUTH]
    )
)

# /filtered가 제거하는 패턴. 영숫자 8자 이상 연속 토큰을 지운다 — marker가 여기 걸린다.
_FILTER = re.compile(r"[A-Za-z0-9]{8,}")


def _page(body: str) -> str:
    return f"<!doctype html><html><body>{body}</body></html>"


def _profile_page(user_id: str) -> str:
    """DVWA와 비슷하게 안정적인 구조 신호를 노출한다(길이 비교로는 구분되지 않게)."""

    name = next(
        (login for login, (_, uid) in _ACCOUNTS.items() if uid == user_id), None
    )
    if name is None:
        return _page("<div id=\"profile-info\"><p>존재하지 않는 사용자</p></div>")
    return _page(
        '<div id="profile-info">'
        f'<p>User ID: {user_id}</p><p>Name: {name}</p>'
        '</div>'
    )


def _denied_page() -> str:
    return _page('<div id="profile-info"><p>Access denied.</p></div>')


def _render(path: str, params: dict[str, list[str]], session_user: str | None = None):
    """경로별 반사 동작. GROUND_TRUTH와 반드시 일치해야 한다."""

    q = params.get("q", [""])[0]
    if path == "/text":
        return "text/html", _page(f"<p>검색어: {q}</p>")
    if path == "/attr-quoted":
        return "text/html", _page(f'<input type="text" value="{q}">')
    if path == "/attr-unquoted":
        return "text/html", _page(f"<input type=text value={q}>")
    if path == "/script":
        return "text/html", _page(f'<script>var term = "{q}";</script>')
    if path == "/comment":
        return "text/html", _page(f"<!-- query: {q} --><p>done</p>")
    if path == "/href":
        return "text/html", _page(f'<a href="/go?to={q}">next</a>')
    if path == "/encoded":
        return "text/html", _page(f"<p>검색어: {html.escape(q)}</p>")
    if path == "/filtered":
        return "text/html", _page(f"<p>검색어: {_FILTER.sub('[removed]', q)}</p>")
    if path == "/static":
        return "text/html", _page("<p>결과가 없습니다.</p>")
    if path == "/sqli-error":
        # 따옴표가 구문을 깨고 엔진 오류가 응답에 노출된다.
        if "'" in params.get("id", [""])[0]:
            return "text/html", _page(
                "<h1>Error</h1><pre>SQLITE_ERROR: unrecognized token: "
                f"&quot;{html.escape(params['id'][0])}&quot;</pre>"
            )
        return "text/html", _page("<p>항목 1건</p>")
    if path == "/sqli-status":
        # 오류 본문은 감추지만 상태 코드가 갈린다.
        if "'" in params.get("id", [""])[0]:
            return "text/html", _page("<p>일시적인 오류입니다.</p>"), 500
        return "text/html", _page("<p>항목 1건</p>")
    if path == "/sqli-safe":
        # 바인딩 파라미터. 따옴표는 값의 일부일 뿐 구문을 깨지 않는다.
        return "text/html", _page("<p>일치하는 항목이 없습니다.</p>")
    if path in ("/profile-vuln", "/profile-safe"):
        if session_user is None:
            # 로그인 페이지로 보낸다. 미인증 응답을 정상 객체 접근으로 오인하면 안 된다.
            return "text/html", _page('<form action="/login" method="POST">login</form>'), 302
        requested = params.get("user_id", [""])[0]
        # action은 식별자가 아니지만 없으면 동작하지 않는다 — 원본 보존을 검증하는 자리다.
        if params.get("action", [""])[0] != "view":
            return "text/html", _page("<p>지원하지 않는 동작입니다.</p>"), 400
        _ACCESS_LOG.append((session_user, path, requested))
        if path == "/profile-safe" and requested != session_user:
            return "text/html", _denied_page(), 403
        return "text/html", _profile_page(requested)
    if path == "/json":
        return "application/json", json.dumps({"status": "success", "data": []})
    if path == "/multi":
        a = params.get("a", [""])[0]
        return "text/html", _page(f"<p>a={a}</p><p>b=[not rendered]</p>")
    return "text/html", _index()


def _index() -> str:
    """Recon이 크롤할 수 있도록 서버가 렌더링한 링크를 제공한다(SPA가 아니다)."""

    def query_for(path: str) -> str:
        if path == "/multi":
            return "a=seed&amp;b=seed"
        if path.startswith("/profile-"):
            return "user_id=1&amp;action=view"
        return "q=seed"

    links = "".join(
        f'<li><a href="{path}?{query_for(path)}">{path}</a></li>' for path in _PATHS
    )
    return _page(f"<h1>reflection lab</h1><ul>{links}</ul>")


class _Handler(BaseHTTPRequestHandler):
    def _session_user(self) -> str | None:
        raw = self.headers.get("Cookie", "")
        for chunk in raw.split(";"):
            name, _, value = chunk.strip().partition("=")
            if name == "lab_session":
                return _SESSIONS.get(value)
        return None

    def do_POST(self) -> None:  # noqa: N802
        if urlsplit(self.path).path != "/login":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]
        account = _ACCOUNTS.get(username)
        if account is None or account[0] != password:
            body = _page("<p>Login failed.</p>").encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        session_id = f"sess-{username}-{len(_SESSIONS)}"
        _SESSIONS[session_id] = account[1]
        self.send_response(302)
        self.send_header("Set-Cookie", f"lab_session={session_id}; Path=/; HttpOnly")
        self.send_header("Location", "/home")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path == "/home":
            user = self._session_user()
            body = (
                _page(f"<p>signed in as user {user}</p>")
                if user
                else _page("<p>Please log in.</p>")
            ).encode("utf-8")
            self.send_response(200 if user else 302)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            if not user:
                self.send_header("Location", "/login")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        rendered = _render(parsed.path, parse_qs(parsed.query), self._session_user())
        content_type, body = rendered[0], rendered[1]
        status = rendered[2] if len(rendered) > 2 else 200
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args) -> None:
        # 요청 로그는 남긴다 — 무엇을 언제 찔렀는지 답할 수 있어야 한다.
        sys.stderr.write(f"{self.address_string()} {self.path}\n")


def main(argv: list[str]) -> int:
    port = int(argv[1]) if len(argv) > 1 else DEFAULT_PORT
    reflected = sum(1 for v in GROUND_TRUTH.values() if v["reflected"])
    injectable = sum(1 for v in SQL_GROUND_TRUTH.values() if v["vulnerable"])
    print(f"reflection lab  http://{BIND_HOST}:{port}/")
    bac = sum(1 for v in ACCESS_CONTROL_GROUND_TRUTH.values() if v["vulnerable"])
    print(
        f"정답: 반사 {reflected}/{len(GROUND_TRUTH)}"
        f" · SQLi {injectable}/{len(SQL_GROUND_TRUTH)}"
        f" · Access Control {bac}/{len(ACCESS_CONTROL_GROUND_TRUTH)}"
    )
    print(f"실험 계정: {', '.join(sorted(_ACCOUNTS))} (user_id {', '.join(uid for _, uid in _ACCOUNTS.values())})")
    ThreadingHTTPServer((BIND_HOST, port), _Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
