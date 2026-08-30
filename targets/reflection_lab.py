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

_PATHS = tuple(dict.fromkeys(path for path, _ in GROUND_TRUTH))

# /filtered가 제거하는 패턴. 영숫자 8자 이상 연속 토큰을 지운다 — marker가 여기 걸린다.
_FILTER = re.compile(r"[A-Za-z0-9]{8,}")


def _page(body: str) -> str:
    return f"<!doctype html><html><body>{body}</body></html>"


def _render(path: str, params: dict[str, list[str]]) -> tuple[str, str]:
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
    if path == "/json":
        return "application/json", json.dumps({"status": "success", "data": []})
    if path == "/multi":
        a = params.get("a", [""])[0]
        return "text/html", _page(f"<p>a={a}</p><p>b=[not rendered]</p>")
    return "text/html", _index()


def _index() -> str:
    """Recon이 크롤할 수 있도록 서버가 렌더링한 링크를 제공한다(SPA가 아니다)."""

    links = "".join(
        f'<li><a href="{path}?{"a=seed&amp;b=seed" if path == "/multi" else "q=seed"}">'
        f"{path}</a></li>"
        for path in _PATHS
    )
    return _page(f"<h1>reflection lab</h1><ul>{links}</ul>")


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        content_type, body = _render(parsed.path, parse_qs(parsed.query))
        raw = body.encode("utf-8")
        self.send_response(200)
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
    print(f"reflection lab  http://{BIND_HOST}:{port}/")
    print(f"정답: 파라미터 {len(GROUND_TRUTH)}개 중 반사 {reflected}개")
    ThreadingHTTPServer((BIND_HOST, port), _Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
