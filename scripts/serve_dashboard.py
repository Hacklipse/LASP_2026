"""로컬 대상 Run을 웹 대시보드에서 실행하고 진행 상황을 실시간으로 보여준다.

실행 절차 자체는 dashboard_core 가 CLI 실행기의 함수를 재사용해 수행한다. 이 파일은
HTTP 경계만 맡는다 — 정적 파일, 상태 조회, Run 시작 요청의 검증.

    python3 scripts/serve_dashboard.py
    python3 scripts/serve_dashboard.py --port 8080
    python3 scripts/serve_dashboard.py --allow-host host.docker.internal

대상 범위 — 기본 허용 호스트는 localhost·127.0.0.1 뿐이다. 그 밖의 호스트는
--allow-host 로 명시해야 하고, PolicyGate 가 Run 중에 한 번 더 검사한다.
인가받지 않은 대상에 쓰지 않는다.

웹 경계 — 이 화면은 버튼 하나로 스캔을 시작한다. 그래서
  · 루프백에만 바인딩한다(컨테이너는 예외, 아래 참고)
  · /api/run 은 JSON 본문 + 같은 출처 + 시작 시 발급한 CSRF token 을 모두 요구한다
  · 모든 입력은 형식·열거값·길이를 확인한 뒤에만 Run 으로 넘어간다
"""

from __future__ import annotations

import argparse
import json
import os
import secrets as secrets_module
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))


def check_dependencies() -> str | None:
    """Recon 이 쓰는 HTML 파서가 실제로 동작하는지 미리 확인한다.

    bs4 는 lxml 트리빌더가 없으면 파싱 시점에야 FeatureNotFound 를 던진다. 그러면
    서버는 멀쩡히 뜨고 Run 을 돌린 뒤에야 "recon 단계 실패"로 나타나, 원인이 대상
    사이트인지 환경인지 구분되지 않는다. 시작할 때 한 번 확인하고 끝낸다.
    """

    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return (
            "beautifulsoup4 가 없다. 이 인터프리터에 설치해야 한다:\n"
            f"    {sys.executable} -m pip install beautifulsoup4 lxml"
        )
    try:
        BeautifulSoup("<p>x</p>", "lxml")
    except Exception:
        return (
            "bs4 가 lxml 파서를 찾지 못한다 (Recon 이 이 파서를 쓴다).\n"
            f"    {sys.executable} -m pip install lxml"
        )
    return None


# hacklipse 는 import 시점에 bs4 를 끌어온다. 검사는 그 전에 끝나야 사용자가
# traceback 대신 고칠 수 있는 문장을 본다.
_MISSING_DEPENDENCY = check_dependencies()
if _MISSING_DEPENDENCY is not None:
    print(f"거부: {_MISSING_DEPENDENCY}")
    raise SystemExit(2)

from dashboard_core import (  # noqa: E402
    MODE_GENERIC,
    MODE_JUICE_SHOP,
    MODES,
    VULN_CHOICES,
    AccessAccounts,
    RunOptions,
    RunSecrets,
    RunSupervisor,
)
from hacklipse.bootstrap import (  # noqa: E402
    ANTHROPIC_API_KEY_ENV,
    GEMINI_API_KEY_ENV,
)

WEB_ROOT = Path(__file__).resolve().parent.parent / "web"
# 기본 대상 범위. 실서비스나 외부 대상으로 옮기려면 별도 인가 확인이 선행되어야 한다.
DEFAULT_ALLOWED_HOSTS = ("localhost", "127.0.0.1")
DEFAULT_TARGET = "http://127.0.0.1:3000/"
DEFAULT_BIND = "127.0.0.1"
DEFAULT_PORT = 8899
MAX_BUDGET = 500
# 컨테이너 안에서만 루프백 밖 바인딩을 허용하는 열쇠. compose 가 설정한다.
CONTAINER_BIND_ENV = "HACKLIPSE_DASHBOARD_CONTAINER"
# 본문 상한. 비밀 네 개와 옵션 몇 개면 충분하고, 그 이상은 받을 이유가 없다.
MAX_BODY_BYTES = 16 * 1024
CSRF_HEADER = "X-Hacklipse-CSRF"

# 화면이 고를 수 있는 LLM 구성. 키가 필요한 항목은 환경변수 이름을 함께 들고 있어야
# "왜 못 고르는지"를 화면이 설명할 수 있다. 키 값 자체는 절대 내보내지 않는다.
ENGINES = (
    {"id": "heuristic", "label": "Heuristic (결정적)", "provider": None, "key_env": None},
    {"id": "llm:anthropic", "label": "LLM · Anthropic", "provider": "anthropic", "key_env": ANTHROPIC_API_KEY_ENV},
    {"id": "llm:gemini", "label": "LLM · Gemini", "provider": "gemini", "key_env": GEMINI_API_KEY_ENV},
)
ENGINE_BY_ID = {engine["id"]: engine for engine in ENGINES}

# 고급 실행 조건. 화면·검증·기본값이 모두 이 표 하나에서 나온다.
ADVANCED_CHOICES = (
    {"field": "recon", "label": "Recon", "choices": ("heuristic", "hybrid"), "llm": ("hybrid",)},
    {"field": "surface_collection", "label": "Surface 수집", "choices": ("adaptive", "deterministic"), "llm": ()},
    {"field": "router", "label": "Router", "choices": ("heuristic", "hybrid"), "llm": ("hybrid",)},
    {"field": "router_review", "label": "Router review", "choices": ("weak", "ambiguous"), "llm": ()},
    {"field": "orchestrator", "label": "Orchestrator", "choices": ("heuristic", "hybrid"), "llm": ("hybrid",)},
    {"field": "budget_allocation", "label": "예산 배분", "choices": ("off", "heuristic", "hybrid"), "llm": ("hybrid",)},
    {"field": "report", "label": "Report", "choices": ("heuristic", "llm"), "llm": ("llm",)},
)
BOOLEAN_OPTIONS = (
    {"field": "validation_review", "label": "Validation review", "llm": True},
    {"field": "compare_routers", "label": "Router 비교", "llm": True},
    {"field": "browser", "label": "브라우저 검증", "llm": False},
)

_STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}


class RequestRejected(Exception):
    """요청 형식이나 값이 계약을 벗어났다. 사유는 그대로 화면에 보여준다."""


def _require_str(payload: dict, key: str, *, default: str = "", max_length: int = 300) -> str:
    value = payload.get(key, default)
    if value is None:
        return default
    if not isinstance(value, str):
        raise RequestRejected(f"{key} 는 문자열이어야 한다.")
    if len(value) > max_length:
        raise RequestRejected(f"{key} 가 너무 길다(최대 {max_length}자).")
    return value


def _require_choice(payload: dict, key: str, choices, *, default: str) -> str:
    value = _require_str(payload, key, default=default, max_length=40) or default
    if value not in choices:
        raise RequestRejected(f"{key} 값이 올바르지 않다: {value}")
    return value


def _require_bool(payload: dict, key: str, *, default: bool = False) -> bool:
    value = payload.get(key, default)
    if not isinstance(value, bool):
        raise RequestRejected(f"{key} 는 true/false 여야 한다.")
    return value


def _require_budget(payload: dict) -> int:
    """0 은 "유형별 기본값을 쓴다"는 뜻이다. 화면이 비워 보내는 값이기도 하다."""

    value = payload.get("budget")
    if value in (None, "", 0):
        return 0
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != int(value):
        raise RequestRejected("예산은 정수여야 한다.")
    value = int(value)
    if not 1 <= value <= MAX_BUDGET:
        raise RequestRejected(f"예산은 1 이상 {MAX_BUDGET} 이하여야 한다.")
    return value


def _optional_rpm(payload: dict) -> int | None:
    value = payload.get("llm_rpm_limit")
    if value in (None, ""):
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RequestRejected("LLM RPM 제한은 양의 정수여야 한다.")
    return value


def parse_run_payload(payload, defaults: RunOptions) -> tuple[RunOptions, RunSecrets]:
    """요청 본문을 실행 옵션과 비밀로 나눈다. 비밀은 RunOptions 에 넣지 않는다."""

    if not isinstance(payload, dict):
        raise RequestRejected("본문은 JSON 객체여야 한다.")

    engine_id = _require_choice(payload, "engine", tuple(ENGINE_BY_ID), default="heuristic")
    engine = ENGINE_BY_ID[engine_id]
    if engine["key_env"] and not os.environ.get(engine["key_env"], "").strip():
        raise RequestRejected(
            f"{engine['label']}를 쓰려면 {engine['key_env']} 환경변수가 필요하다."
        )

    options = RunOptions(
        target=_require_str(payload, "target", default=defaults.target).strip(),
        mode=_require_choice(payload, "mode", MODES, default=MODE_GENERIC),
        vuln=_require_choice(payload, "vuln", VULN_CHOICES, default="all"),
        budget=_require_budget(payload),
        profile="llm" if engine["provider"] else "heuristic",
        llm_provider=engine["provider"] or "gemini",
        llm_model=_require_str(payload, "llm_model", max_length=120).strip(),
        llm_rpm_limit=_optional_rpm(payload),
        knowledge_db=_require_str(payload, "knowledge_db", max_length=300).strip(),
        juice_shop_db=_require_str(payload, "juice_shop_db", max_length=300).strip(),
        **{
            spec["field"]: _require_choice(
                payload, spec["field"], spec["choices"], default=spec["choices"][0]
            )
            for spec in ADVANCED_CHOICES
        },
        **{
            spec["field"]: _require_bool(payload, spec["field"])
            for spec in BOOLEAN_OPTIONS
        },
    )
    if not options.target:
        raise RequestRejected("대상 URL이 비어 있다.")

    accounts = payload.get("access_accounts") or {}
    if not isinstance(accounts, dict):
        raise RequestRejected("access_accounts 는 JSON 객체여야 한다.")
    run_secrets = RunSecrets(
        access=AccessAccounts(
            actor_email=_require_str(accounts, "actor_email", max_length=200),
            actor_password=_require_str(accounts, "actor_password", max_length=200),
            owner_email=_require_str(accounts, "owner_email", max_length=200),
            owner_password=_require_str(accounts, "owner_password", max_length=200),
        ),
        ssti_token=_require_str(payload, "ssti_token", max_length=4096),
    )
    return options, run_secrets


def make_handler(supervisor: RunSupervisor, options: argparse.Namespace, csrf_token: str):
    allowed_origins = {
        f"http://{host}:{options.port}" for host in ("127.0.0.1", "localhost")
    }

    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = "hacklipse-dashboard/0.2"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args) -> None:
            if options.verbose:
                super().log_message(fmt, *args)

        # --- 응답 ---

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            # 이 화면은 스캔을 시작할 수 있다. 다른 문서가 프레임에 넣거나 참조로
            # 끌어가지 못하게 막는다. CORS 헤더는 의도적으로 두지 않는다.
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload: dict) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self._send(status, body, "application/json; charset=utf-8")

        # --- 같은 출처 확인 ---

        def _reject_cross_origin(self) -> str | None:
            """다른 출처가 이 API 로 Run 을 시작하지 못하게 한다.

            세 겹이다. (1) Origin 이 있으면 우리 것과 같아야 한다. (2) 본문이
            application/json 이어야 한다 — 단순 form POST 로는 보낼 수 없는 타입이라
            preflight 가 강제되고, 우리는 CORS 를 허용하지 않으므로 거기서 막힌다.
            (3) 시작할 때 만든 token 을 헤더로 요구한다. 다른 출처는 /api/config 를
            읽을 수 없으므로 이 값을 알 수 없다.
            """

            origin = self.headers.get("Origin")
            if origin and origin not in allowed_origins:
                return f"허용되지 않은 Origin이다: {origin}"
            site = (self.headers.get("Sec-Fetch-Site") or "").strip().casefold()
            if site and site not in {"same-origin", "none"}:
                return f"교차 출처 요청은 받지 않는다 (Sec-Fetch-Site: {site})"
            content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip()
            if content_type != "application/json":
                return "Content-Type 은 application/json 이어야 한다."
            if not secrets_module.compare_digest(
                self.headers.get(CSRF_HEADER, ""), csrf_token
            ):
                return f"{CSRF_HEADER} 헤더가 없거나 올바르지 않다."
            return None

        # --- 라우팅 ---

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            path = parsed.path

            if path in _STATIC:
                name, content_type = _STATIC[path]
                file = WEB_ROOT / name
                if not file.is_file():
                    self._json(404, {"error": f"{name}을(를) 찾을 수 없다: {file}"})
                    return
                self._send(200, file.read_bytes(), content_type)
                return

            if path == "/api/config":
                self._json(200, self._config())
                return

            if path == "/api/state":
                since = parse_qs(parsed.query).get("since", ["0"])[0]
                try:
                    since_value = int(since)
                except ValueError:
                    since_value = 0
                self._json(200, supervisor.state.read(since_value))
                return

            self._json(404, {"error": "not found"})

        def _config(self) -> dict:
            return {
                "csrf_token": csrf_token,
                "default_target": options.target,
                "allowed_hosts": sorted(supervisor.allowed_hosts),
                "max_budget": MAX_BUDGET,
                "default_engine": options.engine,
                "modes": [
                    {"id": MODE_GENERIC, "label": "범용 대상"},
                    {"id": MODE_JUICE_SHOP, "label": "Juice Shop"},
                ],
                "vulns": [
                    {"id": name, "label": ("전체 5종" if name == "all" else name)}
                    for name in VULN_CHOICES
                ],
                # 키 "값"은 내보내지 않는다. 고를 수 있는지 여부와 왜 못 고르는지만.
                "engines": [
                    {
                        "id": engine["id"],
                        "label": engine["label"],
                        "available": not engine["key_env"]
                        or bool(os.environ.get(engine["key_env"], "").strip()),
                        "key_env": engine["key_env"],
                    }
                    for engine in ENGINES
                ],
                # LLM 엔진을 골랐을 때만 화면에 나타나는 세부 설정.
                "llm_fields": [
                    {"field": "llm_model", "label": "LLM 모델", "placeholder": "기본 모델"},
                    {"field": "llm_rpm_limit", "label": "분당 호출 상한", "placeholder": "Gemini 14"},
                ],
                "advanced": [
                    {
                        "field": spec["field"],
                        "label": spec["label"],
                        "choices": list(spec["choices"]),
                        "llm_only": list(spec["llm"]),
                    }
                    for spec in ADVANCED_CHOICES
                ],
                "booleans": [
                    {"field": spec["field"], "label": spec["label"], "llm_only": spec["llm"]}
                    for spec in BOOLEAN_OPTIONS
                ],
            }

        def do_POST(self) -> None:  # noqa: N802
            if urlsplit(self.path).path != "/api/run":
                self._json(404, {"error": "not found"})
                return

            rejection = self._reject_cross_origin()
            if rejection is not None:
                self._json(403, {"error": rejection})
                return

            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY_BYTES:
                self._json(413, {"error": "본문이 너무 크다."})
                return
            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self._json(400, {"error": "본문이 올바른 JSON이 아니다."})
                return

            try:
                run_options, run_secrets = parse_run_payload(payload, supervisor.defaults)
            except RequestRejected as error:
                self._json(400, {"error": str(error)})
                return

            rejection = supervisor.validate(run_options, run_secrets)
            if rejection is not None:
                self._json(400, {"error": rejection})
                return

            try:
                supervisor.start(run_options, run_secrets)
            except RuntimeError as error:
                self._json(409, {"error": str(error)})
                return

            # 비밀은 찍지 않는다. 무엇을 어떤 구성으로 돌리는지만 남긴다.
            print(
                f"[run] 시작 — {run_options.target} "
                f"(mode {run_options.mode}, vuln {run_options.vuln}, "
                f"profile {run_options.profile}, 예산 {run_options.resolved_budget()})"
            )
            self._json(202, {"status": "running"})

    return DashboardHandler


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--bind", default=DEFAULT_BIND, help="대시보드 바인드 주소 (기본 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="대시보드 포트 (기본 8899)")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="화면에 채워둘 기본 대상 URL")
    parser.add_argument(
        "--allow-host",
        action="append",
        default=list(DEFAULT_ALLOWED_HOSTS),
        help="허용 호스트 추가. 기본은 localhost·127.0.0.1 뿐이다.",
    )
    parser.add_argument(
        "--engine",
        choices=tuple(ENGINE_BY_ID),
        default="heuristic",
        help="화면에 미리 선택해둘 실행 구성. 실제 선택은 브라우저에서 한다.",
    )
    parser.add_argument("--verbose", action="store_true", help="HTTP 접근 로그를 모두 출력한다")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    options = parse_args(argv)

    # 대시보드는 누구든 Run 을 시작할 수 있는 화면이다. 기본적으로 루프백에만 바인딩해
    # 같은 네트워크의 다른 사람이 이 화면으로 스캔을 돌리지 못하게 한다.
    #
    # 컨테이너는 예외다. Docker 의 포트 공개는 컨테이너의 eth0 로 전달되므로 안에서
    # 루프백에만 바인딩하면 밖에서 아예 닿지 않는다. 대신 컨테이너 밖 노출 범위는
    # compose 의 publish 주소(127.0.0.1:8899)가 책임진다.
    if options.bind not in {"127.0.0.1", "localhost", "::1"}:
        if os.environ.get(CONTAINER_BIND_ENV, "").strip() != "1":
            print(f"거부: 대시보드는 로컬 인터페이스에만 바인딩한다 (요청: {options.bind})")
            print(f"      컨테이너 안에서 실행 중이라면 {CONTAINER_BIND_ENV}=1 을 설정한다.")
            return 2
        print(
            f"주의: {options.bind} 에 바인딩한다. 컨테이너 밖 노출 범위는 "
            "publish 주소가 책임진다 (compose 는 127.0.0.1 로 묶는다)."
        )
    if not (WEB_ROOT / "index.html").is_file():
        print(f"거부: {WEB_ROOT}/index.html 이 없다.")
        return 2

    supervisor = RunSupervisor(
        allowed_hosts=frozenset(options.allow_host),
        defaults=RunOptions(target=options.target),
    )
    csrf_token = secrets_module.token_urlsafe(32)

    server = ThreadingHTTPServer(
        (options.bind, options.port), make_handler(supervisor, options, csrf_token)
    )
    server.daemon_threads = True

    print(f"대시보드   http://{options.bind}:{options.port}/")
    print(f"허용 호스트 {', '.join(sorted(supervisor.allowed_hosts))}")
    print(f"기본 구성   엔진 {options.engine} (브라우저에서 변경 가능)")
    for engine in ENGINES:
        if engine["key_env"]:
            ready = "사용 가능" if os.environ.get(engine["key_env"], "").strip() else f"{engine['key_env']} 없음"
            print(f"  - {engine['label']}: {ready}")
    print("Ctrl+C 로 종료한다.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n종료한다.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
