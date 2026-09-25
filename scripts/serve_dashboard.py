"""로컬 대상 Run을 웹 대시보드에서 실행하고 진행 상황을 실시간으로 보여준다.

기존 실행기(run_baseline.py 등)와 같은 배선을 그대로 쓴다. 이 스크립트가 추가하는 것은
표시 계층뿐이다 — domain·ports·application·adapters 를 수정하지 않는다.

    python3 scripts/serve_dashboard.py
    python3 scripts/serve_dashboard.py --port 8080 --budget 60
    python3 scripts/serve_dashboard.py --engine llm:gemini      # 화면 기본 엔진 지정
    python3 scripts/serve_dashboard.py --allow-host juice.local # 허용 호스트 추가

대상 범위 — 기본 허용 호스트는 localhost·127.0.0.1 뿐이다. run_baseline.py 와 같은
제약이며, 그 밖의 호스트는 --allow-host 로 명시해야 하고 PolicyGate 가 Run 중에 한 번 더
검사한다. 인가받지 않은 대상에 쓰지 않는다.

스레드 모델 — Orchestrator 는 별도 스레드에서 돌고, HTTP 스레드는 Store 를 직접 읽지
않는다. InMemory Store 의 list_by_run 은 dict 를 순회하므로 Run 스레드가 쓰는 동안
읽으면 깨진다. 그래서 화면용 스냅샷은 ProgressSink 콜백 안(=Run 스레드)에서 만들어
불변 dict 로 넘겨두고, HTTP 스레드는 그 dict 만 읽는다.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import traceback
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

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


# hacklipse.adapters 는 import 시점에 bs4 를 끌어온다. 검사는 그 전에 끝나야
# 사용자가 traceback 대신 고칠 수 있는 문장을 본다.
_MISSING_DEPENDENCY = check_dependencies()
if _MISSING_DEPENDENCY is not None:
    print(f"거부: {_MISSING_DEPENDENCY}")
    raise SystemExit(2)


from hacklipse.adapters import HttpExecutionRuntime, SlidingWindowLlmClient  # noqa: E402
from hacklipse.adapters.memory import CallbackProgressLog  # noqa: E402
from hacklipse.application import build_progress_snapshot  # noqa: E402
from hacklipse.application.errors import WorkflowExecutionError  # noqa: E402
from hacklipse.bootstrap import (  # noqa: E402
    DEFAULT_ANTHROPIC_LLM_MODEL,
    DEFAULT_GEMINI_LLM_MODEL,
    build_gemini_llm_client_from_env,
    build_llm_client_from_env,
    build_local_application,
    register_standard_agents,
    standard_router,
)
from hacklipse.domain import RunExecutionProfile, RunRequest, RunScope  # noqa: E402
from hacklipse.ports import LlmRequest, LlmResponse  # noqa: E402
from hacklipse.bootstrap import (  # noqa: E402
    ANTHROPIC_API_KEY_ENV,
    GEMINI_API_KEY_ENV,
)
from hacklipse.ports.errors import LlmCredentialsMissing, RecordNotFound  # noqa: E402

WEB_ROOT = Path(__file__).resolve().parent.parent / "web"
# 기본 대상 범위. 실서비스나 외부 대상으로 옮기려면 별도 인가 확인이 선행되어야 한다.
DEFAULT_ALLOWED_HOSTS = ("localhost", "127.0.0.1")
DEFAULT_TARGET = "http://127.0.0.1:8000/"
DEFAULT_BUDGET = 40
# 화면이 고를 수 있는 실행 구성. 키가 필요한 항목은 환경변수 이름을 함께 들고 있어야
# "왜 못 고르는지"를 화면이 설명할 수 있다. 키 값 자체는 절대 밖으로 내보내지 않는다.
ENGINES = (
    {"id": "heuristic", "label": "Heuristic (결정적)", "provider": None, "key_env": None},
    {"id": "llm:anthropic", "label": "LLM · Anthropic", "provider": "anthropic", "key_env": ANTHROPIC_API_KEY_ENV},
    {"id": "llm:gemini", "label": "LLM · Gemini", "provider": "gemini", "key_env": GEMINI_API_KEY_ENV},
)
ENGINE_BY_ID = {engine["id"]: engine for engine in ENGINES}

# 보고서 축은 Analysis 엔진과 독립이지만, 내러티브는 LLM Client 를 필요로 한다.
# 역할마다 다른 모델을 섞으면 결과 차이가 아키텍처 덕인지 모델 덕인지 갈리지 않으므로
# (bootstrap 의 단일 모델 원칙) 내러티브는 엔진이 쓰는 Client 를 그대로 재사용한다.
REPORTS = (
    {"id": "v1", "label": "v1 (기존)", "format": "v1", "mode": "heuristic", "needs_llm": False},
    {"id": "v2", "label": "v2 결정적", "format": "v2", "mode": "heuristic", "needs_llm": False},
    {"id": "v2-llm", "label": "v2 + LLM 요약", "format": "v2", "mode": "llm", "needs_llm": True},
)
REPORT_BY_ID = {report["id"]: report for report in REPORTS}
MAX_BUDGET = 500
# 컨테이너 안에서만 루프백 밖 바인딩을 허용하는 열쇠. compose 가 설정한다.
CONTAINER_BIND_ENV = "HACKLIPSE_DASHBOARD_CONTAINER"
# 공급자 상한 15 RPM 을 꽉 채우지 않고 한 슬롯을 남긴다. 이 프로세스 밖의 호출이나
# 공급자 집계 경계의 오차로 마지막 하나가 429 가 되는 일을 줄인다.
# run_juice_shop_baseline.py 의 _DEFAULT_GEMINI_RPM_LIMIT 와 같은 값이다.
DEFAULT_GEMINI_RPM_LIMIT = 14

DEFAULT_BIND = "127.0.0.1"
DEFAULT_PORT = 8899

# 정적 파일은 이 두 개만 내보낸다. 경로를 조합하지 않아 디렉터리 탈출이 성립하지 않는다.
_STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}


def _empty_snapshot(budget_total: int) -> dict:
    """Run 이 없을 때도 화면이 같은 모양의 데이터를 받게 한다."""

    return {
        "surface_count": 0,
        "parameter_count": 0,
        "evidence_count": 0,
        "validated_count": 0,
        "budget_used": 0,
        "budget_total": budget_total,
        "llm_calls": 0,
        "llm_input_tokens": 0,
        "llm_output_tokens": 0,
    }


class NoLlmUsage:
    """LLM 을 쓰지 않은 Run 의 사용량. "모른다(정보 없음)"와 "0이다"는 다르다."""

    calls = 0
    input_tokens = 0
    output_tokens = 0


class LlmUsageMeter:
    """LLM 호출 수와 token 만 세는 얇은 래퍼. prompt·응답 본문은 보관하지 않는다.

    Report Agent 는 값이 아니라 살아 있는 계측기를 받는다 — 조립 시점에는 0이고
    보고서를 만들 때 읽어야 하기 때문이다(RunLlmUsageSource).
    """

    def __init__(self, delegate) -> None:
        self._delegate = delegate
        self.calls = 0
        self.input_tokens = 0
        self.output_tokens = 0

    def complete(self, request: LlmRequest) -> LlmResponse:
        response = self._delegate.complete(request)
        self.calls += 1
        usage = response.usage
        self.input_tokens += usage.input_tokens + usage.cache_read_input_tokens
        self.output_tokens += usage.output_tokens
        return response


class DashboardState:
    """화면이 읽는 유일한 상태. Run 스레드가 쓰고 HTTP 스레드가 읽는다."""

    def __init__(self, *, budget: int, target: str) -> None:
        self._lock = threading.Lock()
        self._budget = budget
        self._view = {
            "status": "idle",
            "target": target,
            "engine": None,
            "run_id": None,
            "phase": "init",
            "error": None,
            "current_agent": None,
            "findings_total": 0,
            "snapshot": _empty_snapshot(budget),
            "candidates": [],
            "report": None,
        }
        self._events: list[dict] = []

    # --- Run 스레드가 호출한다 -------------------------------------------------

    def begin(self, target: str, *, budget: int, engine: str) -> None:
        with self._lock:
            self._events = []
            self._budget = budget
            self._view = {
                "status": "running",
                "target": target,
                "engine": engine,
                "run_id": None,
                "phase": "init",
                "error": None,
                "current_agent": None,
                "findings_total": 0,
                "snapshot": _empty_snapshot(budget),
                "candidates": [],
                "report": None,
            }

    def record_event(self, event, *, current_agent: str | None) -> None:
        payload = {
            "sequence": event.sequence,
            "kind": event.kind.value,
            "phase": event.phase,
            "agent_type": event.agent_type,
            "candidate_id": event.candidate_id,
            "vulnerability_type": event.vulnerability_type,
            "surface_path": event.surface_path,
            "detail": event.detail,
            "elapsed_ms": event.elapsed_ms,
            # 도메인 이벤트에는 벽시계 시각이 없다(경과시간만 있다). 활동 로그의
            # 시각은 이 프로세스가 사건을 받은 시점으로 찍는다.
            "time": datetime.now().strftime("%H:%M:%S"),
        }
        with self._lock:
            self._events.append(payload)
            self._view["run_id"] = event.run_id
            self._view["phase"] = event.phase
            self._view["current_agent"] = current_agent

    def update_view(self, **fields) -> None:
        with self._lock:
            self._view.update(fields)

    def finish(self, *, status: str, error: str | None = None) -> None:
        with self._lock:
            self._view["status"] = status
            self._view["error"] = error
            self._view["current_agent"] = None

    # --- HTTP 스레드가 호출한다 ------------------------------------------------

    def read(self, since: int) -> dict:
        with self._lock:
            view = dict(self._view)
            view["snapshot"] = dict(self._view["snapshot"])
            view["candidates"] = list(self._view["candidates"])
            view["events"] = [e for e in self._events if e["sequence"] > since]
            view["last_sequence"] = self._events[-1]["sequence"] if self._events else 0
            return view

    @property
    def running(self) -> bool:
        with self._lock:
            return self._view["status"] == "running"


class RunSupervisor:
    """대시보드가 요청한 Run 하나를 조립하고 백그라운드에서 실행한다."""

    def __init__(self, options: argparse.Namespace) -> None:
        self._options = options
        self._allowed_hosts = frozenset(options.allow_host)
        self.state = DashboardState(budget=options.budget, target=options.target)
        self._thread: threading.Thread | None = None
        self._current_agent: str | None = None
        self._usage: LlmUsageMeter | None = None

    def validate_target(self, target: str) -> str | None:
        """거부 사유를 문자열로 돌려준다. 통과하면 None."""

        parsed = urlsplit(target)
        if parsed.scheme not in {"http", "https"}:
            return "대상 URL은 http 또는 https여야 한다."
        host = (parsed.hostname or "").casefold()
        if host not in self._allowed_hosts:
            allowed = ", ".join(sorted(self._allowed_hosts))
            return f"{host or '(호스트 없음)'}는 허용 대상이 아니다. 허용: {allowed}"
        return None

    def validate_engine(self, engine_id: str) -> str | None:
        """화면이 고른 엔진이 실제로 실행 가능한지 본다. 통과하면 None."""

        engine = ENGINE_BY_ID.get(engine_id)
        if engine is None:
            return f"알 수 없는 실행 구성이다: {engine_id}"
        if engine["key_env"] and not os.environ.get(engine["key_env"], "").strip():
            return f"{engine['label']}를 쓰려면 {engine['key_env']} 환경변수가 필요하다."
        return None

    def validate_report(self, report_id: str, engine_id: str) -> str | None:
        """보고서 구성이 선택한 엔진에서 실제로 만들어질 수 있는지 본다."""

        report = REPORT_BY_ID.get(report_id)
        if report is None:
            return f"알 수 없는 보고서 구성이다: {report_id}"
        if report["needs_llm"] and ENGINE_BY_ID[engine_id]["provider"] is None:
            return "LLM 요약은 LLM 엔진을 선택했을 때만 쓸 수 있다."
        return None

    def start(self, target: str, *, engine_id: str, budget: int, report_id: str) -> None:
        if self.state.running:
            raise RuntimeError("이미 실행 중인 Run이 있다.")
        engine = ENGINE_BY_ID[engine_id]
        report = REPORT_BY_ID[report_id]
        self.state.begin(target, budget=budget, engine=engine["label"])
        self._current_agent = None
        self._thread = threading.Thread(
            target=self._run,
            args=(target, engine, budget, report),
            name="hacklipse-run",
            daemon=True,
        )
        self._thread.start()

    # --- 아래부터는 Run 스레드에서만 실행된다 ----------------------------------

    def _resolved_model(self, engine: dict) -> str:
        if engine["provider"] == "gemini":
            return self._options.llm_model or DEFAULT_GEMINI_LLM_MODEL
        return self._options.llm_model or DEFAULT_ANTHROPIC_LLM_MODEL

    def _build_llm_client(self, engine: dict):
        if engine["provider"] is None:
            return None, None

        if engine["provider"] == "gemini":
            client = build_gemini_llm_client_from_env(
                model=self._options.llm_model or DEFAULT_GEMINI_LLM_MODEL
            )
        else:
            client = build_llm_client_from_env(
                model=self._options.llm_model or DEFAULT_ANTHROPIC_LLM_MODEL
            )

        # 한 Run 이 Recon 계획·Analysis·Validation·Report 요약까지 LLM 을 여러 번
        # 부른다. 무료 등급 Gemini 는 분당 15회라 제한 없이 돌리면 Run 중간에 429 로
        # 죽는다. 기존 실행기와 같은 sliding window 를 씌운다.
        limit = self._options.llm_rpm_limit
        if limit is None and engine["provider"] == "gemini":
            limit = DEFAULT_GEMINI_RPM_LIMIT
        if limit:
            client = SlidingWindowLlmClient(client, max_calls=limit)
        # 계측은 제한 바깥에 둔다. 제한 때문에 대기한 호출도 한 번의 호출이다.
        return LlmUsageMeter(client), limit

    def _run(self, target: str, engine: dict, budget: int, report: dict) -> None:
        try:
            llm_client, rpm_limit = self._build_llm_client(engine)
        except LlmCredentialsMissing as error:
            self.state.finish(status="failed", error=str(error))
            return
        # 보고서에는 항상 사용량 원천을 준다. 결정적 Run 은 0으로 확정된 값이다.
        self._usage = llm_client
        report_usage = llm_client if llm_client is not None else NoLlmUsage()

        app = build_local_application(
            {},
            report_format_version=report["format"],
            report_mode=report["mode"],
            # 내러티브를 켠 경우에만 Client 가 전달된다. 키가 없으면 bootstrap 이
            # 조립 시점에 거부하므로 "켠 줄 알았는데 결정적 보고서"가 나오지 않는다.
            report_llm_client=llm_client if report["mode"] == "llm" else None,
            report_llm_model=self._resolved_model(engine) if report["mode"] == "llm" else "",
            report_llm_usage=report_usage,
            runtime=HttpExecutionRuntime(),
            # Router mode 는 Analysis 프로필과 독립적인 축이다. 기존 실행기와 같이
            # 결정적 Router 를 쓰고, LLM 엔진은 Analyzer 만 교체한다.
            router=standard_router(),
            progress_sink=CallbackProgressLog(self._on_event),
        )
        register_standard_agents(app, llm_client=llm_client)
        self._app = app

        try:
            app.orchestrator.start(
                RunRequest(
                    target_url=target,
                    scope=RunScope(allowed_hosts=self._allowed_hosts),
                    request_budget=budget,
                    # 실제 배선을 그대로 기록한다. 이 값이 보고서의 "실행 조건"이 되고
                    # Facts 해시에 들어가므로, 비워두면 heuristic Run 과 LLM Run 이
                    # 같은 조건으로 기록되어 A/B 비교가 성립하지 않는다.
                    execution_profile=RunExecutionProfile(
                        analysis_profile="llm" if engine["provider"] else "heuristic",
                        # Router·Recon·Orchestrator 는 아직 결정적 구성만 배선한다.
                        recon_mode="heuristic",
                        surface_collection_mode="adaptive",
                        router_mode="heuristic",
                        router_review="weak",
                        orchestrator_mode="heuristic",
                        budget_allocation_mode="off",
                        validation_mode="heuristic",
                        report_mode=report["mode"],
                        llm_provider=engine["provider"] or "",
                        llm_model=self._resolved_model(engine) if engine["provider"] else "",
                        llm_rpm_limit=rpm_limit,
                    ),
                )
            )
        except WorkflowExecutionError as error:
            self._refresh()
            hint = ""
            if "FeatureNotFound" in str(error):
                hint = " — HTML 파서(lxml)가 없다. `pip install lxml` 후 다시 시작한다."
            self.state.finish(status="failed", error=f"Run 실패: {error}{hint}")
            return
        except Exception as error:  # 화면이 조용히 멈추지 않게 사유를 남긴다.
            traceback.print_exc()
            self._refresh()
            self.state.finish(status="failed", error=f"예상치 못한 오류: {error}")
            return

        self._refresh()
        self.state.finish(status="done")

    def _on_event(self, event) -> None:
        """ProgressSink 콜백. Run 스레드에서 호출되므로 여기서 Store를 읽어도 안전하다."""

        if event.kind.value == "agent_started":
            self._current_agent = event.agent_type
        elif event.kind.value in {"agent_completed", "run_completed"}:
            self._current_agent = None

        self.state.record_event(event, current_agent=self._current_agent)
        self._refresh(run_id=event.run_id)

    def _refresh(self, run_id: str | None = None) -> None:
        """현재 Store 내용으로 화면용 스냅샷을 다시 계산한다."""

        app = getattr(self, "_app", None)
        if app is None:
            return
        run_id = run_id or self.state.read(0)["run_id"]
        if run_id is None:
            return
        try:
            run = app.stores.runs.get(run_id)
        except RecordNotFound:
            return

        usage = self._usage
        snapshot = build_progress_snapshot(
            run,
            stores=app.stores,
            budget=app.budget_manager,
            # Store 에 남지 않는 값이라 계측기에서 직접 읽어 넘긴다.
            llm_calls=usage.calls if usage else 0,
            llm_input_tokens=usage.input_tokens if usage else 0,
            llm_output_tokens=usage.output_tokens if usage else 0,
        )
        surfaces = {item.surface_id: item for item in app.stores.surfaces.list_by_run(run_id)}
        findings = {item.candidate_id: item for item in app.stores.findings.list_by_run(run_id)}

        candidates = []
        for item in app.stores.candidates.list_by_run(run_id):
            surface = surfaces.get(item.surface_id)
            finding = findings.get(item.candidate_id)
            candidates.append(
                {
                    "vulnerability_type": item.vulnerability_type,
                    # query 값은 빼고 경로와 파라미터 이름만 넘긴다(ProgressEvent와 같은 기준).
                    "path": urlsplit(surface.url).path if surface else "",
                    "parameters": list(item.exploration_parameters)
                    or (list(surface.parameters) if surface else []),
                    "status": item.status.value,
                    # LASP는 심각도를 매기지 않는다. 기본값 "unrated"면 화면이 보완한다.
                    "severity": finding.severity if finding else None,
                }
            )

        reports = app.stores.reports.list_by_run(run_id)
        self.state.update_view(
            run_id=run_id,
            report=reports[-1].content if reports else None,
            phase=run.phase.value,
            findings_total=len(findings),
            candidates=candidates,
            snapshot={
                "surface_count": snapshot.surface_count,
                "parameter_count": snapshot.parameter_count,
                "evidence_count": snapshot.evidence_count,
                "validated_count": snapshot.validated_count,
                "budget_used": snapshot.budget_used,
                "budget_total": snapshot.budget_total,
                "llm_calls": snapshot.llm_calls,
                "llm_input_tokens": snapshot.llm_input_tokens,
                "llm_output_tokens": snapshot.llm_output_tokens,
            },
        )


def make_handler(supervisor: RunSupervisor, options: argparse.Namespace):
    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = "hacklipse-dashboard/0.1"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args) -> None:
            # 폴링이 초당 한 번씩 찍히면 콘솔이 쓸모없어진다. Run 로그만 남긴다.
            if options.verbose:
                super().log_message(fmt, *args)

        # --- 응답 헬퍼 ---

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload: dict) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self._send(status, body, "application/json; charset=utf-8")

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
                self._json(
                    200,
                    {
                        "default_target": options.target,
                        "allowed_hosts": sorted(supervisor._allowed_hosts),
                        "default_budget": options.budget,
                        "max_budget": MAX_BUDGET,
                        "default_engine": options.engine,
                        "default_report": options.report,
                        "reports": [
                            {
                                "id": report["id"],
                                "label": report["label"],
                                "needs_llm": report["needs_llm"],
                            }
                            for report in REPORTS
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
                    },
                )
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

        def do_POST(self) -> None:  # noqa: N802
            if urlsplit(self.path).path != "/api/run":
                self._json(404, {"error": "not found"})
                return

            length = int(self.headers.get("Content-Length") or 0)
            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self._json(400, {"error": "본문이 올바른 JSON이 아니다."})
                return

            target = str(payload.get("target") or "").strip()
            if not target:
                self._json(400, {"error": "대상 URL이 비어 있다."})
                return

            rejection = supervisor.validate_target(target)
            if rejection is not None:
                self._json(400, {"error": rejection})
                return

            engine_id = str(payload.get("engine") or options.engine)
            rejection = supervisor.validate_engine(engine_id)
            if rejection is not None:
                self._json(400, {"error": rejection})
                return

            try:
                budget = int(payload.get("budget") or options.budget)
            except (TypeError, ValueError):
                self._json(400, {"error": "예산은 정수여야 한다."})
                return
            if not 1 <= budget <= MAX_BUDGET:
                self._json(400, {"error": f"예산은 1 이상 {MAX_BUDGET} 이하여야 한다."})
                return

            report_id = str(payload.get("report") or options.report)
            rejection = supervisor.validate_report(report_id, engine_id)
            if rejection is not None:
                self._json(400, {"error": rejection})
                return

            try:
                supervisor.start(
                    target, engine_id=engine_id, budget=budget, report_id=report_id
                )
            except RuntimeError as error:
                self._json(409, {"error": str(error)})
                return

            print(f"[run] 시작 — {target} (예산 {budget}, 엔진 {engine_id}, 보고서 {report_id})")
            self._json(202, {"status": "running", "target": target})

    return DashboardHandler


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bind", default=DEFAULT_BIND, help="대시보드 바인드 주소 (기본 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="대시보드 포트 (기본 8899)")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="화면에 채워둘 기본 대상 URL")
    parser.add_argument("--budget", type=int, default=DEFAULT_BUDGET, help="Run 요청 예산 (기본 40)")
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
    parser.add_argument(
        "--report",
        choices=tuple(REPORT_BY_ID),
        default="v2",
        help="화면에 미리 선택해둘 보고서 구성. 실제 선택은 브라우저에서 한다.",
    )
    parser.add_argument("--llm-model", default=None, help="기본 모델 대신 쓸 모델 이름")
    parser.add_argument(
        "--llm-rpm-limit",
        type=int,
        default=None,
        help=f"분당 LLM 호출 상한. 미지정 시 Gemini 는 {DEFAULT_GEMINI_RPM_LIMIT}, 그 외는 제한 없음.",
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
    # compose 의 publish 주소(127.0.0.1:8899)가 책임진다. 그 전제를 아는 실행자만
    # 환경변수로 명시하도록 한다 — 실수로 열리는 경로를 만들지 않는다.
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


    supervisor = RunSupervisor(options)
    server = ThreadingHTTPServer((options.bind, options.port), make_handler(supervisor, options))
    server.daemon_threads = True

    print(f"대시보드   http://{options.bind}:{options.port}/")
    print(f"허용 호스트 {', '.join(sorted(supervisor._allowed_hosts))}")
    print(f"기본 구성   엔진 {options.engine} · 보고서 {options.report} · 예산 {options.budget} (브라우저에서 변경 가능)")
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
