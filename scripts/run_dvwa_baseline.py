"""로컬 DVWA에 로그인한 뒤 XSS·SQLi·Path Traversal 분석을 실행한다.

DVWA 인증정보는 명령행 인자나 환경변수로 받지 않고 현재 프로세스에서만 입력받는다.
Task/Evidence/Audit에는 credential_ref와 마스킹된 응답만 남는다.

    python3 scripts/run_dvwa_baseline.py http://127.0.0.1:8080/
    python3 scripts/run_dvwa_baseline.py http://127.0.0.1:8080/ --vuln sqli
    python3 scripts/run_dvwa_baseline.py http://127.0.0.1:8080/ --vuln path_traversal
    python3 scripts/run_dvwa_baseline.py http://127.0.0.1:8080/DVWA/ --vuln xss
    python3 scripts/run_dvwa_baseline.py http://127.0.0.1:8080/ --vuln xss --profile llm
    python3 scripts/run_dvwa_baseline.py http://127.0.0.1:8080/ --vuln xss --profile llm --debug
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
import textwrap
import threading
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urljoin, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from hacklipse.adapters import (  # noqa: E402
    HttpExecutionRuntime,
    InMemoryCredentialResolver,
    InMemoryExecutionAuditLog,
    PlaywrightBrowserRuntime,
    StaticApprovalGate,
)
from hacklipse.application.errors import WorkflowExecutionError  # noqa: E402
from hacklipse.application import OrchestratorConfig  # noqa: E402
from hacklipse.bootstrap import (  # noqa: E402
    DEFAULT_ANTHROPIC_LLM_MODEL,
    DEFAULT_GEMINI_LLM_MODEL,
    build_gemini_llm_client_from_env,
    build_local_application,
    build_llm_client_from_env,
    register_standard_agents,
    standard_router,
)
from hacklipse.domain import RunRequest, RunScope, TaskEnvelope  # noqa: E402
from hacklipse.ports import (  # noqa: E402
    ExecutionAuditEvent,
    FormLoginSpec,
    LlmClient,
    LlmRequest,
    LlmResponse,
    ResolvedHttpCredential,
)
from hacklipse.ports.errors import LlmCredentialsMissing  # noqa: E402

_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1"})
_CREDENTIAL_REF = "interactive-local-dvwa"
_ACTOR_CREDENTIAL_REF = "interactive-local-dvwa-actor"
_OWNER_CREDENTIAL_REF = "interactive-local-dvwa-owner"
_APPROVAL_REF = "interactive-local-dvwa-login"
_DEFAULT_BUDGET = 30
_MAX_LLM_CONTENT_LOG_CHARS = 8_000
_TARGET_PATHS = {
    "access_control": "vulnerabilities/bac/?user_id=1&action=View+Profile",
    "xss": "vulnerabilities/xss_r/?name=seed",
    "sqli": "vulnerabilities/sqli/?id=1&Submit=Submit",
    "path_traversal": "vulnerabilities/fi/?page=include.php",
}
_TARGET_LABELS = {
    "access_control": "Access Control",
    "xss": "XSS",
    "sqli": "SQLi",
    "path_traversal": "Path Traversal",
}

_AGENT_LABELS = {
    "session_authenticator": "인증",
    "recon": "Recon",
    "xss_analyzer": "XSS Analysis",
    "sqli_analyzer": "SQLi Analysis",
    "path_traversal_analyzer": "Path Traversal Analysis",
    "evidence_collector": "Evidence 수집",
    "validation": "Validation",
    "report": "Report",
}


def _safe_log_value(value: object, *, limit: int = 100) -> str:
    """외부 입력의 제어문자가 터미널 출력을 조작하지 못하게 제한한다."""

    text = "".join(
        character if character.isprintable() else "?" for character in str(value)
    )
    return text if len(text) <= limit else f"{text[:limit]}..."


def _safe_llm_content(value: object) -> str:
    """LLM 구조화 출력을 들여쓴 JSON으로 만들고 터미널 제어를 막는다."""

    try:
        serialized = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            default=str,
        )
    except (TypeError, ValueError):
        serialized = json.dumps(str(value), ensure_ascii=False)
    formatted = _safe_multiline_text(serialized)
    if len(formatted) > _MAX_LLM_CONTENT_LOG_CHARS:
        return f"{formatted[:_MAX_LLM_CONTENT_LOG_CHARS]}..."
    return formatted


def _safe_multiline_text(value: object, *, width: int = 100) -> str:
    """원래 줄바꿈은 보존하고 긴 줄은 감싸되 터미널 제어문자는 제거한다."""

    normalized = (
        str(value)
        .replace("\r\n", "\n")
        .replace("\r", "\n")
        .replace("\t", "    ")
    )
    safe = "".join(
        character
        if character == "\n" or character.isprintable()
        else "?"
        for character in normalized
    )
    if len(safe) > _MAX_LLM_CONTENT_LOG_CHARS:
        safe = f"{safe[:_MAX_LLM_CONTENT_LOG_CHARS]}..."
    wrapped: list[str] = []
    for line in safe.split("\n"):
        wrapped.extend(
            textwrap.wrap(
                line,
                width=width,
                replace_whitespace=False,
                drop_whitespace=False,
                break_long_words=True,
                break_on_hyphens=False,
            )
            or [""]
        )
    return "\n".join(wrapped)


def _format_llm_request(request: LlmRequest) -> str:
    """System과 각 message를 사람이 읽기 쉬운 구획으로 분리한다."""

    sections = ["[system]", _safe_multiline_text(request.system or "(없음)")]
    for index, message in enumerate(request.messages, start=1):
        sections.extend(
            (
                "",
                f"[{message.role} #{index}]",
                _safe_multiline_text(message.content),
            )
        )
    return "\n".join(sections)


class _DebugProgress:
    """민감 데이터 없이 현재 Control Plane 진행 상태만 출력한다."""

    def __init__(
        self,
        enabled: bool,
        *,
        writer: Callable[[str], None] | None = None,
    ) -> None:
        self.enabled = enabled
        self._started = time.monotonic()
        self._writer = writer or (lambda message: print(message, flush=True))
        self._lock = threading.Lock()

    def log(self, message: str) -> None:
        if not self.enabled:
            return
        elapsed = time.monotonic() - self._started
        with self._lock:
            try:
                self._writer(f"[debug +{elapsed:6.1f}s] {message}")
            except Exception:
                # 관찰용 출력 실패가 실제 스캔 결과를 바꾸면 안 된다.
                return

    def block(self, title: str, content: str) -> None:
        """여러 줄 내용을 하나의 timestamp 아래 들여써 원자적으로 출력한다."""

        if not self.enabled:
            return
        elapsed = time.monotonic() - self._started
        indented = textwrap.indent(content, "    ")
        with self._lock:
            try:
                self._writer(f"[debug +{elapsed:6.1f}s] {title}\n{indented}")
            except Exception:
                return

    def task_event(
        self,
        event: str,
        task: TaskEnvelope,
        attempt: int,
        elapsed_seconds: float,
    ) -> None:
        agent = _AGENT_LABELS.get(
            task.agent_type, _safe_log_value(task.agent_type)
        )
        if event == "started":
            self.log(
                f"Task 시작: {agent} "
                f"(시도 {attempt}, 제한 {task.timeout_seconds:g}초)"
            )
        elif event == "succeeded":
            self.log(f"Task 완료: {agent} ({elapsed_seconds:.2f}초)")
        elif event == "failed":
            self.log(f"Task 실패: {agent} ({elapsed_seconds:.2f}초)")


def progress_line(event) -> str:
    """진행 사건 한 줄. 민감정보는 이미 중앙에서 제거된 상태로 들어온다."""

    parts = [f"[{event.kind.value}]"]
    if event.vulnerability_type:
        parts.append(event.vulnerability_type)
    elif event.agent_type:
        parts.append(_AGENT_LABELS.get(event.agent_type, _safe_log_value(event.agent_type)))
    if event.surface_path:
        parts.append(event.surface_path)
    if event.detail:
        parts.append(f"({_safe_log_value(event.detail)})")
    parts.append(f"예산 {event.budget_used}/{event.budget_total}")
    return " ".join(parts)


class _LlmUsageMeter:
    """LLM 호출 수와 token 사용량만 세는 얇은 래퍼.

    예산은 지금까지 HTTP 요청 수만 셌는데, LLM 구성에서는 비용이 그쪽에서도 발생한다.
    사용량을 모르면 어느 유형이 비싼지 판단할 수 없어 스케줄링 근거가 없다.

    prompt나 응답 본문은 보관하지 않는다. 숫자만 센다.
    """

    def __init__(self, delegate: LlmClient) -> None:
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

    def summary(self) -> str:
        return (
            f"{self.calls}회, 입력 {self.input_tokens:,} token, "
            f"출력 {self.output_tokens:,} token"
        )


class _ProgressLlmClient:
    """공급자 중립 LlmClient에 안전한 호출 시간 관찰만 덧씌운다."""

    def __init__(
        self,
        delegate: LlmClient,
        *,
        provider: str,
        model: str,
        progress: _DebugProgress,
        heartbeat_seconds: float = 10.0,
        show_content: bool = False,
    ) -> None:
        self._delegate = delegate
        self._provider = _safe_log_value(provider)
        self._model = _safe_log_value(model)
        self._progress = progress
        self._heartbeat_seconds = heartbeat_seconds
        self._show_content = show_content
        self._calls = 0

    def complete(self, request: LlmRequest) -> LlmResponse:
        self._calls += 1
        call_number = self._calls
        started = time.monotonic()
        finished = threading.Event()
        schema = "있음" if request.response_schema is not None else "없음"
        self._progress.log(
            f"LLM 호출 #{call_number} 시작: provider={self._provider}, "
            f"model={self._model}, timeout={request.timeout_seconds:g}초, "
            f"구조화 스키마={schema}"
        )
        if self._show_content:
            self._progress.block(
                f"LLM 호출 #{call_number} 입력",
                _format_llm_request(request),
            )

        def heartbeat() -> None:
            while not finished.wait(self._heartbeat_seconds):
                elapsed = time.monotonic() - started
                self._progress.log(
                    f"LLM 호출 #{call_number} 응답 대기 중 ({elapsed:.0f}초 경과)"
                )

        heartbeat_thread = threading.Thread(target=heartbeat, daemon=True)
        heartbeat_thread.start()
        try:
            response = self._delegate.complete(request)
        except Exception as error:
            elapsed = time.monotonic() - started
            self._progress.log(
                f"LLM 호출 #{call_number} 실패: {type(error).__name__} "
                f"({elapsed:.2f}초)"
            )
            raise
        finally:
            finished.set()
            heartbeat_thread.join(timeout=0.1)

        elapsed = time.monotonic() - started
        self._progress.log(
            f"LLM 호출 #{call_number} 완료 ({elapsed:.2f}초, "
            f"입력 {response.usage.input_tokens} tokens, "
            f"출력 {response.usage.output_tokens} tokens)"
        )
        if self._show_content:
            self._progress.block(
                f"LLM 호출 #{call_number} 응답",
                _safe_llm_content(dict(response.payload)),
            )
        return response


class _DebugAuditLog(InMemoryExecutionAuditLog):
    """감사 이벤트를 저장하면서 query와 자격증명 없이 완료 상태만 보여준다."""

    def __init__(self, progress: _DebugProgress) -> None:
        super().__init__()
        self._progress = progress

    def append(self, event: ExecutionAuditEvent) -> None:
        super().append(event)
        path = urlsplit(event.target).path or "/"
        status = f", status={event.status_code}" if event.status_code is not None else ""
        detail = f", detail={_safe_log_value(event.detail)}" if event.detail else ""
        self._progress.log(
            "HTTP 실행: "
            f"{_safe_log_value(event.tool)} {_safe_log_value(event.method)} "
            f"{_safe_log_value(path)} "
            f"(kind={_safe_log_value(event.request_kind)}, "
            f"outcome={_safe_log_value(event.outcome)}{status}{detail})"
        )


def _format_counts(counts: Counter[str]) -> str:
    if not counts:
        return "없음"
    return ", ".join(f"{name} {count}개" for name, count in counts.items())


def _print_summary(
    *,
    profile: str,
    vuln: str,
    phase: str,
    candidate_counts: Counter[str],
    reflection_count: int,
    sql_error_count: int,
    object_id_auth_count: int,
    path_traversal_count: int,
    browser_execution_count: int,
    audited_execution_count: int,
    finding_counts: Counter[str],
) -> None:
    finding_count = finding_counts.total()
    target_label = _TARGET_LABELS[vuln]
    target_confirmed = finding_counts[target_label] > 0
    verdict = "CONFIRMED (취약점 확인)" if target_confirmed else "미확정"

    print()
    print("=" * 54)
    print("  DVWA Baseline 실행 결과")
    print("=" * 54)
    print()
    print("[실행 정보]")
    print(f"  상태            완료 ({phase})")
    print(f"  분석 대상       {target_label}")
    print(f"  Agent 구성      {profile}")
    print(f"  감사된 실행     {audited_execution_count}회")
    print()
    print("[분석 신호]")
    print(f"  Candidate       {_format_counts(candidate_counts)}")
    print(f"  Reflection      {reflection_count}개")
    print(f"  SQL 오류        {sql_error_count}개")
    print(f"  객체 권한 우회  {object_id_auth_count}개")
    print(f"  OS 파일 읽기 {path_traversal_count}개")
    print(f"  XSS 실행        {browser_execution_count}개")
    print()
    print("[최종 판정]")
    print(f"  결과            {verdict}")
    print(f"  Finding         {finding_count}개")
    print(f"  취약점 유형     {_format_counts(finding_counts)}")
    print("=" * 54)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_url", help="localhost/127.0.0.1 DVWA base URL")
    parser.add_argument(
        "--vuln",
        choices=tuple(_TARGET_PATHS),
        default="xss",
        help="baseline vulnerability type (default: xss)",
    )
    parser.add_argument(
        "--profile",
        choices=("heuristic", "llm"),
        default="heuristic",
        help="analysis profile (default: heuristic)",
    )
    parser.add_argument(
        "--llm-provider",
        choices=("gemini", "anthropic"),
        default="gemini",
        help="LLM provider used with --profile llm (default: gemini)",
    )
    parser.add_argument(
        "--llm-model",
        help="provider model id; provider default is used when omitted",
    )
    parser.add_argument(
        "--dvwa-security",
        choices=("low", "medium", "high", "impossible"),
        default="low",
        help="DVWA security level cookie (default: low)",
    )
    parser.add_argument(
        "--actor-object-id",
        help="권한이 낮은 요청 주체가 소유한 객체 ID (access_control 전용)",
    )
    parser.add_argument(
        "--owner-object-id",
        help="검사 대상 객체의 정상 소유자 객체 ID (access_control 전용)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="민감정보를 제외한 Task/HTTP/LLM 진행 로그 출력",
    )
    parser.add_argument(
        "--debug-llm-content",
        action="store_true",
        help="LLM에 보낸 prompt와 받은 구조화 JSON도 출력",
    )
    args = parser.parse_args(argv[1:])
    debug_enabled = args.debug or args.debug_llm_content
    progress = _DebugProgress(debug_enabled)

    if args.vuln == "path_traversal":
        print(
            "Path Traversal은 별도 파일 생성 없이 고정된 "
            "/etc/os-release 읽기로 검증합니다."
        )

    base_url = args.base_url.rstrip("/") + "/"
    parsed = urlsplit(base_url)
    host = (parsed.hostname or "").casefold()
    if parsed.scheme not in {"http", "https"} or host not in _LOCAL_HOSTS:
        print("거부: 이 실행기는 localhost/127.0.0.1의 HTTP(S) DVWA만 허용한다.")
        return 2

    llm_client = None
    selected_model = ""
    if args.profile == "llm":
        selected_model = args.llm_model or (
            DEFAULT_GEMINI_LLM_MODEL
            if args.llm_provider == "gemini"
            else DEFAULT_ANTHROPIC_LLM_MODEL
        )
        try:
            if args.llm_provider == "gemini":
                llm_client = build_gemini_llm_client_from_env(model=selected_model)
            else:
                llm_client = build_llm_client_from_env(model=selected_model)
        except LlmCredentialsMissing as error:
            print(f"LLM 구성 실패: {error}")
            return 2
        if debug_enabled:
            llm_client = _ProgressLlmClient(
                llm_client,
                provider=args.llm_provider,
                model=selected_model,
                progress=progress,
                show_content=args.debug_llm_content,
            )
        progress.log(
            f"LLM 구성 완료: provider={_safe_log_value(args.llm_provider)}, "
            f"model={_safe_log_value(selected_model)}"
        )
        if args.debug_llm_content:
            progress.log(
                "LLM content 로그 활성화: prompt와 구조화 응답을 로컬 터미널에 출력"
            )

    access_control = args.vuln == "access_control"
    if access_control:
        if not (args.actor_object_id and args.owner_object_id):
            print("access_control 대상은 --actor-object-id와 --owner-object-id가 필요합니다.")
            return 2
        if args.actor_object_id == args.owner_object_id:
            print("actor와 owner 객체 ID가 같으면 권한 대조가 성립하지 않습니다.")
            return 2
        print(
            "주의: DVWA Broken Access Control 페이지는 조회 요청도 접근 로그를 남깁니다.\n"
            "     서로 다른 두 계정으로 각각 로그인하며, 요청 횟수를 최소로 유지합니다."
        )

    login_url = urljoin(base_url, "login.php")
    target_url = urljoin(base_url, _TARGET_PATHS[args.vuln])

    def _login_spec(user: str, secret: str) -> FormLoginSpec:
        return FormLoginSpec(
            login_url=login_url,
            username=user,
            password=secret,
            csrf_field="user_token",
            extra_fields=(("Login", "Login"),),
            failure_marker="Login failed",
            # 로그인 POST의 302만으로는 성공·실패를 구분할 수 없다. 같은 Run
            # 세션으로 보호된 시작 페이지를 읽을 수 있어야 인증 성공이다.
            verification_url=target_url,
            approval_ref=_APPROVAL_REF,
        )

    if access_control:
        actor_user = input("ACTOR (권한 낮은 계정) username: ")
        actor_password = getpass.getpass("ACTOR password: ")
        owner_user = input("OWNER (객체 소유 계정) username: ")
        owner_password = getpass.getpass("OWNER password: ")
        if input("로컬 DVWA에 두 계정 로그인 POST를 실행할까요? [y/N] ").strip().casefold() != "y":
            print("취소했습니다.")
            return 2
        # security Cookie는 중앙 Resolver가 관리한다. Agent와 LLM에는 전달되지 않는다.
        resolver = InMemoryCredentialResolver(
            {
                _ACTOR_CREDENTIAL_REF: ResolvedHttpCredential(
                    cookies=(("security", args.dvwa_security),),
                    form_login=_login_spec(actor_user, actor_password),
                ),
                _OWNER_CREDENTIAL_REF: ResolvedHttpCredential(
                    cookies=(("security", args.dvwa_security),),
                    form_login=_login_spec(owner_user, owner_password),
                ),
            }
        )
        principal_credentials = (
            ("actor", _ACTOR_CREDENTIAL_REF),
            ("owner", _OWNER_CREDENTIAL_REF),
        )
        run_credential_ref = _ACTOR_CREDENTIAL_REF
    else:
        username = input("DVWA username: ")
        password = getpass.getpass("DVWA password: ")
        if input("로컬 DVWA에 로그인 POST를 실행할까요? [y/N] ").strip().casefold() != "y":
            print("취소했습니다.")
            return 2
        principal_credentials = ()
        run_credential_ref = _CREDENTIAL_REF
        resolver = InMemoryCredentialResolver(
            {
                _CREDENTIAL_REF: ResolvedHttpCredential(
                    # DVWA의 보안 단계가 실습 동작을 가리지 않게 고정한다.
                    cookies=(("security", args.dvwa_security),),
                    form_login=_login_spec(username, password),
                )
            }
        )
    http_runtime = HttpExecutionRuntime(credential_resolver=resolver)
    runtime = PlaywrightBrowserRuntime(http_runtime=http_runtime)
    audit = _DebugAuditLog(progress) if debug_enabled else InMemoryExecutionAuditLog()
    app = build_local_application(
        {},
        runtime=runtime,
        router=standard_router(vulnerability_types=(_TARGET_LABELS[args.vuln],)),
        credential_resolver=resolver,
        approval_gate=StaticApprovalGate((_APPROVAL_REF,)),
        audit_log=audit,
        config=OrchestratorConfig(browser_xss_validation=args.vuln == "xss"),
        task_progress_callback=progress.task_event if debug_enabled else None,
    )
    # 이 실행기는 DVWA reflected-XSS/SQLi 파이프라인의 재현 실험이다. 전 사이트를
    # 크롤링하면 비밀번호 변경 같은 상태 변경 GET 폼까지 탐색 대상에 섞이고, 결과도
    # 시작 Surface가 아닌 크롤링 순서에 좌우된다. 대상 페이지 한 장만 열거한다.
    profile = register_standard_agents(
        app,
        llm_client=llm_client,
        recon_max_pages=1,
        actor_object_id=args.actor_object_id,
        owner_object_id=args.owner_object_id,
    )
    if profile == "llm":
        profile = f"llm/{args.llm_provider} ({_safe_log_value(selected_model)})"
    base_path = parsed.path if parsed.path.endswith("/") else f"{parsed.path}/"

    try:
        progress.log(
            f"Run 시작: vuln={_TARGET_LABELS[args.vuln]}, profile={profile}, "
            f"request_budget={_DEFAULT_BUDGET}"
        )
        run = app.orchestrator.start(
            RunRequest(
                target_url=target_url,
                scope=RunScope(
                    allowed_hosts=frozenset({host}),
                    allowed_path_prefixes=(base_path or "/",),
                ),
                request_budget=_DEFAULT_BUDGET,
                credential_ref=run_credential_ref,
                principal_credentials=principal_credentials,
            )
        )
    except WorkflowExecutionError as error:
        print(f"Run 실패: {error}")
        return 1
    progress.log(f"Run 완료: phase={_safe_log_value(run.phase.value)}")

    candidates = app.stores.candidates.list_by_run(run.run_id)
    reflections = tuple(
        item
        for item in app.stores.evidence.list_by_run(run.run_id)
        if item.observation.get("type") == "reflection"
    )
    sql_errors = tuple(
        item
        for item in app.stores.evidence.list_by_run(run.run_id)
        if item.observation.get("type") == "sql_error"
    )
    path_traversals = tuple(
        item
        for item in app.stores.evidence.list_by_run(run.run_id)
        if item.observation.get("type") == "path_traversal_file_read"
    )
    object_id_auths = tuple(
        item
        for item in app.stores.evidence.list_by_run(run.run_id)
        if item.observation.get("type") == "object_id_auth"
    )
    browser_executions = tuple(
        item
        for item in app.stores.evidence.list_by_run(run.run_id)
        if item.observation.get("type") == "browser_execution"
        and item.observation.get("script_executed") is True
    )
    findings = app.stores.findings.list_by_run(run.run_id)
    events = audit.list_by_run(run.run_id)
    _print_summary(
        profile=profile,
        vuln=args.vuln,
        phase=run.phase.value,
        candidate_counts=Counter(c.vulnerability_type for c in candidates),
        reflection_count=len(reflections),
        sql_error_count=len(sql_errors),
        object_id_auth_count=len(object_id_auths),
        path_traversal_count=len(path_traversals),
        browser_execution_count=len(browser_executions),
        audited_execution_count=len(events),
        finding_counts=Counter(item.vulnerability_type for item in findings),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
