"""웹 대시보드가 Run 하나를 조립·실행·정리하는 계층.

이 모듈의 설계 원칙은 하나다 — **CLI 실행기의 절차를 복제하지 않는다.**

run_juice_shop_baseline.py 는 계정 준비, Recon seed, 유형별 세션, 정리까지를 이미
함수로 나눠 두었다. 여기서는 그 함수들을 그대로 import 해서 쓴다. 웹에 같은 절차를
다시 적으면 두 경로가 조용히 갈라지고, 한쪽만 고친 채 "CLI 와 같다"고 믿게 된다.

옵션도 마찬가지다. 화면이 고른 값을 argparse.Namespace 로 바꿔 CLI 와 똑같은
execution_profile_from_args() · build_run_router() · needs_llm() 에 넣는다. 배선과
기록이 같은 함수 하나를 거치므로 "선택지만 보이고 실행은 고정값"이 구조적으로 불가능하다.

비밀 취급 — Access Control 계정의 이메일·비밀번호와 SSTI token 은 RunOptions 에 담지
않는다. 별도의 AccessAccounts/SstiSession 으로 받아 로그인에만 쓰고, 끝나면
resolver.clear() 로 참조를 버린다. 화면 상태(DashboardState)에는 애초에 들어가지 않으므로
/api/state 응답·활동 로그·보고서 어디에도 나타나지 않는다.
"""

from __future__ import annotations

import argparse
import threading
import traceback
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from hacklipse.adapters import (
    HttpExecutionRuntime,
    InMemoryCredentialResolver,
    InMemoryExecutionAuditLog,
    PlaywrightBrowserRuntime,
    SlidingWindowLlmClient,
    StaticApprovalGate,
)
from hacklipse.adapters.knowledge import SQLiteKnowledgeBase
from hacklipse.adapters.llm_budget_allocation_advisor import LlmBudgetAllocationAdvisor
from hacklipse.adapters.llm_orchestration_advisor import LlmOrchestrationAdvisor
from hacklipse.adapters.memory import CallbackProgressLog
from hacklipse.adapters.path_traversal_analysis import PATH_TRAVERSAL_POST_APPROVAL_REF
from hacklipse.adapters.ssti_analysis import SSTI_APPROVAL_REF
from hacklipse.application import OrchestratorConfig, build_progress_snapshot
from hacklipse.application.errors import WorkflowExecutionError
from hacklipse.bootstrap import (
    DEFAULT_ANTHROPIC_LLM_MODEL,
    DEFAULT_GEMINI_LLM_MODEL,
    build_gemini_llm_client_from_env,
    build_llm_client_from_env,
    build_local_application,
    register_standard_agents,
    standard_recon_planner,
)
from hacklipse.domain import RunRequest, RunScope
from hacklipse.ports import LlmRequest, LlmResponse, ResolvedHttpCredential
from hacklipse.ports.errors import LlmCredentialsMissing, RecordNotFound

# CLI 와 공유하는 실행 옵션 계약. Namespace 하나로 같은 함수를 먹인다.
from routing_options import (
    NoLlmUsage,
    build_run_router,
    execution_profile_from_args,
    needs_llm,
)

# CLI 의 준비·정리 절차. 복제하지 않고 그대로 재사용한다.
from run_juice_shop_baseline import (
    _ACCESS_LOGIN_APPROVAL_REF,
    _ACTOR_CREDENTIAL_REF,
    _ALL_MODE_BUDGET,
    _ALL_MODE_RECON_PAGES,
    _BROWSER_VULNS,
    _BUNDLE_DISCOVERY_VULNS,
    _CREDENTIAL_REF,
    _DEFAULT_BUDGET,
    _DEFAULT_GEMINI_RPM_LIMIT,
    _OWNER_CREDENTIAL_REF,
    _PATH_TRAVERSAL_CREDENTIAL_REF,
    _PROVISION_APPROVAL_REF,
    _RECON_CREDENTIAL_REF,
    _TEMP_SSTI_CREDENTIAL_REF,
    _VULN_TARGETS,
    _AccessAccountInput,
    _all_mode_recon_seeds,
    _authenticate_access_control_accounts,
    _cleanup_provisioned_accounts,
    _provision_path_traversal_account,
    _resolve_juice_shop_db,
)

VULN_CHOICES = (*_VULN_TARGETS, "all")
MODE_GENERIC = "generic"
MODE_JUICE_SHOP = "juice-shop"
MODES = (MODE_GENERIC, MODE_JUICE_SHOP)


# ---------------------------------------------------------------- 실행 옵션

@dataclass(frozen=True, slots=True)
class RunOptions:
    """화면이 고른 실행 조건. 비밀은 담지 않는다.

    필드 이름과 값은 CLI 플래그와 1:1 로 맞춘다. to_namespace() 가 이것을 그대로
    argparse.Namespace 로 바꾸므로, 이름이 어긋나면 CLI 쪽 함수에서 즉시 드러난다.
    """

    target: str
    mode: str = MODE_GENERIC
    vuln: str = "all"
    budget: int = 0  # 0 = 유형별 기본값을 쓴다
    profile: str = "heuristic"
    recon: str = "heuristic"
    surface_collection: str = "adaptive"
    router: str = "heuristic"
    router_review: str = "weak"
    compare_routers: bool = False
    orchestrator: str = "heuristic"
    budget_allocation: str = "off"
    validation_review: bool = False
    report: str = "heuristic"
    browser: bool = False
    llm_provider: str = "gemini"
    llm_model: str = ""
    llm_rpm_limit: int | None = None
    knowledge_db: str = ""
    juice_shop_db: str = ""
    routing_log: str = "artifacts/routing-decisions.jsonl"

    def to_namespace(self) -> argparse.Namespace:
        """CLI 함수들이 기대하는 Namespace 로 바꾼다.

        execution_profile_from_args 와 build_run_router 가 이 객체를 읽는다. 여기서
        만든 값이 곧 보고서의 "실행 조건"이 되므로, 화면 선택과 실제 배선이 갈라질
        수 없다.
        """

        return argparse.Namespace(
            profile=self.profile,
            recon=self.recon,
            surface_collection=self.surface_collection,
            router=self.router,
            router_review=self.router_review,
            compare_routers=self.compare_routers,
            orchestrator=self.orchestrator,
            budget_allocation=self.budget_allocation,
            validation_review=self.validation_review,
            report=self.report,
            report_out=None,
            routing_log=self.routing_log,
            llm_provider=self.llm_provider,
            llm_model=self.llm_model or None,
            llm_rpm_limit=self.llm_rpm_limit,
        )

    @property
    def is_juice_shop(self) -> bool:
        return self.mode == MODE_JUICE_SHOP

    @property
    def run_all(self) -> bool:
        return self.is_juice_shop and self.vuln == "all"

    @property
    def needs_browser(self) -> bool:
        """브라우저를 띄울지. Juice Shop 은 CLI 와 같은 유형에서 자동으로 켠다."""

        if self.is_juice_shop:
            return self.vuln in _BROWSER_VULNS
        return self.browser

    @property
    def needs_access_accounts(self) -> bool:
        return self.is_juice_shop and self.vuln in {"access_control", "all"}

    @property
    def needs_path_account(self) -> bool:
        return self.is_juice_shop and self.vuln in {"path_traversal", "all"}

    @property
    def needs_ssti_token(self) -> bool:
        """SSTI 단독 실행만 사용자 token 을 받는다.

        전체 모드는 Path Traversal 준비가 만든 임시 계정 세션을 SSTI 에도 물려주므로
        (CLI 와 같다) 사용자 token 이 필요 없다.
        """

        return self.is_juice_shop and self.vuln == "ssti"

    def resolved_budget(self) -> int:
        if self.budget:
            return self.budget
        if not self.is_juice_shop:
            return _ALL_MODE_BUDGET
        return _ALL_MODE_BUDGET if self.vuln in _BUNDLE_DISCOVERY_VULNS else _DEFAULT_BUDGET

    def resolved_model(self) -> str:
        if not needs_llm(self.to_namespace()):
            return ""
        return self.llm_model or (
            DEFAULT_GEMINI_LLM_MODEL
            if self.llm_provider == "gemini"
            else DEFAULT_ANTHROPIC_LLM_MODEL
        )


@dataclass(frozen=True, slots=True)
class AccessAccounts:
    """Access Control 로그인에만 쓰는 사용자 입력. 로그와 상태에 남기지 않는다."""

    actor_email: str = field(repr=False, default="")
    actor_password: str = field(repr=False, default="")
    owner_email: str = field(repr=False, default="")
    owner_password: str = field(repr=False, default="")

    def is_complete(self) -> bool:
        return all(
            value.strip()
            for value in (
                self.actor_email,
                self.actor_password,
                self.owner_email,
                self.owner_password,
            )
        )

    def to_cli_inputs(self) -> tuple[_AccessAccountInput, _AccessAccountInput]:
        """CLI 가 쓰는 입력 구조로 바꾼다. 검증 규칙도 CLI 와 같은 곳에서 돈다."""

        if self.actor_email.strip().casefold() == self.owner_email.strip().casefold():
            raise ValueError("ACTOR 와 OWNER 는 서로 다른 계정이어야 한다.")
        return (
            _AccessAccountInput(
                role="actor",
                credential_ref=_ACTOR_CREDENTIAL_REF,
                email=self.actor_email.strip(),
                password=self.actor_password,
            ),
            _AccessAccountInput(
                role="owner",
                credential_ref=_OWNER_CREDENTIAL_REF,
                email=self.owner_email.strip(),
                password=self.owner_password,
            ),
        )


@dataclass(frozen=True, slots=True)
class RunSecrets:
    """한 Run 이 시작할 때만 존재하는 비밀 묶음. 어디에도 보관하지 않는다."""

    access: AccessAccounts | None = None
    ssti_token: str = field(repr=False, default="")


# ------------------------------------------------------------------ 계측

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


# ------------------------------------------------------------------ 화면 상태

def _empty_snapshot(budget_total: int) -> dict:
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


def _idle_view(target: str, budget: int) -> dict:
    return {
        "status": "idle",
        "target": target,
        "engine": None,
        "mode": MODE_GENERIC,
        "vuln": "",
        "run_id": None,
        "phase": "init",
        "error": None,
        "notice": None,
        "current_agent": None,
        "findings_total": 0,
        "snapshot": _empty_snapshot(budget),
        "candidates": [],
        "report": None,
    }


class DashboardState:
    """화면이 읽는 유일한 상태. Run 스레드가 쓰고 HTTP 스레드가 읽는다.

    InMemory Store 의 list_by_run 은 dict 를 순회하므로 HTTP 스레드가 직접 읽으면
    Run 스레드의 쓰기와 겹쳐 깨진다. 스냅샷은 Run 스레드에서 만들어 불변 dict 로 둔다.

    비밀은 이 객체에 들어오지 않는다. 화면·활동 로그·API 응답의 유일한 원천이므로
    여기에 없으면 어디에도 새지 않는다.
    """

    def __init__(self, *, budget: int, target: str) -> None:
        self._lock = threading.Lock()
        self._budget = budget
        self._view = _idle_view(target, budget)
        self._events: list[dict] = []

    # --- Run 스레드 ---

    def begin(self, options: RunOptions, *, engine_label: str) -> None:
        with self._lock:
            self._events = []
            self._budget = options.resolved_budget()
            self._view = _idle_view(options.target, self._budget) | {
                "status": "running",
                "engine": engine_label,
                "mode": options.mode,
                "vuln": options.vuln if options.is_juice_shop else "",
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
            # 도메인 이벤트에는 벽시계 시각이 없다(경과시간만 있다).
            "time": datetime.now().strftime("%H:%M:%S"),
        }
        with self._lock:
            self._events.append(payload)
            self._view["run_id"] = event.run_id
            self._view["phase"] = event.phase
            self._view["current_agent"] = current_agent

    def note(self, message: str) -> None:
        """준비·정리처럼 ProgressEvent 가 없는 단계를 활동 로그에 남긴다.

        대상 응답이나 비밀이 아니라 이 프로세스가 한 일만 적는다.
        """

        with self._lock:
            self._events.append(
                {
                    "sequence": -len(self._events) - 1,  # 도메인 순번과 겹치지 않게 음수
                    "kind": "dashboard_note",
                    "phase": self._view["phase"],
                    "agent_type": None,
                    "candidate_id": None,
                    "vulnerability_type": None,
                    "surface_path": None,
                    "detail": message,
                    "elapsed_ms": 0,
                    "time": datetime.now().strftime("%H:%M:%S"),
                }
            )

    def update_view(self, **fields) -> None:
        with self._lock:
            self._view.update(fields)

    def finish(self, *, status: str, error: str | None = None, notice: str | None = None) -> None:
        with self._lock:
            self._view["status"] = status
            self._view["error"] = error
            self._view["notice"] = notice
            self._view["current_agent"] = None

    # --- HTTP 스레드 ---

    def read(self, since: int) -> dict:
        with self._lock:
            view = dict(self._view)
            view["snapshot"] = dict(self._view["snapshot"])
            view["candidates"] = list(self._view["candidates"])
            # note 는 음수 순번이라 since 비교에서 항상 통과한다. 화면은 중복을
            # 시각+본문으로 거르지 않고 순번으로 거르므로 별도 목록으로 넘긴다.
            view["events"] = [
                item for item in self._events if item["sequence"] > since or item["sequence"] < 0
            ]
            positive = [item["sequence"] for item in self._events if item["sequence"] > 0]
            view["last_sequence"] = max(positive, default=0)
            return view

    @property
    def running(self) -> bool:
        with self._lock:
            return self._view["status"] == "running"


# ------------------------------------------------------------------ 실행

class RunSupervisor:
    """Run 하나를 조립하고 백그라운드에서 실행한 뒤 반드시 정리한다."""

    def __init__(self, *, allowed_hosts: frozenset[str], defaults: RunOptions) -> None:
        self.allowed_hosts = allowed_hosts
        self.defaults = defaults
        self.state = DashboardState(
            budget=defaults.resolved_budget(), target=defaults.target
        )
        self._thread: threading.Thread | None = None
        self._current_agent: str | None = None
        self._usage: LlmUsageMeter | None = None
        self._app = None

    # --- 검증 (HTTP 스레드에서 호출) ---

    def validate(self, options: RunOptions, secrets: RunSecrets) -> str | None:
        """거부 사유를 돌려준다. 통과하면 None."""

        parsed = urlsplit(options.target)
        if parsed.scheme not in {"http", "https"}:
            return "대상 URL은 http 또는 https여야 한다."
        host = (parsed.hostname or "").casefold()
        if host not in self.allowed_hosts:
            return (
                f"{host or '(호스트 없음)'}는 허용 대상이 아니다. "
                f"허용: {', '.join(sorted(self.allowed_hosts))}"
            )
        if options.mode not in MODES:
            return f"알 수 없는 실행 모드다: {options.mode}"
        if options.is_juice_shop and options.vuln not in VULN_CHOICES:
            return f"알 수 없는 취약점 유형이다: {options.vuln}"
        if options.validation_review and options.profile != "llm":
            # CLI 와 같은 규칙이다.
            return "Validation review는 Analysis 프로필이 llm일 때만 쓸 수 있다."
        if needs_llm(options.to_namespace()) and not options.resolved_model():
            return "LLM 구성을 골랐지만 모델을 정할 수 없다."
        if options.needs_access_accounts:
            if secrets.access is None or not secrets.access.is_complete():
                return (
                    "Access Control 검증에는 ACTOR/OWNER 테스트 계정 두 개가 필요하다. "
                    "이메일과 비밀번호를 모두 입력한다."
                )
            try:
                secrets.access.to_cli_inputs()
            except ValueError as error:
                return str(error)
        if options.needs_ssti_token and not secrets.ssti_token.strip():
            return "SSTI 단독 검증에는 실습 계정의 token Cookie가 필요하다."
        if options.needs_path_account:
            try:
                _resolve_juice_shop_db(options.juice_shop_db or None)
            except RuntimeError as error:
                return str(error)
        return None

    def start(self, options: RunOptions, secrets: RunSecrets) -> None:
        if self.state.running:
            raise RuntimeError("이미 실행 중인 Run이 있다.")
        self.state.begin(options, engine_label=_engine_label(options))
        self._current_agent = None
        self._usage = None
        self._app = None
        self._thread = threading.Thread(
            target=self._run,
            args=(options, secrets),
            name="hacklipse-run",
            daemon=True,
        )
        self._thread.start()

    # --- 아래부터 Run 스레드 ---

    def _build_llm_client(self, options: RunOptions):
        namespace = options.to_namespace()
        if not needs_llm(namespace):
            return None, None
        model = options.resolved_model()
        if options.llm_provider == "gemini":
            client = build_gemini_llm_client_from_env(model=model)
        else:
            client = build_llm_client_from_env(model=model)

        limit = options.llm_rpm_limit
        if limit is None and options.llm_provider == "gemini":
            # 무료 등급 Gemini 는 분당 15회다. 한 Run 이 Analysis·Validation·Report
            # 요약까지 여러 번 부르므로 제한 없이 돌리면 중간에 429 로 죽는다.
            limit = _DEFAULT_GEMINI_RPM_LIMIT
        if limit:
            client = SlidingWindowLlmClient(client, max_calls=limit)
        # 계측은 제한 바깥에 둔다. 제한 때문에 대기한 호출도 한 번의 호출이다.
        return LlmUsageMeter(client), limit

    def _run(self, options: RunOptions, secrets: RunSecrets) -> None:
        try:
            llm_client, rpm_limit = self._build_llm_client(options)
        except LlmCredentialsMissing as error:
            self.state.finish(status="failed", error=str(error))
            return
        self._usage = llm_client
        namespace = options.to_namespace()
        base_url = options.target.rstrip("/") + "/"
        parsed = urlsplit(base_url)
        host = (parsed.hostname or "").casefold()
        base_path = parsed.path if parsed.path.endswith("/") else f"{parsed.path}/"
        base_path = base_path or "/"

        cleanup_database: Path | None = None
        if options.needs_path_account:
            cleanup_database = _resolve_juice_shop_db(options.juice_shop_db or None)

        try:
            router = build_run_router(
                namespace,
                vulnerability_types=self._vulnerability_types(options),
                llm_client=llm_client,
                selected_model=options.resolved_model(),
            )
        except OSError as error:
            self.state.finish(
                status="failed", error=f"Router 기록 파일을 열 수 없다: {error}"
            )
            return

        plan = _preparation_plan(options, secrets)
        resolver = InMemoryCredentialResolver(plan.credentials)
        http_runtime = HttpExecutionRuntime(credential_resolver=resolver)
        # SPA 의 DOM sink 는 브라우저로만 관측된다. 필요할 때만 감싸 다른 유형의
        # 실행 비용을 늘리지 않는다 — CLI 와 같은 판단이다.
        runtime = (
            PlaywrightBrowserRuntime(http_runtime=http_runtime)
            if options.needs_browser
            else http_runtime
        )
        audit = InMemoryExecutionAuditLog()
        knowledge_base = None
        if options.knowledge_db:
            knowledge_path = Path(options.knowledge_db)
            knowledge_path.parent.mkdir(parents=True, exist_ok=True)
            knowledge_base = SQLiteKnowledgeBase(knowledge_path)

        app = build_local_application(
            {},
            runtime=runtime,
            knowledge_base=knowledge_base,
            orchestration_advisor=(
                LlmOrchestrationAdvisor(llm_client=llm_client)
                if options.orchestrator == "hybrid" and llm_client is not None
                else None
            ),
            budget_allocation_advisor=(
                LlmBudgetAllocationAdvisor(llm_client=llm_client)
                if options.budget_allocation == "hybrid" and llm_client is not None
                else None
            ),
            report_format_version="v2",
            report_mode=options.report,
            report_llm_client=llm_client,
            report_llm_model=options.resolved_model(),
            # 살아 있는 계측기를 넘긴다. client 를 만들지 않았다면 사용량을 모르는
            # 것이 아니라 0회다.
            report_llm_usage=llm_client if llm_client is not None else NoLlmUsage(),
            router=router,
            credential_resolver=resolver,
            approval_gate=StaticApprovalGate(plan.approvals),
            audit_log=audit,
            progress_sink=CallbackProgressLog(self._on_event),
            config=OrchestratorConfig(
                browser_xss_validation=options.needs_browser,
                budget_allocation_enabled=options.budget_allocation != "off",
            ),
        )
        self._app = app

        preparation_run_ids: list[str] = []
        provisioned_accounts: list = []
        run = None
        workflow_error: WorkflowExecutionError | None = None
        cleanup_error: Exception | None = None
        target_url = plan.target_url or base_url
        recon_seed_urls = plan.recon_seed_urls
        run_credential_ref = plan.run_credential_ref
        agent_credentials = plan.agent_credentials
        principal_credentials = plan.principal_credentials
        actor_object_id: str | None = None
        owner_object_id: str | None = None

        try:
            # --- 준비: Access Control 두 계정 로그인 (CLI 함수 그대로) ---
            if options.needs_access_accounts:
                assert secrets.access is not None
                self.state.note("ACTOR/OWNER 테스트 계정 로그인 중")
                actor_object_id, owner_object_id, auth_run_id = (
                    _authenticate_access_control_accounts(
                        app,
                        resolver,
                        secrets.access.to_cli_inputs(),
                        base_url=base_url,
                        host=host,
                        allowed_path_prefix=base_path,
                    )
                )
                preparation_run_ids.append(auth_run_id)
                principal_credentials = (
                    ("actor", _ACTOR_CREDENTIAL_REF),
                    ("owner", _OWNER_CREDENTIAL_REF),
                )
                if options.run_all:
                    # 임의 ID 열거 대신 로그인으로 확인한 Actor basket 만 seed 로 준다.
                    recon_seed_urls = _all_mode_recon_seeds(
                        base_url,
                        include_ssti=True,
                        access_control_object_id=actor_object_id,
                    )
                else:
                    target_url = urljoin(base_url, f"rest/basket/{actor_object_id}")
                    run_credential_ref = _ACTOR_CREDENTIAL_REF
                self.state.note("ACTOR/OWNER 로그인 완료 (basket ID 확인)")

            # --- 준비: Path Traversal/SSTI 용 폐기 계정 (CLI 함수 그대로) ---
            if options.needs_path_account:
                assert cleanup_database is not None
                self.state.note("Path Traversal용 임시 계정 생성 중")
                path_account, provision_run_id = _provision_path_traversal_account(
                    app,
                    resolver,
                    base_url=base_url,
                    host=host,
                    allowed_path_prefix=base_path,
                    cleanup_database=cleanup_database,
                )
                preparation_run_ids.append(provision_run_id)
                provisioned_accounts = [path_account]
                run_credential_ref = _RECON_CREDENTIAL_REF
                agent_credentials = (
                    ("Path Traversal", _PATH_TRAVERSAL_CREDENTIAL_REF),
                )
                if options.run_all:
                    agent_credentials += (("SSTI", _TEMP_SSTI_CREDENTIAL_REF),)
                self.state.note("임시 계정 생성 및 보안 답변 등록 완료")

            needs_discovery = (
                options.vuln in _BUNDLE_DISCOVERY_VULNS if options.is_juice_shop else True
            )
            register_standard_agents(
                app,
                llm_client=llm_client if options.profile == "llm" else None,
                recon_planner=standard_recon_planner(
                    mode=options.recon, llm_client=llm_client
                ),
                recon_max_pages=_ALL_MODE_RECON_PAGES if needs_discovery else 1,
                recon_surface_collection_mode=options.surface_collection,
                recon_seed_urls=recon_seed_urls,
                actor_object_id=actor_object_id,
                owner_object_id=owner_object_id,
                validation_review=options.validation_review,
            )

            try:
                run = app.orchestrator.start(
                    RunRequest(
                        target_url=target_url,
                        scope=RunScope(
                            allowed_hosts=frozenset({host}),
                            allowed_path_prefixes=(base_path,),
                        ),
                        request_budget=options.resolved_budget(),
                        credential_ref=run_credential_ref,
                        principal_credentials=principal_credentials,
                        agent_credentials=agent_credentials,
                        # 실제 배선을 그대로 기록한다. CLI 와 같은 함수를 쓴다.
                        execution_profile=execution_profile_from_args(
                            namespace,
                            selected_model=options.resolved_model(),
                            llm_rpm_limit=rpm_limit,
                        ),
                    )
                )
            except WorkflowExecutionError as error:
                workflow_error = error
        except (RuntimeError, ValueError) as error:
            self._refresh()
            self.state.finish(status="failed", error=f"준비 단계 실패: {error}")
            _release(http_runtime, resolver, preparation_run_ids, run)
            return
        except Exception as error:  # noqa: BLE001 - 화면이 조용히 멈추지 않게 한다
            traceback.print_exc()
            self._refresh()
            self.state.finish(status="failed", error=f"예상치 못한 오류: {error}")
            _release(http_runtime, resolver, preparation_run_ids, run)
            return
        finally:
            # 실패·취소 어느 쪽이든 임시 계정과 credential 은 반드시 정리한다.
            if provisioned_accounts and cleanup_database is not None:
                try:
                    _cleanup_provisioned_accounts(cleanup_database, provisioned_accounts)
                    self.state.note("임시 계정 및 연결 데이터 삭제 완료")
                except Exception as error:  # noqa: BLE001
                    cleanup_error = error
            _release(http_runtime, resolver, preparation_run_ids, run)
            self.state.note("세션 credential 메모리 참조 폐기 완료")

        self._refresh()
        if workflow_error is not None:
            detail = f"Run 실패: {workflow_error}"
            if "FeatureNotFound" in str(workflow_error):
                detail += " — HTML 파서(lxml)가 없다. `pip install lxml` 후 다시 시작한다."
            self.state.finish(
                status="failed",
                error=detail,
                notice=(
                    f"임시 계정 정리 실패: {cleanup_error}" if cleanup_error else None
                ),
            )
            return
        self.state.finish(
            status="done",
            notice=f"임시 계정 정리 실패: {cleanup_error}" if cleanup_error else None,
        )

    @staticmethod
    def _vulnerability_types(options: RunOptions):
        """Router 가 만들 Candidate 유형을 제한한다. 전체 모드는 제한하지 않는다."""

        if not options.is_juice_shop or options.vuln == "all":
            return None
        return (_VULN_TARGETS[options.vuln].label,)

    def _on_event(self, event) -> None:
        if event.kind.value == "agent_started":
            self._current_agent = event.agent_type
        elif event.kind.value in {"agent_completed", "run_completed"}:
            self._current_agent = None
        self.state.record_event(event, current_agent=self._current_agent)
        self._refresh(run_id=event.run_id)

    def _refresh(self, run_id: str | None = None) -> None:
        """현재 Store 내용으로 화면용 스냅샷을 다시 계산한다(Run 스레드에서만)."""

        app = self._app
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
                    # query 값은 빼고 경로와 파라미터 이름만 넘긴다.
                    "path": urlsplit(surface.url).path if surface else "",
                    "parameters": list(item.exploration_parameters)
                    or (list(surface.parameters) if surface else []),
                    "status": item.status.value,
                    "reason": item.last_error,
                    "severity": finding.severity if finding else None,
                }
            )

        reports = app.stores.reports.list_by_run(run_id)
        self.state.update_view(
            run_id=run_id,
            phase=run.phase.value,
            findings_total=len(findings),
            candidates=candidates,
            report=reports[-1].content if reports else None,
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


@dataclass(frozen=True, slots=True)
class _PreparationPlan:
    """Run 시작 전에 정해지는 자격증명·승인·seed 묶음."""

    credentials: dict
    approvals: tuple[str, ...]
    recon_seed_urls: tuple[str, ...]
    agent_credentials: tuple[tuple[str, str], ...]
    principal_credentials: tuple[tuple[str, str], ...]
    run_credential_ref: str | None
    target_url: str | None


def _preparation_plan(options: RunOptions, secrets: RunSecrets) -> _PreparationPlan:
    """CLI main() 의 유형별 분기를 값으로만 옮긴 것. 절차 자체는 CLI 함수가 한다."""

    base_url = options.target.rstrip("/") + "/"
    if not options.is_juice_shop:
        # 범용 대상에는 Juice Shop 전용 계정 생성·DB 정리를 적용하지 않는다.
        return _PreparationPlan({}, (), (), (), (), None, base_url)

    if options.run_all:
        return _PreparationPlan(
            credentials={},
            approvals=(
                _PROVISION_APPROVAL_REF,
                _ACCESS_LOGIN_APPROVAL_REF,
                PATH_TRAVERSAL_POST_APPROVAL_REF,
                SSTI_APPROVAL_REF,
            ),
            recon_seed_urls=_all_mode_recon_seeds(base_url, include_ssti=True),
            agent_credentials=(),
            principal_credentials=(),
            run_credential_ref=None,
            target_url=base_url,
        )

    target = _VULN_TARGETS[options.vuln]
    if options.vuln == "access_control":
        # 시작 Surface 는 로그인으로 확인한 Actor basket 이라 실행 중에 정해진다.
        return _PreparationPlan({}, (_ACCESS_LOGIN_APPROVAL_REF,), (), (), (), None, None)
    if options.vuln == "path_traversal":
        return _PreparationPlan(
            {}, (_PROVISION_APPROVAL_REF, PATH_TRAVERSAL_POST_APPROVAL_REF),
            (), (), (), None, base_url,
        )
    if options.vuln == "ssti":
        return _PreparationPlan(
            credentials={
                _CREDENTIAL_REF: ResolvedHttpCredential(
                    cookies=(("token", secrets.ssti_token.strip()),)
                )
            },
            approvals=(SSTI_APPROVAL_REF,),
            recon_seed_urls=(),
            agent_credentials=(),
            principal_credentials=(),
            run_credential_ref=_CREDENTIAL_REF,
            target_url=urljoin(base_url, target.seed_path or ""),
        )
    # sqli, xss — 인증도 정리도 필요 없다.
    return _PreparationPlan(
        {}, (), (), (), (), None,
        base_url if target.seed_path is None else urljoin(base_url, target.seed_path),
    )


def _release(http_runtime, resolver, preparation_run_ids, run) -> None:
    """세션과 credential 참조를 모두 놓는다. 실패 경로에서도 반드시 불린다."""

    if run is not None:
        http_runtime.close_session(run.run_id)
    for run_id in preparation_run_ids:
        http_runtime.close_session(run_id)
    resolver.clear()


def _engine_label(options: RunOptions) -> str:
    if options.profile != "llm":
        return "Heuristic (결정적)"
    return f"LLM · {options.llm_provider} / {options.resolved_model()}"
