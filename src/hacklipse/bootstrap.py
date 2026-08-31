"""Port 구현체를 선택하고 실행 가능한 로컬 애플리케이션으로 조립한다."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Collection, Mapping, Protocol

from hacklipse.adapters import (
    AllowlistPolicyGate,
    AnthropicLlmClient,
    BoundedRetryPolicy,
    DisabledExecutionRuntime,
    FormLoginWorker,
    GeminiLlmClient,
    HeuristicSqliAnalyzer,
    HeuristicXssAnalyzer,
    InMemoryBudgetManager,
    InMemoryExecutionAuditLog,
    LlmSqliAnalyzer,
    LlmXssAnalyzer,
    LocalTaskDispatcher,
    MarkdownReportAgent,
    MemoryStoreBundle,
    ReconAgent,
    RuleBasedVulnerabilityRouter,
    SensitiveDataSanitizer,
    ValidationAgent,
)
from hacklipse.adapters.routing import DEFAULT_RULES, DEFAULT_SURFACE_RULES
from hacklipse.adapters.recon import DEFAULT_MAX_PAGES
from hacklipse.application import (
    Orchestrator,
    OrchestratorConfig,
    RunStateMachine,
    RuntimeEvidenceCollector,
    TaskExecutor,
    TaskFactory,
)
from hacklipse.domain import TaskEnvelope
from hacklipse.ports import (
    Agent,
    BudgetManager,
    ApprovalGate,
    CandidateStore,
    EvidenceStore,
    EvidenceSanitizer,
    ExecutionAuditLog,
    ExecutionRuntime,
    FindingStore,
    ReportStore,
    RetryPolicy,
    RunStore,
    SurfaceStore,
    LlmClient,
    CredentialResolver,
    TaskStore,
    VulnerabilityRouter,
)
from hacklipse.ports.errors import LlmCredentialsMissing

# 자격증명은 환경변수로만 받는다. 파일에 두면 커밋에 딸려 들어갈 수 있고, Task에 실으면
# 감사 로그·프롬프트로 새어 나간다(TaskEnvelope에는 원문 필드 자체가 없다).
ANTHROPIC_API_KEY_ENV = "ANTHROPIC_API_KEY"
GEMINI_API_KEY_ENV = "GEMINI_API_KEY"
# 기존 호출자와 테스트의 공개 이름을 유지한다.
API_KEY_ENV = ANTHROPIC_API_KEY_ENV

# 주 실험은 단일 모델로 고정한다. 역할별로 모델을 섞으면 성능 차이가 아키텍처 덕인지
# 모델 덕인지 분리되지 않는다. 더 강한 모델은 같은 배선에서 model만 바꿔 2차 실험으로 돌린다.
DEFAULT_ANTHROPIC_LLM_MODEL = "claude-sonnet-5"
DEFAULT_GEMINI_LLM_MODEL = "gemini-3.5-flash-lite"
# 기존 Anthropic builder의 기본값 이름을 호환성 목적으로 유지한다.
DEFAULT_LLM_MODEL = DEFAULT_ANTHROPIC_LLM_MODEL


def build_llm_client_from_env(*, model: str = DEFAULT_LLM_MODEL) -> AnthropicLlmClient:
    """환경변수에서 자격증명을 읽어 LLM Client를 만든다.

    build_local_application이 자동으로 부르지 않는다. DisabledExecutionRuntime과 같은
    규칙이다 — 호출자가 명시적으로 주입해야 LLM이 붙는다. 키가 없으면 조용히 비활성화되지
    않고 여기서 실패한다.
    """

    api_key = os.environ.get(ANTHROPIC_API_KEY_ENV, "").strip()
    if not api_key:
        raise LlmCredentialsMissing(
            f"{ANTHROPIC_API_KEY_ENV} is not set; "
            "export it or pass an explicit LlmClient"
        )
    return AnthropicLlmClient(api_key=api_key, model=model)


def build_gemini_llm_client_from_env(
    *, model: str = DEFAULT_GEMINI_LLM_MODEL
) -> GeminiLlmClient:
    """환경변수의 Gemini API Key로 공급자 중립 LlmClient를 만든다."""

    api_key = os.environ.get(GEMINI_API_KEY_ENV, "").strip()
    if not api_key:
        raise LlmCredentialsMissing(
            f"{GEMINI_API_KEY_ENV} is not set; "
            "export it or pass an explicit LlmClient"
        )
    return GeminiLlmClient(api_key=api_key, model=model)


class StoreBundle(Protocol):
    """bootstrap이 조립에 사용하는 저장소 묶음의 구조적 계약."""

    runs: RunStore
    tasks: TaskStore
    evidence: EvidenceStore
    surfaces: SurfaceStore
    candidates: CandidateStore
    findings: FindingStore
    reports: ReportStore


@dataclass(slots=True)
class LocalApplication:
    """조립된 Orchestrator와 로컬 Adapter를 호출자에게 제공한다."""

    orchestrator: Orchestrator
    stores: StoreBundle
    dispatcher: LocalTaskDispatcher
    budget_manager: BudgetManager
    policy_gate: AllowlistPolicyGate
    runtime: ExecutionRuntime
    collector: RuntimeEvidenceCollector
    audit_log: ExecutionAuditLog


def build_local_application(
    agents: Mapping[str, Agent],
    *,
    stores: StoreBundle | None = None,
    budget_manager: BudgetManager | None = None,
    runtime: ExecutionRuntime | None = None,
    router: VulnerabilityRouter | None = None,
    retry_policy: RetryPolicy | None = None,
    config: OrchestratorConfig | None = None,
    credential_resolver: CredentialResolver | None = None,
    evidence_sanitizer: EvidenceSanitizer | None = None,
    audit_log: ExecutionAuditLog | None = None,
    approval_gate: ApprovalGate | None = None,
    agent_allowed_tools: Mapping[str, tuple[str, ...]] | None = None,
    task_progress_callback: Callable[[str, TaskEnvelope, int, float], None]
    | None = None,
) -> LocalApplication:
    """기본적으로 네트워크를 활성화하지 않는 로컬 시스템을 조립한다."""

    # 모든 컴포넌트는 여기에서 생성하여 의존 관계가 코드 전역에 흩어지지 않게 한다.
    selected_stores = stores if stores is not None else MemoryStoreBundle()
    dispatcher = LocalTaskDispatcher()
    selected_budget = (
        budget_manager if budget_manager is not None else InMemoryBudgetManager()
    )
    policy = AllowlistPolicyGate(approval_gate=approval_gate)
    # 명시적인 Runtime 주입이 없으면 외부 실행을 전부 거부하는 구현을 선택한다.
    selected_runtime = runtime or DisabledExecutionRuntime()
    selected_config = config or OrchestratorConfig()
    selected_audit = audit_log or InMemoryExecutionAuditLog()
    selected_sanitizer = evidence_sanitizer or SensitiveDataSanitizer(
        credential_resolver
    )
    # 항상 만들어 노출한다 — Recon처럼 이 collector를 직접 주입받아야 하는 Agent는
    # agents 인자로 들어가기 전에 이미 collector가 필요해서 순환이 생기기 때문에,
    # 호출자가 build 후 app.collector로 받아 별도로 등록한다.
    collector = RuntimeEvidenceCollector(
        run_store=selected_stores.runs,
        evidence_store=selected_stores.evidence,
        policy_gate=policy,
        budget_manager=selected_budget,
        runtime=selected_runtime,
        evidence_sanitizer=selected_sanitizer,
        audit_log=selected_audit,
    )

    for agent_type, agent in agents.items():
        # 실제 Recon/Analysis/Validation Agent는 호출자가 명시적으로 제공해야 한다.
        dispatcher.register(
            agent_type,
            agent,
            allowed_tools=(agent_allowed_tools or {}).get(agent_type, ()),
        )

    if selected_config.report_agent_type not in agents:
        # 별도 Report Agent가 없으면 판정을 바꾸지 않는 기본 Markdown 구현을 사용한다.
        dispatcher.register(
            selected_config.report_agent_type,
            MarkdownReportAgent(
                finding_store=selected_stores.findings,
                evidence_store=selected_stores.evidence,
            ),
            allowed_tools=(),
        )
    if selected_config.evidence_collector_agent_type not in agents:
        # 추가 증적 수집은 공통 정책·예산·Runtime 경계를 거치는 Worker로 연결한다.
        dispatcher.register(
            selected_config.evidence_collector_agent_type,
            collector,
            allowed_tools=("http_get", "http_post", "browser_xss"),
        )
    if credential_resolver is not None and selected_config.authentication_agent_type not in agents:
        dispatcher.register(
            selected_config.authentication_agent_type,
            FormLoginWorker(
                credential_resolver=credential_resolver,
                collector=collector,
            ),
            allowed_tools=("http_get", "http_post"),
        )

    # Task 실행기와 Orchestrator는 Port만 바라보며 구체 Adapter를 직접 생성하지 않는다.
    task_executor = TaskExecutor(
        dispatcher=dispatcher,
        task_store=selected_stores.tasks,
        budget_manager=selected_budget,
        retry_policy=retry_policy or BoundedRetryPolicy(),
        progress_callback=task_progress_callback,
    )
    orchestrator = Orchestrator(
        run_store=selected_stores.runs,
        evidence_store=selected_stores.evidence,
        candidate_store=selected_stores.candidates,
        finding_store=selected_stores.findings,
        report_store=selected_stores.reports,
        surface_store=selected_stores.surfaces,
        policy_gate=policy,
        budget_manager=selected_budget,
        router=router or RuleBasedVulnerabilityRouter(),
        task_executor=task_executor,
        state_machine=RunStateMachine(),
        task_factory=TaskFactory(),
        config=selected_config,
    )
    return LocalApplication(
        orchestrator=orchestrator,
        stores=selected_stores,
        dispatcher=dispatcher,
        budget_manager=selected_budget,
        policy_gate=policy,
        runtime=selected_runtime,
        collector=collector,
        audit_log=selected_audit,
    )


# 실제로 구현된 Analysis Agent. Router가 이 목록 밖 Candidate를 만들면 Dispatcher가
# AgentUnavailable로 Run 전체를 실패시키므로, 배선과 라우팅 규칙이 같은 목록을 봐야 한다.
# Analyzer를 추가하면 여기 한 줄만 늘리면 Router가 따라온다.
IMPLEMENTED_ANALYZERS = ("xss_analyzer", "sqli_analyzer")


def standard_router(
    vulnerability_types: Collection[str] | None = None,
) -> RuleBasedVulnerabilityRouter:
    """구현된 Analyzer로만 라우팅하는 Router를 만든다.

    미구현 취약점 유형을 조용히 건너뛰는 것이 아니라 애초에 Candidate를 만들지 않는다.
    "검사했는데 없었다"와 "검사하지 않았다"를 결과에서 구분할 수 있어야 한다.
    """

    selected_types = (
        frozenset(vulnerability_types) if vulnerability_types is not None else None
    )
    return RuleBasedVulnerabilityRouter(
        rules=tuple(
            rule
            for rule in DEFAULT_RULES
            if rule.agent_type in IMPLEMENTED_ANALYZERS
            and (selected_types is None or rule.vulnerability_type in selected_types)
        ),
        surface_rules=tuple(
            rule
            for rule in DEFAULT_SURFACE_RULES
            if rule.agent_type in IMPLEMENTED_ANALYZERS
            and (selected_types is None or rule.vulnerability_type in selected_types)
        ),
    )


def register_standard_agents(
    app: LocalApplication,
    *,
    llm_client: LlmClient | None = None,
    recon_max_pages: int = DEFAULT_MAX_PAGES,
) -> str:
    """Recon/Analysis/Validation을 표준 배선으로 등록하고 구성 이름을 돌려준다.

    llm_client가 없으면 결정적 baseline(대조군), 있으면 LLM 구현을 꽂는다. 두 구성은
    같은 Surface에서 같은 Observation 유형을 만들어야 비교가 성립하므로, 갈라지는 지점을
    이 함수 하나로 제한한다.
    """

    app.dispatcher.register(
        "recon",
        ReconAgent(
            collector=app.collector,
            evidence_store=app.stores.evidence,
            surface_store=app.stores.surfaces,
            max_pages=recon_max_pages,
        ),
        allowed_tools=("http_get",),
    )
    if llm_client is None:
        xss_analyzer: Agent = HeuristicXssAnalyzer(
            candidate_store=app.stores.candidates,
            surface_store=app.stores.surfaces,
            evidence_store=app.stores.evidence,
        )
        sqli_analyzer: Agent = HeuristicSqliAnalyzer(
            candidate_store=app.stores.candidates,
            surface_store=app.stores.surfaces,
            evidence_store=app.stores.evidence,
        )
        profile = "heuristic"
    else:
        xss_analyzer = LlmXssAnalyzer(
            llm_client=llm_client,
            candidate_store=app.stores.candidates,
            surface_store=app.stores.surfaces,
            evidence_store=app.stores.evidence,
        )
        sqli_analyzer = LlmSqliAnalyzer(
            llm_client=llm_client,
            candidate_store=app.stores.candidates,
            surface_store=app.stores.surfaces,
            evidence_store=app.stores.evidence,
        )
        profile = "llm"
    app.dispatcher.register(
        "xss_analyzer", xss_analyzer, allowed_tools=("http_get",)
    )
    app.dispatcher.register(
        "sqli_analyzer",
        sqli_analyzer,
        allowed_tools=("http_get",),
    )
    app.dispatcher.register(
        "validation",
        ValidationAgent(
            candidate_store=app.stores.candidates,
            evidence_store=app.stores.evidence,
            surface_store=app.stores.surfaces,
        ),
        allowed_tools=("http_get", "browser_xss"),
    )
    return profile
