"""Port 구현체를 선택하고 실행 가능한 로컬 애플리케이션으로 조립한다."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from hacklipse.adapters import (
    AllowlistPolicyGate,
    BoundedRetryPolicy,
    DisabledExecutionRuntime,
    InMemoryBudgetManager,
    LocalTaskDispatcher,
    MarkdownReportAgent,
    MemoryStoreBundle,
    RuleBasedVulnerabilityRouter,
)
from hacklipse.application import (
    Orchestrator,
    OrchestratorConfig,
    RunStateMachine,
    RuntimeEvidenceCollector,
    TaskExecutor,
    TaskFactory,
)
from hacklipse.ports import Agent, ExecutionRuntime, RetryPolicy, VulnerabilityRouter


@dataclass(slots=True)
class LocalApplication:
    """조립된 Orchestrator와 로컬 Adapter를 호출자에게 제공한다."""

    orchestrator: Orchestrator
    stores: MemoryStoreBundle
    dispatcher: LocalTaskDispatcher
    budget_manager: InMemoryBudgetManager
    policy_gate: AllowlistPolicyGate
    runtime: ExecutionRuntime
    collector: RuntimeEvidenceCollector


def build_local_application(
    agents: Mapping[str, Agent],
    *,
    runtime: ExecutionRuntime | None = None,
    router: VulnerabilityRouter | None = None,
    retry_policy: RetryPolicy | None = None,
    config: OrchestratorConfig | None = None,
) -> LocalApplication:
    """기본적으로 네트워크를 활성화하지 않는 로컬 시스템을 조립한다."""

    # 모든 컴포넌트는 여기에서 생성하여 의존 관계가 코드 전역에 흩어지지 않게 한다.
    stores = MemoryStoreBundle()
    dispatcher = LocalTaskDispatcher()
    budget = InMemoryBudgetManager()
    policy = AllowlistPolicyGate()
    # 명시적인 Runtime 주입이 없으면 외부 실행을 전부 거부하는 구현을 선택한다.
    selected_runtime = runtime or DisabledExecutionRuntime()
    selected_config = config or OrchestratorConfig()
    # 항상 만들어 노출한다 — Recon처럼 이 collector를 직접 주입받아야 하는 Agent는
    # agents 인자로 들어가기 전에 이미 collector가 필요해서 순환이 생기기 때문에,
    # 호출자가 build 후 app.collector로 받아 별도로 등록한다.
    collector = RuntimeEvidenceCollector(
        run_store=stores.runs,
        evidence_store=stores.evidence,
        policy_gate=policy,
        budget_manager=budget,
        runtime=selected_runtime,
    )

    for agent_type, agent in agents.items():
        # 실제 Recon/Analysis/Validation Agent는 호출자가 명시적으로 제공해야 한다.
        dispatcher.register(agent_type, agent)

    if selected_config.report_agent_type not in agents:
        # 별도 Report Agent가 없으면 판정을 바꾸지 않는 기본 Markdown 구현을 사용한다.
        dispatcher.register(
            selected_config.report_agent_type,
            MarkdownReportAgent(
                finding_store=stores.findings,
                evidence_store=stores.evidence,
            ),
        )
    if selected_config.evidence_collector_agent_type not in agents:
        # 추가 증적 수집은 공통 정책·예산·Runtime 경계를 거치는 Worker로 연결한다.
        dispatcher.register(selected_config.evidence_collector_agent_type, collector)

    # Task 실행기와 Orchestrator는 Port만 바라보며 구체 Adapter를 직접 생성하지 않는다.
    task_executor = TaskExecutor(
        dispatcher=dispatcher,
        task_store=stores.tasks,
        budget_manager=budget,
        retry_policy=retry_policy or BoundedRetryPolicy(),
    )
    orchestrator = Orchestrator(
        run_store=stores.runs,
        evidence_store=stores.evidence,
        candidate_store=stores.candidates,
        finding_store=stores.findings,
        report_store=stores.reports,
        policy_gate=policy,
        budget_manager=budget,
        router=router or RuleBasedVulnerabilityRouter(),
        task_executor=task_executor,
        state_machine=RunStateMachine(),
        task_factory=TaskFactory(),
        config=selected_config,
    )
    return LocalApplication(
        orchestrator=orchestrator,
        stores=stores,
        dispatcher=dispatcher,
        budget_manager=budget,
        policy_gate=policy,
        runtime=selected_runtime,
        collector=collector,
    )
