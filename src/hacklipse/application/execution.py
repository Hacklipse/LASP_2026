"""외부 실행을 정책·예산·Evidence 저장 경계 안에서 수행한다."""

from __future__ import annotations

from collections.abc import Callable
from uuid import uuid4

from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Evidence,
    ExecutionRequest,
    TaskEnvelope,
)
from hacklipse.ports import BudgetManager, EvidenceStore, ExecutionRuntime, PolicyGate, RunStore

from .errors import AgentContractError


class RuntimeEvidenceCollector:
    """모든 Runtime 결과를 먼저 Evidence로 바꾸는 정책 통제 Worker."""

    def __init__(
        self,
        *,
        run_store: RunStore,
        evidence_store: EvidenceStore,
        policy_gate: PolicyGate,
        budget_manager: BudgetManager,
        runtime: ExecutionRuntime,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._runs = run_store
        self._evidence = evidence_store
        self._policy = policy_gate
        self._budget = budget_manager
        self._runtime = runtime
        self._id_factory = id_factory or (lambda: str(uuid4()))

    def handle(self, task: TaskEnvelope) -> AgentResult:
        """증적 요청을 검증하고 Runtime 결과를 append-only Evidence로 저장한다."""

        request_spec = task.evidence_request
        if request_spec is None or task.target_url is None:
            raise AgentContractError("evidence collection task is missing its request")
        if request_spec.suggested_tool not in task.allowed_tools:
            raise AgentContractError("requested execution tool is not allowed by the task")

        # 저장된 Run을 신뢰 기준으로 사용해 Task가 임의 정책을 주입하지 못하게 한다.
        run = self._runs.get(task.run_id)
        execution_id = f"exec-{self._id_factory()}"
        request = ExecutionRequest(
            execution_id=execution_id,
            run_id=task.run_id,
            task_id=task.task_id,
            tool=request_spec.suggested_tool,
            target_url=task.target_url,
            surface_id=request_spec.surface_id,
            purpose=request_spec.reason,
        )
        # 실제 호출 직전에 Scope와 예산을 검사해 우회 실행을 막는다.
        self._policy.validate_execution(run, request)
        self._budget.consume(run.run_id, 1)
        result = self._runtime.execute(request)
        if result.execution_id != execution_id:
            raise AgentContractError("runtime result does not match execution request")

        # Runtime 결과는 메시지로 중계하지 않고 Evidence Store에 먼저 기록한다.
        evidence_id = f"evi-{self._id_factory()}"
        self._evidence.append(
            Evidence(
                evidence_id=evidence_id,
                run_id=run.run_id,
                surface_id=request.surface_id,
                created_by=f"execution_runtime:{request.tool}",
                evidence_type=result.evidence_type,
                observation=result.observation,
                artifact_refs=result.artifact_refs,
                content_hash=result.content_hash,
            )
        )
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=(evidence_id,),
        )
