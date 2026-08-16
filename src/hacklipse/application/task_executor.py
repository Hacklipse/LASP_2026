"""Task 저장, Dispatcher 호출, 재시도를 하나의 실행 경계로 묶는다."""

from __future__ import annotations

from hacklipse.domain import AgentResult, AgentResultStatus, TaskEnvelope, TaskRecord, TaskStatus
from hacklipse.ports import BudgetManager, RetryPolicy, TaskDispatcher, TaskStore

from .errors import AgentContractError


class TaskExecutor:
    """Task 영속화, Dispatcher 호출, 제한된 복구 절차를 담당한다."""

    def __init__(
        self,
        *,
        dispatcher: TaskDispatcher,
        task_store: TaskStore,
        budget_manager: BudgetManager,
        retry_policy: RetryPolicy,
    ) -> None:
        self._dispatcher = dispatcher
        self._tasks = task_store
        self._budget = budget_manager
        self._retry = retry_policy

    def execute(self, envelope: TaskEnvelope) -> AgentResult:
        """Task를 기록하고 성공하거나 재시도 한도에 도달할 때까지 실행한다."""

        # PENDING 레코드를 먼저 남겨 실행 전부터 Task를 추적할 수 있게 한다.
        record = TaskRecord(envelope=envelope)
        self._tasks.add(record)
        attempt = 0

        while True:
            attempt += 1
            try:
                # Agent를 호출하기 전에 남은 Run 예산을 확인한다.
                self._budget.ensure_available(envelope)
                record = record.with_status(TaskStatus.RUNNING, attempts=attempt)
                self._tasks.save(record)
                result = self._dispatcher.dispatch(envelope)
                self._validate_result(envelope, result)
                record = record.with_status(TaskStatus.SUCCEEDED, attempts=attempt)
                self._tasks.save(record)
                return result
            except Exception as error:
                # 실패를 기록한 후 RetryPolicy에 다음 시도 여부를 위임한다.
                record = record.with_status(
                    TaskStatus.FAILED, attempts=attempt, error=str(error)
                )
                self._tasks.save(record)
                if not self._retry.should_retry(attempt, error):
                    raise

    @staticmethod
    def _validate_result(envelope: TaskEnvelope, result: AgentResult) -> None:
        """Agent 결과가 요청 Task와 일치하고 명시적 실패가 아닌지 확인한다."""

        if result.task_id != envelope.task_id:
            raise AgentContractError("agent result task_id does not match its envelope")
        if result.status is AgentResultStatus.FAILED:
            raise AgentContractError(result.message or "agent reported failure")
