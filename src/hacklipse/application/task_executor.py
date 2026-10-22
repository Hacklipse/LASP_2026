"""Task 저장, Dispatcher 호출, 재시도를 하나의 실행 경계로 묶는다."""

from __future__ import annotations

import json

import signal
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import replace

from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    HttpRequestKind,
    TaskEnvelope,
    TaskRecord,
    TaskStatus,
)
from hacklipse.ports import BudgetManager, RetryPolicy, TaskDispatcher, TaskStore
from hacklipse.ports.errors import TaskTimeout

from .errors import AgentContractError, safe_error_reason


_PROTECTED_SSRF_ENDPOINT = "https://protected-ssrf-endpoint.invalid/"
_PROTECTED_SSRF_VALUE = "protected"


class TaskExecutor:
    """Task 영속화, Dispatcher 호출, 제한된 복구 절차를 담당한다."""

    def __init__(
        self,
        *,
        dispatcher: TaskDispatcher,
        task_store: TaskStore,
        budget_manager: BudgetManager,
        retry_policy: RetryPolicy,
        progress_callback: Callable[[str, TaskEnvelope, int, float], None]
        | None = None,
    ) -> None:
        self._dispatcher = dispatcher
        self._tasks = task_store
        self._budget = budget_manager
        self._retry = retry_policy
        self._progress = progress_callback

    def execute(self, envelope: TaskEnvelope) -> AgentResult:
        """Task를 기록하고 성공하거나 재시도 한도에 도달할 때까지 실행한다."""

        # PENDING 레코드를 먼저 남겨 실행 전부터 Task를 추적할 수 있게 한다.
        # SSRF 확인 주소는 Worker에만 원본으로 전달하고 저장·진행 알림에는 남기지 않는다.
        observable_envelope = _protected_observable_envelope(envelope)
        record = TaskRecord(envelope=observable_envelope)
        self._tasks.add(record)
        attempt = 0

        while True:
            attempt += 1
            started = time.monotonic()
            self._notify("started", observable_envelope, attempt, 0.0)
            try:
                # Agent를 호출하기 전에 남은 Run 예산을 확인한다.
                self._budget.ensure_available(envelope)
                record = record.with_status(TaskStatus.RUNNING, attempts=attempt)
                self._tasks.save(record)
                with _task_deadline(envelope.timeout_seconds):
                    result = self._dispatcher.dispatch(envelope)
                self._validate_result(envelope, result)
                record = record.with_status(TaskStatus.SUCCEEDED, attempts=attempt)
                self._tasks.save(record)
                self._notify(
                    "succeeded", observable_envelope, attempt, time.monotonic() - started
                )
                return result
            except Exception as error:
                # 실패를 기록한 후 RetryPolicy에 다음 시도 여부를 위임한다.
                record = record.with_status(
                    TaskStatus.FAILED,
                    attempts=attempt,
                    error=safe_error_reason(error),
                )
                self._tasks.save(record)
                self._notify(
                    "failed", observable_envelope, attempt, time.monotonic() - started
                )
                if not self._retry.should_retry(attempt, error):
                    raise

    def _notify(
        self,
        event: str,
        envelope: TaskEnvelope,
        attempt: int,
        elapsed_seconds: float,
    ) -> None:
        """관찰용 callback 실패가 실제 Task 결과를 바꾸지 않게 격리한다."""

        if self._progress is None:
            return
        try:
            self._progress(event, envelope, attempt, elapsed_seconds)
        except Exception:
            # Debug UI는 Control Plane의 성공·실패 의미를 바꿀 권한이 없다.
            return

    @staticmethod
    def _validate_result(envelope: TaskEnvelope, result: AgentResult) -> None:
        """Agent 결과가 요청 Task와 일치하고 명시적 실패가 아닌지 확인한다."""

        if result.task_id != envelope.task_id:
            raise AgentContractError("agent result task_id does not match its envelope")
        if result.status is AgentResultStatus.FAILED:
            raise AgentContractError(result.message or "agent reported failure")


def _protected_observable_envelope(envelope: TaskEnvelope) -> TaskEnvelope:
    """TaskStore·UI에서는 SSRF 실행 주소와 동반 값을 보호한다."""

    evidence_request = envelope.evidence_request
    request = evidence_request.http_request if evidence_request is not None else None
    if request is None or request.request_kind not in {
        HttpRequestKind.SSRF_PROBE,
        HttpRequestKind.SSRF_CANARY_PROBE,
        HttpRequestKind.SSRF_OWNED_RECEIVER_PROBE,
        HttpRequestKind.SSRF_WORKFLOW_OWNED_PROBE,
        HttpRequestKind.SSRF_CSV_UPLOAD_PROBE,
    }:
        return envelope

    def protected(value: str) -> str:
        return (
            _PROTECTED_SSRF_ENDPOINT
            if value.casefold().startswith(("http://", "https://"))
            else _PROTECTED_SSRF_VALUE
        )

    protected_body = _PROTECTED_SSRF_VALUE if request.body is not None else None
    if request.request_kind is HttpRequestKind.SSRF_CSV_UPLOAD_PROBE:
        assert request.body is not None
        prefix, separator, remainder = request.body.partition("\r\n\r\n")
        row, newline, trailer = remainder.partition("\n")
        category, delimiter, _ = row.partition(";")
        if not (separator and newline and delimiter):
            raise AgentContractError("CSV probe body is malformed")
        protected_body = (
            prefix + separator + category + delimiter
            + "http://%31%32%37%2e%30%2e%30%2e%31:9/redacted"
            + newline + trailer
        )
    elif request.method.upper() == "POST" and request.body is not None:
        # Keep only field names in observable tasks. The execution worker uses
        # its original envelope, which remains bound to the issued URL ticket.
        def protect_json(value):
            if isinstance(value, dict):
                return {name: protect_json(item) for name, item in value.items()}
            if isinstance(value, str):
                return protected(value)
            return _PROTECTED_SSRF_VALUE
        protected_body = json.dumps(protect_json(json.loads(request.body)))

    protected_request = replace(
        request,
        query_parameters=(
            request.query_parameters
            if request.request_kind is HttpRequestKind.SSRF_CSV_UPLOAD_PROBE
            else tuple((name, protected(value)) for name, value in request.query_parameters)
        ),
        form_parameters=tuple(
            (name, protected(value)) for name, value in request.form_parameters
        ),
        headers=(
            request.headers if request.method.upper() == "POST"
            else tuple((name, _PROTECTED_SSRF_VALUE) for name, _ in request.headers)
        ),
        body=protected_body,
    )
    return replace(
        envelope,
        evidence_request=replace(evidence_request, http_request=protected_request),
    )


@contextmanager
def _task_deadline(timeout_seconds: float):
    """동기식 로컬 Task에 wall-clock 제한을 적용한다.

    POSIX 메인 스레드에서는 SIGALRM으로 블로킹 호출까지 중단한다. 신호를 안전하게
    사용할 수 없는 스레드/플랫폼에서는 반환 직후 초과를 실패로 판정한다. 외부 HTTP와
    LLM 호출은 별도 request timeout도 받아 이 fallback에서도 무한 대기를 피한다.
    """

    started = time.monotonic()
    can_interrupt = bool(
        threading.current_thread() is threading.main_thread()
        and hasattr(signal, "SIGALRM")
        and hasattr(signal, "setitimer")
        and signal.getitimer(signal.ITIMER_REAL)[0] == 0
    )
    if not can_interrupt:
        yield
        elapsed = time.monotonic() - started
        if elapsed > timeout_seconds:
            raise TaskTimeout(f"task exceeded its {timeout_seconds}s deadline")
        return

    previous_handler = signal.getsignal(signal.SIGALRM)

    def expire(signum, frame) -> None:
        del signum, frame
        raise TaskTimeout(f"task exceeded its {timeout_seconds}s deadline")

    signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, timeout_seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
