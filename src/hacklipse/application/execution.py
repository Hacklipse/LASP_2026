"""외부 실행을 정책·예산·Evidence 저장 경계 안에서 수행한다."""

from __future__ import annotations

from collections.abc import Callable
from uuid import uuid4

from hacklipse.domain import (
    AccessPrincipalRole,
    AgentResult,
    AgentResultStatus,
    Evidence,
    EvidenceRequest,
    ExecutionRequest,
    ExecutionResult,
    HttpRequestSpec,
    Run,
    TaskEnvelope,
)
from hacklipse.ports import (
    BudgetManager,
    EvidenceSanitizer,
    EvidenceStore,
    ExecutionAuditEvent,
    ExecutionAuditLog,
    ExecutionRuntime,
    PolicyGate,
    RunStore,
)
from hacklipse.ports.errors import PolicyViolation

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
        evidence_sanitizer: EvidenceSanitizer | None = None,
        audit_log: ExecutionAuditLog | None = None,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._runs = run_store
        self._evidence = evidence_store
        self._policy = policy_gate
        self._budget = budget_manager
        self._runtime = runtime
        self._sanitizer = evidence_sanitizer
        self._audit = audit_log
        self._id_factory = id_factory or (lambda: str(uuid4()))

    def collect(
        self,
        run_id: str,
        target_url: str,
        spec: EvidenceRequest,
        *,
        task_id: str,
        validation_id: str | None = None,
        timeout_seconds: float = 120.0,
        approval_ref: str | None = None,
        credential_ref: str | None = None,
    ) -> str:
        """정책·예산·Runtime 경계를 거쳐 Evidence를 저장하고 ID를 반환한다."""

        evidence_id, _ = self.collect_with_result(
            run_id,
            target_url,
            spec,
            task_id=task_id,
            validation_id=validation_id,
            timeout_seconds=timeout_seconds,
            approval_ref=approval_ref,
            credential_ref=credential_ref,
        )
        return evidence_id

    def collect_with_result(
        self,
        run_id: str,
        target_url: str,
        spec: EvidenceRequest,
        *,
        task_id: str,
        validation_id: str | None = None,
        timeout_seconds: float = 120.0,
        approval_ref: str | None = None,
        credential_ref: str | None = None,
    ) -> tuple[str, ExecutionResult]:
        """중앙 인증 Worker가 raw 결과를 일시적으로 읽되 저장본은 마스킹한다."""

        # 저장된 Run을 신뢰 기준으로 사용해 Task가 임의 정책을 주입하지 못하게 한다.
        run = self._runs.get(run_id)
        execution_id = f"exec-{self._id_factory()}"
        http_request = spec.http_request or HttpRequestSpec()
        request = ExecutionRequest(
            execution_id=execution_id,
            run_id=run_id,
            task_id=task_id,
            tool=spec.suggested_tool,
            target_url=target_url,
            surface_id=spec.surface_id,
            purpose=spec.reason,
            method=http_request.method,
            query_parameters=http_request.query_parameters,
            headers=http_request.headers,
            body=http_request.body,
            request_kind=http_request.request_kind,
            identifier_parameter=http_request.identifier_parameter,
            validation_id=validation_id,
            timeout_seconds=min(timeout_seconds, run.timeout_seconds),
            credential_ref=_credential_for(run, spec.principal_role, credential_ref),
            approval_ref=approval_ref,
            scope=run.scope,
        )
        # 실제 호출 직전에 Scope와 예산을 검사해 우회 실행을 막는다.
        try:
            self._policy.validate_execution(run, request)
            self._budget.consume(run.run_id, 1)
            result = self._runtime.execute(request)
        except Exception as error:
            self._record_audit(request, "blocked_or_failed", detail=type(error).__name__)
            raise
        if result.execution_id != execution_id:
            error = AgentContractError("runtime result does not match execution request")
            self._record_audit(request, "failed", detail=type(error).__name__)
            raise error

        try:
            stored_result = (
                self._sanitizer.sanitize(request, result)
                if self._sanitizer is not None
                else result
            )
            # Runtime 결과는 메시지로 중계하지 않고 Evidence Store에 먼저 기록한다.
            evidence_id = f"evi-{self._id_factory()}"
            observation = dict(stored_result.observation)
            # Runtime 구현이 바뀌어도 control/probe 출처가 Evidence에서 사라지지 않게 한다.
            observation.setdefault("request_kind", request.request_kind.value)
            observation.setdefault("requested_url", request.resolved_url)
            observation.setdefault("method", request.method.upper())
            # requested_url과 body는 저장 전에 마스킹될 수 있다. Agent가 표시 문자열을
            # Evidence 연결 키로 쓰지 않도록, 실행 직전 명세의 비가역 fingerprint를
            # Collector가 신뢰 가능한 값으로 덮어쓴다.
            observation["request_fingerprint"] = spec.request_fingerprint(target_url)
            self._evidence.append(
                Evidence(
                    evidence_id=evidence_id,
                    run_id=run.run_id,
                    surface_id=request.surface_id,
                    created_by=f"execution_runtime:{request.tool}",
                    evidence_type=stored_result.evidence_type,
                    source_task_id=task_id,
                    validation_id=validation_id,
                    observation=observation,
                    artifact_refs=stored_result.artifact_refs,
                    content_hash=stored_result.content_hash,
                )
            )
        except Exception as error:
            self._record_audit(request, "failed", detail=type(error).__name__)
            raise
        status = observation.get("status")
        self._record_audit(
            request,
            "completed",
            status_code=status if isinstance(status, int) else None,
        )
        return evidence_id, result

    def _record_audit(
        self,
        request: ExecutionRequest,
        outcome: str,
        *,
        status_code: int | None = None,
        detail: str | None = None,
    ) -> None:
        if self._audit is None:
            return
        from urllib.parse import urlsplit, urlunsplit

        parsed = urlsplit(request.resolved_url)
        target = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
        self._audit.append(
            ExecutionAuditEvent(
                execution_id=request.execution_id,
                run_id=request.run_id,
                task_id=request.task_id,
                tool=request.tool,
                method=request.method.upper(),
                target=target,
                request_kind=request.request_kind.value,
                outcome=outcome,
                status_code=status_code,
                detail=detail,
            )
        )

    # TO DO collect 호출
    def handle(self, task: TaskEnvelope) -> AgentResult:
        """증적 요청 계약을 검증하고 공통 수집 경계에 실행을 위임한다."""

        request_spec = task.evidence_request
        if request_spec is None or task.target_url is None:
            raise AgentContractError("evidence collection task is missing its request")
        if request_spec.suggested_tool not in task.allowed_tools:
            raise AgentContractError("requested execution tool is not allowed by the task")

        evidence_id = self.collect(
            task.run_id,
            task.target_url,
            request_spec,
            task_id=task.task_id,
            validation_id=task.validation_id,
            timeout_seconds=task.timeout_seconds,
            approval_ref=request_spec.approval_ref,
        )
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=(evidence_id,),
        )


def _credential_for(
    run: Run,
    role: AccessPrincipalRole | None,
    requested: str | None = None,
) -> str | None:
    """Agent가 지정한 역할을 Run에 등록된 자격증명으로만 해석한다.

    Agent와 LLM은 credential_ref를 직접 고를 수 없다. `EvidenceRequest`에는 역할만
    담을 수 있고, 그 역할이 현재 Run에 등록되어 있지 않으면 요청이 거부된다. 이 해석이
    중앙에 있어야 ACTOR/OWNER 세션이 섞이지 않는다.

    `requested`는 중앙 인증 Worker처럼 어떤 주체의 세션을 세울지 Orchestrator가 이미
    정해 둔 경우에만 쓴다. 그 경우에도 Run에 등록된 참조가 아니면 거부하므로, 임의
    자격증명을 끌어다 쓰는 경로는 되지 않는다.
    """

    if role is not None:
        registered = dict(run.principal_credentials)
        credential_ref = registered.get(role.value)
        if not credential_ref:
            raise PolicyViolation(
                f"run has no credential registered for principal role: {role.value}"
            )
        return credential_ref
    if requested is not None:
        allowed = {run.credential_ref, *(ref for _, ref in run.principal_credentials)}
        if requested not in allowed:
            raise PolicyViolation(
                "execution requested a credential that is not registered for this run"
            )
        return requested
    return run.credential_ref
