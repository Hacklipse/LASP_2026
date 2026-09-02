"""전체 Run 순서를 중앙 통제하되 세부 구현은 각 컴포넌트에 위임한다."""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from uuid import uuid4

from hacklipse.domain import (
    CandidateStatus,
    ProgressEvent,
    ProgressEventKind,
    AgentResult,
    AgentResultStatus,
    Candidate,
    Finding,
    Run,
    RunPhase,
    RunRequest,
    ValidationProofType,
    ValidationVerdict,
)
from hacklipse.ports import (
    BudgetManager,
    CandidateStore,
    EvidenceStore,
    FindingStore,
    PolicyGate,
    ProgressSink,
    ReportStore,
    RunStore,
    SurfaceStore,
    VulnerabilityRouter,
)
from hacklipse.ports.errors import AgentUnavailable, BudgetExceeded

from .errors import AgentContractError, WorkflowExecutionError, safe_error_reason
from .state_machine import RunStateMachine
from .task_executor import TaskExecutor
from .task_factory import TaskFactory


_PROOF_TYPE_BY_VULNERABILITY = {
    "XSS": ValidationProofType.XSS_EXECUTION,
    "SQLi": ValidationProofType.SQLI_EFFECT,
    "Access Control": ValidationProofType.UNAUTHORIZED_OBJECT_ACCESS,
    "Path Traversal": ValidationProofType.PATH_TRAVERSAL_FILE_READ,
    "SSTI": ValidationProofType.SSTI_EXECUTION,
}


@dataclass(frozen=True, slots=True)
class OrchestratorConfig:
    """워크플로 역할별 Agent 이름과 추가 증적 반복 상한."""

    recon_agent_type: str = "recon"
    validation_agent_type: str = "validation"
    evidence_collector_agent_type: str = "evidence_collector"
    report_agent_type: str = "report"
    authentication_agent_type: str = "session_authenticator"
    max_evidence_rounds: int = 1
    browser_xss_validation: bool = False

    def __post_init__(self) -> None:
        if self.max_evidence_rounds < 0:
            raise ValueError("max_evidence_rounds cannot be negative")


class Orchestrator:
    """세부 구현 책임을 위임한 얇은 중앙 Control Plane."""

    def __init__(
        self,
        *,
        run_store: RunStore,
        evidence_store: EvidenceStore,
        candidate_store: CandidateStore,
        finding_store: FindingStore,
        report_store: ReportStore,
        surface_store: SurfaceStore,
        policy_gate: PolicyGate,
        budget_manager: BudgetManager,
        router: VulnerabilityRouter,
        task_executor: TaskExecutor,
        state_machine: RunStateMachine,
        task_factory: TaskFactory,
        config: OrchestratorConfig | None = None,
        id_factory: Callable[[], str] | None = None,
        progress_sink: ProgressSink | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._runs = run_store
        self._evidence = evidence_store
        self._candidates = candidate_store
        self._findings = finding_store
        self._reports = report_store
        self._surfaces = surface_store
        self._policy = policy_gate
        self._budget = budget_manager
        self._router = router
        self._tasks = task_executor
        self._state = state_machine
        self._task_factory = task_factory
        self._config = config or OrchestratorConfig()
        self._id_factory = id_factory or (lambda: str(uuid4()))
        self._progress = progress_sink
        self._sequence = 0
        # 경과 시간만 쓰므로 단조 시계를 쓴다. 시스템 시각이 바뀌어도 구간 길이가
        # 음수가 되지 않는다. 테스트는 결정적 시계를 주입한다.
        self._clock = clock or time.monotonic
        self._started_at: float | None = None

    def start(self, request: RunRequest) -> Run:
        """사용자 입력을 검증하고 새로운 Run을 생성한 뒤 실행한다."""

        # Run을 만들기 전에 Scope를 검사하여 잘못된 대상이 저장되지 않게 한다.
        self._policy.validate_run(request)
        run = Run(
            run_id=f"run-{self._id_factory()}",
            target_url=request.target_url,
            scope=request.scope,
            policy_profile=request.policy_profile,
            request_budget=request.request_budget,
            timeout_seconds=request.timeout_seconds,
            credential_ref=request.credential_ref,
            agent_credentials=request.agent_credentials,
            principal_credentials=request.principal_credentials,
        )
        # Run과 예산을 먼저 등록한 뒤 첫 단계인 RECON으로 전이한다.
        self._runs.add(run)
        self._budget.open_run(run.run_id, run.request_budget)
        # Orchestrator 인스턴스를 재사용해도 진행 순번과 경과 시간은 Run마다 새로
        # 시작해야 한다. 그렇지 않으면 두 번째 Run의 단계 비용이 첫 Run까지 포함한다.
        self._sequence = 0
        self._started_at = None
        self._emit(run, ProgressEventKind.RUN_STARTED, detail=run.policy_profile)
        run = self._state.transition(run, RunPhase.RECON)
        self._runs.save(run)
        return self.resume(run.run_id)

    def resume(self, run_id: str) -> Run:
        """저장된 현재 phase부터 동기식 워크플로를 이어서 실행한다."""

        run = self._runs.get(run_id)
        if run.phase in {RunPhase.DONE, RunPhase.FAILED}:
            return run

        try:
            if run.phase in {
                RunPhase.RECON,
                RunPhase.ROUTE,
                RunPhase.ANALYZE,
                RunPhase.VALIDATE,
            }:
                # 프로세스 재시작 시 메모리 CookieJar가 사라질 수 있으므로 resume마다
                # 중앙 인증 Worker를 다시 실행한다. 비밀 원문은 Task에 들어가지 않는다.
                # Access Control처럼 주체가 둘 이상이면 역할별 세션을 각각 확립해야 한다.
                # 한쪽만 인증되면 owner control이 로그인 페이지를 받아 판정이 성립하지 않는다.
                for credential_ref in _run_credentials(run):
                    auth_task = self._task_factory.authentication(
                        run,
                        agent_type=self._config.authentication_agent_type,
                        request_budget=self._budget.remaining(run.run_id),
                        credential_ref=credential_ref,
                    )
                    auth_result = self._tasks.execute(auth_task)
                    self._require_completed(auth_result, "authentication")
                    run = self._merge_agent_result(run, auth_result)
                    self._runs.save(run)
            # 단계 순서와 분기만 판단하고 실제 작업은 하위 컴포넌트에 맡긴다.
            while run.phase not in {RunPhase.DONE, RunPhase.FAILED}:
                self._emit(run, ProgressEventKind.PHASE_CHANGED)
                if run.phase is RunPhase.RECON:
                    run = self._recon(run)
                    run = self._state.transition(run, RunPhase.ROUTE)
                elif run.phase is RunPhase.ROUTE:
                    run = self._route(run)
                    next_phase = RunPhase.ANALYZE if run.candidate_ids else RunPhase.REPORT
                    run = self._state.transition(run, next_phase)
                elif run.phase is RunPhase.ANALYZE:
                    run = self._analyze(run)
                    run = self._state.transition(run, RunPhase.VALIDATE)
                elif run.phase is RunPhase.VALIDATE:
                    run = self._validate(run)
                    run = self._state.transition(run, RunPhase.REPORT)
                elif run.phase is RunPhase.REPORT:
                    run = self._report(run)
                    run = self._state.transition(run, RunPhase.DONE)
                else:
                    raise AgentContractError(f"unsupported active phase: {run.phase}")
                self._runs.save(run)
            self._emit(run, ProgressEventKind.RUN_COMPLETED)
            return run
        except Exception as error:
            # 하위 컴포넌트 실패도 Run의 FAILED 상태와 원인으로 일관되게 남긴다.
            failed = self._state.fail(run, error)
            self._runs.save(failed)
            raise WorkflowExecutionError(
                run.run_id, run.phase.value, safe_error_reason(error)
            ) from error

    def _recon(self, run: Run) -> Run:
        """Recon Task를 실행하고 새 Evidence·Surface 참조를 Run에 병합한다."""

        task = self._task_factory.recon(
            run,
            agent_type=self._config.recon_agent_type,
            request_budget=self._budget.remaining(run.run_id),
        )
        result = self._tasks.execute(task)
        self._require_completed(result, "recon")
        return self._merge_agent_result(run, result)

    def _emit(
        self,
        run: Run,
        kind: ProgressEventKind,
        *,
        agent_type: str | None = None,
        candidate: Candidate | None = None,
        surface_url: str | None = None,
        detail: str | None = None,
    ) -> None:
        """진행 사건을 중앙에서 하나씩 만든다.

        Agent가 직접 출력하지 않고 여기만 거치게 해야 순서가 보장되고, 민감정보를
        제거하는 규칙을 한곳에서 지킬 수 있다. Sink가 없으면 아무 일도 하지 않는다.
        """

        if self._progress is None:
            return
        now = self._clock()
        if self._started_at is None:
            self._started_at = now
        self._sequence += 1
        try:
            used = max(0, run.request_budget - self._budget.remaining(run.run_id))
        except Exception:
            used = 0
        self._progress.emit(
            ProgressEvent(
                run_id=run.run_id,
                sequence=self._sequence,
                kind=kind,
                phase=run.phase.value,
                agent_type=agent_type,
                candidate_id=candidate.candidate_id if candidate else None,
                vulnerability_type=candidate.vulnerability_type if candidate else None,
                # query 값에는 검색어·토큰이 실릴 수 있다. 경로만 남긴다.
                surface_path=_path_only(surface_url),
                detail=detail,
                budget_used=used,
                budget_total=run.request_budget,
                elapsed_ms=max(0, int((now - self._started_at) * 1000)),
            )
        )

    def _route(self, run: Run) -> Run:
        """저장된 Surface·Evidence를 Router에 전달하고 Candidate를 저장한다."""

        surfaces = self._surfaces.list_by_run(run.run_id)
        evidence = self._evidence.get_many(run.run_id, run.evidence_ids)
        decisions = self._router.route(run, surfaces, evidence)
        # Router가 매긴 우선순위를 실행 순서로 쓴다. 예산이 모자라면 뒤쪽이 잘리므로
        # 어떤 Candidate가 먼저 실행되는지가 곧 무엇을 포기하는지에 대한 결정이 된다.
        # 같은 우선순위는 Router가 만든 순서를 유지한다(안정 정렬).
        decisions = sorted(decisions, key=lambda item: item.priority, reverse=True)
        candidate_ids = list(run.candidate_ids)
        for decision in decisions:
            candidate = decision.candidate
            # Router가 다른 Run의 Candidate를 섞는 계약 위반을 차단한다.
            if candidate.run_id != run.run_id:
                raise AgentContractError("router returned a candidate for another run")
            self._candidates.add(candidate)
            candidate_ids.append(candidate.candidate_id)
            self._emit(
                run,
                ProgressEventKind.CANDIDATE_QUEUED,
                agent_type=candidate.assigned_agent,
                candidate=candidate,
            )
        return run.with_updates(candidate_ids=tuple(dict.fromkeys(candidate_ids)))

    def _analyze(self, run: Run) -> Run:
        """Candidate별로 Analysis를 수행하되 대상 쪽 실패를 서로 격리한다.

        한 Run에 여러 취약점 Candidate가 있으면 하나가 실패했다고 나머지 검사를
        취소해서는 안 된다. 실패는 해당 Candidate에 사유와 함께 남기고 계속 진행한다.
        다만 모든 실패를 격리하지는 않는다(`_CANDIDATE_FATAL_ERRORS` 참고).
        """

        current = run
        for candidate_id in run.candidate_ids:
            candidate = self._candidates.get(run.run_id, candidate_id)
            # 이미 처리된 Candidate는 재개 시 중복 분석하지 않는다.
            if not _pending_in(candidate, CandidateStatus.ROUTED):
                continue
            if self._budget.remaining(run.run_id) <= 0:
                # 남은 예산이 없으면 시작하지 않는다. 일부만 요청하고 죽으면 아무것도
                # 얻지 못한 채 예산만 쓰고, 결과에는 실패로 남는다.
                current = self._skip_candidate_for_budget(current, candidate_id)
                continue
            try:
                current = self._analyze_candidate(current, candidate)
            except Exception as error:
                current = self._fail_candidate(current, candidate_id, error)
        return current

    def _analyze_candidate(self, run: Run, candidate: Candidate) -> Run:
        """Candidate 하나를 분석한다. 실패는 호출자가 격리한다."""

        current = run
        # Candidate가 참조하는 Run-scoped Surface를 실제 Analysis 대상으로 해석한다.
        surface = self._surfaces.get(run.run_id, candidate.surface_id)
        self._emit(
            run,
            ProgressEventKind.AGENT_STARTED,
            agent_type=candidate.assigned_agent,
            candidate=candidate,
            surface_url=surface.url,
        )
        for evidence_round in range(self._config.max_evidence_rounds + 1):
            task = self._task_factory.analysis(
                current,
                candidate,
                target_url=surface.url,
                request_budget=self._budget.remaining(run.run_id),
            )
            result = self._tasks.execute(task)

            # Agent가 요청 계획과 함께 만든 Observation이 있다면 먼저 병합한다.
            current = self._merge_agent_result(current, result)
            candidate = candidate.add_evidence(result.new_evidence_ids)
            self._candidates.save(candidate)

            if result.status is AgentResultStatus.COMPLETED:
                candidate = candidate.set_status(CandidateStatus.ANALYZED)
                self._candidates.save(candidate)
                self._emit(
                    current,
                    ProgressEventKind.AGENT_COMPLETED,
                    agent_type=candidate.assigned_agent,
                    candidate=candidate,
                    surface_url=surface.url,
                )
                break
            if result.status is not AgentResultStatus.NEEDS_EVIDENCE:
                raise AgentContractError("analysis did not complete")
            if not result.evidence_requests:
                raise AgentContractError(
                    "analysis requested evidence without an EvidenceRequest"
                )
            if evidence_round >= self._config.max_evidence_rounds:
                raise AgentContractError("analysis evidence rounds exhausted")

            # Agent는 실행하지 않고 요청만 반환한다. 실제 실행은 중앙 수집 Task가 맡는다.
            for request in result.evidence_requests:
                if request.surface_id != candidate.surface_id:
                    raise AgentContractError(
                        "analysis evidence request references a different surface"
                    )
                if request.suggested_tool not in task.allowed_tools:
                    raise AgentContractError(
                        "analysis requested a tool that is not allowed by its task"
                    )
                collection_task = self._task_factory.evidence_collection(
                    current,
                    candidate,
                    request,
                    target_url=surface.url,
                    agent_type=self._config.evidence_collector_agent_type,
                    request_budget=self._budget.remaining(run.run_id),
                )
                collection = self._tasks.execute(collection_task)
                self._require_completed(collection, "evidence collection")
                current = self._merge_agent_result(current, collection)
                candidate = candidate.add_evidence(collection.new_evidence_ids)
                self._candidates.save(candidate)
                self._emit(
                    current,
                    ProgressEventKind.EVIDENCE_COLLECTED,
                    agent_type=candidate.assigned_agent,
                    candidate=candidate,
                    surface_url=surface.url,
                    detail=request.suggested_tool,
                )
        return current

    def _validate(self, run: Run) -> Run:
        """Candidate를 독립 검증하고 필요하면 추가 Evidence 수집을 조정한다."""

        current = run
        # 부분 재개를 고려해 저장소에 이미 존재하는 Finding부터 복원한다.
        finding_ids = [item.finding_id for item in self._findings.list_by_run(run.run_id)]
        for candidate_id in run.candidate_ids:
            candidate = self._candidates.get(run.run_id, candidate_id)
            if not _pending_in(candidate, CandidateStatus.ANALYZED):
                continue
            if self._budget.remaining(run.run_id) <= 0:
                current = self._skip_candidate_for_budget(current, candidate_id)
                continue
            try:
                current, finding_id = self._validate_candidate(current, candidate)
            except Exception as error:
                current = self._fail_candidate(current, candidate_id, error)
                continue
            if finding_id is not None:
                finding_ids.append(finding_id)
        return current.with_updates(finding_ids=tuple(dict.fromkeys(finding_ids)))

    def _validate_candidate(
        self, run: Run, candidate: Candidate
    ) -> tuple[Run, str | None]:
        """Candidate 하나를 독립 검증한다. 실패는 호출자가 격리한다."""

        current = run
        validation = None
        validation_id = f"validation-{self._id_factory()}"
        self._emit(
            run,
            ProgressEventKind.AGENT_STARTED,
            agent_type=self._config.validation_agent_type,
            candidate=candidate,
        )

        for evidence_round in range(self._config.max_evidence_rounds + 1):
            # Analysis 결론 대신 Candidate와 Evidence 참조만 Validator에 전달한다.
            task = self._task_factory.validation(
                current,
                candidate,
                validation_id=validation_id,
                agent_type=self._config.validation_agent_type,
                request_budget=self._budget.remaining(run.run_id),
                browser_xss_enabled=self._config.browser_xss_validation,
            )
            result = self._tasks.execute(task)
            if result.status is AgentResultStatus.COMPLETED:
                if result.evidence_requests:
                    raise AgentContractError(
                        "completed validation cannot request more evidence"
                    )
                validation = result.validation
                if validation is None:
                    raise AgentContractError(
                        "completed validation did not return a verdict"
                    )
                self._validate_validation_contract(
                    run, candidate, validation, validation_id
                )
                break

            if result.status is not AgentResultStatus.NEEDS_EVIDENCE:
                raise AgentContractError("validation did not complete")
            if result.validation is not None:
                raise AgentContractError(
                    "incomplete validation cannot return a final verdict"
                )
            if not result.evidence_requests:
                raise AgentContractError(
                    "validation requested evidence without an EvidenceRequest"
                )
            if evidence_round >= self._config.max_evidence_rounds:
                break

            # Validator는 요청만 제안한다. 실제 실행과 provenance 부여는 중앙에서 한다.
            for request in result.evidence_requests:
                if request.surface_id != candidate.surface_id:
                    raise AgentContractError(
                        "validation evidence request references a different surface"
                    )
                if request.suggested_tool not in task.allowed_tools:
                    raise AgentContractError(
                        "validation requested a tool that is not allowed by its task"
                    )
                surface = self._surfaces.get(run.run_id, request.surface_id)
                collection_task = self._task_factory.evidence_collection(
                    current,
                    candidate,
                    request,
                    target_url=surface.url,
                    agent_type=self._config.evidence_collector_agent_type,
                    request_budget=self._budget.remaining(run.run_id),
                    validation_id=validation_id,
                )
                collection = self._tasks.execute(collection_task)
                self._require_completed(collection, "evidence collection")
                current = self._merge_agent_result(current, collection)
                candidate = candidate.add_evidence(collection.new_evidence_ids)
                self._candidates.save(candidate)

        if validation is None:
            # 반복 상한 안에 판정을 얻지 못하면 Finding으로 승격하지 않는다.
            candidate = candidate.set_status(CandidateStatus.SUSPECTED)
            self._candidates.save(candidate)
            return current, None

        finding_id = None
        if validation.verdict is ValidationVerdict.CONFIRMED:
            # 도메인 팩토리가 판정과 Evidence 불변식을 한 번 더 확인한다.
            finding = Finding.from_confirmed(
                finding_id=f"finding-{self._id_factory()}",
                candidate=candidate,
                validation=validation,
            )
            self._findings.add(finding)
            finding_id = finding.finding_id
            self._emit(
                current,
                ProgressEventKind.FINDING_CREATED,
                agent_type=self._config.validation_agent_type,
                candidate=candidate,
            )
        status = CandidateStatus(validation.verdict.value)
        # Validator의 reason은 외부 응답을 포함할 수 있어 그대로 저장하지 않는다.
        # BLOCKED는 판정은 났지만 검증을 완료하지 못했다는 사실만 일반화해 남긴다.
        reason = "validation blocked" if status is CandidateStatus.BLOCKED else None
        candidate = candidate.set_status(status, reason=reason)
        self._candidates.save(candidate)
        self._emit(
            current,
            ProgressEventKind.AGENT_COMPLETED,
            agent_type=self._config.validation_agent_type,
            candidate=candidate,
            detail=validation.verdict.value,
        )
        return current, finding_id

    def _fail_candidate(self, run: Run, candidate_id: str, error: Exception) -> Run:
        """실패한 Candidate에만 사유를 남기고 나머지 검사를 계속한다.

        Run 전체를 FAILED로 만들면 함께 실행한 다른 취약점 결과까지 버려진다. 반대로
        조용히 넘어가면 검사하지 못한 Candidate가 안전한 것처럼 보인다.

        계약 위반과 미등록 Agent는 격리하지 않는다. 그것은 대상이 협조하지 않은 것이
        아니라 프레임워크나 Agent 자신이 규칙을 어긴 것이고, 그 상태로 얻은 나머지
        결과는 신뢰할 수 없다.
        """

        if isinstance(error, _CANDIDATE_FATAL_ERRORS):
            raise error
        if isinstance(error, BudgetExceeded):
            # 예산 부족은 대상의 문제도 Agent의 결함도 아니다. 실행하지 못한 것이다.
            return self._skip_candidate_for_budget(
                run, candidate_id, "BudgetExceeded: request budget exhausted"
            )
        candidate = self._candidates.get(run.run_id, candidate_id)
        self._candidates.save(candidate.fail(safe_error_reason(error)))
        self._emit(
            run,
            ProgressEventKind.CANDIDATE_FAILED,
            agent_type=candidate.assigned_agent,
            candidate=candidate,
            detail=type(error).__name__,
        )
        return run

    def _skip_candidate_for_budget(
        self, run: Run, candidate_id: str, detail: str | None = None
    ) -> Run:
        """예산이 모자라 검사하지 못한 Candidate를 실패와 구분해 기록한다."""

        candidate = self._candidates.get(run.run_id, candidate_id)
        reason = detail or f"request budget exhausted for {run.run_id}"
        self._candidates.save(candidate.skip_for_budget(reason))
        self._emit(
            run,
            ProgressEventKind.CANDIDATE_SKIPPED,
            agent_type=candidate.assigned_agent,
            candidate=candidate,
            detail="budget",
        )
        return run

    def _report(self, run: Run) -> Run:
        """확정 Finding만 Report Agent에 전달하고 산출물을 저장한다."""

        existing = self._reports.list_by_run(run.run_id)
        # 이미 만든 보고서는 재개 시 다시 생성하지 않는다.
        if existing:
            return run.with_updates(report_ids=tuple(item.report_id for item in existing))
        task = self._task_factory.report(run, agent_type=self._config.report_agent_type)
        result = self._tasks.execute(task)
        self._require_completed(result, "report")
        for report in result.reports:
            if report.run_id != run.run_id:
                raise AgentContractError("report belongs to another run")
            self._reports.add(report)
        return run.with_updates(report_ids=tuple(item.report_id for item in result.reports))

    def _merge_agent_result(self, run: Run, result: AgentResult) -> Run:
        """반환된 ID의 Evidence 실재 여부를 확인하고 Run에 병합한다."""

        if result.new_evidence_ids:
            self._evidence.get_many(run.run_id, result.new_evidence_ids)
        return run.with_updates(
            evidence_ids=self._merge(run.evidence_ids, result.new_evidence_ids),
            surface_ids=self._merge(run.surface_ids, result.surface_ids),
        )

    def _validate_validation_contract(
        self,
        run: Run,
        candidate: Candidate,
        validation: object,
        expected_validation_id: str,
    ) -> None:
        """판정 소유 관계와 현재 Validation 세션 Evidence만 사용했는지 검사한다."""

        from hacklipse.domain import ValidationResult

        if not isinstance(validation, ValidationResult):
            raise AgentContractError("validation agent returned an invalid result")
        if validation.run_id != run.run_id or validation.candidate_id != candidate.candidate_id:
            raise AgentContractError("validation result references the wrong run or candidate")
        if validation.validation_id != expected_validation_id:
            raise AgentContractError("validation result references a different session")

        evidence = self._evidence.get_many(run.run_id, validation.evidence_ids)
        if validation.reproduction_count != len(evidence):
            raise AgentContractError(
                "validation reproduction count does not match its evidence"
            )
        for item in evidence:
            if item.validation_id != expected_validation_id:
                raise AgentContractError(
                    "validation result references evidence from another provenance"
                )
            if not item.created_by.startswith("execution_runtime:"):
                raise AgentContractError(
                    "validation result must reference centrally collected runtime evidence"
                )
            if item.source_task_id is None:
                raise AgentContractError(
                    "validation evidence is missing its collection task provenance"
                )
            if item.surface_id != candidate.surface_id:
                raise AgentContractError(
                    "validation result references evidence from another surface"
                )

        if validation.verdict is ValidationVerdict.CONFIRMED:
            expected_proof = _PROOF_TYPE_BY_VULNERABILITY.get(
                candidate.vulnerability_type
            )
            if expected_proof is None or validation.proof is None:
                raise AgentContractError(
                    "confirmed validation has no supported vulnerability proof"
                )
            if validation.proof.proof_type is not expected_proof:
                raise AgentContractError(
                    "validation proof type does not match the candidate vulnerability"
                )

    @staticmethod
    def _require_completed(result: AgentResult, role: str) -> None:
        """완료가 필수인 단계의 미완료 결과가 다음 단계로 넘어가지 않게 한다."""

        if result.status is not AgentResultStatus.COMPLETED:
            raise AgentContractError(f"{role} did not complete")

    @staticmethod
    def _merge(current: Sequence[str], added: Sequence[str]) -> tuple[str, ...]:
        """ID 순서를 유지하면서 중복을 제거한다."""

        return tuple(dict.fromkeys((*current, *added)))


def _path_only(url: str | None) -> str | None:
    """진행 사건에 남길 경로만 뽑는다. query와 fragment는 버린다."""

    if url is None:
        return None
    from urllib.parse import urlsplit

    return urlsplit(url).path or "/"


def _pending_in(candidate: Candidate, phase_status: CandidateStatus) -> bool:
    """이 단계에서 아직 처리해야 하는 Candidate인지 판단한다.

    예산이 모자라 건너뛴 Candidate는 재개 대상이다. 그대로 두면 예산을 늘려 다시
    실행해도 영원히 검사되지 않는다. 다만 어느 단계에서 멈췄는지를 지켜야 한다.
    검증 직전에 멈춘 Candidate를 분석부터 다시 돌리면 이미 쓴 예산을 또 쓴다.

    재시도 횟수를 따로 세지 않는 이유는 시작 전에 잔여 예산을 확인하기 때문이다.
    예산이 없으면 요청을 한 번도 보내지 않고 다시 건너뛰므로 반복이 비용을 늘리지
    않는다.
    """

    if candidate.status is phase_status:
        return True
    return (
        candidate.status is CandidateStatus.SKIPPED_BUDGET
        and candidate.resume_status is phase_status
    )


# Candidate 단위로 격리하지 않는 실패. 대상 쪽 문제가 아니라 시스템 쪽 문제이므로
# Run 전체를 실패시켜 드러낸다. 여기 없는 예외(HTTP 오류, 인증 실패, 정책 차단,
# 예산 초과)는 해당 Candidate만 failed로 남기고 나머지 검사를 계속한다.
_CANDIDATE_FATAL_ERRORS = (AgentContractError, AgentUnavailable)


def _run_credentials(run: Run) -> tuple[str, ...]:
    """이 Run에서 세션을 확립해야 하는 자격증명 참조를 중복 없이 모은다.

    Run 기본값, Access Control의 주체별 자격증명, 취약점 유형별 자격증명을 모두 포함한다.
    하나라도 빠지면 해당 Agent가 인증되지 않은 세션으로 요청해 결과를 오해하게 된다.
    """

    refs = [run.credential_ref] if run.credential_ref else []
    refs.extend(ref for _, ref in run.principal_credentials if ref)
    refs.extend(ref for _, ref in run.agent_credentials if ref)
    return tuple(dict.fromkeys(refs))
