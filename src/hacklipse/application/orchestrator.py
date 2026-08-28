"""전체 Run 순서를 중앙 통제하되 세부 구현은 각 컴포넌트에 위임한다."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from uuid import uuid4

from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Candidate,
    Finding,
    Run,
    RunPhase,
    RunRequest,
    ValidationVerdict,
)
from hacklipse.ports import (
    BudgetManager,
    CandidateStore,
    EvidenceStore,
    FindingStore,
    PolicyGate,
    ReportStore,
    RunStore,
    SurfaceStore,
    VulnerabilityRouter,
)

from .errors import AgentContractError, WorkflowExecutionError
from .state_machine import RunStateMachine
from .task_executor import TaskExecutor
from .task_factory import TaskFactory


@dataclass(frozen=True, slots=True)
class OrchestratorConfig:
    """워크플로 역할별 Agent 이름과 추가 증적 반복 상한."""

    recon_agent_type: str = "recon"
    validation_agent_type: str = "validation"
    evidence_collector_agent_type: str = "evidence_collector"
    report_agent_type: str = "report"
    max_evidence_rounds: int = 1

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
        )
        # Run과 예산을 먼저 등록한 뒤 첫 단계인 RECON으로 전이한다.
        self._runs.add(run)
        self._budget.open_run(run.run_id, run.request_budget)
        run = self._state.transition(run, RunPhase.RECON)
        self._runs.save(run)
        return self.resume(run.run_id)

    def resume(self, run_id: str) -> Run:
        """저장된 현재 phase부터 동기식 워크플로를 이어서 실행한다."""

        run = self._runs.get(run_id)
        if run.phase in {RunPhase.DONE, RunPhase.FAILED}:
            return run

        try:
            # 단계 순서와 분기만 판단하고 실제 작업은 하위 컴포넌트에 맡긴다.
            while run.phase not in {RunPhase.DONE, RunPhase.FAILED}:
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
            return run
        except Exception as error:
            # 하위 컴포넌트 실패도 Run의 FAILED 상태와 원인으로 일관되게 남긴다.
            failed = self._state.fail(run, error)
            self._runs.save(failed)
            raise WorkflowExecutionError(run.run_id, run.phase.value, str(error)) from error

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

    def _route(self, run: Run) -> Run:
        """저장된 Surface·Evidence를 Router에 전달하고 Candidate를 저장한다."""

        surfaces = self._surfaces.list_by_run(run.run_id)
        evidence = self._evidence.get_many(run.run_id, run.evidence_ids)
        decisions = self._router.route(run, surfaces, evidence)
        candidate_ids = list(run.candidate_ids)
        for decision in decisions:
            candidate = decision.candidate
            # Router가 다른 Run의 Candidate를 섞는 계약 위반을 차단한다.
            if candidate.run_id != run.run_id:
                raise AgentContractError("router returned a candidate for another run")
            self._candidates.add(candidate)
            candidate_ids.append(candidate.candidate_id)
        return run.with_updates(candidate_ids=tuple(dict.fromkeys(candidate_ids)))

    def _analyze(self, run: Run) -> Run:
        """라우팅된 각 Candidate를 담당 Analysis Agent에 전달한다."""

        current = run
        for candidate_id in run.candidate_ids:
            candidate = self._candidates.get(run.run_id, candidate_id)
            # 이미 처리된 Candidate는 재개 시 중복 분석하지 않는다.
            if candidate.status != "routed":
                continue
            # Candidate가 참조하는 Run-scoped Surface를 실제 Analysis 대상으로 해석한다.
            surface = self._surfaces.get(run.run_id, candidate.surface_id)
            task = self._task_factory.analysis(
                current,
                candidate,
                target_url=surface.url,
                request_budget=self._budget.remaining(run.run_id),
            )
            result = self._tasks.execute(task)
            self._require_completed(result, "analysis")
            current = self._merge_agent_result(current, result)
            candidate = candidate.add_evidence(result.new_evidence_ids).set_status("analyzed")
            self._candidates.save(candidate)
        return current

    def _validate(self, run: Run) -> Run:
        """Candidate를 독립 검증하고 필요하면 추가 Evidence 수집을 조정한다."""

        current = run
        # 부분 재개를 고려해 저장소에 이미 존재하는 Finding부터 복원한다.
        finding_ids = [item.finding_id for item in self._findings.list_by_run(run.run_id)]
        for candidate_id in run.candidate_ids:
            candidate = self._candidates.get(run.run_id, candidate_id)
            if candidate.status != "analyzed":
                continue
            validation = None

            for evidence_round in range(self._config.max_evidence_rounds + 1):
                # Analysis 결론 대신 Candidate와 Evidence 참조만 Validator에 전달한다.
                task = self._task_factory.validation(
                    current,
                    candidate,
                    agent_type=self._config.validation_agent_type,
                    request_budget=self._budget.remaining(run.run_id),
                )
                result = self._tasks.execute(task)
                validation = result.validation
                requests = result.evidence_requests
                if validation is not None:
                    self._validate_validation_contract(run, candidate, validation)
                    requests = requests or validation.evidence_requests

                if requests and evidence_round < self._config.max_evidence_rounds:
                    # Validator가 Worker를 직접 호출하지 않고 Orchestrator가 수집 Task를 만든다.
                    for request in requests:
                        if request.surface_id != candidate.surface_id:
                            raise AgentContractError(
                                "validation evidence request references a different surface"
                            )
                        surface = self._surfaces.get(run.run_id, request.surface_id)
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
                    continue
                break

            if validation is None:
                # 반복 상한 안에 판정을 얻지 못하면 Finding으로 승격하지 않는다.
                candidate = candidate.set_status("suspected")
                self._candidates.save(candidate)
                continue

            if validation.verdict is ValidationVerdict.CONFIRMED:
                # 도메인 팩토리가 판정과 Evidence 불변식을 한 번 더 확인한다.
                finding = Finding.from_confirmed(
                    finding_id=f"finding-{self._id_factory()}",
                    candidate=candidate,
                    validation=validation,
                )
                self._findings.add(finding)
                finding_ids.append(finding.finding_id)
            candidate = candidate.set_status(validation.verdict.value)
            self._candidates.save(candidate)

        return current.with_updates(finding_ids=tuple(dict.fromkeys(finding_ids)))

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
        self, run: Run, candidate: Candidate, validation: object
    ) -> None:
        """Validation 결과의 타입·소유 관계·Evidence 실재 여부를 검사한다."""

        from hacklipse.domain import ValidationResult

        if not isinstance(validation, ValidationResult):
            raise AgentContractError("validation agent returned an invalid result")
        if validation.run_id != run.run_id or validation.candidate_id != candidate.candidate_id:
            raise AgentContractError("validation result references the wrong run or candidate")
        self._evidence.get_many(run.run_id, validation.evidence_ids)

    @staticmethod
    def _require_completed(result: AgentResult, role: str) -> None:
        """완료가 필수인 단계의 미완료 결과가 다음 단계로 넘어가지 않게 한다."""

        if result.status is not AgentResultStatus.COMPLETED:
            raise AgentContractError(f"{role} did not complete")

    @staticmethod
    def _merge(current: Sequence[str], added: Sequence[str]) -> tuple[str, ...]:
        """ID 순서를 유지하면서 중복을 제거한다."""

        return tuple(dict.fromkeys((*current, *added)))
