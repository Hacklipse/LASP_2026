"""워크플로 단계별 최소 TaskEnvelope 생성 규칙."""

from __future__ import annotations

from collections.abc import Callable
from uuid import uuid4

from hacklipse.domain import Candidate, EvidenceRequest, Run, TaskEnvelope


class TaskFactory:
    """Evidence 본문이나 Agent 추론을 넣지 않고 최소 작업 메시지만 생성한다."""

    def __init__(self, id_factory: Callable[[], str] | None = None) -> None:
        # 테스트에서는 결정적 ID 생성기를 주입할 수 있고, 기본값은 UUID를 사용한다.
        self._id_factory = id_factory or (lambda: f"task-{uuid4()}")

    def recon(self, run: Run, *, agent_type: str, request_budget: int) -> TaskEnvelope:
        """대상 URL을 탐색할 Recon Task를 생성한다."""

        return self._base(
            run,
            agent_type=agent_type,
            request_budget=request_budget,
            target_url=run.target_url,
            # HttpExecutionRuntime의 GET 실행 도구 이름과 맞춰야 collect()가 통과한다.
            allowed_tools=("http_get",),
        )

    def analysis(
        self, run: Run, candidate: Candidate, *, request_budget: int
    ) -> TaskEnvelope:
        """Candidate와 연결된 Evidence ID만 포함한 Analysis Task를 생성한다."""

        return self._base(
            run,
            agent_type=candidate.assigned_agent,
            request_budget=request_budget,
            surface_id=candidate.surface_id,
            candidate_id=candidate.candidate_id,
            evidence_ids=candidate.evidence_ids,
        )

    def validation(
        self,
        run: Run,
        candidate: Candidate,
        *,
        agent_type: str,
        request_budget: int,
    ) -> TaskEnvelope:
        """Candidate/Evidence 참조만 전달하는 Validation Task를 생성한다."""

        return self._base(
            run,
            agent_type=agent_type,
            request_budget=request_budget,
            surface_id=candidate.surface_id,
            candidate_id=candidate.candidate_id,
            evidence_ids=candidate.evidence_ids,
        )

    def evidence_collection(
        self,
        run: Run,
        candidate: Candidate,
        request: EvidenceRequest,
        *,
        agent_type: str,
        request_budget: int,
    ) -> TaskEnvelope:
        """추가 증적 요청을 공통 Runtime Worker용 Task로 변환한다."""

        return self._base(
            run,
            agent_type=agent_type,
            request_budget=request_budget,
            target_url=run.target_url,
            surface_id=candidate.surface_id,
            candidate_id=candidate.candidate_id,
            evidence_ids=candidate.evidence_ids,
            allowed_tools=(request.suggested_tool,),
            evidence_request=request,
        )

    def report(self, run: Run, *, agent_type: str) -> TaskEnvelope:
        """확정 Finding ID만 포함한 Report Task를 생성한다."""

        return self._base(
            run,
            agent_type=agent_type,
            request_budget=0,
            finding_ids=run.finding_ids,
        )

    def _base(
        self,
        run: Run,
        *,
        agent_type: str,
        request_budget: int,
        target_url: str | None = None,
        surface_id: str | None = None,
        candidate_id: str | None = None,
        evidence_ids: tuple[str, ...] = (),
        finding_ids: tuple[str, ...] = (),
        allowed_tools: tuple[str, ...] = (),
        evidence_request: EvidenceRequest | None = None,
    ) -> TaskEnvelope:
        """모든 Task에 공통인 Run·정책·예산 정보를 조립한다."""

        return TaskEnvelope(
            task_id=self._id_factory(),
            run_id=run.run_id,
            agent_type=agent_type,
            target_url=target_url,
            surface_id=surface_id,
            candidate_id=candidate_id,
            evidence_ids=evidence_ids,
            finding_ids=finding_ids,
            allowed_tools=allowed_tools,
            request_budget=request_budget,
            policy_profile=run.policy_profile,
            evidence_request=evidence_request,
        )
