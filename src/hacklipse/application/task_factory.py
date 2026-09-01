"""워크플로 단계별 최소 TaskEnvelope 생성 규칙."""

from __future__ import annotations

from collections.abc import Callable
from uuid import uuid4

from hacklipse.domain import Candidate, EvidenceRequest, Run, TaskEnvelope

_PATH_TRAVERSAL_TOOL = "path_traversal_probe"
_ACCESS_CONTROL_TOOL = "access_control_probe"
_SSTI_TOOL = "ssti_probe"


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
        self,
        run: Run,
        candidate: Candidate,
        *,
        target_url: str,
        request_budget: int,
    ) -> TaskEnvelope:
        """Candidate의 실제 Surface URL과 Evidence 참조를 Analysis Task에 담는다."""

        if candidate.vulnerability_type == "Path Traversal":
            allowed_tools = (_PATH_TRAVERSAL_TOOL,)
        elif candidate.vulnerability_type == "Access Control":
            # 권한 우회 탐침은 전용 도구로만 나간다. 일반 http_get을 허용하면 Agent가
            # 식별자 제약과 헤더 금지 규칙을 우회한 요청을 만들 수 있다.
            allowed_tools = (_ACCESS_CONTROL_TOOL,)
        elif candidate.vulnerability_type == "SSTI":
            allowed_tools = (_SSTI_TOOL,)
        else:
            allowed_tools = ("http_get",)
        return self._base(
            run,
            agent_type=candidate.assigned_agent,
            request_budget=request_budget,
            target_url=target_url,
            surface_id=candidate.surface_id,
            candidate_id=candidate.candidate_id,
            evidence_ids=candidate.evidence_ids,
            allowed_tools=allowed_tools,
        )

    def validation(
        self,
        run: Run,
        candidate: Candidate,
        *,
        validation_id: str,
        agent_type: str,
        request_budget: int,
        browser_xss_enabled: bool = False,
    ) -> TaskEnvelope:
        """Candidate/Evidence 참조만 전달하는 Validation Task를 생성한다."""

        if candidate.vulnerability_type == "XSS" and browser_xss_enabled:
            allowed_tools = ("http_get", "browser_xss")
        elif candidate.vulnerability_type == "Path Traversal":
            allowed_tools = (_PATH_TRAVERSAL_TOOL,)
        elif candidate.vulnerability_type == "Access Control":
            allowed_tools = (_ACCESS_CONTROL_TOOL,)
        elif candidate.vulnerability_type == "SSTI":
            allowed_tools = (_SSTI_TOOL,)
        else:
            allowed_tools = ("http_get",)
        return self._base(
            run,
            agent_type=agent_type,
            request_budget=request_budget,
            surface_id=candidate.surface_id,
            candidate_id=candidate.candidate_id,
            evidence_ids=candidate.evidence_ids,
            allowed_tools=allowed_tools,
            validation_id=validation_id,
        )

    def evidence_collection(
        self,
        run: Run,
        candidate: Candidate,
        request: EvidenceRequest,
        *,
        target_url: str,
        agent_type: str,
        request_budget: int,
        validation_id: str | None = None,
    ) -> TaskEnvelope:
        """추가 증적 요청을 공통 Runtime Worker용 Task로 변환한다."""

        return self._base(
            run,
            agent_type=agent_type,
            request_budget=request_budget,
            target_url=target_url,
            surface_id=candidate.surface_id,
            candidate_id=candidate.candidate_id,
            evidence_ids=candidate.evidence_ids,
            allowed_tools=(request.suggested_tool,),
            validation_id=validation_id,
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

    def authentication(
        self,
        run: Run,
        *,
        agent_type: str,
        request_budget: int,
        credential_ref: str | None = None,
    ) -> TaskEnvelope:
        """비밀 원문 없이 credential_ref만 중앙 인증 Worker에 전달한다.

        Access Control처럼 주체가 둘 이상인 검사에서는 역할별로 각각 인증해야 하므로
        어떤 참조를 인증할지 호출자가 지정할 수 있다.
        """

        selected = credential_ref or run.credential_ref
        if selected is None:
            raise ValueError("authentication task requires a credential reference")
        return self._base(
            run,
            agent_type=agent_type,
            request_budget=request_budget,
            target_url=run.target_url,
            allowed_tools=("http_get", "http_post"),
            credential_ref=selected,
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
        validation_id: str | None = None,
        evidence_request: EvidenceRequest | None = None,
        credential_ref: str | None = None,
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
            timeout_seconds=run.timeout_seconds,
            credential_ref=credential_ref or run.credential_ref,
            validation_id=validation_id,
            evidence_request=evidence_request,
        )
