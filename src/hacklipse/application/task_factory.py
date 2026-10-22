"""워크플로 단계별 최소 TaskEnvelope 생성 규칙."""

from __future__ import annotations

from collections.abc import Callable
from uuid import uuid4

from hacklipse.domain import (
    Candidate,
    EvidenceRequest,
    KnowledgeHint,
    Run,
    Surface,
    TaskEnvelope,
    credential_for_vulnerability,
    HttpRequestKind,
)

_PATH_TRAVERSAL_TOOL = "path_traversal_probe"
_ACCESS_CONTROL_TOOL = "access_control_probe"
_ARBITRARY_FILE_READ_TOOL = "arbitrary_file_read_probe"
_ARBITRARY_FILE_READ_TYPE = "Arbitrary File Read"
_SSTI_TOOL = "ssti_probe"
_BROWSER_XSS_TOOL = "browser_xss"
# XSS 는 담당 Agent 가 둘이다. 서버 반사는 http_get, SPA 의 DOM 반사는 브라우저로만
# 관측된다. 도구는 취약점 유형이 아니라 그 Agent 가 무엇으로 요청하는지에 달려 있다.
_BROWSER_XSS_ANALYZER = "browser_xss_analyzer"
_POSTMESSAGE_XSS_ANALYZER = "postmessage_xss_analyzer"
_PUBLIC_LOGIN_CREDENTIAL_TYPE = "Exposed Working Credentials"
_SSRF_TOOLS = (
    "get_surface_context", "probe_observed_url_input", "read_probe_result",
)


class TaskFactory:
    """Evidence 본문이나 Agent 추론을 넣지 않고 최소 작업 메시지만 생성한다."""

    def __init__(self, id_factory: Callable[[], str] | None = None) -> None:
        # 테스트에서는 결정적 ID 생성기를 주입할 수 있고, 기본값은 UUID를 사용한다.
        self._id_factory = id_factory or (lambda: f"task-{uuid4()}")

    def recon(
        self,
        run: Run,
        *,
        agent_type: str,
        request_budget: int,
        target_surface: Surface | None = None,
    ) -> TaskEnvelope:
        """대상 URL을 탐색할 Recon Task를 생성한다."""

        return self._base(
            run,
            agent_type=agent_type,
            request_budget=request_budget,
            target_url=target_surface.url if target_surface is not None else run.target_url,
            surface_id=target_surface.surface_id if target_surface is not None else None,
            # HttpExecutionRuntime의 GET 실행 도구 이름과 맞춰야 collect()가 통과한다.
            allowed_tools=("http_get",),
            # Recon은 특정 취약점에 속하지 않는 탐색이므로 Run 기본 세션으로 돈다.
            credential_ref=run.credential_ref,
        )

    def analysis(
        self,
        run: Run,
        candidate: Candidate,
        *,
        target_url: str,
        request_budget: int,
        surface_method: str = "GET",
        knowledge_hints: tuple[KnowledgeHint, ...] = (),
        validation_request_reserve: int = 0,
    ) -> TaskEnvelope:
        """Candidate의 실제 Surface URL과 Evidence 참조를 Analysis Task에 담는다."""

        if candidate.assigned_agent in {_BROWSER_XSS_ANALYZER, _POSTMESSAGE_XSS_ANALYZER}:
            allowed_tools = (_BROWSER_XSS_TOOL,)
        elif candidate.vulnerability_type == "Path Traversal":
            allowed_tools = (_PATH_TRAVERSAL_TOOL,)
        elif candidate.vulnerability_type == _ARBITRARY_FILE_READ_TYPE:
            allowed_tools = (_ARBITRARY_FILE_READ_TOOL,)
        elif candidate.vulnerability_type == "Access Control":
            # 권한 우회 탐침은 전용 도구로만 나간다. 일반 http_get을 허용하면 Agent가
            # 식별자 제약과 헤더 금지 규칙을 우회한 요청을 만들 수 있다.
            allowed_tools = (_ACCESS_CONTROL_TOOL,)
        elif candidate.vulnerability_type == "SSTI":
            allowed_tools = (_SSTI_TOOL,)
        elif candidate.vulnerability_type in {_PUBLIC_LOGIN_CREDENTIAL_TYPE, "File Upload"}:
            allowed_tools = ("http_get", "http_post")
        elif candidate.vulnerability_type == "SSRF":
            if candidate.analysis_strategy_id == "declared_json_webhook_internal_request_log_probe":
                allowed_tools = ("http_post", "http_delete", *_SSRF_TOOLS)
            elif candidate.analysis_strategy_id == "declared_json_workflow_internal_request_log_probe":
                allowed_tools = ("http_get", "http_post", *_SSRF_TOOLS)
            else:
                allowed_tools = (
                    "http_post" if surface_method.upper() == "POST" else "http_get",
                    *_SSRF_TOOLS,
                )
        elif candidate.vulnerability_type == "SQLi":
            allowed_tools = (
                "http_post" if surface_method.upper() == "POST" else "http_get",
            )
        else:
            allowed_tools = ("http_get",)
        return self._base(
            run,
            agent_type=candidate.assigned_agent,
            request_budget=request_budget,
            validation_request_reserve=validation_request_reserve,
            target_url=target_url,
            surface_id=candidate.surface_id,
            candidate_id=candidate.candidate_id,
            evidence_ids=candidate.evidence_ids,
            knowledge_hints=knowledge_hints,
            allowed_tools=allowed_tools,
            credential_ref=credential_for_vulnerability(
                run, candidate.vulnerability_type
            ),
        )

    def validation(
        self,
        run: Run,
        candidate: Candidate,
        *,
        validation_id: str,
        agent_type: str,
        request_budget: int,
        surface_method: str = "GET",
        browser_xss_enabled: bool = False,
    ) -> TaskEnvelope:
        """Candidate/Evidence 참조만 전달하는 Validation Task를 생성한다."""

        if candidate.vulnerability_type == "XSS" and browser_xss_enabled:
            allowed_tools = ("http_get", "browser_xss")
        elif candidate.vulnerability_type == "Path Traversal":
            allowed_tools = (_PATH_TRAVERSAL_TOOL,)
        elif candidate.vulnerability_type == _ARBITRARY_FILE_READ_TYPE:
            allowed_tools = (_ARBITRARY_FILE_READ_TOOL,)
        elif candidate.vulnerability_type == "Access Control":
            allowed_tools = (_ACCESS_CONTROL_TOOL,)
        elif candidate.vulnerability_type == "SSTI":
            allowed_tools = (_SSTI_TOOL,)
        elif candidate.vulnerability_type in {_PUBLIC_LOGIN_CREDENTIAL_TYPE, "File Upload"}:
            allowed_tools = ("http_get", "http_post")
        elif candidate.vulnerability_type == "SQLi":
            allowed_tools = (
                "http_post" if surface_method.upper() == "POST" else "http_get",
            )
        elif candidate.vulnerability_type == "SSRF":
            if candidate.analysis_strategy_id == "declared_json_webhook_internal_request_log_probe":
                allowed_tools = ("http_post", "http_delete")
            elif candidate.analysis_strategy_id == "declared_json_workflow_internal_request_log_probe":
                allowed_tools = ("http_get", "http_post")
            else:
                allowed_tools = (
                    "http_post" if surface_method.upper() == "POST" else "http_get",
                )
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
            credential_ref=credential_for_vulnerability(
                run, candidate.vulnerability_type
            ),
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

        if request.target_url_override is not None and not (
            request.suggested_tool == _ARBITRARY_FILE_READ_TOOL
            and request.http_request is not None
            and request.http_request.request_kind is HttpRequestKind.FILE_READ_PUBLIC_CHECK
        ):
            raise ValueError("target URL override is reserved for file-read public checks")
        return self._base(
            run,
            agent_type=agent_type,
            request_budget=request_budget,
            target_url=request.target_url_override or target_url,
            surface_id=candidate.surface_id,
            candidate_id=candidate.candidate_id,
            evidence_ids=candidate.evidence_ids,
            allowed_tools=(request.suggested_tool,),
            validation_id=validation_id,
            evidence_request=request,
            # 증적 수집도 Candidate가 속한 취약점 유형의 세션으로 나가야 한다.
            # Run 기본값을 쓰면 유형별 인증 분리가 이 지점에서 무너진다.
            credential_ref=credential_for_vulnerability(
                run, candidate.vulnerability_type
            ),
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
        validation_id: str | None = None,
    ) -> TaskEnvelope:
        """비밀 원문 없이 credential_ref만 중앙 인증 Worker에 전달한다.

        Access Control처럼 주체가 둘 이상인 검사에서는 역할별로 각각 인증해야 하므로
        어떤 참조를 인증할지 호출자가 지정할 수 있다.

        ``validation_id``가 주어지면 그 Validation 세션에 대해 인증한다. 독립 재현은
        세션을 일부러 분리하므로(런타임의 세션 키에 validation_id가 들어간다) 분석
        단계에서 세운 로그인이 그쪽으로 넘어가지 않는다.
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
            validation_id=validation_id,
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
        knowledge_hints: tuple[KnowledgeHint, ...] = (),
        finding_ids: tuple[str, ...] = (),
        allowed_tools: tuple[str, ...] = (),
        validation_id: str | None = None,
        evidence_request: EvidenceRequest | None = None,
        credential_ref: str | None = None,
        validation_request_reserve: int = 0,
    ) -> TaskEnvelope:
        """모든 Task에 공통인 Run·정책·예산 정보를 조립한다.

        credential_ref는 호출자가 해석해서 넘긴다. 여기서 Run 기본값으로 되돌리면
        "이 유형에는 자격증명을 주지 않는다"는 결정을 표현할 수 없다.
        """

        return TaskEnvelope(
            task_id=self._id_factory(),
            run_id=run.run_id,
            agent_type=agent_type,
            target_url=target_url,
            surface_id=surface_id,
            candidate_id=candidate_id,
            evidence_ids=evidence_ids,
            knowledge_hints=knowledge_hints,
            finding_ids=finding_ids,
            allowed_tools=allowed_tools,
            request_budget=request_budget,
            validation_request_reserve=validation_request_reserve,
            policy_profile=run.policy_profile,
            timeout_seconds=run.timeout_seconds,
            credential_ref=credential_ref,
            validation_id=validation_id,
            evidence_request=evidence_request,
        )
