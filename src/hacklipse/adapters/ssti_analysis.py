"""고정 산술식만 사용하는 결정적 SSTI baseline Agent.

Juice Shop의 프로필 username처럼 저장 후 서버 템플릿에서 렌더링되는 입력을 대상으로 한다.
Agent는 외부 요청을 직접 실행하지 않고, 다음 고정 순서의 EvidenceRequest만 반환한다.

    안전한 control 이름 설정 → 조회 → 고정 산술식 설정 → 조회 → 안전한 이름으로 정리

산술식은 파일·환경변수·프로세스·네트워크에 접근하지 않는다. 전용 Policy가 정확히 이
값과 ``/profile``의 username 필드만 허용하므로 LLM이나 Agent가 명령 실행형 문자열로
확장할 수 없다.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from urllib.parse import urlencode, urlsplit
from uuid import uuid4

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Candidate,
    Evidence,
    EvidenceRequest,
    ExecutionRequest,
    HttpRequestKind,
    HttpRequestSpec,
    Surface,
    TaskEnvelope,
)
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore

SSTI_TOOL = "ssti_probe"
SSTI_APPROVAL_REF = "approve-local-ssti-profile-update"
HEURISTIC_SSTI_ANALYZER = "heuristic_ssti_analyzer"
SSTI_OBSERVATION = "template_execution"

# 서버에 영향을 주지 않는 순수 산술식 하나만 허용한다. 결과는 짧고 고유하며 현재
# 민감정보 마스킹 규칙의 전화번호/주민번호 패턴에도 걸리지 않는다.
SSTI_CONTROL_VALUE = "hacklipse-ssti-control"
SSTI_SAFE_EXPRESSION = "#{713*17}"
SSTI_EXPECTED_RESULT = "12121"
SSTI_CLEANUP_VALUE = "hacklipse-ssti-restored"
SSTI_PARAMETER_HINTS = frozenset({"username", "name", "template", "content", "message"})


def validate_ssti_request(request: ExecutionRequest) -> None:
    """전용 SSTI 도구를 Juice Shop형 안전 산술 검증 계약으로 제한한다."""

    if request.tool != SSTI_TOOL:
        raise ValueError("SSTI request must use its dedicated tool")
    if request.query_parameters:
        raise ValueError("SSTI profile probe does not allow query parameters")
    if not urlsplit(request.resolved_url).path.rstrip("/").endswith("/profile"):
        raise ValueError("SSTI safe probe is restricted to a /profile endpoint")

    method = request.method.upper()
    if method == "GET":
        if request.body is not None or request.headers:
            raise ValueError("SSTI observation fetch must be a plain GET")
        if request.request_kind not in {
            HttpRequestKind.CONTROL,
            HttpRequestKind.SSTI_PROBE,
        }:
            raise ValueError("SSTI observation fetch has an invalid request kind")
        return

    if method != "POST":
        raise ValueError("SSTI safe probe supports only GET and POST")
    if request.approval_ref != SSTI_APPROVAL_REF:
        raise ValueError("SSTI profile update requires its explicit approval reference")
    if request.headers != (("Content-Type", "application/x-www-form-urlencoded"),):
        raise ValueError("SSTI profile update requires form-urlencoded content")
    expected = {
        HttpRequestKind.CONTROL: SSTI_CONTROL_VALUE,
        HttpRequestKind.SSTI_PROBE: SSTI_SAFE_EXPRESSION,
        HttpRequestKind.SSTI_CLEANUP: SSTI_CLEANUP_VALUE,
    }.get(request.request_kind)
    if expected is None or request.body != urlencode((("username", expected),)):
        raise ValueError("SSTI profile update may only set the fixed safe username value")


def resolve_ssti_task(
    task: TaskEnvelope,
    *,
    candidate_store: CandidateStore,
    surface_store: SurfaceStore,
) -> tuple[Candidate, Surface, tuple[str, ...]]:
    """SSTI Analysis Task가 저장된 POST Surface와 일치하는지 확인한다."""

    if task.candidate_id is None or task.surface_id is None or task.target_url is None:
        raise AgentContractError("SSTI analysis task is missing candidate or surface context")
    if SSTI_TOOL not in task.allowed_tools:
        raise AgentContractError("SSTI execution tool is not allowed by the task")
    candidate = candidate_store.get(task.run_id, task.candidate_id)
    if candidate.vulnerability_type != "SSTI":
        raise AgentContractError("SSTI analyzer received a different candidate type")
    if candidate.surface_id != task.surface_id:
        raise AgentContractError("SSTI candidate and task reference different surfaces")
    surface = surface_store.get(task.run_id, task.surface_id)
    if surface.url != task.target_url:
        raise AgentContractError("SSTI task target does not match its surface")
    if surface.method.upper() != "POST" or not surface.parameters:
        raise AgentContractError("SSTI analysis requires a parameterized POST surface")
    return candidate, surface, tuple(dict.fromkeys(surface.parameters))


def heuristic_ssti_parameters(parameters: Sequence[str]) -> tuple[str, ...]:
    """템플릿에 렌더링될 가능성이 있는 이름 필드만 결정적으로 선택한다."""

    return tuple(
        name
        for name in dict.fromkeys(parameters)
        if name.casefold() in SSTI_PARAMETER_HINTS
    )


def build_ssti_requests(
    surface: Surface,
    parameter: str,
    *,
    purpose: str,
) -> tuple[EvidenceRequest, ...]:
    """한 필드에 대한 설정/조회/정리 요청을 실행 순서대로 만든다."""

    if parameter not in surface.parameters:
        raise AgentContractError("SSTI parameter must belong to the surface")
    if parameter != "username":
        # 첫 수직 구현은 Juice Shop의 검증된 username 계약만 실행한다. LLM이 name이나
        # content를 골라도 임의 상태 변경으로 이어지지 않게 여기서 한 번 더 좁힌다.
        raise AgentContractError("SSTI safe profile probe only supports username")

    def update(value: str, kind: HttpRequestKind, label: str) -> EvidenceRequest:
        return EvidenceRequest(
            evidence_type="http_redirect",
            surface_id=surface.surface_id,
            reason=f"{label} for {purpose}",
            suggested_tool=SSTI_TOOL,
            approval_ref=SSTI_APPROVAL_REF,
            http_request=HttpRequestSpec(
                method="POST",
                headers=(("Content-Type", "application/x-www-form-urlencoded"),),
                body=urlencode((("username", value),)),
                request_kind=kind,
            ),
        )

    def fetch(kind: HttpRequestKind, label: str) -> EvidenceRequest:
        return EvidenceRequest(
            evidence_type="http_response",
            surface_id=surface.surface_id,
            reason=f"{label} for {purpose}",
            suggested_tool=SSTI_TOOL,
            http_request=HttpRequestSpec(method="GET", request_kind=kind),
        )

    return (
        update(SSTI_CONTROL_VALUE, HttpRequestKind.CONTROL, "set SSTI control username"),
        fetch(HttpRequestKind.CONTROL, "fetch SSTI control rendering"),
        update(SSTI_SAFE_EXPRESSION, HttpRequestKind.SSTI_PROBE, "set fixed SSTI arithmetic probe"),
        fetch(HttpRequestKind.SSTI_PROBE, "fetch SSTI probe rendering"),
        update(SSTI_CLEANUP_VALUE, HttpRequestKind.SSTI_CLEANUP, "restore safe SSTI username"),
    )


def matching_ssti_evidence(
    evidence: Sequence[Evidence], target_url: str, request: EvidenceRequest
) -> Evidence | None:
    """POST도 포함하는 SSTI 요청을 비가역 fingerprint로 다시 연결한다."""

    if request.http_request is None:
        return None
    expected = request.request_fingerprint(target_url)
    method = request.http_request.method.upper()
    kind = request.http_request.request_kind.value
    for item in reversed(evidence):
        if (
            item.created_by.startswith("execution_runtime:")
            and item.observation.get("request_fingerprint") == expected
            and str(item.observation.get("method", "")).upper() == method
            and item.observation.get("request_kind") == kind
        ):
            return item
    return None


def ssti_execution_signal(collected: Sequence[Evidence | None]) -> bool:
    """고정 control은 문자 그대로, probe만 산술 결과로 렌더링됐는지 확인한다."""

    if len(collected) != 5 or any(item is None for item in collected):
        return False
    control_update, control_fetch, probe_update, probe_fetch, cleanup = collected
    assert control_update and control_fetch and probe_update and probe_fetch and cleanup

    update_statuses = (
        control_update.observation.get("status"),
        probe_update.observation.get("status"),
        cleanup.observation.get("status"),
    )
    if any(status not in {302, 303} for status in update_statuses):
        return False
    if control_fetch.observation.get("status") != 200 or probe_fetch.observation.get("status") != 200:
        return False
    control_body = control_fetch.observation.get("body")
    probe_body = probe_fetch.observation.get("body")
    if not isinstance(control_body, str) or not isinstance(probe_body, str):
        return False
    rendered_result = f">{SSTI_EXPECTED_RESULT}<"
    # Juice Shop은 평가 결과를 프로필 본문에 렌더링하면서, 편집용 input의 value에는
    # 저장된 원본 ``#{...}``를 그대로 남긴다. 따라서 원본 표현식이 응답 어딘가에
    # 존재한다는 이유만으로 실패 처리하면 안 된다. control에는 없던 고정 산술 결과가
    # probe의 텍스트 렌더링 위치에 생겼는지를 차등 비교한다.
    return bool(
        SSTI_CONTROL_VALUE in control_body
        and rendered_result not in control_body
        and rendered_result in probe_body
    )


def record_ssti_observation(
    *,
    task: TaskEnvelope,
    surface: Surface,
    parameter: str,
    collected: Sequence[Evidence | None],
    evidence: Sequence[Evidence],
    evidence_store: EvidenceStore,
    created_by: str,
    id_factory: Callable[[], str],
    extra: dict[str, object] | None = None,
) -> tuple[str, ...]:
    """Python이 확인한 산술 평가 사실만 공통 Observation으로 저장한다."""

    if not ssti_execution_signal(collected):
        return ()
    concrete = tuple(item for item in collected if item is not None)
    control_fetch = concrete[1]
    probe_fetch = concrete[3]
    if any(
        item.created_by == created_by
        and item.observation.get("type") == SSTI_OBSERVATION
        and item.observation.get("parameter") == parameter
        and item.observation.get("control_evidence_id") == control_fetch.evidence_id
        and item.observation.get("probe_evidence_id") == probe_fetch.evidence_id
        for item in evidence
    ):
        return ()
    observation: dict[str, object] = {
        "type": SSTI_OBSERVATION,
        "parameter": parameter,
        "engine": "pug",
        "proof_kind": "fixed_arithmetic",
        "expected_result": SSTI_EXPECTED_RESULT,
        "control_evidence_id": control_fetch.evidence_id,
        "probe_evidence_id": probe_fetch.evidence_id,
        "cleanup_evidence_id": concrete[4].evidence_id,
    }
    if extra:
        observation.update(extra)
    evidence_id = f"evi-{id_factory()}"
    evidence_store.append(
        Evidence(
            evidence_id=evidence_id,
            run_id=task.run_id,
            surface_id=surface.surface_id,
            created_by=created_by,
            evidence_type="observation",
            observation=observation,
        )
    )
    return (evidence_id,)


class HeuristicSstiAnalyzer:
    """username Surface에 고정 산술 control/probe를 요청하는 baseline Agent."""

    def __init__(
        self,
        *,
        candidate_store: CandidateStore,
        surface_store: SurfaceStore,
        evidence_store: EvidenceStore,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._candidates = candidate_store
        self._surfaces = surface_store
        self._evidence = evidence_store
        self._id_factory = id_factory or (lambda: str(uuid4()))

    def handle(self, task: TaskEnvelope) -> AgentResult:
        candidate, surface, parameters = resolve_ssti_task(
            task,
            candidate_store=self._candidates,
            surface_store=self._surfaces,
        )
        selected = heuristic_ssti_parameters(parameters)
        if "username" not in selected:
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.COMPLETED,
                candidate_ids=(candidate.candidate_id,),
            )
        requests = build_ssti_requests(
            surface,
            "username",
            purpose=f"SSTI candidate {candidate.candidate_id}",
        )
        evidence = tuple(self._evidence.get_many(task.run_id, task.evidence_ids))
        collected = tuple(
            matching_ssti_evidence(evidence, surface.url, request) for request in requests
        )
        missing = tuple(
            request for request, item in zip(requests, collected) if item is None
        )
        if missing:
            if task.request_budget < len(missing):
                raise AgentContractError("SSTI baseline lacks budget for its safe request sequence")
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
                candidate_ids=(candidate.candidate_id,),
            )
        new_ids = record_ssti_observation(
            task=task,
            surface=surface,
            parameter="username",
            collected=collected,
            evidence=evidence,
            evidence_store=self._evidence,
            created_by=HEURISTIC_SSTI_ANALYZER,
            id_factory=self._id_factory,
        )
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=new_ids,
            candidate_ids=(candidate.candidate_id,),
        )
