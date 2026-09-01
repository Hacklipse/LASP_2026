"""LLM 없이 객체 단위 권한 우회 신호를 수집하는 Access Control baseline Agent.

방식 — 서로 다른 두 인증 주체로 같은 객체를 요청하고 응답을 대조한다.

    A. actor self    ACTOR 세션 + actor 객체    "정상 접근은 어떻게 보이는가"
    B. owner control OWNER 세션 + owner 객체    "그 객체가 실제로 존재하고 주인은 볼 수 있는가"
    C. unauthorized  ACTOR 세션 + owner 객체    "남의 객체가 보이는가"

C 하나만으로는 판정할 수 없다. 객체가 아예 없어도, 로그인이 풀려도, 오류 페이지가 떠도
"뭔가 응답이 왔다"는 점은 같기 때문이다. A와 B가 있어야 "정상 접근이 어떤 모양인지"와
"그 객체가 실재하는지"를 각각 고정할 수 있고, 그때 비로소 C의 의미가 정해진다.

Agent는 자격증명을 고르지 않는다. `principal_role`로 역할만 지정하고, 역할에서
credential_ref로의 해석은 중앙 Collector가 Run에 등록된 매핑으로만 수행한다. 따라서
이 Agent도 LLM도 username·password·Cookie·Authorization을 알 수 없다.

여기서 만드는 것은 "actor 세션에서 owner 객체가 노출됐다"는 관찰이지 취약점 판정이
아니다. 확정은 독립 Validation이 자체 세션에서 세 요청을 다시 수행해야 가능하다.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from uuid import uuid4

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import (
    AccessPrincipalRole,
    AgentResult,
    AgentResultStatus,
    Evidence,
    EvidenceRequest,
    HttpRequestKind,
    HttpRequestSpec,
    Surface,
    TaskEnvelope,
)
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore

from .probing import matching_evidence, resolve_analysis_task, response_body
from .request_safety import object_identifier_parameters

ACCESS_CONTROL_TOOL = "access_control_probe"
HEURISTIC_ACCESS_CONTROL_ANALYZER = "heuristic_access_control_analyzer"

_OBSERVATION_TYPE = "object_id_auth"

# 접근이 거부됐거나 세션이 끊겼음을 나타내는 문구. 이런 응답을 정상 객체 접근으로
# 오인하면 안전한 대상을 취약하다고 보고하게 된다.
_DENIAL_MARKERS = (
    "access denied",
    "not authorised",
    "not authorized",
    "unauthorized",
    "permission denied",
    "forbidden",
    "please log in",
    "login failed",
    "sign in to continue",
)

# 로그인 페이지로 돌아왔는지 판별하는 신호. 200으로 로그인 폼을 돌려주는 앱이 많다.
_LOGIN_MARKERS = ("name=\"password\"", "name='password'", "type=\"password\"", "type='password'")

_OBJECT_ID = re.compile(r"^[0-9]{1,10}$")


class HeuristicAccessControlAnalyzer:
    """세 요청의 대조로 객체 권한 우회 신호를 결정적으로 판정하는 Analysis Agent.

    외부 요청은 직접 실행하지 않고 EvidenceRequest로 Orchestrator에 반환한다.
    """

    def __init__(
        self,
        *,
        candidate_store: CandidateStore,
        surface_store: SurfaceStore,
        evidence_store: EvidenceStore,
        actor_object_id: str | None = None,
        owner_object_id: str | None = None,
        identifier_selector: Callable[[Sequence[str]], str | None] | None = None,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._candidates = candidate_store
        self._surfaces = surface_store
        self._evidence = evidence_store
        self._actor_object_id = actor_object_id
        self._owner_object_id = owner_object_id
        # 식별자 선택만 교체 가능하다. LLM 구성은 여기만 바꾸고 요청 조립·판정은 공유한다.
        self._select_identifier = identifier_selector or _first_identifier
        self._id_factory = id_factory or (lambda: str(uuid4()))

    def handle(self, task: TaskEnvelope) -> AgentResult:
        """필요한 요청은 중앙 수집으로 반환하고, 수집 뒤 노출 여부를 판정한다."""

        candidate, surface, parameters = resolve_analysis_task(
            task,
            vulnerability_type="Access Control",
            candidate_store=self._candidates,
            surface_store=self._surfaces,
            required_tool=ACCESS_CONTROL_TOOL,
        )
        identifier = self._select_identifier(parameters)
        if identifier is None:
            # 객체 식별자가 없으면 권한 우회를 판정할 수 없다. 조용히 통과시키지 않고
            # 요청도 쓰지 않은 채 끝낸다.
            return self._completed(task, candidate.candidate_id, ())

        actor_id, owner_id = self._object_ids()
        if actor_id is None or owner_id is None or actor_id == owner_id:
            # 두 주체의 객체가 지정되지 않았거나 같으면 대조가 성립하지 않는다.
            return self._completed(task, candidate.candidate_id, ())

        requests = build_access_control_requests(
            surface, identifier, actor_object_id=actor_id, owner_object_id=owner_id,
            purpose=f"Access Control candidate {candidate.candidate_id}",
        )
        evidence = tuple(self._evidence.get_many(task.run_id, task.evidence_ids))
        collected = tuple(
            matching_evidence(evidence, surface.url, request) for request in requests
        )
        missing = tuple(
            request for request, item in zip(requests, collected) if item is None
        )
        if missing:
            if task.request_budget < len(missing):
                raise AgentContractError(
                    "access control baseline lacks budget for its remaining requests"
                )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
                candidate_ids=(candidate.candidate_id,),
            )

        actor_control, owner_control, probe = collected
        if actor_control is None or owner_control is None or probe is None:
            raise AgentContractError("access control evidence was not collected")

        if not unauthorized_object_exposed(owner_control, probe, owner_id):
            return self._completed(task, candidate.candidate_id, ())
        if _has_record(evidence, identifier, actor_control, owner_control, probe):
            return self._completed(task, candidate.candidate_id, ())

        observation_id = f"evi-{self._id_factory()}"
        self._evidence.append(
            Evidence(
                evidence_id=observation_id,
                run_id=task.run_id,
                surface_id=surface.surface_id,
                created_by=HEURISTIC_ACCESS_CONTROL_ANALYZER,
                evidence_type="observation",
                observation={
                    # Router.DEFAULT_RULES의 "object_id_auth" 규칙과 맞는 유형이어야 한다.
                    "type": _OBSERVATION_TYPE,
                    "identifier_parameter": identifier,
                    "actor_object_id": actor_id,
                    "owner_object_id": owner_id,
                    "actor_control_evidence_id": actor_control.evidence_id,
                    "owner_control_evidence_id": owner_control.evidence_id,
                    "probe_evidence_id": probe.evidence_id,
                    "signal": "unauthorized_owner_object_exposed",
                },
            )
        )
        return self._completed(task, candidate.candidate_id, (observation_id,))

    def _object_ids(self) -> tuple[str | None, str | None]:
        for value in (self._actor_object_id, self._owner_object_id):
            if value is not None and _OBJECT_ID.fullmatch(value) is None:
                raise AgentContractError(f"access control object id must be numeric: {value!r}")
        return self._actor_object_id, self._owner_object_id

    @staticmethod
    def _completed(
        task: TaskEnvelope, candidate_id: str, evidence_ids: tuple[str, ...]
    ) -> AgentResult:
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=evidence_ids,
            candidate_ids=(candidate_id,),
        )


def _first_identifier(parameters: Sequence[str]) -> str | None:
    """이름 규칙으로 객체 식별자를 고르는 기본 선택자."""

    candidates = object_identifier_parameters(parameters)
    return candidates[0] if candidates else None


def build_access_control_requests(
    surface: Surface,
    identifier: str,
    *,
    actor_object_id: str,
    owner_object_id: str,
    purpose: str,
) -> tuple[EvidenceRequest, ...]:
    """actor self / owner control / unauthorized probe 세 요청을 만든다.

    식별자 파라미터 값만 바꾸고 나머지 query는 Recon이 관측한 원본을 그대로 보존한다.
    값이 바뀌는 자리를 하나로 묶어야 응답 차이의 원인이 권한 하나로 좁혀진다.
    """

    plans = (
        (AccessPrincipalRole.ACTOR, actor_object_id, "actor self control"),
        (AccessPrincipalRole.OWNER, owner_object_id, "owner control"),
        (AccessPrincipalRole.ACTOR, owner_object_id, "unauthorized owner object probe"),
    )
    return tuple(
        EvidenceRequest(
            evidence_type="http_response",
            surface_id=surface.surface_id,
            reason=f"{label} for {purpose}",
            suggested_tool=ACCESS_CONTROL_TOOL,
            principal_role=role,
            http_request=HttpRequestSpec(
                method="GET",
                query_parameters=_query_for(surface, identifier, object_id),
                request_kind=HttpRequestKind.ACCESS_CONTROL_PROBE,
                identifier_parameter=identifier,
            ),
        )
        for role, object_id, label in plans
    )


def _query_for(
    surface: Surface, identifier: str, object_id: str
) -> tuple[tuple[str, str], ...]:
    """식별자만 교체하고 나머지 파라미터는 관측된 원본 값을 유지한다."""

    observed = dict(surface.observed_query)
    return tuple(
        (name, object_id if name == identifier else observed.get(name, ""))
        for name in dict.fromkeys(surface.parameters)
    )


def unauthorized_object_exposed(
    owner_control: Evidence, probe: Evidence, owner_object_id: str
) -> bool:
    """owner 객체가 actor 세션 응답에서도 확인되는지 판정한다.

    본문 전체 해시나 길이 비교는 쓰지 않는다. 로그인 페이지와 프로필 페이지가 우연히
    비슷한 길이일 수 있고, 페이지에 시각이나 토큰이 섞이면 해시는 매번 달라진다.
    대신 "그 객체를 가리키는 안정적인 구조 신호"가 양쪽에 함께 있는지를 본다.
    """

    owner_body = response_body(owner_control)
    probe_body = response_body(probe)
    if owner_body is None or probe_body is None:
        return False
    # owner가 자기 객체를 못 봤다면 그 객체가 실재하는지 자체가 불확실하다.
    if not _shows_object(owner_control, owner_body, owner_object_id):
        return False
    return _shows_object(probe, probe_body, owner_object_id)


def _shows_object(evidence: Evidence, body: str, object_id: str) -> bool:
    """응답이 해당 객체를 실제로 보여주는지 확인한다."""

    status = evidence.observation.get("status")
    if isinstance(status, int) and status >= 400:
        return False
    if evidence.observation.get("type") in ("http_error", "http_redirect"):
        return False
    lowered = body.casefold()
    if any(marker in lowered for marker in _DENIAL_MARKERS):
        return False
    if any(marker.casefold() in lowered for marker in _LOGIN_MARKERS):
        return False
    return _object_signal(lowered, object_id)


def _object_signal(lowered_body: str, object_id: str) -> bool:
    """객체 식별자가 내용으로 표시됐는지 확인한다.

    쿼리 문자열에 그 값이 있었다는 사실만으로는 부족하다 — 요청에 넣었으니 당연히
    페이지 어딘가에 남을 수 있다. 필드 이름과 함께 나타난 경우만 인정한다.
    """

    patterns = (
        rf"user\s*id\s*[:=]?\s*{re.escape(object_id)}\b",
        rf"\bid\s*[:=]\s*{re.escape(object_id)}\b",
        rf'name="user_?id"[^>]*value="{re.escape(object_id)}"',
    )
    return any(re.search(pattern, lowered_body) for pattern in patterns)


def _has_record(
    evidence: Sequence[Evidence],
    identifier: str,
    actor_control: Evidence,
    owner_control: Evidence,
    probe: Evidence,
) -> bool:
    """같은 근거 조합의 Observation이 이미 있는지 확인한다(재개 시 중복 방지)."""

    return any(
        item.created_by == HEURISTIC_ACCESS_CONTROL_ANALYZER
        and item.observation.get("type") == _OBSERVATION_TYPE
        and item.observation.get("identifier_parameter") == identifier
        and item.observation.get("actor_control_evidence_id") == actor_control.evidence_id
        and item.observation.get("owner_control_evidence_id") == owner_control.evidence_id
        and item.observation.get("probe_evidence_id") == probe.evidence_id
        for item in evidence
    )


def validate_access_control_request(request) -> None:
    """Runtime 직전 마지막 관문. 도메인 검증과 같은 규칙을 실행 경계에서 다시 본다.

    Agent가 EvidenceRequest를 만드는 경로를 우회해 ExecutionRequest를 직접 만들어도
    같은 제약을 받게 한다. 표면이 넓어지는 방향의 변경은 두 곳을 모두 고쳐야 한다.
    """

    if request.method.upper() != "GET":
        raise ValueError("access control probe must be a GET request")
    if request.headers:
        raise ValueError("access control probe cannot set request headers")
    if request.body is not None:
        raise ValueError("access control probe cannot carry a body")
    if request.request_kind is not HttpRequestKind.ACCESS_CONTROL_PROBE:
        raise ValueError("access control tool requires an access control probe kind")
    identifier = request.identifier_parameter
    if not identifier:
        raise ValueError("access control probe must name its identifier parameter")
    names = [name for name, _ in request.query_parameters]
    if names.count(identifier) != 1:
        raise ValueError("access control identifier must appear exactly once")
    for name, value in request.query_parameters:
        if name == identifier and _OBJECT_ID.fullmatch(value) is None:
            raise ValueError(f"access control object id must be numeric: {value!r}")
