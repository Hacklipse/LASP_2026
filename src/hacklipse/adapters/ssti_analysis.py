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
from hacklipse.ports.errors import BudgetExceeded
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

# GET 쿼리 경로용 방언별 표현식. 산술은 POST 경로와 같은 713*17로 고정해 기대 결과가
# 한 문자열로 유지된다. #{...}만 쓰면 Jinja2·Twig·FreeMarker 계열에서는 평가 자체가
# 일어나지 않아 "취약하지 않다"와 "문법이 안 맞았다"를 구분할 수 없다.
SSTI_QUERY_PROBES = (
    ("curly", "{{713*17}}"),      # Jinja2, Twig, Liquid, Django
    ("dollar", "${713*17}"),      # FreeMarker, JSP EL, Thymeleaf
    ("hash", "#{713*17}"),        # Ruby/Slim, Pug
    ("erb", "<%=713*17%>"),       # ERB, EJS
)
# 쿼리 probe가 보낼 수 있는 값 전체. 안전 검증기가 이 집합 밖의 값을 거부한다.
SSTI_PROBE_EXPRESSIONS = frozenset(
    expression for _, expression in SSTI_QUERY_PROBES
)
SSTI_QUERY_VALUES = frozenset({SSTI_CONTROL_VALUE, *SSTI_PROBE_EXPRESSIONS})
# POST 폼 경로에서 한 요청이 실을 수 있는 필드 수 상한.
_MAX_SSTI_FORM_FIELDS = 16
# 템플릿 식을 여는 두 글자. 탐침이 아닌 필드로 템플릿 문법이 흘러드는 것을 막는다.
# 한 글자(`#`, `$`)로 막으면 관측된 정상 값까지 거부해 폼이 성립하지 않는다.
_TEMPLATE_OPENERS = ("{{", "${", "#{", "<%")


def validate_ssti_request(request: ExecutionRequest) -> None:
    """전용 SSTI 도구를 Juice Shop형 안전 산술 검증 계약으로 제한한다."""

    if request.tool != SSTI_TOOL:
        raise ValueError("SSTI request must use its dedicated tool")

    if request.query_parameters:
        # GET 쿼리 읽기 경로. POST /profile 계약과 달리 엔드포인트를 제한하지 않는
        # 대신, 상태를 바꿀 수 없는 모양으로만 좁힌다 — 단일 쿼리 좌표, 고정된 값
        # 집합, 본문·헤더·승인참조 없음. username만 허용한 이유는 프로필 필드에
        # 쓰기 때문이고, 읽기 요청에는 그 위험이 없다.
        if request.method.upper() != "GET":
            raise ValueError("SSTI query probe must be a GET")
        if request.body is not None or request.headers:
            raise ValueError("SSTI query probe must carry no body or headers")
        # approval_ref는 검사하지 않는다. 수집 경계가 Run 기본 승인 참조를 채워 넣을 수
        # 있고(execution.py의 _default_approval_ref), 읽기 요청에 참조가 붙어 있다는
        # 사실 자체는 해롭지 않다. 읽기임을 보장하는 것은 아래 좌표·값 제약이다.
        if len(request.query_parameters) != 1:
            raise ValueError("SSTI query probe sets exactly one coordinate")
        if request.query_parameters[0][1] not in SSTI_QUERY_VALUES:
            raise ValueError("SSTI query probe may only send its fixed safe values")
        if request.request_kind not in {
            HttpRequestKind.CONTROL,
            HttpRequestKind.SSTI_PROBE,
        }:
            raise ValueError("SSTI query probe has an invalid request kind")
        return

    if request.form_parameters:
        # 상태 없이 즉시 렌더링하는 POST 폼 경로. /profile 계약과 달리 대상의 저장
        # 상태를 바꾸지 않으므로 설정·정리 시퀀스가 없고 엔드포인트도 제한하지 않는
        # 대신, "바꾸는 좌표는 하나, 그 값은 고정 집합" 으로만 좁힌다. 나머지 필드는
        # 폼이 성립하는 데 필요한 관측된 값이므로 그대로 두되 템플릿 문법은 막는다.
        if request.method.upper() != "POST":
            raise ValueError("SSTI form probe must be a POST")
        if request.body is not None or request.headers:
            raise ValueError("SSTI form probe must carry no raw body or headers")
        if request.query_parameters:
            raise ValueError("SSTI form probe sets no query coordinate")
        if request.request_kind not in {
            HttpRequestKind.CONTROL,
            HttpRequestKind.SSTI_PROBE,
        }:
            raise ValueError("SSTI form probe has an invalid request kind")
        if len(request.form_parameters) > _MAX_SSTI_FORM_FIELDS:
            raise ValueError("SSTI form probe sends a bounded number of fields")
        expressions = tuple(
            value for _, value in request.form_parameters
            if value in SSTI_PROBE_EXPRESSIONS
        )
        if request.request_kind is HttpRequestKind.CONTROL:
            if expressions:
                raise ValueError("SSTI form control cannot carry a probe expression")
        elif len(expressions) != 1:
            raise ValueError(
                "SSTI form probe sets exactly one coordinate to a fixed expression"
            )
        if any(
            opener in value
            for _, value in request.form_parameters
            if value not in SSTI_QUERY_VALUES
            for opener in _TEMPLATE_OPENERS
        ):
            raise ValueError("SSTI form probe may not carry template syntax in other fields")
        return

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
    if surface.method.upper() not in {"POST", "GET"} or not surface.parameters:
        raise AgentContractError(
            "SSTI analysis requires a parameterized GET or POST surface"
        )
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


def build_ssti_query_requests(
    surface: Surface,
    parameter: str,
    *,
    purpose: str,
) -> tuple[EvidenceRequest, ...]:
    """GET 쿼리 한 좌표에 control 1회와 방언별 probe를 요청한다.

    POST 경로의 5요청 시퀀스(설정·조회·설정·조회·정리)를 쓰지 않는다. GET은 상태를
    남기지 않으므로 설정과 정리가 필요 없고, 대신 템플릿 방언마다 표현식이 달라
    probe를 방언 수만큼 보낸다.
    """

    if parameter not in surface.parameters:
        raise AgentContractError("SSTI parameter must belong to the surface")

    def fetch(value: str, kind: HttpRequestKind, label: str) -> EvidenceRequest:
        return EvidenceRequest(
            evidence_type="http_response",
            surface_id=surface.surface_id,
            reason=f"{label} for {purpose}",
            suggested_tool=SSTI_TOOL,
            http_request=HttpRequestSpec(
                method="GET",
                query_parameters=((parameter, value),),
                request_kind=kind,
            ),
        )

    requests = [
        fetch(SSTI_CONTROL_VALUE, HttpRequestKind.CONTROL, "fetch SSTI query control")
    ]
    requests.extend(
        fetch(
            expression,
            HttpRequestKind.SSTI_PROBE,
            f"fetch SSTI {dialect} arithmetic probe",
        )
        for dialect, expression in SSTI_QUERY_PROBES
    )
    return tuple(requests)


def build_ssti_form_requests(
    surface: Surface,
    parameter: str,
    *,
    purpose: str,
) -> tuple[EvidenceRequest, ...]:
    """상태 없이 즉시 렌더링하는 POST 폼 한 좌표에 control과 방언별 probe를 요청한다.

    /profile 계약의 5요청 시퀀스(설정·조회·설정·조회·정리)를 쓰지 않는다. 그 경로는
    대상의 저장된 프로필을 바꾸므로 정리가 필요하지만, 여기서 보낸 값은 그 응답에만
    렌더링되므로 GET 쿼리 경로와 같은 control 1회 + 방언별 probe로 충분하다.

    바꾸는 좌표는 하나다. 나머지 필드는 관측된 값을 그대로 싣는다 — 버튼 이름이나
    고정 필드가 빠지면 분기 자체에 닿지 못하는 폼이 흔하다.
    """

    if parameter not in surface.parameters:
        raise AgentContractError("SSTI parameter must belong to the surface")
    if surface.method.upper() != "POST":
        raise AgentContractError("SSTI form probe needs a POST surface")
    observed = dict(surface.observed_query)

    def send(value: str, kind: HttpRequestKind, label: str) -> EvidenceRequest:
        return EvidenceRequest(
            evidence_type="http_response",
            surface_id=surface.surface_id,
            reason=f"{label} for {purpose}",
            suggested_tool=SSTI_TOOL,
            http_request=HttpRequestSpec(
                method="POST",
                form_parameters=tuple(
                    (
                        name,
                        value if name == parameter
                        else observed.get(name) or SSTI_CONTROL_VALUE,
                    )
                    for name in surface.parameters
                ),
                request_kind=kind,
            ),
        )

    requests = [
        send(SSTI_CONTROL_VALUE, HttpRequestKind.CONTROL, "send SSTI form control")
    ]
    requests.extend(
        send(
            expression,
            HttpRequestKind.SSTI_PROBE,
            f"send SSTI {dialect} arithmetic probe",
        )
        for dialect, expression in SSTI_QUERY_PROBES
    )
    return tuple(requests)


def ssti_query_execution_signal(
    collected: Sequence[Evidence | None],
) -> str | None:
    """평가가 일어난 방언 이름을 돌려준다. 없으면 None.

    반사만으로는 통과할 수 없다. 반사하는 엔드포인트는 control에서 control 값을
    그대로 되돌려주고 probe에서는 표현식 원문을 되돌려줄 뿐, 고정 산술 결과는
    평가가 실제로 일어나지 않으면 나타나지 않는다. 그래서 control이 입력을 되돌려
    준다는 사실을 먼저 요구하고(엔드포인트가 입력으로 답한다는 증명), 그 control에
    결과가 없고 probe에만 있을 때만 참으로 본다.
    """

    if len(collected) != len(SSTI_QUERY_PROBES) + 1:
        return None
    control, *probes = collected
    if control is None or control.observation.get("status") != 200:
        return None
    control_body = control.observation.get("body")
    if not isinstance(control_body, str):
        return None
    if SSTI_CONTROL_VALUE not in control_body:
        return None  # 입력을 되돌려주지 않는 좌표 — 차등 비교의 전제가 없다
    if SSTI_EXPECTED_RESULT in control_body:
        return None  # 결과 문자열이 입력과 무관하게 이미 존재한다

    for (dialect, _expression), probe in zip(SSTI_QUERY_PROBES, probes):
        if probe is None or probe.observation.get("status") != 200:
            continue
        probe_body = probe.observation.get("body")
        if isinstance(probe_body, str) and SSTI_EXPECTED_RESULT in probe_body:
            return dialect
    return None


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


def record_ssti_query_observation(
    *,
    task: TaskEnvelope,
    surface: Surface,
    parameter: str,
    dialect: str,
    collected: Sequence[Evidence | None],
    evidence: Sequence[Evidence],
    evidence_store: EvidenceStore,
    created_by: str,
    id_factory: Callable[[], str],
    extra: dict[str, object] | None = None,
) -> tuple[str, ...]:
    """상태를 남기지 않는 경로가 확인한 산술 평가 사실을 공통 Observation으로 저장한다."""

    control = collected[0]
    probe_index = next(
        index
        for index, (name, _expression) in enumerate(SSTI_QUERY_PROBES, start=1)
        if name == dialect
    )
    probe = collected[probe_index]
    if control is None or probe is None:
        return ()
    if any(
        item.created_by == created_by
        and item.observation.get("type") == SSTI_OBSERVATION
        and item.observation.get("parameter") == parameter
        and item.observation.get("control_evidence_id") == control.evidence_id
        and item.observation.get("probe_evidence_id") == probe.evidence_id
        for item in evidence
    ):
        return ()
    evidence_id = f"evi-{id_factory()}"
    evidence_store.append(
        Evidence(
            evidence_id=evidence_id,
            run_id=task.run_id,
            surface_id=surface.surface_id,
            created_by=created_by,
            evidence_type="observation",
            observation={
                "type": SSTI_OBSERVATION,
                "parameter": parameter,
                "engine": dialect,
                "proof_kind": "fixed_arithmetic",
                "expected_result": SSTI_EXPECTED_RESULT,
                "control_evidence_id": control.evidence_id,
                "probe_evidence_id": probe.evidence_id,
                **(extra or {}),
            },
        )
    )
    return (evidence_id,)


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


def handle_stateless_ssti_surface(
    *,
    task: TaskEnvelope,
    candidate: Candidate,
    surface: Surface,
    selected: Sequence[str],
    build: Callable[..., tuple[EvidenceRequest, ...]],
    evidence: Sequence[Evidence],
    evidence_store: EvidenceStore,
    created_by: str,
    id_factory: Callable[[], str],
    new_evidence_ids: Sequence[str] = (),
    extra: dict[str, object] | None = None,
) -> AgentResult:
    """상태를 남기지 않는 좌표의 공통 분석 흐름.

    heuristic과 LLM 구현이 같은 함수를 쓴다. 두 구현이 각자 이 흐름을 들고 있으면
    한쪽에만 경로가 생기고 다른 쪽은 조용히 신호를 만들지 못한다 — SSTI에서 이미
    그렇게 갈라졌다. 요청 모양만 build가, 선택 근거만 extra가 결정한다.
    """

    if not selected:
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=tuple(new_evidence_ids),
            candidate_ids=(candidate.candidate_id,),
        )
    parameter = selected[0]
    requests = build(
        surface, parameter, purpose=f"SSTI candidate {candidate.candidate_id}",
    )
    collected = tuple(
        matching_ssti_evidence(evidence, surface.url, request) for request in requests
    )
    missing = tuple(
        request for request, item in zip(requests, collected) if item is None
    )
    if missing:
        if task.request_budget < len(missing):
            raise BudgetExceeded("SSTI stateless probe lacks budget for its request set")
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.NEEDS_EVIDENCE,
            evidence_requests=missing,
            new_evidence_ids=tuple(new_evidence_ids),
            candidate_ids=(candidate.candidate_id,),
        )
    dialect = ssti_query_execution_signal(collected)
    recorded = (
        record_ssti_query_observation(
            task=task,
            surface=surface,
            parameter=parameter,
            dialect=dialect,
            collected=collected,
            evidence=evidence,
            evidence_store=evidence_store,
            created_by=created_by,
            id_factory=id_factory,
            extra=extra,
        )
        if dialect
        else ()
    )
    return AgentResult(
        task_id=task.task_id,
        status=AgentResultStatus.COMPLETED,
        new_evidence_ids=(*new_evidence_ids, *recorded),
        candidate_ids=(candidate.candidate_id,),
    )


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

    def _handle_form_surface(
        self,
        task: TaskEnvelope,
        candidate: Candidate,
        surface: Surface,
        selected: Sequence[str],
    ) -> AgentResult:
        """상태를 남기지 않는 POST 폼 좌표를 방언별 고정 산술로 확인한다."""

        return self._handle_stateless_surface(
            task, candidate, surface, selected, build_ssti_form_requests,
        )

    def _handle_query_surface(
        self,
        task: TaskEnvelope,
        candidate: Candidate,
        surface: Surface,
        selected: Sequence[str],
    ) -> AgentResult:
        """GET 쿼리 좌표를 방언별 고정 산술로 확인한다."""

        return self._handle_stateless_surface(
            task, candidate, surface, selected, build_ssti_query_requests,
        )

    def _handle_stateless_surface(
        self,
        task: TaskEnvelope,
        candidate: Candidate,
        surface: Surface,
        selected: Sequence[str],
        build: Callable[..., tuple[EvidenceRequest, ...]],
    ) -> AgentResult:
        return handle_stateless_ssti_surface(
            task=task,
            candidate=candidate,
            surface=surface,
            selected=selected,
            build=build,
            evidence=tuple(self._evidence.get_many(task.run_id, task.evidence_ids)),
            evidence_store=self._evidence,
            created_by=HEURISTIC_SSTI_ANALYZER,
            id_factory=self._id_factory,
        )

    def handle(self, task: TaskEnvelope) -> AgentResult:
        candidate, surface, parameters = resolve_ssti_task(
            task,
            candidate_store=self._candidates,
            surface_store=self._surfaces,
        )
        selected = heuristic_ssti_parameters(parameters)
        if surface.method.upper() == "GET":
            return self._handle_query_surface(task, candidate, surface, selected)
        if "username" not in selected:
            # username이 아니면 /profile 저장 계약을 쓸 수 없다. 그래도 보낸 값을 그
            # 응답에 바로 렌더링하는 폼이면 상태를 남기지 않는 경로로 확인할 수 있다.
            return self._handle_form_surface(task, candidate, surface, selected)
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
                raise BudgetExceeded("SSTI baseline lacks budget for its safe request sequence")
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
