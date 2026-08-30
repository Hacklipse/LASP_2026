"""control/probe 대조 탐침의 공용 부품.

XSS와 SQLi는 신호가 다르지만 절차는 같다 — 기준선 요청 하나를 보내고, 파라미터마다
하나씩만 값을 바꾼 탐침을 보내고, 두 응답의 차이만 신호로 인정한다. control 대조가
오탐을 막는 장치다: 대상이 원래 갖고 있던 내용을 탐침 결과로 오인하지 않는다.

여기 있는 함수를 모든 Analyzer가 공유해야 결과를 같은 축에서 비교할 수 있다. 값의
형태는 도메인(`HttpRequestSpec`)이 PROBE 요청에 대해 강제하므로, 이 모듈을 우회해
임의 페이로드를 만들어도 Runtime에 도달하지 못한다.
"""

from __future__ import annotations

from collections.abc import Sequence
from urllib.parse import urlencode, urlsplit, urlunsplit

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import (
    Candidate,
    Evidence,
    EvidenceRequest,
    HttpRequestKind,
    HttpRequestSpec,
    Surface,
    TaskEnvelope,
)
from hacklipse.ports import CandidateStore, SurfaceStore

ANALYSIS_TOOL = "http_get"
CONTROL_VALUE = "hacklipse-control"

# marker 안에서 허용하는 숫자 연속 길이. Evidence는 저장 전에 PII 마스킹을 거치는데,
# 긴 숫자열은 전화번호·주민번호 패턴에 우연히 걸려 marker가 삭제될 수 있다. 그러면
# 신호를 놓치고 "취약하지 않음"으로 보고하게 된다 — 보안 도구에서 가장 위험한 실패다.
# 마스킹 규칙이 앞으로 늘어나도 안전하도록, 확률이 아니라 구조로 막는다.
_MARKER_CHUNK = 4
_MARKER_SEPARATOR = "z"


def probe_marker(raw: str, *, prefix: str = "hacklipse") -> str:
    """마스킹 규칙에 걸리지 않는 고유 marker를 만든다.

    영숫자만 남기고 4자마다 문자를 끼워 숫자 연속을 끊는다. 페이로드가 아니라
    우연히 나올 리 없는 무해한 식별자다.
    """

    compact = "".join(char for char in raw if char.isalnum())
    if not compact:
        raise AgentContractError("probe marker source produced no usable characters")
    chunks = [
        compact[index : index + _MARKER_CHUNK]
        for index in range(0, len(compact), _MARKER_CHUNK)
    ]
    return prefix + _MARKER_SEPARATOR.join(chunks)


def resolve_analysis_task(
    task: TaskEnvelope,
    *,
    vulnerability_type: str,
    candidate_store: CandidateStore,
    surface_store: SurfaceStore,
) -> tuple[Candidate, Surface, tuple[str, ...]]:
    """Analysis Task의 Candidate/Surface를 확인하고 탐침 대상 파라미터를 정리한다.

    Task가 지시한 target_url과 Store에 저장된 Surface가 다르면 거부한다 — Task를 통해
    다른 대상으로 요청을 유도하는 경로를 막는다.
    """

    if task.candidate_id is None or task.surface_id is None or task.target_url is None:
        raise AgentContractError("analysis task is missing candidate or surface context")
    if ANALYSIS_TOOL not in task.allowed_tools:
        raise AgentContractError("analysis HTTP tool is not allowed by the task")

    candidate = candidate_store.get(task.run_id, task.candidate_id)
    if candidate.vulnerability_type != vulnerability_type:
        raise AgentContractError(
            f"{vulnerability_type} analyzer received a {candidate.vulnerability_type} candidate"
        )
    if candidate.surface_id != task.surface_id:
        raise AgentContractError("candidate and task reference different surfaces")

    surface = surface_store.get(task.run_id, task.surface_id)
    if surface.url != task.target_url:
        raise AgentContractError("analysis task target does not match its surface")
    if surface.method.upper() != "GET" or not surface.parameters:
        raise AgentContractError("analysis supports parameterized GET surfaces only")

    # 중복 파라미터명(?a=1&a=2)은 하나로 접는다. 안 그러면 같은 곳에 탐침을 두 번 보낸다.
    return candidate, surface, tuple(dict.fromkeys(surface.parameters))


def build_probe_requests(
    surface: Surface,
    parameters: Sequence[str],
    *,
    control_value: str,
    probe_value: str,
    purpose: str,
) -> tuple[EvidenceRequest, ...]:
    """control 1개 + 파라미터별 probe N개를 만든다.

    파라미터마다 하나씩만 값을 바꾼다. 전부 동시에 바꾸면 어느 파라미터가 신호를
    만들었는지 구분할 수 없다. 값은 호출자가 넘긴 두 개로 고정되며, 그 형태는
    도메인이 PROBE 요청에 대해 검증한다.
    """

    if not parameters:
        raise AgentContractError("probe plan must name at least one parameter")

    requests = [
        _request(
            surface.surface_id,
            tuple((name, control_value) for name in parameters),
            HttpRequestKind.CONTROL,
            reason=f"control request for {purpose}",
        )
    ]
    for parameter in parameters:
        requests.append(
            _request(
                surface.surface_id,
                tuple(
                    (name, probe_value if name == parameter else control_value)
                    for name in parameters
                ),
                HttpRequestKind.PROBE,
                reason=f"probe for parameter {parameter} on {purpose}",
            )
        )
    return tuple(requests)


def _request(
    surface_id: str,
    query_parameters: tuple[tuple[str, str], ...],
    request_kind: HttpRequestKind,
    *,
    reason: str,
) -> EvidenceRequest:
    return EvidenceRequest(
        evidence_type="http_response",
        surface_id=surface_id,
        reason=reason,
        suggested_tool=ANALYSIS_TOOL,
        http_request=HttpRequestSpec(
            method="GET",
            query_parameters=query_parameters,
            request_kind=request_kind,
        ),
    )


def matching_evidence(
    evidence: Sequence[Evidence], target_url: str, request: EvidenceRequest
) -> Evidence | None:
    """자신이 요청한 명세와 일치하는 중앙 수집 Evidence를 최신 것부터 찾는다."""

    if request.http_request is None:
        return None
    expected_url = resolved_url(target_url, request.http_request.query_parameters)
    expected_kind = request.http_request.request_kind.value
    for item in reversed(evidence):
        observation = item.observation
        if (
            item.created_by.startswith("execution_runtime:")
            and observation.get("requested_url") == expected_url
            and observation.get("request_kind") == expected_kind
            and str(observation.get("method", "GET")).upper() == "GET"
        ):
            return item
    return None


def resolved_url(
    target_url: str, query_parameters: tuple[tuple[str, str], ...]
) -> str:
    """기존 query를 보존하면서 구조화 파라미터를 인코딩한 실제 요청 URL."""

    parsed = urlsplit(target_url)
    encoded = urlencode(query_parameters)
    query = parsed.query
    if encoded:
        query = f"{query}&{encoded}" if query else encoded
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def response_body(evidence: Evidence) -> str | None:
    body = evidence.observation.get("body")
    return body if isinstance(body, str) else None


def has_observation_record(
    evidence: Sequence[Evidence],
    created_by: str,
    observation_type: str,
    parameter: str,
    control_evidence_id: str,
    probe_evidence_id: str,
) -> bool:
    """같은 근거 조합의 Observation이 이미 있는지 확인한다(재개 시 중복 방지)."""

    return any(
        item.created_by == created_by
        and item.observation.get("type") == observation_type
        and item.observation.get("parameter") == parameter
        and item.observation.get("control_evidence_id") == control_evidence_id
        and item.observation.get("probe_evidence_id") == probe_evidence_id
        for item in evidence
    )


def marker_reflected(
    control_body: str | None, probe_body: str | None, marker: str
) -> bool:
    """marker가 control에는 없고 probe에는 있을 때만 반사로 인정한다.

    control 비교가 오탐을 막는다 — 페이지가 원래부터 그 문자열을 갖고 있으면
    probe만 봐서는 반사인지 구분할 수 없다.
    """

    return bool(
        probe_body is not None
        and marker in probe_body
        and (control_body is None or marker not in control_body)
    )
