"""LLM 없이 고정 규칙으로 reflected-input 신호를 수집하는 XSS baseline Agent.

여기 있는 모듈 함수(`resolve_xss_task`, `build_probe_requests`, `matching_evidence`,
`marker_reflected`)는 LLM 구현과 공유한다. 두 구현이 같은 사전 조건·같은 요청 형태·
같은 반사 판정을 써야 동일 Surface에서의 결과를 비교할 수 있다(연구 대조군 요건).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from urllib.parse import urlencode, urlsplit, urlunsplit
from uuid import uuid4

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Candidate,
    Evidence,
    EvidenceRequest,
    HttpRequestKind,
    HttpRequestSpec,
    Surface,
    TaskEnvelope,
)
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore

XSS_ANALYSIS_TOOL = "http_get"
CONTROL_VALUE = "hacklipse-control"
_REFLECTION_MARKER = "hacklipse7331"

HEURISTIC_XSS_ANALYZER = "heuristic_xss_analyzer"


def resolve_xss_task(
    task: TaskEnvelope,
    *,
    candidate_store: CandidateStore,
    surface_store: SurfaceStore,
) -> tuple[Candidate, Surface, tuple[str, ...]]:
    """XSS Analysis Task의 Candidate/Surface를 확인하고 탐침 대상 파라미터를 정리한다.

    Task가 지시한 target_url과 Store에 저장된 Surface가 다르면 거부한다 — Task를 통해
    다른 대상으로 요청을 유도하는 경로를 막는다.
    """

    if task.candidate_id is None or task.surface_id is None or task.target_url is None:
        raise AgentContractError("xss analysis task is missing candidate or surface context")
    if XSS_ANALYSIS_TOOL not in task.allowed_tools:
        raise AgentContractError("xss analysis HTTP tool is not allowed by the task")

    candidate = candidate_store.get(task.run_id, task.candidate_id)
    if candidate.vulnerability_type != "XSS":
        raise AgentContractError("xss analyzer received a non-XSS candidate")
    if candidate.surface_id != task.surface_id:
        raise AgentContractError("xss candidate and task reference different surfaces")

    surface = surface_store.get(task.run_id, task.surface_id)
    if surface.url != task.target_url:
        raise AgentContractError("xss analysis task target does not match its surface")
    if surface.method.upper() != "GET" or not surface.parameters:
        raise AgentContractError("xss analysis supports parameterized GET surfaces only")

    # 중복 파라미터명(?a=1&a=2)은 하나로 접는다. 안 그러면 같은 곳에 프로브를 두 번 보낸다.
    parameters = tuple(dict.fromkeys(surface.parameters))
    return candidate, surface, parameters


def build_probe_requests(
    surface: Surface,
    parameters: Sequence[str],
    *,
    marker: str,
    purpose: str,
) -> tuple[EvidenceRequest, ...]:
    """control 1개 + 파라미터별 probe N개를 만든다.

    파라미터마다 하나씩만 marker로 바꾼다. 전부 동시에 넣으면 어느 파라미터가 반사됐는지
    구분할 수 없다. 값은 호출자가 아니라 이 함수가 정한 marker/CONTROL_VALUE로 고정되며
    페이로드가 실릴 자리가 없다.
    """

    if not parameters:
        raise AgentContractError("xss probe plan must name at least one parameter")

    requests = [
        _request(
            surface.surface_id,
            tuple((name, CONTROL_VALUE) for name in parameters),
            HttpRequestKind.CONTROL,
            reason=f"XSS control request for {purpose}",
        )
    ]
    for parameter in parameters:
        requests.append(
            _request(
                surface.surface_id,
                tuple(
                    (name, marker if name == parameter else CONTROL_VALUE)
                    for name in parameters
                ),
                HttpRequestKind.PROBE,
                reason=f"XSS reflection probe for parameter {parameter} on {purpose}",
            )
        )
    return tuple(requests)


class HeuristicXssAnalyzer:
    """control/probe 응답의 marker 반사를 결정적으로 비교하는 Analysis Agent.

    외부 요청은 직접 실행하지 않고 EvidenceRequest로 Orchestrator에 반환한다.
    입력 반사 신호만 만들며 최종 취약점 판정은 독립 Validation의 책임이다.
    """

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
        """필요한 요청은 중앙 수집으로 반환하고, 수집 뒤 반사를 판정한다."""

        candidate, surface, parameters = resolve_xss_task(
            task, candidate_store=self._candidates, surface_store=self._surfaces
        )
        requests = build_probe_requests(
            surface,
            parameters,
            marker=_REFLECTION_MARKER,
            purpose=f"candidate {candidate.candidate_id}",
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
                    "xss baseline lacks budget for its remaining evidence requests"
                )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
                candidate_ids=(candidate.candidate_id,),
            )

        control = collected[0]
        if control is None:  # missing 분기 이후에는 도달하지 않는 방어선.
            raise AgentContractError("xss baseline control evidence was not collected")
        control_body = response_body(control)
        new_evidence_ids: list[str] = []

        for parameter, probe in zip(parameters, collected[1:]):
            if probe is None:  # missing 분기 이후에는 도달하지 않는 방어선.
                raise AgentContractError("xss baseline probe evidence was not collected")
            if marker_reflected(
                control_body, response_body(probe), _REFLECTION_MARKER
            ) and not has_reflection_record(
                evidence,
                HEURISTIC_XSS_ANALYZER,
                parameter,
                control.evidence_id,
                probe.evidence_id,
            ):
                reflection_id = f"evi-{self._id_factory()}"
                self._evidence.append(
                    Evidence(
                        evidence_id=reflection_id,
                        run_id=task.run_id,
                        surface_id=surface.surface_id,
                        created_by=HEURISTIC_XSS_ANALYZER,
                        evidence_type="observation",
                        observation={
                            "type": "reflection",
                            "parameter": parameter,
                            "control_evidence_id": control.evidence_id,
                            "probe_evidence_id": probe.evidence_id,
                        },
                    )
                )
                new_evidence_ids.append(reflection_id)

        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=tuple(new_evidence_ids),
            candidate_ids=(candidate.candidate_id,),
        )


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
        suggested_tool=XSS_ANALYSIS_TOOL,
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
    expected_url = _resolved_url(target_url, request.http_request.query_parameters)
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


def _resolved_url(
    target_url: str, query_parameters: tuple[tuple[str, str], ...]
) -> str:
    parsed = urlsplit(target_url)
    encoded = urlencode(query_parameters)
    query = parsed.query
    if encoded:
        query = f"{query}&{encoded}" if query else encoded
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def response_body(evidence: Evidence) -> str | None:
    body = evidence.observation.get("body")
    return body if isinstance(body, str) else None


def has_reflection_record(
    evidence: Sequence[Evidence],
    created_by: str,
    parameter: str,
    control_evidence_id: str,
    probe_evidence_id: str,
) -> bool:
    """같은 근거 조합의 reflection Observation이 이미 있는지 확인한다(재개 시 중복 방지)."""

    return any(
        item.created_by == created_by
        and item.observation.get("type") == "reflection"
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
