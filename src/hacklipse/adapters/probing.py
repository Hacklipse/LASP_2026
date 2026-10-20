"""control/probe 대조 탐침의 공용 부품.

XSS와 SQLi는 신호가 다르지만 절차는 같다 — 기준선 요청 하나를 보내고, 파라미터마다
하나씩만 값을 바꾼 탐침을 보내고, 두 응답의 차이만 신호로 인정한다. control 대조가
오탐을 막는 장치다: 대상이 원래 갖고 있던 내용을 탐침 결과로 오인하지 않는다.

여기 있는 함수를 모든 Analyzer가 공유해야 결과를 같은 축에서 비교할 수 있다. 값의
형태는 도메인(`HttpRequestSpec`)이 PROBE 요청에 대해 강제하므로, 이 모듈을 우회해
임의 페이로드를 만들어도 Runtime에 도달하지 못한다.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from urllib.parse import urlencode, urlsplit, urlunsplit

from hacklipse.application.errors import AgentContractError, LlmOutputContractError
from hacklipse.domain import (
    SQLI_BOOLEAN_PREDICATES,
    SQLI_NUMERIC_PREDICATES,
    SQLI_STRING_PREDICATES,
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
    required_tool: str | None = ANALYSIS_TOOL,
    allow_parameterless_get: bool = False,
    allowed_methods: tuple[str, ...] = ("GET",),
) -> tuple[Candidate, Surface, tuple[str, ...]]:
    """Analysis Task의 Candidate/Surface를 확인하고 탐침 대상 파라미터를 정리한다.

    Task가 지시한 target_url과 Store에 저장된 Surface가 다르면 거부한다 — Task를 통해
    다른 대상으로 요청을 유도하는 경로를 막는다.
    """

    if task.candidate_id is None or task.surface_id is None or task.target_url is None:
        raise AgentContractError("analysis task is missing candidate or surface context")
    candidate = candidate_store.get(task.run_id, task.candidate_id)
    if candidate.vulnerability_type != vulnerability_type:
        raise AgentContractError(
            f"{vulnerability_type} analyzer received a {candidate.vulnerability_type} candidate"
        )
    if candidate.surface_id != task.surface_id:
        raise AgentContractError("candidate and task reference different surfaces")

    surface = surface_store.get(task.run_id, task.surface_id)
    selected_tool = required_tool or (
        "http_post" if surface.method.upper() == "POST" else ANALYSIS_TOOL
    )
    if selected_tool not in task.allowed_tools:
        raise AgentContractError("analysis execution tool is not allowed by the task")
    if surface.url != task.target_url:
        raise AgentContractError("analysis task target does not match its surface")
    if surface.method.upper() not in allowed_methods or (
        not surface.parameters and not allow_parameterless_get
    ):
        methods = "/".join(allowed_methods)
        raise AgentContractError(
            f"analysis supports parameterized {methods} surfaces only"
        )

    # 중복 파라미터명(?a=1&a=2)은 하나로 접는다. 안 그러면 같은 곳에 탐침을 두 번 보낸다.
    return candidate, surface, tuple(dict.fromkeys(surface.parameters))


def validate_probe_selection(
    raw: object,
    offered: tuple[str, ...],
    request_budget: int,
    *,
    analyzer_name: str,
    control_requests: int = 1,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """LLM 선택을 실제 Surface와 요청 예산 안으로 제한한다.

    control 한 건이 항상 필요하므로 선택 가능한 probe 수는 남은 예산보다 하나 적다.
    브라우저 DOM 반사처럼 control 요청이 없는 흐름은 ``control_requests=0``을 넘긴다 —
    값이 DOM 에 있는지 없는지가 그 자체로 차이라 비교 대상 요청이 필요 없다.
    존재하지 않는 파라미터는 조용히 버리지 않고 복구 가능한 LLM 출력 오류로 처리한다.
    """

    if not isinstance(raw, list):
        raise LlmOutputContractError(f"{analyzer_name} plan did not return a parameter list")
    selected: list[str] = []
    for name in raw:
        if not isinstance(name, str):
            raise LlmOutputContractError(
                f"{analyzer_name} plan returned a non-string parameter"
            )
        if name not in offered:
            raise LlmOutputContractError(
                f"{analyzer_name} plan named a parameter that is not on the surface: "
                f"{name}"
            )
        if name not in selected:
            selected.append(name)

    affordable = max(request_budget - control_requests, 0)
    if len(selected) <= affordable:
        return tuple(selected), ()
    return tuple(selected[:affordable]), tuple(selected[affordable:])


def build_probe_requests(
    surface: Surface,
    parameters: Sequence[str],
    *,
    control_value: str,
    probe_value: str,
    purpose: str,
    probe_parameters: Sequence[str] | None = None,
    suggested_tool: str = ANALYSIS_TOOL,
) -> tuple[EvidenceRequest, ...]:
    """control 1개 + 선택한 파라미터별 probe N개를 만든다.

    파라미터마다 하나씩만 값을 바꾼다. 전부 동시에 바꾸면 어느 파라미터가 신호를
    만들었는지 구분할 수 없다. ``parameters``는 요청이 성립하는 데 필요한 전체 입력을,
    ``probe_parameters``는 그중 실제로 바꿀 입력을 뜻한다. 예를 들어 DVWA SQLi는 id를
    probe하더라도 Submit이 함께 있어야 SQL 분기가 실행된다.
    """

    all_parameters = tuple(dict.fromkeys(parameters))
    selected_parameters = (
        tuple(dict.fromkeys(probe_parameters))
        if probe_parameters is not None
        else all_parameters
    )
    if not all_parameters or not selected_parameters:
        raise AgentContractError("probe plan must name at least one parameter")
    if any(parameter not in all_parameters for parameter in selected_parameters):
        raise AgentContractError("probe parameter must belong to the request surface")

    observed_values = dict(surface.observed_query)

    def baseline(name: str) -> str:
        return observed_values.get(name, control_value)

    # Most probes are expressed as ``control + suffix``.  Apply that suffix to
    # an actually observed value when one exists, preserving routing fields,
    # nonces, numeric identifiers, and other request preconditions.
    probe_suffix = (
        probe_value[len(control_value) :]
        if probe_value.startswith(control_value)
        else None
    )

    def mutated(name: str) -> str:
        if probe_suffix is not None:
            return baseline(name) + probe_suffix
        return probe_value

    def control_parameters() -> tuple[tuple[str, str], ...]:
        return tuple((name, baseline(name)) for name in all_parameters)

    requests = [
        _request(
            surface.surface_id,
            surface.method,
            control_parameters(),
            HttpRequestKind.CONTROL,
            reason=f"control request for {purpose}",
            suggested_tool=(
                "http_post" if surface.method.upper() == "POST" else suggested_tool
            ),
        )
    ]
    for parameter in selected_parameters:
        requests.append(
            _request(
                surface.surface_id,
                surface.method,
                tuple(
                    (
                        name,
                        mutated(name)
                        if name == parameter
                        else baseline(name),
                    )
                    for name in all_parameters
                ),
                HttpRequestKind.PROBE,
                reason=f"probe for parameter {parameter} on {purpose}",
                suggested_tool=(
                    "http_post" if surface.method.upper() == "POST" else suggested_tool
                ),
            )
        )
    return tuple(requests)


# 한 분석에서 boolean 차등에 쓸 요청 수 상한. 좌표 수 × 술어 수가 예산을 먹지 않게
# 묶는다. 쌍 단위이므로 항상 짝수다.
_MAX_SQLI_BOOLEAN_REQUESTS = 8
_SQLI_NUMERIC_BASELINE = re.compile(r"[+-]?\d+(?:\.\d+)?")
_ALL_PREDICATES = SQLI_BOOLEAN_PREDICATES


def sqli_boolean_predicates(
    baseline: str | None,
) -> tuple[tuple[str, str, str], ...]:
    """그 좌표에 보낼 술어 쌍들을 고정 순서로 돌려준다.

    관측된 값이 숫자면 숫자 술어만, 문자열이면 문자열 술어만 쓴다. 값을 관측하지
    못한 좌표는 컬럼 타입을 알 수 없으므로 양쪽을 모두 보낸다 — 빈 입력을 "1"로
    채운 뒤 그 모양만 보고 숫자로 단정하면, 문자열 컬럼에서는 성립하는 쌍을 한 번도
    보내지 않게 된다.
    """

    if baseline is None:
        # 상한에 걸려 뒤가 잘리므로 값이 큰 순서로 섞는다: 고전적인 문자열·숫자 쌍을
        # 먼저, 그다음 공백·`and`를 지우는 필터를 지나는 쌍을 둔다.
        by_name = {name: pair for pair in _ALL_PREDICATES for name in (pair[0],)}
        return tuple(by_name[name] for name in (
            "single_and_spaced", "and_spaced", "double_or_tight",
            "single_or_tight", "double_and_spaced", "or_tight",
        ))
    if _SQLI_NUMERIC_BASELINE.fullmatch(baseline) is not None:
        return SQLI_NUMERIC_PREDICATES
    return SQLI_STRING_PREDICATES


def sqli_boolean_plan(
    surface: Surface,
    probe_parameters: Sequence[str],
    *,
    predicates: Sequence[str] | None = None,
    per_parameter_limit: int | None = None,
) -> tuple[tuple[str, str], ...]:
    """어느 좌표에 어떤 술어 쌍을 보낼지 (좌표, 술어이름) 순서로 고정한다.

    요청 목록과 소비자의 해석이 각자 색인을 계산하면 쌍이 늘어날 때 어긋난다. 계획을
    한 곳에서 만들고 양쪽이 같은 것을 보게 한다. ``predicates``를 주면 그 이름만
    남겨 Validation이 신호를 만든 쌍 하나만 재현한다.

    상한에 걸릴 때 한 좌표가 예산을 다 먹지 않게 술어를 번갈아 돌린다.
    ``per_parameter_limit``은 좌표마다 쓸 쌍의 수를 묶는다 — 어떤 쌍이 통했는지 적어
    두지 않은 옛 Evidence를 재현할 때, 재현이 분석보다 비싸지지 않게 한다.
    """

    observed = dict(surface.observed_query)
    wanted = None if predicates is None else set(predicates)
    per_parameter = [
        (
            parameter,
            [
                name
                for name, _true, _false in sqli_boolean_predicates(
                    observed.get(parameter) or None
                )
                if wanted is None or name in wanted
            ][:per_parameter_limit],
        )
        for parameter in dict.fromkeys(probe_parameters)
    ]
    plan: list[tuple[str, str]] = []
    for round_index in range(max((len(names) for _, names in per_parameter), default=0)):
        for parameter, names in per_parameter:
            if round_index >= len(names):
                continue
            if 2 * (len(plan) + 1) > _MAX_SQLI_BOOLEAN_REQUESTS:
                return tuple(plan)
            plan.append((parameter, names[round_index]))
    return tuple(plan)


def build_sqli_boolean_requests(
    surface: Surface,
    parameters: Sequence[str],
    *,
    probe_parameters: Sequence[str],
    purpose: str,
    predicates: Sequence[str] | None = None,
    per_parameter_limit: int | None = None,
) -> tuple[EvidenceRequest, ...]:
    """Build bounded true/false SQL predicates while preserving request prerequisites.

    Only one field changes in each request.  Observed action, nonce, submit, and
    companion values stay intact.  The payload grammar is enforced again by
    ``HttpRequestSpec`` and excludes comments, stacked queries, extraction, and
    delay functions.
    """

    all_parameters = tuple(dict.fromkeys(parameters))
    selected = tuple(dict.fromkeys(probe_parameters))
    if not selected or any(name not in all_parameters for name in selected):
        raise AgentContractError("SQLi boolean probes require offered parameters")
    observed = dict(surface.observed_query)

    def baseline(name: str) -> str:
        # Empty form controls usually mean "no filter" and often skip the server
        # branch entirely.  A benign non-empty scalar reaches the same branch while
        # observed non-empty routing, nonce, and identifier values stay unchanged.
        return observed.get(name) or "1"

    requests: list[EvidenceRequest] = []
    for parameter, predicate in sqli_boolean_plan(
        surface, selected, predicates=predicates,
        per_parameter_limit=per_parameter_limit,
    ):
        true_suffix, false_suffix = next(
            (true, false)
            for name, true, false in SQLI_BOOLEAN_PREDICATES
            if name == predicate
        )
        for suffix, kind, label in (
            (true_suffix, HttpRequestKind.SQLI_BOOLEAN_TRUE, f"{predicate} true"),
            (false_suffix, HttpRequestKind.SQLI_BOOLEAN_FALSE, f"{predicate} false"),
        ):
            requests.append(
                _request(
                    surface.surface_id,
                    surface.method,
                    tuple(
                        (
                            name,
                            baseline(name) + suffix
                            if name == parameter
                            else baseline(name),
                        )
                        for name in all_parameters
                    ),
                    kind,
                    reason=f"{label} predicate for parameter {parameter} on {purpose}",
                    suggested_tool=(
                        "http_post" if surface.method.upper() == "POST" else ANALYSIS_TOOL
                    ),
                )
            )
    return tuple(requests)


def _request(
    surface_id: str,
    method: str,
    parameters: tuple[tuple[str, str], ...],
    request_kind: HttpRequestKind,
    *,
    reason: str,
    suggested_tool: str,
) -> EvidenceRequest:
    normalized_method = method.upper()
    if normalized_method not in {"GET", "POST"}:
        raise AgentContractError("probe request supports GET or POST surfaces only")
    query_parameters = parameters if normalized_method == "GET" else ()
    form_parameters = parameters if normalized_method == "POST" else ()
    return EvidenceRequest(
        evidence_type="http_response",
        surface_id=surface_id,
        reason=reason,
        suggested_tool=suggested_tool,
        http_request=HttpRequestSpec(
            method=normalized_method,
            query_parameters=query_parameters,
            form_parameters=form_parameters,
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
    expected_method = request.http_request.method.upper()
    expected_fingerprint = request.request_fingerprint(target_url)
    for item in reversed(evidence):
        observation = item.observation
        fingerprint = observation.get("request_fingerprint")
        if (
            item.created_by.startswith("execution_runtime:")
            and (
                fingerprint == expected_fingerprint
                # 이전 저장본·테스트 대역과의 읽기 호환. 새 Collector Evidence에는
                # 항상 fingerprint가 있으므로 마스킹 URL에 의존하지 않는다.
                or (
                    fingerprint is None
                    and observation.get("requested_url") == expected_url
                )
            )
            and observation.get("request_kind") == expected_kind
            and str(observation.get("method", "GET")).upper() == expected_method
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


# Payload를 고를 수 있는 반사 맥락. LLM이 말하는 coarse context와 달리 이 값은 Python이
# 응답 본문에서 직접 계산한 사실이다. 어떤 payload를 보낼지가 여기서 갈리므로, 맥락
# 판정을 LLM에 맡기면 LLM이 사실상 payload를 고르게 된다.
PAYLOAD_CONTEXTS = (
    "html_text",
    "js_string_double",
    "js_string_single",
    "uri_attribute",
    "attribute_double",
    "attribute_single",
    "unclassified",
)
# 한 응답에서 분류할 반사 자리 수의 상한. 같은 값이 수백 번 되돌아오는 페이지에서
# 전체를 훑지 않는다.
_MAX_CONTEXT_SITES = 8
# javascript: URI가 자동으로 실행되는 속성. href처럼 사용자 조작이 필요한 것은
# 자동 탐침으로 재현할 수 없으므로 넣지 않는다.
_URI_ATTRIBUTES = frozenset({"src", "action", "formaction", "data", "poster"})
_SCRIPT_OPEN = re.compile(r"<script\b[^>]*>", re.I)
_SCRIPT_CLOSE = re.compile(r"</script\s*>", re.I)
_ATTRIBUTE_BEFORE = re.compile(r"([A-Za-z_:][\w:.-]{0,40})\s*=\s*(\"|')$")
_MAX_CONTEXT_BODY = 2 * 1024 * 1024


def payload_contexts(body: str | None, marker: str) -> tuple[str, ...]:
    """marker가 떨어진 구문 맥락들을 결정적으로 분류한다.

    HTML text 맥락만 가정한 `<img onerror=...>` 한 형태로는 JS 문자열 리터럴이나
    URI 속성에 떨어진 반사를 실행으로 재현할 수 없다. 맥락을 알면 그 맥락에 맞는
    고정 payload 하나만 보낼 수 있다 — 형태는 코드에 박혀 있고 marker만 바뀐다.

    한 값이 여러 곳에 반사되면 맥락도 여러 개다. 중복을 제거해 등장 순서대로
    돌려주고, 분류하지 못한 자리는 payload를 고를 근거가 없으므로 버린다.
    """

    if not body or len(body) > _MAX_CONTEXT_BODY:
        return ()
    found: list[str] = []
    for match in list(re.finditer(re.escape(marker), body))[:_MAX_CONTEXT_SITES]:
        context = _payload_context_at(body, marker, match.start())
        if context != "unclassified" and context not in found:
            found.append(context)
    return tuple(found)


def _payload_context_at(body: str, marker: str, index: int) -> str:
    before = body[:index]

    opened = None
    for match in _SCRIPT_OPEN.finditer(before):
        opened = match
    if opened is not None and not _SCRIPT_CLOSE.search(before, opened.end()):
        # <script> 안이다. 여는 따옴표가 marker 앞에 있고 닫는 짝이 뒤에 있어야
        # 문자열 리터럴 안이라고 말할 수 있다.
        script = before[opened.end():]
        rest = body[index + len(marker):]
        end = _SCRIPT_CLOSE.search(rest)
        after = rest[: end.start()] if end else rest
        for quote, context in (('"', "js_string_double"), ("'", "js_string_single")):
            if script.count(quote) % 2 == 1 and quote in after:
                return context
        return "unclassified"

    tag_open = before.rfind("<")
    if tag_open == -1 or tag_open < before.rfind(">"):
        return "html_text"
    attribute = _ATTRIBUTE_BEFORE.search(before[tag_open:])
    if attribute is None:
        return "unclassified"
    name, quote = attribute.group(1).casefold(), attribute.group(2)
    if quote not in body[index + len(marker):]:
        return "unclassified"
    if name in _URI_ATTRIBUTES and body[index:].startswith(marker):
        return "uri_attribute"
    return "attribute_double" if quote == '"' else "attribute_single"
