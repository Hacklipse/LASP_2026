"""LLM 없이 SQL 구문 오류 신호를 수집하는 SQLi baseline Agent.

방식 — 값 뒤에 작은따옴표 하나만 붙여 SQL 파서에 닿는지 본다.

    control  ?q=hacklipsez1a2z3b4
    probe    ?q=hacklipsez1a2z3b4'

control과 probe가 따옴표 하나만 다르므로 응답 차이의 원인이 하나로 좁혀진다. 값 길이나
내용이 다르면 차이가 따옴표 때문인지 값 때문인지 구분할 수 없다.

최소 침해 — 따옴표는 구문 오류를 내고 트랜잭션을 실패시킨다. 데이터를 꺼내지도, 상태를
바꾸지도, 인증을 우회하지도 않는다. `' OR 1=1--`, `UNION SELECT`, `; DROP`, `SLEEP()`은
보내지 않으며 도메인의 PROBE 값 화이트리스트가 애초에 이런 문자열을 거부한다.

여기서 만드는 것은 "SQL 파서에 입력이 닿았다"는 관찰이지 취약점 판정이 아니다. 확정은
Validation이 별도 control/probe를 실행해 같은 차이를 재현하고 SQLI_EFFECT proof를
만들었을 때만 가능하다.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from uuid import uuid4

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import (
    SQLI_BOOLEAN_PREDICATES,
    AgentResult,
    AgentResultStatus,
    Evidence,
    TaskEnvelope,
)
from hacklipse.ports.errors import BudgetExceeded
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore

from .probing import (
    ANALYSIS_TOOL,
    build_probe_requests,
    build_sqli_boolean_requests,
    sqli_boolean_plan,
    has_observation_record,
    matching_evidence,
    probe_marker,
    resolve_analysis_task,
    response_body,
)
from .graphql_discovery import (
    graphql_auth_blocked_response, graphql_query_plans, graphql_query_requests,
)

SQLI_ANALYSIS_TOOL = ANALYSIS_TOOL
HEURISTIC_SQLI_ANALYZER = "heuristic_sqli_analyzer"

# 구문을 깨뜨리는 최소 단위. 이것 하나로 SQL 파서 도달 여부가 드러난다.
_SYNTAX_BREAKER = "'"

# 엔진별 오류 서명. 어떤 DB인지까지 관찰에 남기면 후속 Validation이 취약점별 proof를
# 설계할 때 근거가 된다.
_ENGINE_SIGNATURES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("sqlite", ("sqlite_error", "sqlite3.operationalerror", "unrecognized token")),
    ("mysql", ("you have an error in your sql syntax", "mysqlsyntaxerror", "mysql_fetch")),
    ("postgresql", ("pg::syntaxerror", "unterminated quoted string", "psycopg2.errors")),
    ("oracle", ("ora-00933", "ora-00921", "ora-01756", "quoted string not properly terminated")),
    ("mssql", ("unclosed quotation mark", "incorrect syntax near", "microsoft odbc sql")),
    ("generic", ("sql syntax", "syntax error", "sqlexception", "odbc driver")),
)

# 5xx는 그 자체로 신호다. 정상 값에는 200을 주고 따옴표에만 500을 준다면 입력이 쿼리
# 문자열로 들어갔을 가능성이 높다. 오류 문자열이 없어도(운영 환경에서 흔하다) 잡힌다.
_SERVER_ERROR = range(500, 600)


class HeuristicSqliAnalyzer:
    """control/probe 응답의 SQL 오류 차이를 결정적으로 비교하는 Analysis Agent.

    외부 요청은 직접 실행하지 않고 EvidenceRequest로 Orchestrator에 반환한다.
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
        """필요한 요청은 중앙 수집으로 반환하고, 수집 뒤 오류 차이를 판정한다."""

        candidate, surface, parameters = resolve_analysis_task(
            task,
            vulnerability_type="SQLi",
            candidate_store=self._candidates,
            surface_store=self._surfaces,
            allow_parameterless_get=True,
            required_tool=None,
            allowed_methods=("GET", "POST"),
        )
        evidence = tuple(self._evidence.get_many(task.run_id, task.evidence_ids))
        graphql_plans = tuple(
            plan
            for item in evidence
            if item.surface_id == surface.surface_id
            for plan in graphql_query_plans(item)
        )
        if graphql_plans and "graphql_introspection" in surface.discovery_types:
            return self._handle_graphql(task, candidate, surface, evidence, graphql_plans)
        if not parameters:
            raise AgentContractError("SQLi analysis needs a parameterized read surface")
        # control과 probe가 따옴표 하나만 다르도록 같은 marker를 기준값으로 쓴다.
        marker = probe_marker(_stable_seed(task, candidate.candidate_id))
        requests = build_probe_requests(
            surface,
            parameters,
            control_value=marker,
            probe_value=marker + _SYNTAX_BREAKER,
            purpose=f"SQLi candidate {candidate.candidate_id}",
        )
        collected = tuple(
            matching_evidence(evidence, surface.url, request) for request in requests
        )
        missing = tuple(
            request for request, item in zip(requests, collected) if item is None
        )

        if missing:
            if task.request_budget < len(missing):
                raise BudgetExceeded(
                    "sqli baseline lacks budget for its remaining evidence requests"
                )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
                candidate_ids=(candidate.candidate_id,),
            )

        control = collected[0]
        if control is None:  # missing 분기 이후에는 도달하지 않는 방어선.
            raise AgentContractError("sqli baseline control evidence was not collected")

        new_evidence_ids: list[str] = []
        found_error_signal = False
        for parameter, probe in zip(parameters, collected[1:]):
            if probe is None:  # missing 분기 이후에는 도달하지 않는 방어선.
                raise AgentContractError("sqli baseline probe evidence was not collected")
            signal = sql_error_signal(control, probe)
            if signal is None:
                continue
            found_error_signal = True
            if has_observation_record(
                evidence,
                HEURISTIC_SQLI_ANALYZER,
                "sql_error",
                parameter,
                control.evidence_id,
                probe.evidence_id,
            ):
                continue
            observation_id = f"evi-{self._id_factory()}"
            self._evidence.append(
                Evidence(
                    evidence_id=observation_id,
                    run_id=task.run_id,
                    surface_id=surface.surface_id,
                    created_by=HEURISTIC_SQLI_ANALYZER,
                    evidence_type="observation",
                    observation={
                        # Router.DEFAULT_RULES의 "sql_error" 규칙과 맞는 유형이어야 한다.
                        "type": "sql_error",
                        "parameter": parameter,
                        "control_evidence_id": control.evidence_id,
                        "probe_evidence_id": probe.evidence_id,
                        **signal,
                    },
                )
            )
            new_evidence_ids.append(observation_id)

        if not found_error_signal:
            boolean_plan = sqli_boolean_plan(surface, parameters)
            boolean_requests = build_sqli_boolean_requests(
                surface,
                parameters,
                probe_parameters=parameters,
                purpose=f"SQLi candidate {candidate.candidate_id}",
            )
            boolean_evidence = tuple(
                matching_evidence(evidence, surface.url, request)
                for request in boolean_requests
            )
            missing_boolean = tuple(
                request
                for request, item in zip(boolean_requests, boolean_evidence)
                if item is None
            )
            if missing_boolean:
                if task.request_budget < len(missing_boolean):
                    raise BudgetExceeded(
                        "sqli baseline lacks budget for boolean differential requests"
                    )
                return AgentResult(
                    task_id=task.task_id,
                    status=AgentResultStatus.NEEDS_EVIDENCE,
                    evidence_requests=missing_boolean,
                    new_evidence_ids=tuple(new_evidence_ids),
                    candidate_ids=(candidate.candidate_id,),
                )

            signalled: set[str] = set()
            for index, (parameter, predicate) in enumerate(boolean_plan):
                if parameter in signalled:
                    # 한 좌표에 두 술어가 모두 통하면 사실은 하나다. 관측을 늘리지 않는다.
                    continue
                true_response = boolean_evidence[index * 2]
                false_response = boolean_evidence[index * 2 + 1]
                if true_response is None or false_response is None:
                    raise AgentContractError("SQLi boolean evidence was not collected")
                signal = sql_boolean_signal(
                    true_response, false_response, predicate
                )
                if signal is not None:
                    signalled.add(parameter)
                if signal is None or has_observation_record(
                    evidence,
                    HEURISTIC_SQLI_ANALYZER,
                    "sqli_differential",
                    parameter,
                    true_response.evidence_id,
                    false_response.evidence_id,
                ):
                    continue
                observation_id = f"evi-{self._id_factory()}"
                self._evidence.append(
                    Evidence(
                        evidence_id=observation_id,
                        run_id=task.run_id,
                        surface_id=surface.surface_id,
                        created_by=HEURISTIC_SQLI_ANALYZER,
                        evidence_type="observation",
                        observation={
                            "type": "sqli_differential",
                            "parameter": parameter,
                            "control_evidence_id": true_response.evidence_id,
                            "probe_evidence_id": false_response.evidence_id,
                            # 어떤 술어 쌍이 차등을 만들었는지 남긴다. Validation이
                            # 그 쌍 하나만 다시 보내므로 재현이 싸고 증명이 구체적이다.
                            "predicate": predicate,
                            **signal,
                        },
                    )
                )
                new_evidence_ids.append(observation_id)

        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=tuple(new_evidence_ids),
            candidate_ids=(candidate.candidate_id,),
        )

    def _handle_graphql(
        self, task: TaskEnvelope, candidate, surface, evidence, plans,
    ) -> AgentResult:
        """Probe only schema-derived read queries via the domain's bounded kind."""

        marker = probe_marker(_stable_seed(task, candidate.candidate_id))
        requests = tuple(
            request
            for plan in plans
            for request in graphql_query_requests(
                surface.surface_id, plan, marker,
                f"GraphQL SQLi candidate {candidate.candidate_id}",
            )
        )
        collected = tuple(
            matching_evidence(evidence, surface.url, request) for request in requests
        )
        missing = tuple(
            request for request, item in zip(requests, collected) if item is None
        )
        if missing:
            if task.request_budget < len(missing):
                raise BudgetExceeded(
                    "GraphQL SQLi analysis lacks budget for comparable query pairs",
                    required_requests=len(missing),
                )
            return AgentResult(
                task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
                candidate_ids=(candidate.candidate_id,),
            )
        new_evidence_ids: list[str] = []
        for index, plan in enumerate(plans):
            control, probe = collected[2 * index:2 * index + 2]
            if control is None or probe is None:
                raise AgentContractError("GraphQL SQLi response pair is missing")
            signal = sql_error_signal(control, probe)
            parameter = f"{plan.field}.{plan.argument}"
            outcome = (
                "authentication_required"
                if graphql_auth_blocked_response(control)
                or graphql_auth_blocked_response(probe)
                else "sql_error_signal" if signal is not None
                else "incomparable_response" if any(
                    item.observation.get("type") in {"http_error", "http_redirect"}
                    for item in (control, probe)
                ) else "no_sql_error_signal"
            )
            if not has_observation_record(
                evidence, HEURISTIC_SQLI_ANALYZER, "graphql_query_probe_result",
                parameter, control.evidence_id, probe.evidence_id,
            ):
                trace_id = f"evi-{self._id_factory()}"
                self._evidence.append(Evidence(
                    evidence_id=trace_id, run_id=task.run_id,
                    surface_id=surface.surface_id, created_by=HEURISTIC_SQLI_ANALYZER,
                    evidence_type="observation",
                    observation={
                        "type": "graphql_query_probe_result",
                        "parameter": parameter,
                        "graphql_field": plan.field,
                        "graphql_argument": plan.argument,
                        "outcome": outcome,
                        "control_evidence_id": control.evidence_id,
                        "probe_evidence_id": probe.evidence_id,
                    },
                ))
                new_evidence_ids.append(trace_id)
            if signal is None or has_observation_record(
                evidence, HEURISTIC_SQLI_ANALYZER, "sql_error", parameter,
                control.evidence_id, probe.evidence_id,
            ):
                continue
            observation_id = f"evi-{self._id_factory()}"
            self._evidence.append(Evidence(
                evidence_id=observation_id, run_id=task.run_id,
                surface_id=surface.surface_id, created_by=HEURISTIC_SQLI_ANALYZER,
                evidence_type="observation",
                observation={
                    "type": "sql_error", "parameter": parameter,
                    "graphql_field": plan.field, "graphql_argument": plan.argument,
                    "control_evidence_id": control.evidence_id,
                    "probe_evidence_id": probe.evidence_id,
                    **signal,
                },
            ))
            new_evidence_ids.append(observation_id)
        return AgentResult(
            task_id=task.task_id, status=AgentResultStatus.COMPLETED,
            new_evidence_ids=tuple(new_evidence_ids),
            candidate_ids=(candidate.candidate_id,),
        )


def _stable_seed(task: TaskEnvelope, candidate_id: str) -> str:
    """재호출 시에도 같은 marker가 나오도록 Task 문맥에서 값을 만든다.

    무작위 값을 쓰면 두 번째 호출이 첫 번째가 수집한 Evidence를 못 찾아 증적 요청이
    무한히 반복된다.
    """

    return f"{task.run_id}{candidate_id}"


def sql_error_signal(control: Evidence, probe: Evidence) -> dict[str, object] | None:
    """control에는 없고 probe에만 나타난 SQL 오류 신호를 찾는다."""

    control_body = (response_body(control) or "").casefold()
    probe_body = (response_body(probe) or "").casefold()

    engine = _engine_of(probe_body)
    if engine is not None and _engine_of(control_body) is None:
        return {"signal": "error_message", "engine": engine}

    control_status = control.observation.get("status")
    probe_status = probe.observation.get("status")
    if (
        isinstance(probe_status, int)
        and probe_status in _SERVER_ERROR
        and isinstance(control_status, int)
        and control_status not in _SERVER_ERROR
    ):
        # 오류 문자열을 숨기는 대상에서도 상태 차이는 남는다.
        return {
            "signal": "status_differential",
            "engine": None,
            "control_status": control_status,
            "probe_status": probe_status,
        }
    return None


def sql_boolean_signal(
    true_response: Evidence,
    false_response: Evidence,
    predicate: str | None = None,
) -> dict[str, object] | None:
    """Recognize a bounded true/false predicate response differential.

    ``predicate``는 그 쌍에 실제로 보낸 접미사를 돌려받기 위한 것이다. 보낸 문자열을
    응답에서 빼고 비교해야 "SQL 분기가 갈렸다"와 "내가 보낸 값이 그대로 보인다"가
    구분된다. 이름을 주지 않으면 모든 술어의 접미사를 다 빼서 보수적으로 본다.
    """

    if any(
        item.observation.get("type") == "http_error"
        for item in (true_response, false_response)
    ):
        return None
    true_status = true_response.observation.get("status")
    false_status = false_response.observation.get("status")
    true_body = response_body(true_response)
    false_body = response_body(false_response)
    status_changed = (
        isinstance(true_status, int)
        and isinstance(false_status, int)
        and true_status != false_status
    )
    if predicate is None:
        normalized_true = true_body
        normalized_false = false_body
        for _name, true_suffix, false_suffix in SQLI_BOOLEAN_PREDICATES:
            normalized_true = _normalize_boolean_probe_reflection(
                normalized_true, true_suffix
            )
            normalized_false = _normalize_boolean_probe_reflection(
                normalized_false, false_suffix
            )
    else:
        true_suffix, false_suffix = next(
            (true, false)
            for name, true, false in SQLI_BOOLEAN_PREDICATES
            if name == predicate
        )
        normalized_true = _normalize_boolean_probe_reflection(true_body, true_suffix)
        normalized_false = _normalize_boolean_probe_reflection(false_body, false_suffix)
    body_changed = (
        normalized_true is not None
        and normalized_false is not None
        and normalized_true != normalized_false
    )
    if not status_changed and not body_changed:
        return None
    return {
        "signal": "boolean_response_differential",
        "engine": None,
        "true_status": true_status if isinstance(true_status, int) else None,
        "false_status": false_status if isinstance(false_status, int) else None,
        "true_body_bytes": len(true_body.encode("utf-8")) if isinstance(true_body, str) else None,
        "false_body_bytes": len(false_body.encode("utf-8")) if isinstance(false_body, str) else None,
    }


# 술어 리터럴을 지우고 비교해야 "응답이 달라졌다"와 "보낸 값이 그대로 되돌아왔다"가
# 갈린다. 지우지 못한 모양이 하나라도 있으면 반사만으로 차등이 생겨 오탐이 된다.
#
# 패턴 하나로 모든 모양을 덮으려 하면 반드시 뚫린다. XBEN-047은 쌍따옴표를 지우고
# 되돌려주므로 `1"or"1"="1` 이 `1or1=1` 로 붙어 나오고, 단어 경계를 요구하는 패턴은
# 그것을 보지 못해 SQL이 없는 앱에서 차등이 생겼다. 그래서 패턴에 기대지 않고 **우리가
# 보낸 문자열 자체**를 응답에서 뺀다. 대상이 흔히 가하는 변형(따옴표 제거, 공백 제거,
# HTML escape)만 기계적으로 만들어 함께 빼며, 추측한 값은 쓰지 않는다.
_HTML_ESCAPES = (('"', "&quot;"), ("'", "&#39;"), ("'", "&#039;"), ("'", "&apos;"))


def boolean_probe_manglings(value: str) -> tuple[str, ...]:
    """대상이 되돌려줄 수 있는 그 값의 변형들. 길이 순으로 길게 먼저 뺀다."""

    without_quotes = value.replace('"', "").replace("'", "")
    forms = {
        value,
        without_quotes,
        re.sub(r"\s+", "", value),
        re.sub(r"\s+", "", without_quotes),
    }
    for raw, escaped in _HTML_ESCAPES:
        if raw in value:
            forms.add(value.replace(raw, escaped))
            forms.add(re.sub(r"\s+", "", value.replace(raw, escaped)))
    return tuple(sorted((form for form in forms if form), key=len, reverse=True))


def _normalize_boolean_probe_reflection(
    body: str | None, sent: str | None = None
) -> str | None:
    """Remove the deliberate predicate literal before comparing response bodies."""

    if body is None:
        return None
    normalized = body
    if sent:
        for form in boolean_probe_manglings(sent):
            normalized = normalized.replace(form, "<sqli-bool-probe>")
    return normalized.strip()


def _engine_of(body: str) -> str | None:
    for engine, signatures in _ENGINE_SIGNATURES:
        if any(signature in body for signature in signatures):
            return engine
    return None
