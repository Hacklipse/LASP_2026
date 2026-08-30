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
독립 Validation의 책임이며, 현재 baseline은 SQLI_EFFECT proof를 만들지 않으므로
Finding으로 승격되지 않는다.
"""

from __future__ import annotations

from collections.abc import Callable
from uuid import uuid4

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import AgentResult, AgentResultStatus, Evidence, TaskEnvelope
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore

from .probing import (
    ANALYSIS_TOOL,
    build_probe_requests,
    has_observation_record,
    matching_evidence,
    probe_marker,
    resolve_analysis_task,
    response_body,
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
        )
        # control과 probe가 따옴표 하나만 다르도록 같은 marker를 기준값으로 쓴다.
        marker = probe_marker(_stable_seed(task, candidate.candidate_id))
        requests = build_probe_requests(
            surface,
            parameters,
            control_value=marker,
            probe_value=marker + _SYNTAX_BREAKER,
            purpose=f"SQLi candidate {candidate.candidate_id}",
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
        for parameter, probe in zip(parameters, collected[1:]):
            if probe is None:  # missing 분기 이후에는 도달하지 않는 방어선.
                raise AgentContractError("sqli baseline probe evidence was not collected")
            signal = _syntax_error_signal(control, probe)
            if signal is None:
                continue
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

        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=tuple(new_evidence_ids),
            candidate_ids=(candidate.candidate_id,),
        )


def _stable_seed(task: TaskEnvelope, candidate_id: str) -> str:
    """재호출 시에도 같은 marker가 나오도록 Task 문맥에서 값을 만든다.

    무작위 값을 쓰면 두 번째 호출이 첫 번째가 수집한 Evidence를 못 찾아 증적 요청이
    무한히 반복된다.
    """

    return f"{task.run_id}{candidate_id}"


def _syntax_error_signal(control: Evidence, probe: Evidence) -> dict[str, object] | None:
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


def _engine_of(body: str) -> str | None:
    for engine, signatures in _ENGINE_SIGNATURES:
        if any(signature in body for signature in signatures):
            return engine
    return None
