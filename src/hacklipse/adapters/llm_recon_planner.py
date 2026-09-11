"""LLM으로 이미 발견된 Recon 후보의 방문 순서·범위만 판단하는 선택적 Planner.

역할은 구조적으로 분리한다.

    Python  HTML/JS 정적 분석으로 pending Surface 후보를 발견 (recon.py, 결정적)
    LLM     그 후보 중 남은 예산 안에서 어떤 순서로 더 볼지만 선택 (이 파일)

LLM은 새 URL을 생성하지 않는다. 이미 발견된 `ReconCandidate.surface_id` 중에서만 고르고,
이 파일은 그 선택값을 검증해 요청으로 만들지 않는다 — 순서 힌트만 반환한다. 실제 방문은
여전히 `recon.py`의 결정적 `crawl()`이 기존 `RuntimeEvidenceCollector` 경로로 수행한다.

`probing.py`의 `validate_probe_selection()`은 참고하지 않는다. 그 함수는 Analysis Agent가
실행 대상(파라미터 값)을 확정하는 계약이라 존재하지 않는 선택을 `AgentContractError`로
올리는 것이 맞다. 여기 선택은 이미 발견된 Surface의 순서 힌트일 뿐이라 실행 대상이
아니고, 잘못된 개별 항목 때문에 Run을 죽이면 안 된다. 그래서 Recon 전용
`_validate_recon_selection()`을 이 파일 안에 별도로 둔다.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, Mapping, Protocol

from hacklipse.domain import Evidence, TaskEnvelope
from hacklipse.ports.errors import LlmRefused, LlmResponseFormatError, LlmTimeout, LlmTransportError
from hacklipse.ports.llm import LlmClient, LlmMessage, LlmRequest

from .llm_parameter_names import alias_parameter_names

# recon.py가 Evidence.created_by에 쓰는 고정 식별자. selection_source(llm/fallback)와
# 별개로, "이 판단을 만든 컴포넌트가 무엇인가"는 항상 이 값으로 고정한다.
RECON_PLANNER = "llm_recon_planner"
_PLAN_OBSERVATION = "recon_plan"
RECON_PLANNER_STATUS_PREFIX = "recon_planner:"

_PLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "ranked_surface_ids": {
            "type": "array",
            "items": {"type": "string"},
        },
        "action": {
            "type": "string",
            "enum": ["continue", "stop"],
        },
        "reason": {"type": "string"},
    },
    "required": ["ranked_surface_ids", "action", "reason"],
    "additionalProperties": False,
}

_PLAN_SYSTEM = (
    "You choose which already-discovered endpoints of a single authorized reconnaissance "
    "session are worth visiting next, and in what order. You never invent new endpoints, "
    "parameters, or query values: you only rank and select among the exact surface_id "
    "values offered to you. Structured observation types (for example a restricted file "
    "path or an unlinked render parameter candidate) suggest a surface is more worth "
    "visiting than a plain navigation link. Return action=\"stop\" if none of the offered "
    "surfaces are worth spending the remaining request budget on."
)


@dataclass(frozen=True, slots=True)
class ReconCandidate:
    """Planner에게 제공하는 pending Surface 하나. 관측 값이나 응답 본문은 담지 않는다."""

    surface_id: str
    path: str
    method: str
    parameter_names: tuple[str, ...]
    observation_types: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReconPlan:
    """Planner의 판단 결과. Store에 쓰는 것은 recon.py의 책임이다."""

    ranked_surface_ids: tuple[str, ...]
    action: Literal["continue", "stop"]
    reason: str
    dropped_for_budget: tuple[str, ...]
    rejected_surface_ids: tuple[str, ...]
    source: Literal["llm", "deterministic_fallback"]


class ReconPlanner(Protocol):
    def plan(
        self,
        *,
        task: TaskEnvelope,
        candidates: tuple[ReconCandidate, ...],
        remaining_budget: int,
    ) -> ReconPlan: ...


def recon_plan_status_detail(plan: ReconPlan) -> str:
    """진행 이벤트에 실을 수 있는 고정된 Planner 상태를 만든다.

    LLM의 자유 텍스트 ``reason``이나 예외 메시지는 진행 화면에 내보내지 않는다.
    fallback 원인은 코드가 만든 분류값으로만 축약해 비밀·응답 원문이 로그로 새는
    경로를 만들지 않는다.
    """

    return _status_detail(plan.source, plan.reason)


def recon_plan_status_from_observation(
    observation: Mapping[str, object],
) -> str | None:
    """저장된 ``recon_plan`` Evidence에서 안전한 표시 상태만 복원한다."""

    if observation.get("type") != _PLAN_OBSERVATION:
        return None
    source = observation.get("selection_source")
    reason = observation.get("reason")
    if source not in ("llm", "deterministic_fallback") or not isinstance(reason, str):
        return None
    return _status_detail(source, reason)


def _status_detail(source: object, reason: str) -> str:
    if source == "llm":
        return f"{RECON_PLANNER_STATUS_PREFIX}llm_success"

    if reason == "no remaining recon budget":
        label = "no_budget"
    elif reason.startswith("llm_call_failed:LlmTimeout"):
        label = "timeout"
    elif reason.startswith("llm_call_failed:LlmTransportError"):
        label = "transport_error"
    elif reason.startswith("llm_call_failed:LlmResponseFormatError"):
        label = "invalid_response"
    elif reason.startswith("llm_call_failed:LlmRefused"):
        label = "refused"
    elif reason.startswith("invalid_llm_plan:"):
        label = "invalid_response"
    else:
        label = "unknown"
    return f"{RECON_PLANNER_STATUS_PREFIX}fallback:{label}"


class _InvalidReconPlan(ValueError):
    """Planner 출력의 **구조** 자체가 깨졌을 때만 발생한다.

    존재하지 않는 ID나 중복 ID는 이 예외를 쓰지 않는다 — 그 항목만 버리고 계속
    진행한다(항목 위반). 이 예외는 구조 위반(리스트가 아니거나 원소가 문자열이 아님,
    action/reason의 타입·값이 잘못됨)에만 쓰고, `LlmReconPlanner.plan()` 안에서만
    잡혀 전체 deterministic fallback으로 바뀐다 — `ReconAgent` 밖으로 전파되지 않는다.
    """


class LlmReconPlanner:
    """LLM 순서 힌트와 결정적 fallback을 함께 제공하되 Store에 쓰지 않는다."""

    def __init__(self, *, llm_client: LlmClient) -> None:
        self._llm = llm_client

    def plan(
        self,
        *,
        task: TaskEnvelope,
        candidates: tuple[ReconCandidate, ...],
        remaining_budget: int,
    ) -> ReconPlan:
        if remaining_budget <= 0:
            # 방문할 예산이 없다는 사실 자체가 결정적이므로 LLM을 부를 필요가 없다.
            return ReconPlan(
                ranked_surface_ids=(),
                action="continue",
                reason="no remaining recon budget",
                dropped_for_budget=tuple(candidate.surface_id for candidate in candidates),
                rejected_surface_ids=(),
                source="deterministic_fallback",
            )

        offered = tuple(candidate.surface_id for candidate in candidates)
        try:
            response = self._llm.complete(
                LlmRequest(
                    messages=(
                        LlmMessage(
                            role="user",
                            content=_prompt(candidates, remaining_budget),
                        ),
                    ),
                    system=_PLAN_SYSTEM,
                    response_schema=_PLAN_SCHEMA,
                    timeout_seconds=task.timeout_seconds,
                )
            )
        except (LlmTimeout, LlmTransportError, LlmResponseFormatError, LlmRefused) as exc:
            # LlmCredentialsMissing은 일부러 잡지 않는다 — 키가 없어서 조용히
            # 휴리스틱으로 돌았는데 LLM 결과인 줄 아는 오독을 막아야 한다.
            return _deterministic_fallback(
                candidates, reason=f"llm_call_failed:{type(exc).__name__}"
            )

        try:
            return _parse_plan(response.payload, offered, remaining_budget)
        except _InvalidReconPlan as exc:
            return _deterministic_fallback(candidates, reason=f"invalid_llm_plan:{exc}")


def _prompt(candidates: tuple[ReconCandidate, ...], remaining_budget: int) -> str:
    lines = [f"Remaining request budget: {remaining_budget}", "Candidates:"]
    for candidate in candidates:
        parameters = ", ".join(
            alias_parameter_names(candidate.parameter_names).prompt_names
        ) or "(none)"
        observations = ", ".join(candidate.observation_types) or "(none)"
        lines.append(
            f"- surface_id={candidate.surface_id} method={candidate.method} "
            f"path={candidate.path} parameters=[{parameters}] observations=[{observations}]"
        )
    lines.append(
        "Select which surface_id values are worth visiting next, ranked most valuable first."
    )
    return "\n".join(lines)


def _parse_plan(
    payload: object, offered: tuple[str, ...], remaining_budget: int
) -> ReconPlan:
    if not isinstance(payload, dict):
        raise _InvalidReconPlan("llm recon plan response was not a json object")

    action = payload.get("action")
    reason = payload.get("reason")
    if action not in ("continue", "stop"):
        raise _InvalidReconPlan("recon plan action must be 'continue' or 'stop'")
    if not isinstance(reason, str):
        raise _InvalidReconPlan("recon plan reason must be a string")

    # action과 무관하게 구조 검증은 항상 돈다 — stop이라고 ranked_surface_ids의 모양이
    # 깨져도 되는 게 아니다. 구조 위반은 stop이든 continue든 똑같이 전체 fallback으로
    # 넘어가야 한다(_InvalidReconPlan은 여기서 잡지 않고 plan()까지 그대로 전파한다).
    selected, dropped_for_budget, rejected = _validate_recon_selection(
        payload.get("ranked_surface_ids"), offered, remaining_budget
    )

    if action == "stop":
        # stop이면 유효했던 선택도 방문하지 않는다(계약 §3.4). 다만 무엇을 거부·절삭
        # 했는지는 감사를 위해 그대로 남긴다.
        return ReconPlan(
            ranked_surface_ids=(),
            action="stop",
            reason=reason,
            dropped_for_budget=dropped_for_budget,
            rejected_surface_ids=rejected,
            source="llm",
        )

    return ReconPlan(
        ranked_surface_ids=selected,
        action="continue",
        reason=reason,
        dropped_for_budget=dropped_for_budget,
        rejected_surface_ids=rejected,
        source="llm",
    )


def _validate_recon_selection(
    raw: object,
    offered: tuple[str, ...],
    remaining_budget: int,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """LLM의 순서 선택을 실제 후보와 남은 예산 안으로 제한한다.

    Analysis용 ``validate_probe_selection()``과 달리 구조 위반과 항목 위반을 구분한다.

        구조 위반(리스트가 아님, 원소가 문자열이 아님) → ``_InvalidReconPlan``을 올려
            전체 deterministic fallback으로 넘긴다.
        항목 위반(후보에 없는 ID, 이미 선택된 ID의 중복) → 그 항목만
            ``rejected_surface_ids``로 버리고 계속 진행한다. Recon 선택은 실행 값이
            아니라 이미 발견된 Surface의 순서 힌트이므로, 개별 항목이 잘못됐다고
            나머지 유효한 선택까지 버릴 이유가 없다.

    Analysis의 ``validate_probe_selection()``은 control 요청 한 자리를 남기려 예산에서
    1을 뺀다. Recon에는 control 개념이 없으므로 남은 예산을 그대로 쓴다.
    """

    if not isinstance(raw, list):
        raise _InvalidReconPlan("ranked_surface_ids must be a list")

    selected: list[str] = []
    rejected: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            raise _InvalidReconPlan("ranked_surface_ids must contain only strings")
        if item not in offered or item in selected:
            rejected.append(item)
            continue
        selected.append(item)

    affordable = max(remaining_budget, 0)
    if len(selected) <= affordable:
        return tuple(selected), (), tuple(rejected)
    return tuple(selected[:affordable]), tuple(selected[affordable:]), tuple(rejected)


def _deterministic_fallback(
    candidates: tuple[ReconCandidate, ...], *, reason: str
) -> ReconPlan:
    """LLM을 못 믿을 때 기존 FIFO 순서 전체를 그대로 돌려준다.

    예산 절삭은 하지 않는다 — ``recon.py``의 ``crawl()``이 어차피 ``page_budget``에서
    스스로 멈추므로, 여기서 잘라내지 않아도 예산을 넘겨 쓰지 않는다.
    """

    return ReconPlan(
        ranked_surface_ids=tuple(candidate.surface_id for candidate in candidates),
        action="continue",
        reason=reason,
        dropped_for_budget=(),
        rejected_surface_ids=(),
        source="deterministic_fallback",
    )


def _restored_string_tuple(value: object) -> tuple[str, ...] | None:
    """저장된 Evidence 필드가 문자열 리스트일 때만 복원한다. 그 외엔 손상으로 본다."""

    if not isinstance(value, list):
        return None
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            return None
        result.append(item)
    return tuple(result)


def find_stored_recon_plan(
    evidence: Sequence[Evidence], offered_surface_ids: tuple[str, ...]
) -> tuple[ReconPlan, str] | None:
    """재개 시 같은 후보 집합에 대한 유효한 recon_plan Evidence를 복원한다.

    ``offered_surface_ids``가 저장된 계획의 것과 정확히 같을 때만 재사용한다 — 후보
    집합이나 순서가 달라졌으면 예전 계획을 지금 후보에 잘못 적용하게 된다.

    저장된 Evidence는 이 프로세스가 쓴 게 아닐 수도 있는 영속 데이터다. 필드 타입이
    깨졌거나, ``ranked_surface_ids``가 지금 후보 밖 ID·중복을 담고 있거나, ``stop``인데
    ``ranked_surface_ids``가 비어 있지 않으면 신뢰하지 않고 건너뛴다 — 그 기록은 못 쓴
    셈 치고 더 오래된 기록을 계속 찾다가, 끝까지 없으면 ``None``을 돌려줘 호출자가 새
    계획을 만들게 한다.
    """

    offered_set = set(offered_surface_ids)
    for item in reversed(evidence):
        observation = item.observation
        offered_in_evidence = observation.get("offered_surface_ids")
        if (
            item.created_by != RECON_PLANNER
            or observation.get("type") != _PLAN_OBSERVATION
            or not isinstance(offered_in_evidence, list)
            or tuple(offered_in_evidence) != offered_surface_ids
        ):
            continue

        action = observation.get("action")
        reason = observation.get("reason")
        source = observation.get("selection_source")
        if (
            action not in ("continue", "stop")
            or not isinstance(reason, str)
            or source not in ("llm", "deterministic_fallback")
        ):
            continue

        ranked = _restored_string_tuple(observation.get("ranked_surface_ids"))
        dropped = _restored_string_tuple(observation.get("dropped_for_budget"))
        rejected = _restored_string_tuple(observation.get("rejected_surface_ids"))
        if ranked is None or dropped is None or rejected is None:
            continue
        if action == "stop":
            if ranked:
                continue  # stop인데 ranked가 비어있지 않으면 손상된 기록이다.
        elif len(set(ranked)) != len(ranked) or any(
            surface_id not in offered_set for surface_id in ranked
        ):
            continue  # 중복이거나 지금 후보 밖 ID가 섞여 있다.

        return (
            ReconPlan(
                ranked_surface_ids=ranked,
                action=action,
                reason=reason,
                dropped_for_budget=dropped,
                rejected_surface_ids=rejected,
                source=source,
            ),
            item.evidence_id,
        )
    return None


def build_recon_plan_observation(
    plan: ReconPlan, offered_surface_ids: tuple[str, ...]
) -> dict[str, object]:
    """recon.py가 저장할 Evidence.observation payload를 계약(§3.6)대로 만든다."""

    return {
        "type": _PLAN_OBSERVATION,
        "ranked_surface_ids": list(plan.ranked_surface_ids),
        "action": plan.action,
        "reason": plan.reason,
        "offered_surface_ids": list(offered_surface_ids),
        "dropped_for_budget": list(plan.dropped_for_budget),
        "rejected_surface_ids": list(plan.rejected_surface_ids),
        "selection_source": plan.source,
    }
