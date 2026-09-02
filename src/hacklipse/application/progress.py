"""Store에서 Run 진행 상태를 계산한다.

진행 상태를 따로 누적하지 않고 매번 Store에서 다시 센다. 누적하면 실제 저장 내용과
어긋날 수 있고, 어긋난 쪽이 "완료"를 표시하면 검사되지 않은 항목이 검사된 것처럼
보인다. 계산 비용보다 이 오류의 대가가 크다.

여기서 만드는 것은 숫자와 식별자뿐이다. 문구·색·기호는 CLI나 웹 UI가 정한다.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from hacklipse.domain import (
    Candidate,
    CandidateStatus,
    ProgressSnapshot,
    Run,
    UncheckedCandidate,
)
from hacklipse.ports import BudgetManager

# 판정까지 끝난 Candidate 상태. Validation이 verdict 값을 그대로 상태로 쓴다.
_VALIDATED_STATUSES = frozenset(
    {
        CandidateStatus.CONFIRMED,
        CandidateStatus.REJECTED,
        CandidateStatus.SUSPECTED,
        CandidateStatus.BLOCKED,
    }
)
# 검사를 끝내지 못한 상태. "검사했는데 없었다"와 구분해서 보여줘야 한다.
_UNCHECKED_STATUSES = frozenset(
    {
        CandidateStatus.FAILED,
        CandidateStatus.SKIPPED_BUDGET,
        CandidateStatus.BLOCKED,
    }
)


def build_progress_snapshot(
    run: Run,
    *,
    stores,
    budget: BudgetManager | None = None,
    llm_calls: int = 0,
    llm_input_tokens: int = 0,
    llm_output_tokens: int = 0,
) -> ProgressSnapshot:
    """현재 Store 내용으로 Run 진행 상태를 계산한다.

    LLM 사용량은 Store에 남지 않으므로 호출자가 계측값을 넘긴다. prompt나 응답 본문은
    받지 않고 숫자만 받는다.
    """

    surfaces = stores.surfaces.list_by_run(run.run_id)
    candidates = stores.candidates.list_by_run(run.run_id)
    evidence = stores.evidence.list_by_run(run.run_id)
    findings = stores.findings.list_by_run(run.run_id)

    parameters = {
        name for surface in surfaces for name in surface.parameters
    }
    # Analysis가 남긴 Observation만 신호로 센다. Runtime이 저장한 응답 Evidence는
    # 요청 수이지 탐지 결과가 아니다.
    signals = Counter(
        str(item.observation.get("type"))
        for item in evidence
        if item.evidence_type == "observation" and item.observation.get("type")
    )

    return ProgressSnapshot(
        run_id=run.run_id,
        phase=run.phase.value,
        surface_count=len(surfaces),
        parameter_count=len(parameters),
        candidates_by_type=_counted(item.vulnerability_type for item in candidates),
        candidates_by_status=_counted(item.status.value for item in candidates),
        evidence_count=len(evidence),
        signals_by_type=tuple(sorted(signals.items())),
        validated_count=sum(
            1 for item in candidates if item.status in _VALIDATED_STATUSES
        ),
        findings_by_type=_counted(item.vulnerability_type for item in findings),
        budget_used=_budget_used(run, budget),
        budget_total=run.request_budget,
        llm_calls=llm_calls,
        llm_input_tokens=llm_input_tokens,
        llm_output_tokens=llm_output_tokens,
        unchecked=_unchecked(candidates),
        last_error=run.last_error,
    )


def _counted(values) -> tuple[tuple[str, int], ...]:
    """세어서 개수 내림차순, 같은 개수는 이름순으로 정렬한다."""

    counts = Counter(values)
    return tuple(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def _budget_used(run: Run, budget: BudgetManager | None) -> int:
    if budget is None:
        return 0
    try:
        return max(0, run.request_budget - budget.remaining(run.run_id))
    except Exception:
        # 예산 기록이 없는 Run(재개 전, 테스트 대역)에서도 나머지 진행 상태는 보여준다.
        return 0


def _unchecked(candidates: Sequence[Candidate]) -> tuple[UncheckedCandidate, ...]:
    return tuple(
        UncheckedCandidate(
            vulnerability_type=item.vulnerability_type,
            status=item.status.value,
            reason=item.last_error,
        )
        for item in candidates
        if item.status in _UNCHECKED_STATUSES
    )
