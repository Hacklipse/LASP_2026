"""과거 KnowledgeCase를 현재 Analysis용 안전한 참고 정보로 축소한다."""

from __future__ import annotations

from collections.abc import Mapping

from hacklipse.domain import (
    Candidate,
    KnowledgeCase,
    KnowledgeHint,
    KnowledgeQuery,
    Surface,
    generalize_parameter_names,
    generalize_surface_path,
)
from hacklipse.ports import KnowledgeBase


class KnowledgeContextProvider:
    """Candidate와 구조가 가까운 과거 사례를 provenance 없이 반환한다.

    Knowledge는 현재 대상에서 관측한 Evidence가 아니다. 이 Provider는 Finding이나
    Validation을 만들지 않고, Analysis Task에 실을 읽기 전용 힌트만 만든다.
    """

    def __init__(self, knowledge_base: KnowledgeBase, *, limit: int = 3) -> None:
        if not 1 <= limit <= 10:
            raise ValueError("knowledge context limit must be between 1 and 10")
        self._knowledge = knowledge_base
        self._limit = limit

    def for_candidate(
        self, candidate: Candidate, surface: Surface
    ) -> tuple[KnowledgeHint, ...]:
        if candidate.run_id != surface.run_id:
            raise ValueError("knowledge context sources must belong to the same run")
        if candidate.surface_id != surface.surface_id:
            raise ValueError("knowledge context candidate must reference its surface")

        # 먼저 category로만 넓게 가져온 뒤 구조화 metadata로 관련성을 판정한다.
        # 자유 텍스트 점수는 GET/POST 같은 흔한 토큰 하나만 겹쳐도 무관한 Case를
        # 반환할 수 있어 현재 Surface의 재사용 경계로 쓰지 않는다.
        cases = self._knowledge.search(
            KnowledgeQuery(
                category=candidate.vulnerability_type,
                text="",
                limit=100,
            )
        )

        current_run_ref = f"run:{candidate.run_id}"
        ranked: list[tuple[int, int, KnowledgeCase]] = []
        for index, case in enumerate(cases):
            # 비정상 재처리로 현재 Run이 이미 발행된 경우에도 자기 결과를 선행 지식으로
            # 다시 먹이지 않는다.
            if current_run_ref in case.provenance_refs:
                continue
            score = _structured_relevance(case.metadata, surface)
            if score is None:
                continue
            ranked.append((-score, index, case))
        ranked.sort(key=lambda item: (item[0], item[1]))

        hints: list[KnowledgeHint] = []
        for _, _, case in ranked:
            hints.append(
                KnowledgeHint(
                    case_id=case.case_id,
                    category=case.category,
                    summary=case.summary,
                    # Run/Finding/Validation provenance는 의도적으로 복사하지 않는다.
                    metadata=dict(case.metadata),
                )
            )
            if len(hints) >= self._limit:
                break
        return tuple(hints)


def _structured_relevance(metadata: Mapping[str, str], surface: Surface) -> int | None:
    """흔한 메서드·인증 토큰만 같은 Case는 현재 Surface와 관련 없다고 본다."""

    path = generalize_surface_path(surface.url)
    method = surface.method.upper()
    parameters = set(generalize_parameter_names(surface.parameters))
    case_path = metadata.get("surface_path")
    case_method = metadata.get("surface_method", "").upper()
    case_auth = metadata.get("requires_auth")
    current_auth = "true" if surface.requires_auth else "false"
    case_parameters = _metadata_names(metadata.get("parameter_names"))
    signal_parameters = _metadata_names(metadata.get("signal_parameter_names"))

    exact_path = case_path == path
    signal_overlap = parameters.intersection(signal_parameters)
    # 같은 경로이거나, 과거에 실제 신호를 만든 이름이 현재 Surface에도 있어야 한다.
    # 단순히 둘 다 POST/unauthenticated인 것은 재사용 근거가 아니다.
    if not exact_path and not signal_overlap:
        return None

    score = 100 if exact_path else 0
    score += 20 * len(signal_overlap)
    score += 3 * len(parameters.intersection(case_parameters))
    if case_method == method:
        score += 10
    if case_auth == current_auth:
        score += 5
    return score


def _metadata_names(value: object) -> frozenset[str]:
    if not isinstance(value, str):
        return frozenset()
    return frozenset(item for item in value.split(",") if item)
