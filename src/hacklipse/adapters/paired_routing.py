"""한 Recon 결과를 두 Router에 제공한다. 선택한 Router의 후보만 실제 분석한다."""

from __future__ import annotations

from collections.abc import Sequence

from hacklipse.domain import Evidence, RouteDecision, Run, Surface
from hacklipse.ports.agents import VulnerabilityRouter


class PairedVulnerabilityRouter:
    """서버를 다시 탐색하지 않고 같은 Run/Surface/Evidence 순서로 비교한다.

    Shadow 결과는 저장·실행하지 않는다. 외부 요청과 Findings는 primary에만 귀속된다.
    두 Router의 audit sink는 같은 입력 지문과 서로 다른 mode로 각각 기록한다.
    """

    def __init__(
        self, *, heuristic: VulnerabilityRouter, hybrid: VulnerabilityRouter, primary: str,
    ) -> None:
        if primary not in {"heuristic", "hybrid"}:
            raise ValueError("primary router must be heuristic or hybrid")
        self.heuristic = heuristic
        self.hybrid = hybrid
        self.primary = primary

    def route(
        self, run: Run, surfaces: Sequence[Surface], evidence: Sequence[Evidence],
    ) -> tuple[RouteDecision, ...]:
        surfaces, evidence = tuple(surfaces), tuple(evidence)
        baseline = self.heuristic.route(run, surfaces, evidence)
        assisted = self.hybrid.route(run, surfaces, evidence)
        return baseline if self.primary == "heuristic" else assisted
