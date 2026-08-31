"""로컬 대상 1회 Run을 실행하고 A/B 비교용 지표를 출력한다.

마일스톤 A는 Finding이 구조적으로 0개다(CONFIRMED에 ValidationProof가 필요하고 그걸
만드는 코드가 아직 없다). 따라서 A와 B를 Finding 개수로 비교할 수 없고, 아래 지표로
비교한다 — 발견 Surface 수, Candidate 분포, reflection 신호 수, 총 요청 수,
신호 1개당 요청 수.

대상은 로컬 컨테이너로 한정한다(계획서 "대상 범위"). allowed_hosts를 localhost로 고정하며
그 밖의 호스트는 PolicyGate가 요청 전에 거부한다.

    python3 scripts/run_baseline.py http://localhost:3000/
    python3 scripts/run_baseline.py http://localhost:3000/rest/products/search?q=test
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from hacklipse.adapters import HttpExecutionRuntime  # noqa: E402
from hacklipse.application.errors import WorkflowExecutionError  # noqa: E402
from hacklipse.bootstrap import (  # noqa: E402
    build_local_application,
    register_standard_agents,
    standard_router,
)
from hacklipse.domain import RunRequest, RunScope  # noqa: E402

# 로컬 대상만 허용한다. 실서비스나 외부 대상으로 옮기려면 별도 인가 확인이 선행되어야 한다.
ALLOWED_HOSTS = frozenset({"localhost", "127.0.0.1"})
DEFAULT_BUDGET = 40


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    target = argv[1]
    budget = int(argv[2]) if len(argv) > 2 else DEFAULT_BUDGET

    host = (urlsplit(target).hostname or "").casefold()
    if host not in ALLOWED_HOSTS:
        print(f"거부: {host!r}는 로컬 대상이 아니다. 허용: {sorted(ALLOWED_HOSTS)}")
        return 2

    app = build_local_application(
        {}, runtime=HttpExecutionRuntime(), router=standard_router()
    )
    profile = register_standard_agents(app)  # llm_client 없음 → 대조군

    print(f"대상   {target}")
    print(f"구성   {profile}")
    print(f"예산   {budget} 요청\n")

    try:
        run = app.orchestrator.start(
            RunRequest(
                target_url=target,
                scope=RunScope(allowed_hosts=ALLOWED_HOSTS),
                request_budget=budget,
            )
        )
    except WorkflowExecutionError as error:
        print(f"Run 실패: {error}")
        return 1

    _report(app, run, profile, target, budget)
    return 0


def _report(app, run, profile: str, target: str, budget: int) -> None:
    surfaces = app.stores.surfaces.list_by_run(run.run_id)
    candidates = app.stores.candidates.list_by_run(run.run_id)
    evidence = app.stores.evidence.list_by_run(run.run_id)
    findings = app.stores.findings.list_by_run(run.run_id)
    tasks = app.stores.tasks.list_by_run(run.run_id)

    reflections = [e for e in evidence if e.observation.get("type") == "reflection"]
    http_evidence = [e for e in evidence if e.created_by.startswith("execution_runtime:")]
    used = budget - app.budget_manager.remaining(run.run_id)

    print(f"phase                 {run.phase.value}")
    print(f"발견 Surface          {len(surfaces)}")
    print(f"Candidate             {len(candidates)}  {dict(Counter(c.vulnerability_type for c in candidates))}")
    print(f"Candidate 상태        {dict(Counter(c.status for c in candidates))}")
    print(f"reflection 신호       {len(reflections)}")
    print(f"HTTP 요청             {used}")
    print(f"신호 1개당 요청       {used / len(reflections):.1f}" if reflections else "신호 1개당 요청       n/a (신호 0)")
    print(f"Finding               {len(findings)}")
    print(f"Task 순서             {[t.envelope.agent_type for t in tasks]}")

    if surfaces:
        print("\n--- Surface ---")
        for surface in surfaces[:15]:
            params = ",".join(surface.parameters) or "-"
            print(f"  {surface.method:4} {surface.url}  params={params}")
        if len(surfaces) > 15:
            print(f"  ... 외 {len(surfaces) - 15}개")

    if reflections:
        print("\n--- reflection 신호 ---")
        for item in reflections:
            observation = dict(item.observation)
            print(f"  {item.created_by}  {json.dumps(observation, ensure_ascii=False)}")

    print("\n--- HTTP 응답 요약 ---")
    for item in http_evidence[:10]:
        observation = item.observation
        body = observation.get("body")
        print(
            f"  {observation.get('request_kind'):8} {observation.get('status')} "
            f"{observation.get('body_bytes', 0):>7}B  {observation.get('requested_url')}"
            + ("" if isinstance(body, str) else "  (본문 비텍스트)")
        )
    if len(http_evidence) > 10:
        print(f"  ... 외 {len(http_evidence) - 10}개")

    reports = app.stores.reports.list_by_run(run.run_id)
    if reports:
        print("\n--- 보고서 ---")
        print("\n".join(f"  {line}" for line in reports[0].content.splitlines()))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
