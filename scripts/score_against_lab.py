"""reflection lab 정답과 대조해 탐지 성능을 채점한다.

유명 대상(juice-shop, DVWA)에서는 정답을 모르고 학습 데이터 암기 여부도 통제할 수
없으므로 정밀도·재현율을 계산할 수 없다. 자체 대상에서만 가능하다.

    python3 targets/reflection_lab.py 8000 &        # 먼저 대상을 띄운다
    python3 scripts/score_against_lab.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import urlsplit

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

from targets.reflection_lab import GROUND_TRUTH  # noqa: E402

from hacklipse.adapters import HttpExecutionRuntime  # noqa: E402
from hacklipse.bootstrap import (  # noqa: E402
    build_local_application,
    register_standard_agents,
    standard_router,
)
from hacklipse.domain import RunRequest, RunScope  # noqa: E402

LAB_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
BUDGET = 200


def main(argv: list[str]) -> int:
    port = int(argv[1]) if len(argv) > 1 else DEFAULT_PORT
    target = f"http://{LAB_HOST}:{port}/"

    app = build_local_application(
        {}, runtime=HttpExecutionRuntime(), router=standard_router()
    )
    profile = register_standard_agents(app)  # llm_client 없음 → 대조군

    run = app.orchestrator.start(
        RunRequest(
            target_url=target,
            scope=RunScope(allowed_hosts=frozenset({LAB_HOST})),
            request_budget=BUDGET,
        )
    )

    surfaces = {s.surface_id: s for s in app.stores.surfaces.list_by_run(run.run_id)}
    detected: dict[tuple[str, str], dict] = {}
    for item in app.stores.evidence.list_by_run(run.run_id):
        if item.observation.get("type") != "reflection":
            continue
        surface = surfaces.get(item.surface_id or "")
        if surface is None:
            continue
        key = (urlsplit(surface.url).path, str(item.observation.get("parameter")))
        detected[key] = dict(item.observation)

    _score(profile, run, app, detected)
    return 0


def _score(profile: str, run, app, detected: dict) -> None:
    expected_true = {k for k, v in GROUND_TRUTH.items() if v["reflected"]}
    expected_false = {k for k, v in GROUND_TRUTH.items() if not v["reflected"]}
    found = set(detected)

    tp = sorted(found & expected_true)
    fp = sorted(found & expected_false)
    fn = sorted(expected_true - found)
    # 정답 목록에 없는 곳에서 신호가 났다면 그것도 오탐이다.
    unknown = sorted(found - expected_true - expected_false)

    precision = len(tp) / len(found) if found else 0.0
    recall = len(tp) / len(expected_true) if expected_true else 0.0

    print(f"구성            {profile}")
    print(f"phase           {run.phase.value}")
    print(f"발견 Surface    {len(app.stores.surfaces.list_by_run(run.run_id))}")
    print(f"Candidate       {len(app.stores.candidates.list_by_run(run.run_id))}")
    print(f"HTTP 요청       {BUDGET - app.budget_manager.remaining(run.run_id)}")
    print()
    print(f"정답 반사       {len(expected_true)}")
    print(f"탐지            {len(found)}")
    print(f"  TP            {len(tp)}   {[f'{p}?{q}' for p, q in tp]}")
    print(f"  FP            {len(fp)}   {[f'{p}?{q}' for p, q in fp]}")
    print(f"  FN            {len(fn)}   {[f'{p}?{q}' for p, q in fn]}")
    if unknown:
        print(f"  정답 밖       {len(unknown)}   {[f'{p}?{q}' for p, q in unknown]}")
    print()
    print(f"정밀도          {precision:.2f}")
    print(f"재현율          {recall:.2f}")

    # 맥락 분류는 LLM 구성에만 있다. 대조군은 이 축 자체를 만들지 못한다.
    classified = {k: v for k, v in detected.items() if "context" in v}
    print(f"\n맥락 분류       {len(classified)}/{len(detected)} 신호")
    if not classified:
        print("  대조군은 '반사됨'까지만 말한다. 어디에 반사됐는지는 만들지 못한다.")
        return
    correct = sum(
        1
        for key, observation in classified.items()
        if GROUND_TRUTH.get(key, {}).get("context") == observation.get("context")
    )
    print(f"  맥락 정확도   {correct}/{len(classified)}")
    for key, observation in sorted(classified.items()):
        truth = GROUND_TRUTH.get(key, {})
        mark = "✅" if truth.get("context") == observation.get("context") else "❌"
        print(
            f"  {mark} {key[0]}?{key[1]}  예측={observation.get('context')}"
            f"/enc={observation.get('encoded')}  정답={truth.get('context')}"
            f"/enc={truth.get('encoded')}"
        )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
