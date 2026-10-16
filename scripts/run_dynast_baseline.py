"""실행 중인 로컬 DynAST-Bench 앱을 정답 없이 자동 탐색한다.

기본값: auto/base-url, browser Recon, heuristic, 요청 상한 80.
보고서와 판단 로그는 artifacts/dynast-bench/에 실행별 파일로 저장한다.
대상 기동·초기화는 dynast-bench CLI에서 별도로 수행한다.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# 공용 auto 실행 경로를 재사용하며 Juice Shop의 계정 준비/seed 모드는 노출하지 않는다.
from run_juice_shop_baseline import main as run_auto  # noqa: E402

DEFAULT_ARTIFACT_DIRECTORY = Path("artifacts/dynast-bench")


def main(argv: list[str]) -> int:
    return run_auto(
        argv,
        auto_runner_name="DynAST-Bench",
        artifact_directory=DEFAULT_ARTIFACT_DIRECTORY,
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
