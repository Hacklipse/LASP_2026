"""실행 중인 로컬 DynAST-Bench 앱을 정답 없이 자동 탐색한다.

기본값: auto/base-url, browser Recon, heuristic, 요청 상한 80.
보고서와 판단 로그는 artifacts/dynast-bench/에 실행별 파일로 저장한다.
대상 기동·초기화는 dynast-bench CLI에서 별도로 수행한다.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# 공용 auto 실행 경로를 재사용하며 Juice Shop의 계정 준비/seed 모드는 노출하지 않는다.
from run_juice_shop_baseline import main as run_auto  # noqa: E402
from dynast_scoring import write_dynast_documents  # noqa: E402

DEFAULT_ARTIFACT_DIRECTORY = Path("artifacts/dynast-bench")


def _configure_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--app", help="DynAST app name for scorer export")
    parser.add_argument("--variant", choices=("vuln", "safe"),
                        help="explicit target twin for scorer export")
    parser.add_argument("--anonymous", action="store_true",
                        help="run without prompting for a target session Cookie")
    parser.add_argument("--session-cookie-stdin", action="store_true",
                        help="read a target session Cookie from stdin without terminal prompting")
    parser.add_argument("--session-authorization-stdin", action="store_true",
                        help="read a target Bearer authorization from stdin without recording it")
    parser.add_argument("--owner-session-cookie-stdin", action="store_true",
                        help="read a second local principal Cookie from stdin for independent access checks")
    parser.add_argument("--access-actor-object-id")
    parser.add_argument("--access-owner-object-id")


def _validate_args(args: argparse.Namespace) -> str | None:
    if bool(args.app) != bool(args.variant):
        return "채점 파일을 만들려면 --app과 --variant를 함께 지정해야 합니다."
    if args.app and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", args.app) is None:
        return "--app은 짧은 소문자 DynAST 앱 이름이어야 합니다."
    if args.app and not args.code_version:
        return "채점 파일에는 비교 가능한 --code-version이 필요합니다."
    if sum((args.anonymous, args.session_cookie_stdin, args.session_authorization_stdin)) > 1:
        return "익명, Cookie, Bearer 세션 모드는 하나만 선택할 수 있습니다."
    if args.session_authorization_stdin and args.owner_session_cookie_stdin:
        return "Bearer 세션은 Cookie 기반 두 주체 검사와 함께 사용할 수 없습니다."
    dual = (
        args.owner_session_cookie_stdin,
        args.access_actor_object_id is not None,
        args.access_owner_object_id is not None,
    )
    if any(dual):
        if not all(dual) or not args.session_cookie_stdin:
            return "두 주체 검사는 두 Cookie와 actor/owner 객체 ID를 함께 요구합니다."
        if not all(
            re.fullmatch(r"[1-9][0-9]{0,9}", value)
            for value in (args.access_actor_object_id, args.access_owner_object_id)
        ) or args.access_actor_object_id == args.access_owner_object_id:
            return "두 주체의 객체 ID는 서로 다른 양의 숫자여야 합니다."
    return None


def _on_completed(args: argparse.Namespace, app, run) -> None:
    if not args.app:
        return
    findings, endpoints = write_dynast_documents(
        app, run, app_name=args.app, variant=args.variant,
        report_path=args.report_out,
    )
    print(f"DynAST 채점 입력: {findings} · {endpoints}")


def main(argv: list[str]) -> int:
    return run_auto(
        argv,
        auto_runner_name="DynAST-Bench",
        artifact_directory=DEFAULT_ARTIFACT_DIRECTORY,
        configure_parser=_configure_parser,
        validate_args=_validate_args,
        on_completed=_on_completed,
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
