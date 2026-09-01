"""로컬 OWASP Juice Shop 프로필에서 고정 산술식 SSTI 검증을 실행한다.

브라우저에 로그인한 전용 실습 계정의 ``token`` Cookie 값을 숨김 입력으로 받는다.
토큰은 CredentialResolver 메모리에만 존재하며 Task·Evidence·감사 로그·LLM prompt에는
들어가지 않는다. 실행은 username을 일시적으로 바꾸고 마지막에 고정된 안전 이름으로
정리하므로 개인 계정이 아닌 폐기 가능한 로컬 실습 계정을 사용해야 한다.

    py scripts/run_juice_shop_baseline.py http://127.0.0.1:3000/
    py scripts/run_juice_shop_baseline.py http://127.0.0.1:3000/ --profile llm --debug-llm-content
"""

from __future__ import annotations

import argparse
import getpass
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urljoin, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from hacklipse.adapters import (  # noqa: E402
    HttpExecutionRuntime,
    InMemoryCredentialResolver,
    InMemoryExecutionAuditLog,
    StaticApprovalGate,
)
from hacklipse.adapters.ssti_analysis import (  # noqa: E402
    SSTI_APPROVAL_REF,
    SSTI_CLEANUP_VALUE,
    SSTI_OBSERVATION,
)
from hacklipse.application.errors import WorkflowExecutionError  # noqa: E402
from hacklipse.bootstrap import (  # noqa: E402
    DEFAULT_ANTHROPIC_LLM_MODEL,
    DEFAULT_GEMINI_LLM_MODEL,
    build_gemini_llm_client_from_env,
    build_llm_client_from_env,
    build_local_application,
    register_standard_agents,
    standard_router,
)
from hacklipse.domain import RunRequest, RunScope  # noqa: E402
from hacklipse.ports import ResolvedHttpCredential  # noqa: E402
from hacklipse.ports.errors import LlmCredentialsMissing  # noqa: E402

# 기존 DVWA 실행기와 같은 안전한 디버그 출력 구현을 재사용한다. 이 모듈은 main guard가
# 있어 import만으로 실행되지 않는다.
from run_dvwa_baseline import (  # noqa: E402
    _DebugAuditLog,
    _DebugProgress,
    _ProgressLlmClient,
    _safe_log_value,
)

_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1"})
_CREDENTIAL_REF = "interactive-local-juice-shop"
_DEFAULT_BUDGET = 20


def _format_counts(counts: Counter[str]) -> str:
    if not counts:
        return "없음"
    return ", ".join(f"{name} {count}개" for name, count in counts.items())


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_url", help="localhost/127.0.0.1 Juice Shop base URL")
    parser.add_argument(
        "--profile",
        choices=("heuristic", "llm"),
        default="heuristic",
        help="analysis profile (default: heuristic)",
    )
    parser.add_argument(
        "--llm-provider",
        choices=("gemini", "anthropic"),
        default="gemini",
        help="LLM provider used with --profile llm (default: gemini)",
    )
    parser.add_argument("--llm-model", help="provider model id")
    parser.add_argument("--debug", action="store_true", help="안전한 진행 로그 출력")
    parser.add_argument(
        "--debug-llm-content",
        action="store_true",
        help="LLM prompt와 구조화 응답 출력",
    )
    args = parser.parse_args(argv[1:])

    base_url = args.base_url.rstrip("/") + "/"
    parsed = urlsplit(base_url)
    host = (parsed.hostname or "").casefold()
    if parsed.scheme not in {"http", "https"} or host not in _LOCAL_HOSTS:
        print("거부: 이 실행기는 localhost/127.0.0.1의 Juice Shop만 허용합니다.")
        return 2
    target_url = urljoin(base_url, "profile")

    debug_enabled = args.debug or args.debug_llm_content
    progress = _DebugProgress(debug_enabled)
    llm_client = None
    selected_model = ""
    if args.profile == "llm":
        selected_model = args.llm_model or (
            DEFAULT_GEMINI_LLM_MODEL
            if args.llm_provider == "gemini"
            else DEFAULT_ANTHROPIC_LLM_MODEL
        )
        try:
            if args.llm_provider == "gemini":
                llm_client = build_gemini_llm_client_from_env(model=selected_model)
            else:
                llm_client = build_llm_client_from_env(model=selected_model)
        except LlmCredentialsMissing as error:
            print(f"LLM 구성 실패: {error}")
            return 2
        if debug_enabled:
            llm_client = _ProgressLlmClient(
                llm_client,
                provider=args.llm_provider,
                model=selected_model,
                progress=progress,
                show_content=args.debug_llm_content,
            )
        progress.log(
            f"LLM 구성 완료: provider={_safe_log_value(args.llm_provider)}, "
            f"model={_safe_log_value(selected_model)}"
        )

    print("브라우저 개발자 도구에서 로컬 Juice Shop의 token Cookie 값을 확인하세요.")
    token = getpass.getpass("Juice Shop token Cookie (숨김 입력): ").strip()
    if not token:
        print("취소: token Cookie가 비어 있습니다.")
        return 2
    print(
        "이 검증은 전용 실습 계정의 username을 control/산술식으로 변경한 뒤 "
        f"{SSTI_CLEANUP_VALUE!r}(으)로 정리합니다."
    )
    if input("로컬 Juice Shop SSTI 검증을 실행할까요? [y/N] ").strip().casefold() != "y":
        print("취소했습니다.")
        return 2

    resolver = InMemoryCredentialResolver(
        {
            _CREDENTIAL_REF: ResolvedHttpCredential(
                cookies=(("token", token),),
            )
        }
    )
    runtime = HttpExecutionRuntime(credential_resolver=resolver)
    audit = _DebugAuditLog(progress) if debug_enabled else InMemoryExecutionAuditLog()
    app = build_local_application(
        {},
        runtime=runtime,
        router=standard_router(vulnerability_types=("SSTI",)),
        credential_resolver=resolver,
        approval_gate=StaticApprovalGate((SSTI_APPROVAL_REF,)),
        audit_log=audit,
        task_progress_callback=progress.task_event if debug_enabled else None,
    )
    profile = register_standard_agents(app, llm_client=llm_client, recon_max_pages=1)
    if profile == "llm":
        profile = f"llm/{args.llm_provider} ({_safe_log_value(selected_model)})"

    base_path = parsed.path if parsed.path.endswith("/") else f"{parsed.path}/"
    try:
        progress.log(
            f"Run 시작: target=SSTI, profile={profile}, request_budget={_DEFAULT_BUDGET}"
        )
        run = app.orchestrator.start(
            RunRequest(
                target_url=target_url,
                scope=RunScope(
                    allowed_hosts=frozenset({host}),
                    allowed_path_prefixes=(base_path or "/",),
                ),
                request_budget=_DEFAULT_BUDGET,
                credential_ref=_CREDENTIAL_REF,
            )
        )
    except WorkflowExecutionError as error:
        print(f"Run 실패: {error}")
        return 1
    progress.log(f"Run 완료: phase={_safe_log_value(run.phase.value)}")

    candidates = app.stores.candidates.list_by_run(run.run_id)
    evidence = app.stores.evidence.list_by_run(run.run_id)
    findings = app.stores.findings.list_by_run(run.run_id)
    candidate_counts = Counter(item.vulnerability_type for item in candidates)
    finding_counts = Counter(item.vulnerability_type for item in findings)
    execution_signals = sum(
        1 for item in evidence if item.observation.get("type") == SSTI_OBSERVATION
    )
    verdict = (
        "CONFIRMED (취약점 확인)" if finding_counts["SSTI"] else "미확정"
    )

    print()
    print("=" * 54)
    print("  Juice Shop SSTI 실행 결과")
    print("=" * 54)
    print()
    print("[실행 정보]")
    print(f"  상태            완료 ({run.phase.value})")
    print("  분석 대상       SSTI")
    print(f"  Agent 구성      {profile}")
    print(f"  감사된 실행     {len(audit.list_by_run(run.run_id))}회")
    print()
    print("[분석 신호]")
    print(f"  Candidate       {_format_counts(candidate_counts)}")
    print(f"  템플릿 산술 실행 {execution_signals}개")
    print()
    print("[최종 판정]")
    print(f"  결과            {verdict}")
    print(f"  Finding         {len(findings)}개")
    print(f"  취약점 유형     {_format_counts(finding_counts)}")
    if not candidates:
        print()
        print("  참고: Candidate가 없으면 token이 만료됐거나 /profile 폼을 읽지 못했을 수 있습니다.")
    print("=" * 54)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
