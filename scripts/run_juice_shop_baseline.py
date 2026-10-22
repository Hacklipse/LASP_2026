"""로컬 OWASP Juice Shop에서 다중 취약점 baseline 검증을 실행한다.

취약점마다 인증과 정리 요구가 다르다.

    SQLi            인증 없음. 읽기 전용 GET. 정리할 상태가 없다.
    SSTI            실습 계정 token Cookie. username을 바꾸므로 고정값으로 되돌린다.
    Path Traversal  임시 계정으로 서버 렌더링 폼의 고정 safe-file 읽기를 검증한다.
    Access Control  사용자가 제공한 전용 테스트 계정 두 개로 소유 객체를 교차 검증한다.
    all             한 Run에서 여러 유형을 함께 검사한다. 유형별 자격증명은 Run에
                    따로 등록되고, 등록하지 않은 유형은 자격증명 없이 실행된다.

비밀은 Task·Evidence·감사 로그·LLM prompt에 들어가지 않는다. SSTI는 username을 일시적으로
변경하므로 개인 계정이 아닌 실습 계정을 사용한다.

    py scripts/run_juice_shop_baseline.py http://127.0.0.1:3000/
    py scripts/run_juice_shop_baseline.py http://127.0.0.1:3000/ --vuln sqli
    py scripts/run_juice_shop_baseline.py http://127.0.0.1:3000/ --vuln access_control
    py scripts/run_juice_shop_baseline.py http://127.0.0.1:3000/ --vuln all
    py scripts/run_juice_shop_baseline.py http://127.0.0.1:3000/ --knowledge-db knowledge.sqlite
    py scripts/run_juice_shop_baseline.py http://127.0.0.1:3000/ --profile llm --debug-llm-content
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import secrets
import sqlite3
import sys
import warnings
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urljoin, urlsplit
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
# 같은 디렉터리의 공용 모듈을 직접 실행할 때와 tests 에서 import 할 때 모두
# 같은 이름으로 찾을 수 있게 한다.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from hacklipse.adapters import (  # noqa: E402
    HttpExecutionRuntime,
    InMemoryCredentialResolver,
    InMemoryExecutionAuditLog,
    PlaywrightBrowserRuntime,
    SlidingWindowLlmClient,
    StaticApprovalGate,
)
from hacklipse.adapters.ssti_analysis import (  # noqa: E402
    SSTI_APPROVAL_REF,
    SSTI_CLEANUP_VALUE,
    SSTI_OBSERVATION,
)
from hacklipse.adapters.path_traversal_analysis import (  # noqa: E402
    PATH_TRAVERSAL_POST_APPROVAL_REF,
)
from hacklipse.adapters.llm_recon_planner import (  # noqa: E402
    recon_plan_status_from_observation,
)
from hacklipse.adapters.llm_orchestration_advisor import LlmOrchestrationAdvisor  # noqa: E402
from hacklipse.adapters.llm_budget_allocation_advisor import LlmBudgetAllocationAdvisor  # noqa: E402
from hacklipse.adapters.reporting import build_ssrf_review_fact  # noqa: E402
from hacklipse.adapters.report_contract import SsrfReviewFact  # noqa: E402
from hacklipse.adapters.local_ssrf_callback import LocalSsrfCallbackService  # noqa: E402
from hacklipse.adapters.interactsh_callback import InteractshCliCallbackService  # noqa: E402
from hacklipse.adapters.routing_audit import JsonlRoutingAuditLog  # noqa: E402
from hacklipse.adapters.security import redacted_internal_url_path  # noqa: E402
from hacklipse.application import OrchestratorConfig, build_progress_snapshot  # noqa: E402
from hacklipse.application.errors import (  # noqa: E402
    AgentContractError,
    WorkflowExecutionError,
)
from hacklipse.adapters.knowledge import SQLiteKnowledgeBase  # noqa: E402
from hacklipse.bootstrap import (  # noqa: E402
    DEFAULT_ANTHROPIC_LLM_MODEL,
    DEFAULT_GEMINI_LLM_MODEL,
    build_gemini_llm_client_from_env,
    build_llm_client_from_env,
    build_local_application,
    register_standard_agents,
    standard_recon_planner,
)
from hacklipse.domain import (  # noqa: E402
    CandidateStatus,
    DomainInvariantError,
    EvidenceRequest,
    HttpRequestSpec,
    Run,
    RunRequest,
    RunScope,
    SsrfCanaryProofTarget,
    SsrfDestinationPolicy,
    SsrfDestinationRule,
    SsrfExecutionApproval,
    SsrfPolicyAssertion,
    SsrfPolicyEvidenceStatus,
    SsrfPolicySource,
    SsrfVerificationStrategy,
    ValidationReasonCode,
    ssrf_destination_origin,
    validate_ssrf_opaque_reference,
)
from hacklipse.ports import ResolvedHttpCredential  # noqa: E402
from hacklipse.ports.errors import LlmCredentialsMissing  # noqa: E402

# 기존 DVWA 실행기와 같은 안전한 디버그 출력 구현을 재사용한다. 이 모듈은 main guard가
# 있어 import만으로 실행되지 않는다.
from progress_view import RunProgressView, format_recon_planner_status  # noqa: E402
from routing_options import (  # noqa: E402
    add_routing_arguments,
    assemble_with_ssrf_cleanup,
    close_ssrf_services,
    NoLlmUsage,
    append_run_result,
    build_run_router,
    write_report_artifact,
    execution_profile_from_args,
    needs_llm,
)
from run_dvwa_baseline import (  # noqa: E402
    _DebugAuditLog,
    _DebugProgress,
    _LlmUsageMeter,
    _ProgressLlmClient,
    _safe_log_value,
)

_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1"})
_CREDENTIAL_REF = "interactive-local-juice-shop"
_AUTO_SESSION_CREDENTIAL_REF = "interactive-local-juice-shop-auto-session"
_AUTO_OWNER_CREDENTIAL_REF = "local-auto-owner-session"
_ACTOR_CREDENTIAL_REF = "interactive-local-juice-shop-actor"
_OWNER_CREDENTIAL_REF = "interactive-local-juice-shop-owner"
_RECON_CREDENTIAL_REF = "temporary-local-juice-shop-recon"
_PATH_TRAVERSAL_CREDENTIAL_REF = "temporary-local-juice-shop-path-traversal"
_TEMP_SSTI_CREDENTIAL_REF = "temporary-local-juice-shop-ssti"
_PROVISION_SESSION_REF = "temporary-local-juice-shop-provisioning-session"
_PROVISION_APPROVAL_REF = "interactive-local-juice-shop-account-provisioning"
_ACCESS_LOGIN_APPROVAL_REF = "interactive-local-juice-shop-access-login"
_STATE_CHANGING_APPROVAL_REF = "interactive-local-juice-shop-state-changing"
_DEFAULT_BUDGET = 20
# 전체 모드는 Recon 크롤링과 여러 Candidate 분석을 한 Run에서 감당해야 한다. 정확한
# 배분은 Task 3(Budget·스케줄링)에서 다루고, 여기서는 우선 상한만 넉넉히 잡는다.
_ALL_MODE_BUDGET = 80
_ALL_MODE_RECON_PAGES = 12
# 공급자 상한 15 RPM을 꽉 채우지 않고 한 슬롯을 남긴다. 이 프로세스 밖에서 발생한
# 호출이나 공급자 집계 경계의 오차 때문에 15번째가 429가 되는 일을 줄인다.
_DEFAULT_GEMINI_RPM_LIMIT = 14
_OBJECT_ID = re.compile(r"^[0-9]{1,10}$")
_KNOWLEDGE_DIRECTORY = Path("knowledge")
_MAX_SESSION_COOKIE_LENGTH = 16_384
_MAX_SESSION_COOKIE_COUNT = 64
_MAX_SESSION_AUTHORIZATION_LENGTH = 8192
_OPAQUE_SSRF_REVIEW_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:#-]{0,199}\Z")


def _parse_session_cookie(value: str) -> ResolvedHttpCredential:
    """브라우저에서 복사한 Cookie 헤더 값을 메모리 credential로 변환한다.

    원문은 예외 메시지나 로그에 포함하지 않는다. ``Cookie:`` 접두사는 편의를 위해
    허용하지만, 임의 헤더 전체가 아니라 이름/값 쌍만 받는다.
    """

    raw = value.strip()
    if raw.casefold().startswith("cookie:"):
        raw = raw.split(":", 1)[1].strip()
    if not raw:
        raise ValueError("세션 Cookie가 비어 있습니다")
    if len(raw) > _MAX_SESSION_COOKIE_LENGTH:
        raise ValueError("세션 Cookie가 허용 길이를 초과했습니다")
    pairs: list[tuple[str, str]] = []
    for part in raw.split(";"):
        item = part.strip()
        if not item:
            continue
        if "=" not in item:
            raise ValueError("세션 Cookie는 name=value 형식이어야 합니다")
        name, cookie_value = item.split("=", 1)
        name = name.strip()
        cookie_value = cookie_value.strip()
        if not name or not cookie_value:
            raise ValueError("세션 Cookie 이름과 값은 비어 있을 수 없습니다")
        pairs.append((name, cookie_value))
    if not pairs:
        raise ValueError("세션 Cookie에 name=value 항목이 없습니다")
    if len(pairs) > _MAX_SESSION_COOKIE_COUNT:
        raise ValueError("세션 Cookie 항목 수가 허용 범위를 초과했습니다")
    try:
        return ResolvedHttpCredential(cookies=tuple(pairs))
    except ValueError as error:
        raise ValueError("세션 Cookie 형식이 올바르지 않습니다") from error


def _prompt_optional_session_cookie(
    *, password_fn=None,
) -> ResolvedHttpCredential | None:
    """auto Run용 로그인 Cookie를 숨김 입력으로 받고, 빈 입력은 익명 실행으로 둔다."""

    password_fn = getpass.getpass if password_fn is None else password_fn
    value = password_fn(
        "로그인 세션 Cookie (선택, name=value 형식, 익명 실행은 Enter): "
    )
    if not value.strip():
        return None
    return _parse_session_cookie(value)


def _read_session_cookie_stdin() -> ResolvedHttpCredential:
    """Consume the explicitly requested credential from a private stdin pipe."""

    value = sys.stdin.readline(_MAX_SESSION_COOKIE_LENGTH + 2)
    if not value:
        raise ValueError("stdin에 로그인 세션 Cookie가 없습니다")
    return _parse_session_cookie(value)


def _read_session_authorization_stdin() -> ResolvedHttpCredential:
    """Read a bearer credential for the target origin without recording it."""

    value = sys.stdin.readline(_MAX_SESSION_AUTHORIZATION_LENGTH + 2).strip()
    if value.casefold().startswith("authorization:"):
        value = value.split(":", 1)[1].strip()
    if (
        len(value) > _MAX_SESSION_AUTHORIZATION_LENGTH
        or re.fullmatch(r"Bearer [A-Za-z0-9._~-]{1,8000}", value) is None
    ):
        raise ValueError("세션 Authorization은 Bearer 토큰 형식이어야 합니다")
    return ResolvedHttpCredential(authorization=value)


def _recon_planner_summary(evidence) -> str | None:
    """가장 최근 Recon 계획을 최종 결과용 안전 문구로 바꾼다."""

    for item in reversed(tuple(evidence)):
        if (
            item.created_by != "llm_recon_planner"
            or item.evidence_type != "observation"
        ):
            continue
        detail = recon_plan_status_from_observation(item.observation)
        if detail is not None:
            return format_recon_planner_status(detail)
    return None


def _knowledge_database_path(value: str) -> Path:
    """파일명만 받은 DB와 SQLite sidecar를 전용 디렉터리에 모은다."""

    path = Path(value)
    if path.parent == Path("."):
        return _KNOWLEDGE_DIRECTORY / path.name
    return path


def _print_execution_preview(
    args: argparse.Namespace,
    *,
    target_label: str,
    selected_model: str,
    rpm_limit: int | None,
    runner_name: str = "Juice Shop",
) -> None:
    """실행 직전 설정과 통합 검사의 안전 조치를 읽기 쉽게 표시한다."""

    run_all = args.vuln == "all"
    auto_scan = args.vuln == "auto"
    analysis = args.profile
    if args.profile == "llm":
        analysis = f"llm · {args.llm_provider}/{selected_model}"
    knowledge = (
        _safe_log_value(str(_knowledge_database_path(args.knowledge_db)), limit=300)
        if args.knowledge_db
        else "끔"
    )
    print("=" * 58)
    print(f"  {runner_name} 실행 전 확인")
    print("=" * 58)
    print("\n[실행 구성]")
    print(f"  검사 대상       {'통합 검사 (5종)' if run_all else target_label}")
    print(f"  Analysis        {analysis}")
    print(f"  Recon           {args.recon}")
    print(f"  브라우저 Recon  {'사용' if getattr(args, 'browser_recon', False) else '끔'}")
    print(f"  Recon 시작      {getattr(args, 'recon_entry', 'targeted')}")
    print(f"  Surface 수집    {getattr(args, 'surface_collection', 'adaptive')}")
    router_detail = (
        "primary hypotheses"
        if args.router == "agentic"
        else f"review {args.router_review}"
    )
    print(f"  Router          {args.router} · {router_detail}")
    ssrf_mode = getattr(args, "ssrf_oast", "off")
    print(f"  SSRF callback   {ssrf_mode if ssrf_mode != 'off' else '로컬 실험 수신기' if getattr(args, 'ssrf_local_callback', False) else '끔'}")
    print(
        "  SSRF Recon 검토 "
        f"{'사용 (Recon 후 선택)' if getattr(args, 'ssrf_review', False) else '끔'}"
    )
    if getattr(args, "ssrf_review", False):
        print("  SSRF 내부 확인  Recon 후 운영자 선택·별도 승인 시에만 사용")
    if ssrf_mode == "public_interactsh":
        print("  외부 전송 고지  공개 Interactsh에 callback 접속 메타데이터가 전달됩니다.")
    print(f"  Orchestrator    {getattr(args, 'orchestrator', 'heuristic')}")
    print(f"  Report          {getattr(args, 'report', 'heuristic')}")
    print(f"  예산 배분       {getattr(args, 'budget_allocation', 'off')}")
    print(f"  Router 비교     {'켬' if args.compare_routers else '끔'}")
    print(
        "  상태 변경 승인  "
        f"{'허용 (명시적 옵션)' if getattr(args, 'approve_state_changing', False) else '차단'}"
    )
    if needs_llm(args):
        limit = f"{rpm_limit}회 / rolling 60초" if rpm_limit is not None else "없음"
        print(f"  LLM 호출 제한   {limit}")
    print(f"  Knowledge       {knowledge}")
    print(
        "  판단 기록       "
        f"{_safe_log_value(args.routing_log, limit=300)}"
    )

    if run_all:
        print("\n[검사 범위]")
        print("  포함            XSS · SQLi · Path Traversal · SSTI · Access Control")
        print("\n[계정 및 정리]")
        print("  XSS · SQLi      인증 없이 실행")
        print("  Path Traversal  폐기 가능한 임시 계정과 분리 세션 사용")
        print("  SSTI            폐기 가능한 임시 계정과 분리 세션 사용")
        print(f"                  검증 후 username을 {SSTI_CLEANUP_VALUE!r}(으)로 복구")
        print("  Access Control  입력받은 전용 테스트 계정 두 개를 메모리에서만 사용")
        print("  종료 처리       임시 계정 데이터 삭제 및 입력 credential 폐기")
    elif auto_scan:
        print("\n[검사 범위]")
        print("  포함            현재 Run에서 발견되고 정책상 실행 가능한 Analyzer 후보")
        print("  로그인 세션     실행 직전 선택 입력 (메모리에서만 사용)")
        excluded = "대상별 seed · 계정 준비"
        if not getattr(args, "approve_state_changing", False):
            excluded += " · 상태 변경 승인"
        print(f"  제외            {excluded}")
    print("=" * 58)


@dataclass(frozen=True, slots=True)
class _VulnTarget:
    """취약점 유형별로 실행기가 알아야 하는 값.

    유형이 늘 때마다 if/else 가지를 여기저기 늘리지 않도록 한곳에 모은다. 인증과
    정리 절차는 유형마다 실제로 다르므로 표에 넣지 않고 명시적으로 분기한다.
    """

    label: str  # Router에 넘기는 vulnerability_type
    seed_path: str | None  # base_url 기준 시작 Surface. Access Control은 실행 중 결정된다.
    signal: str  # Analysis가 남기는 Observation type
    signal_label: str  # 결과 화면에 쓰는 신호 이름


_VULN_TARGETS = {
    "sqli": _VulnTarget("SQLi", "rest/products/search?q=seed", "sql_error", "SQL 오류"),
    "ssti": _VulnTarget("SSTI", "profile", SSTI_OBSERVATION, "템플릿 산술 실행"),
    # SPA 라우트는 서버 경로가 아니다. Recon 이 번들에서 찾아내므로 seed 는 홈이다.
    "xss": _VulnTarget("XSS", None, "reflection", "DOM 반사"),
    # /ftp 디렉터리는 번들의 템플릿 리터럴에서만 드러난다. seed 없이 Recon 이 찾는다.
    "path_traversal": _VulnTarget(
        "Path Traversal", None, "path_traversal_file_read", "로컬 파일 읽기"
    ),
    "access_control": _VulnTarget(
        "Access Control", None, "object_id_auth", "객체 권한 우회"
    ),
    "source_map": _VulnTarget(
        "Source Map Exposure", None, "source_map_content_exposure", "공개 source map 원본 소스"
    ),
}
# 브라우저를 쓰는 유형. Playwright Runtime 과 브라우저 검증을 함께 켠다.
_BROWSER_VULNS = frozenset({"xss", "auto", "all"})
# 시작 URL 에 표면이 없고 JS 번들과 디렉터리 목록을 거쳐야 찾을 수 있는 유형.
# 정찰 페이지 수와 예산을 전체 모드와 같게 준다.
_BUNDLE_DISCOVERY_VULNS = frozenset({"xss", "path_traversal", "source_map", "auto", "all"})


@dataclass(slots=True)
class _ProvisionedAccount:
    role: str
    credential_ref: str
    user_id: int
    email: str
    basket_id: str | None = None


@dataclass(frozen=True, slots=True)
class _AccessAccountInput:
    """Access Control 로그인에만 잠시 쓰는 사용자 입력. repr에는 비밀을 숨긴다."""

    role: str
    credential_ref: str
    email: str = field(repr=False)
    password: str = field(repr=False)


def _format_counts(counts: Counter[str]) -> str:
    if not counts:
        return "없음"
    return ", ".join(f"{name} {count}개" for name, count in counts.items())


def _ssrf_review_summary_lines(review: SsrfReviewFact) -> tuple[str, ...]:
    """Render the closed, URL-free SSRF review state for the terminal."""

    status_labels = {
        "NOT_TESTED": "분석 대상 없음 또는 미검토",
        "REVIEW_REQUIRED": "운영자 검토 필요",
        "CALLBACK_OBSERVED": "서버 요청 관측 · 정책 위반 미입증",
        "CANARY_OBSERVED_POLICY_PENDING": "서버 요청 관측 · 정책 근거 필요",
        "CONFIRMED_POLICY_VIOLATION": "목적지 정책 위반 독립 재현",
        "CALLBACK_PROVIDER_BLOCKED": "확인 Provider 사용 불가",
        "EXECUTION_APPROVAL_PENDING": "실행 승인 대기",
        "POLICY_EVIDENCE_PENDING": "목적지 정책 근거 대기",
        "VALIDATION_BUDGET_INSUFFICIENT": "Validation 예산 부족",
        "CALLBACK_NOT_OBSERVED": "Callback HTTP 발신 미관측",
        "CALLBACK_ANALYSIS_OBSERVED": "Callback Analysis 관측 · 독립 검증 대기",
        "CALLBACK_NOT_REPRODUCED": "Callback 독립 재현 실패",
        "CANARY_ANALYSIS_OBSERVED": "Canary Analysis 관측 · 독립 검증 대기",
        "CANARY_NOT_REPRODUCED": "Canary 독립 재현 실패",
        "OWNED_RECEIVER_OBSERVED_POLICY_PENDING": (
            "운영자 소유 Receiver A/B 관측 · 정책 근거 필요"
        ),
        "OWNED_RECEIVER_ANALYSIS_OBSERVED": (
            "운영자 소유 Receiver Analysis 관측 · 독립 검증 대기"
        ),
        "OWNED_RECEIVER_NOT_REPRODUCED": "운영자 소유 Receiver 독립 재현 실패",
        "OWNED_RECEIVER_NOT_OBSERVED": "운영자 소유 Receiver 발신 미관측",
        "OWNED_RECEIVER_PROVIDER_BLOCKED": "운영자 소유 Receiver 장애",
    }
    status_labels.update({
        "OBSERVATION_PROVIDER_BLOCKED": "서버 요청 관측 Provider 사용 불가",
        "ALLOWED_DESTINATION": "허용된 목적지의 정상 동작",
    })
    lines = (
        f"  URL 처리 Surface {review.url_surface_count}개",
        "  수동 분석       "
        + ("완료" if review.manual_analysis_completed else "미완료"),
        "  서버 요청 확인  "
        + ("수행" if review.verification_performed else "미수행"),
        f"  상태            {status_labels.get(review.final_status, review.final_status)}",
        f"  Reason          {review.reason_code}",
    )
    lines = (
        *lines[:2],
        "  실행 승인        "
        + ("등록" if review.execution_approval_registered else "미등록"),
        "  승인 Surface     " + (review.approved_surface_id or "없음"),
        "  Recon 단서 사용  "
        + ("승인" if review.destination_hint_use_approved else "미승인"),
        "  목적지 정책      "
        + ("등록" if review.destination_policy_registered else "미등록"),
        "  정책 출처        " + (review.destination_policy_source or "없음"),
        "  관측 기록        "
        + ("있음" if review.observation_recorded else "없음"),
        f"  Callback 전략   {review.callback_status}",
        f"  Canary 전략     {review.canary_status}",
        f"  Receiver 전략   {review.owned_receiver_status}",
        *lines[2:],
    )
    if review.final_status == "REVIEW_REQUIRED" and review.manual_analysis_completed:
        lines = (*lines,
            "  요약            SSRF 분석: 운영자 검토 등록 / "
            "서버 요청 확인: 미수행 / 결과: 운영자 검토 필요",
        )
    elif review.final_status == "REVIEW_REQUIRED":
        lines = (*lines,
            "  요약            Recon URL 좌표 분류 완료 / 운영자 검토: 대기 / "
            "서버 요청 확인: 미수행 / 결과: 아직 검사에 사용되지 않음",
        )
    if not review.verification_performed:
        return (*lines, "  참고            실제 확인 미수행은 취약점 없음 판정이 아닙니다.")
    return lines


def _ssrf_review_options(app, run: Run) -> tuple[tuple[dict[str, str], ...], tuple[dict[str, str], ...]]:
    """Return value-free review coordinates and sanitized hints from this Run."""

    surfaces = {
        item.surface_id: item
        for item in app.stores.surfaces.list_by_run(run.run_id)
        if item.surface_id in run.surface_ids
    }
    coordinates: list[dict[str, str]] = []
    hints: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for evidence in app.stores.evidence.list_by_run(run.run_id):
        if evidence.created_by != "recon" or evidence.surface_id not in surfaces:
            continue
        observation = evidence.observation
        if observation.get("type") == "ssrf_url_fetch_review":
            surface = surfaces[evidence.surface_id]
            if surface.method.upper() != "GET":
                continue
            sources = observation.get("parameter_sources")
            parameter_names = observation.get("parameter_names")
            if not isinstance(sources, list) or not isinstance(parameter_names, list):
                continue
            for item in sources:
                if not isinstance(item, dict):
                    continue
                name, source = item.get("name"), item.get("source")
                if not isinstance(name, str) or not isinstance(source, str):
                    continue
                if name not in parameter_names or name not in surface.parameters:
                    continue
                key = (surface.surface_id, name)
                if key in seen:
                    continue
                seen.add(key)
                coordinates.append({
                    "surface_id": surface.surface_id,
                    "parameter": name,
                    "source": source,
                })
        elif observation.get("type") == "ssrf_destination_hint":
            origin = observation.get("destination_origin")
            path_hint = observation.get("path_hint")
            source = observation.get("source")
            if not all(isinstance(value, str) for value in (origin, path_hint, source)):
                continue
            parsed = urlsplit(origin)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.netloc
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
                or "?" in path_hint
                or "#" in path_hint
            ):
                continue
            hints.append({
                "evidence_id": evidence.evidence_id,
                "surface_id": evidence.surface_id,
                "destination_origin": origin,
                "path_hint": redacted_internal_url_path(path_hint),
                "source": source,
            })
    return (
        tuple(sorted(
            coordinates,
            key=lambda item: (item["surface_id"], item["parameter"]),
        )),
        tuple(sorted(hints, key=lambda item: item["evidence_id"])),
    )


def _prompt_choice(
    prompt: str, choices: tuple[object, ...], *, input_fn,
) -> object | None:
    """Select one numbered item; an empty answer safely skips the review."""

    while True:
        answer = input_fn(prompt).strip()
        if not answer or answer.casefold() in {"s", "skip"}:
            return None
        if answer.isdigit() and 1 <= int(answer) <= len(choices):
            return choices[int(answer) - 1]
        print(f"  1~{len(choices)} 중 하나를 입력하거나 Enter로 건너뛰세요.")


def _prompt_opaque_ssrf_reference(
    prompt: str, *, input_fn, required_prefix: str = "",
) -> str:
    """Accept only a short operator reference, never a URL or secret material."""

    while True:
        value = input_fn(prompt).strip()
        try:
            validate_ssrf_opaque_reference(value, "SSRF operator reference")
        except DomainInvariantError:
            pass
        else:
            if (
                _OPAQUE_SSRF_REVIEW_REF.fullmatch(value) is not None
                and "://" not in value
                and (not required_prefix or value.startswith(required_prefix))
            ):
                return value
        print("  URL·token·Evidence ID가 아닌 짧은 승인자 ID만 입력하세요.")


def _run_ssrf_review_gate(
    app, run: Run, *, callback_mode: str, owned_receiver_mode: bool = False,
    input_fn=None, secret_input_fn=None, allow_initial_internal: bool = False,
    preselected_registration=None, force_internal: bool = False,
) -> bool:
    """Review one exact coordinate after Recon, without persisting endpoint URLs."""

    input_fn = input if input_fn is None else input_fn
    coordinates, hints = _ssrf_review_options(app, run)
    print("\n[SSRF URL 처리 좌표 검토]")
    print(
        "  선택한 좌표에서만 확인 요청을 수행합니다. "
        "callback 수신이나 Recon 단서만으로 취약점을 확정하지 않습니다."
    )
    if not coordinates:
        print("  현재 Run에서 검토 가능한 URL 입력 좌표가 없습니다.")
        # An optional Recon round may still discover an eligible coordinate.
        return False
    if preselected_registration is None:
        for index, item in enumerate(coordinates, start=1):
            print(
                f"  {index}. Surface {item['surface_id']} · "
                f"parameter {item['parameter']} · source {item['source']}"
            )
        selected = _prompt_choice(
            "검토할 좌표 번호 (Enter: 건너뛰기): ", coordinates, input_fn=input_fn,
        )
    else:
        selected = next((
            item for item in coordinates
            if item["surface_id"] == preselected_registration.surface_id
            and item["parameter"] == preselected_registration.parameter
        ), None)
    if selected is None:
        app.ssrf_reviews.skip(
            run.run_id,
            SsrfVerificationStrategy.INTERNAL_CANARY
            if force_internal else SsrfVerificationStrategy.PASSIVE,
        )
        print("  이번 Run의 SSRF 좌표 검토를 건너뜁니다.")
        return True
    assert isinstance(selected, dict)

    hint = None
    if hints:
        print("  이 Run에서 Recon이 저장한 정제된 목적지 단서 (실행 주소가 아님):")
        for index, item in enumerate(hints, start=1):
            print(
                f"    {index}. {item['destination_origin']}{item['path_hint']} "
                f"· source Surface {item['surface_id']} · {item['source']} "
                f"· Evidence {item['evidence_id']}"
            )
        hint = _prompt_choice(
            "참고 단서 번호 (Enter: 선택 안 함): ", hints, input_fn=input_fn,
        )
    else:
        print("  이 Run에 정제된 목적지 단서는 없습니다.")

    if not force_internal and owned_receiver_mode and input_fn(
        "명시적으로 실행한 운영자 소유 로컬 Receiver로 "
        "서버 발신을 확인합니까? [y/N] "
    ).strip().casefold() == "y":
        if input_fn(
            "이 Receiver 주소로 선택한 좌표의 확인 요청을 "
            "실행하도록 승인합니까? [y/N] "
        ).strip().casefold() != "y":
            app.ssrf_reviews.skip(
                run.run_id, SsrfVerificationStrategy.OWNED_RECEIVER,
            )
            print("  실행 승인이 없어 이번 검토를 건너뜁니다.")
            return True
        approved_by = _prompt_opaque_ssrf_reference(
            "승인자 참조 ID: ", input_fn=input_fn,
        )
        now = datetime.now(timezone.utc)
        receiver_origin = app.ssrf_owned_receiver_origin
        if not receiver_origin:
            app.ssrf_reviews.skip(
                run.run_id, SsrfVerificationStrategy.OWNED_RECEIVER,
            )
            print("  운영자 소유 Receiver가 사용 불가해 건너뜁니다.")
            return True
        register_policy = input_fn(
            f"대상 규칙상 Surface {selected['surface_id']}의 "
            f"{selected['parameter']} 입력이 이 Receiver에 접근하면 안 된다는 "
            "정책 증언도 등록합니까? [y/N] "
        ).strip().casefold() == "y"
        policy = None
        if register_policy:
            source_ref = _prompt_opaque_ssrf_reference(
                "목적지 규칙 출처 참조 ID (operator:<id>): ",
                input_fn=input_fn, required_prefix="operator:",
            )
            policy = SsrfDestinationPolicy(
                policy_id=f"ssrf-policy-{uuid4()}",
                surface_id=selected["surface_id"],
                destination_rule=SsrfDestinationRule.FORBIDDEN,
                source_type=SsrfPolicySource.OPERATOR_ATTESTATION,
                source_reference=source_ref,
                approved_by=approved_by,
                created_at=now,
                destination_origin=ssrf_destination_origin(receiver_origin),
                assertion=SsrfPolicyAssertion.TARGET_MUST_NOT_REACH_DESTINATION,
                evidence_status=SsrfPolicyEvidenceStatus.ATTESTED,
            )
        approval = SsrfExecutionApproval(
            approval_id=f"approval-{uuid4()}",
            surface_id=selected["surface_id"],
            verification_endpoint_ref=app.ssrf_owned_receiver_endpoint_ref(run.run_id),
            approved_by=approved_by,
            approved_at=now,
        )
        app.collector.register_ssrf_review(
            run_id=run.run_id,
            parameter=selected["parameter"],
            hint_evidence_id=(hint["evidence_id"] if isinstance(hint, dict) else None),
            approval=approval,
            destination_policy=policy,
            hint_use_approved=False,
            approved_destination_url=receiver_origin,
            verification_strategy=SsrfVerificationStrategy.OWNED_RECEIVER,
        )
        print(
            "  운영자 소유 Receiver A/B 확인을 진행합니다. "
            + (
                "정책이 없어 성공해도 SUSPECTED로 유지됩니다."
                if policy is None else "Surface에 결합된 목적지 정책도 검증합니다."
            )
        )
        return True

    internal = force_internal or (
        allow_initial_internal
        and input_fn(
            "운영자 소유의 비민감 내부 확인 주소를 사용합니까? [y/N] "
        ).strip().casefold() == "y"
    )
    if internal:
        marker = os.environ.get("HACKLIPSE_SSRF_CANARY_MARKER", "")
        if not marker:
            print("  내부 확인에는 HACKLIPSE_SSRF_CANARY_MARKER 설정이 필요합니다.")
            app.ssrf_reviews.skip(
                run.run_id, SsrfVerificationStrategy.INTERNAL_CANARY,
            )
            return True
        if secret_input_fn is None and not sys.stdin.isatty():
            print("  내부 확인 주소는 비표시 입력을 지원하는 터미널에서만 받습니다.")
            app.ssrf_reviews.skip(
                run.run_id, SsrfVerificationStrategy.INTERNAL_CANARY,
            )
            return True
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                exact_url = (secret_input_fn or getpass.getpass)(
                    "정확한 확인 주소 URL (화면에 표시하지 않음): "
                ).strip()
        except (EOFError, OSError, getpass.GetPassWarning):
            print("  비표시 입력을 사용할 수 없어 이번 검토를 건너뜁니다.")
            app.ssrf_reviews.skip(
                run.run_id, SsrfVerificationStrategy.INTERNAL_CANARY,
            )
            return True
        if not exact_url:
            print("  확인 주소를 입력하지 않아 이번 검토를 건너뜁니다.")
            app.ssrf_reviews.skip(
                run.run_id, SsrfVerificationStrategy.INTERNAL_CANARY,
            )
            return True
        if input_fn(
            "이 주소로 선택한 좌표의 확인 요청을 실행하도록 승인합니까? [y/N] "
        ).strip().casefold() != "y":
            app.ssrf_reviews.skip(
                run.run_id, SsrfVerificationStrategy.INTERNAL_CANARY,
            )
            print("  실행 승인이 없어 이번 검토를 건너뜁니다.")
            return True
        hint_use_approved = False
        if isinstance(hint, dict):
            hint_use_approved = input_fn(
                "선택한 Recon 단서의 관측된 origin/path와 이 정확한 "
                "주소가 같은지 HMAC으로 검증한 뒤, 이 Surface의 확인 "
                "목적지로 사용하도록 승인합니까? [y/N] "
            ).strip().casefold() == "y"
        register_policy = input_fn(
            f"대상 규칙상 Surface {selected['surface_id']}의 {selected['parameter']} "
            "입력이 이 주소에 접근하면 안 된다는 정책 증언도 등록합니까? [y/N] "
        ).strip().casefold() == "y"
        source_ref = ""
        if register_policy:
            print("  Operator-attested policy references use the operator:<id> format.")
            source_ref = _prompt_opaque_ssrf_reference(
                "목적지 규칙 출처 참조 ID (operator:<id>): ",
                input_fn=input_fn, required_prefix="operator:",
            )
        approved_by = _prompt_opaque_ssrf_reference(
            "승인자 참조 ID: ", input_fn=input_fn,
        )
        now = datetime.now(timezone.utc)
        policy = (
            SsrfDestinationPolicy(
                policy_id=f"ssrf-policy-{uuid4()}",
                surface_id=selected["surface_id"],
                destination_rule=SsrfDestinationRule.FORBIDDEN,
                source_type=SsrfPolicySource.OPERATOR_ATTESTATION,
                source_reference=source_ref,
                approved_by=approved_by,
                created_at=now,
                destination_origin=ssrf_destination_origin(exact_url),
                assertion=SsrfPolicyAssertion.TARGET_MUST_NOT_REACH_DESTINATION,
                evidence_status=SsrfPolicyEvidenceStatus.ATTESTED,
            )
            if register_policy else None
        )
        try:
            canary = SsrfCanaryProofTarget(
                url=exact_url, marker=marker,
                surface_id=selected["surface_id"],
                destination_policy=policy, operator_approved=True,
            )
        except ValueError as error:
            app.ssrf_reviews.skip(
                run.run_id, SsrfVerificationStrategy.INTERNAL_CANARY,
            )
            print(f"  내부 확인 주소 또는 marker가 유효하지 않아 건너뜁니다: {error}")
            return True
        approval = SsrfExecutionApproval(
            approval_id=f"approval-{uuid4()}",
            surface_id=selected["surface_id"],
            verification_endpoint_ref=app.ssrf_verification_endpoint_ref(
                run.run_id, exact_url,
            ),
            approved_by=approved_by,
            approved_at=now,
        )
        try:
            app.collector.register_ssrf_review(
                run_id=run.run_id,
                parameter=selected["parameter"],
                hint_evidence_id=(
                    hint["evidence_id"] if isinstance(hint, dict) else None
                ),
                approval=approval,
                destination_policy=policy,
                hint_use_approved=hint_use_approved,
                approved_destination_url=exact_url,
                verification_strategy=SsrfVerificationStrategy.INTERNAL_CANARY,
            )
        except AgentContractError:
            app.ssrf_reviews.skip(
                run.run_id, SsrfVerificationStrategy.INTERNAL_CANARY,
            )
            print(
                "  선택한 Recon 단서와 승인 주소가 일치하지 않아 "
                "이번 검토를 건너뜁니다."
            )
            return True
        app.register_ssrf_canary_proof(run.run_id, canary)
        if policy is None:
            print(
                "  선택한 좌표에서 승인된 내부 확인을 진행합니다. "
                "목적지 정책이 없어 성공해도 SUSPECTED로 유지됩니다."
            )
        else:
            print("  선택한 좌표에서 승인된 내부 확인과 정책 검증을 진행합니다.")
        return True

    if callback_mode == "off":
        app.ssrf_reviews.skip(run.run_id, SsrfVerificationStrategy.CALLBACK)
        print("  callback과 내부 확인 주소가 없어 이번 검토를 건너뜁니다.")
        return True
    if input_fn("선택한 좌표에 callback 확인 요청을 실행할까요? [y/N] ").strip().casefold() != "y":
        app.ssrf_reviews.skip(run.run_id, SsrfVerificationStrategy.CALLBACK)
        print("  이번 Run의 SSRF 좌표 검토를 건너뜁니다.")
        return True
    approved_by = _prompt_opaque_ssrf_reference(
        "승인자 참조 ID: ", input_fn=input_fn,
    )
    now = datetime.now(timezone.utc)
    approval = SsrfExecutionApproval(
        approval_id=f"approval-{uuid4()}",
        surface_id=selected["surface_id"],
        verification_endpoint_ref=f"callback-{callback_mode}",
        approved_by=approved_by,
        approved_at=now,
    )
    app.collector.register_ssrf_review(
        run_id=run.run_id,
        parameter=selected["parameter"],
        hint_evidence_id=(hint["evidence_id"] if isinstance(hint, dict) else None),
        approval=approval,
        destination_policy=None,
        hint_use_approved=False,
        approved_destination_url=None,
        verification_strategy=SsrfVerificationStrategy.CALLBACK,
    )
    print("  선택한 입력 좌표에서 callback 확인을 진행합니다. 확정 판정은 하지 않습니다.")
    return True


def _restore_ssrf_internal_canary_proof(
    app, run: Run, registration, primary, *, secret_input_fn=None,
) -> bool:
    """Re-enter one approved endpoint without persisting its URL or marker."""

    if (
        registration.surface_id != primary.surface_id
        or registration.parameter != primary.parameter
    ):
        print("  Stored internal approval does not match the A/B-proven coordinate.")
        return False
    marker = os.environ.get("HACKLIPSE_SSRF_CANARY_MARKER", "")
    if not marker:
        print("  Re-entry requires HACKLIPSE_SSRF_CANARY_MARKER.")
        return False
    if secret_input_fn is None and not sys.stdin.isatty():
        print("  Re-entry requires a terminal that supports hidden input.")
        return False
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            exact_url = (secret_input_fn or getpass.getpass)(
                "Previously approved internal URL (hidden; blank to decline): "
            ).strip()
    except (EOFError, OSError, getpass.GetPassWarning):
        print("  Hidden input is unavailable; the follow-up is stopped safely.")
        return False
    if not exact_url:
        print("  Internal URL re-entry was declined; the follow-up is stopped safely.")
        return False
    if not secrets.compare_digest(
        registration.execution_approval.verification_endpoint_ref,
        app.ssrf_verification_endpoint_ref(run.run_id, exact_url),
    ):
        print("  Re-entered URL does not match the persisted approval reference.")
        return False
    try:
        app.register_ssrf_canary_proof(
            run.run_id,
            SsrfCanaryProofTarget(
                url=exact_url,
                marker=marker,
                surface_id=registration.surface_id,
                destination_policy=registration.destination_policy,
                operator_approved=True,
            ),
        )
    except (AgentContractError, DomainInvariantError, ValueError):
        print("  Stored internal approval could not be restored safely.")
        return False
    print("  Restored the approved internal proof in process memory.")
    return True


def _run_ssrf_internal_followup_gate(
    app, run: Run, *, input_fn=None, secret_input_fn=None,
) -> bool:
    """Approve one internal-canary pass for the exact A/B-proven coordinate."""

    input_fn = input if input_fn is None else input_fn
    eligible = []
    for candidate in app.stores.candidates.list_by_run(run.run_id):
        strategy = None
        if (
            candidate.status is CandidateStatus.SUSPECTED
            and candidate.validation_reason_code
            is ValidationReasonCode.SSRF_CALLBACK_ONLY
        ):
            strategy = SsrfVerificationStrategy.CALLBACK
        elif (
            candidate.status is CandidateStatus.SUSPECTED
            and candidate.validation_reason_code
            is ValidationReasonCode.SSRF_OWNED_RECEIVER_ONLY
        ):
            strategy = SsrfVerificationStrategy.OWNED_RECEIVER
        if strategy is None:
            continue
        registration = app.ssrf_reviews.get_for_surface(
            run_id=run.run_id,
            surface_id=candidate.surface_id,
            strategy=strategy,
        )
        if registration is not None:
            eligible.append((candidate.candidate_id, registration))
    if not eligible:
        print("  A/B로 재현된 SSRF 좌표와 실행 승인을 찾지 못했습니다.")
        return False
    _, primary = min(eligible, key=lambda item: item[0])

    existing = app.ssrf_reviews.get_for_run(
        run.run_id, SsrfVerificationStrategy.INTERNAL_CANARY,
    )
    if existing is not None:
        if app.collector.ssrf_canary_proof_for_run(run.run_id) is None:
            return _restore_ssrf_internal_canary_proof(
                app, run, existing, primary, secret_input_fn=secret_input_fn,
            )
        # Exact URL and marker intentionally remain process-local. A restored
        # registration without those secrets must never be executed blindly.
        if app.collector.ssrf_canary_proof_for_run(run.run_id) is not None:
            return True
        print(
            "  이전 내부 확인 승인의 비밀값이 재시작 후 복원되지 "
            "않아 추가 탐침을 실행하지 않습니다."
        )
        return False

    print("\n[SSRF 내부 목적지 후속 검토]")
    print(
        "  독립적인 callback/Receiver A·B 재현이 확인된 같은 "
        "Surface·parameter만 사용합니다."
    )
    if input_fn(
        "Recon 단서나 운영자 입력의 비민감 내부 확인 주소로 "
        "후속 검증할까요? [y/N] "
    ).strip().casefold() != "y":
        app.ssrf_reviews.skip(
            run.run_id, SsrfVerificationStrategy.INTERNAL_CANARY,
        )
        return False

    _run_ssrf_review_gate(
        app,
        run,
        callback_mode="off",
        owned_receiver_mode=False,
        input_fn=input_fn,
        secret_input_fn=secret_input_fn,
        allow_initial_internal=False,
        preselected_registration=primary,
        force_internal=True,
    )
    registration = app.ssrf_reviews.get_for_run(
        run.run_id, SsrfVerificationStrategy.INTERNAL_CANARY,
    )
    return (
        registration is not None
        and app.collector.ssrf_canary_proof_for_run(run.run_id) is not None
    )


def _blocked_analyzer_gaps(router) -> tuple[object, ...]:
    # Candidate totals are vulnerability-wide, but a gap belongs to one capability.
    return tuple(
        item
        for item in getattr(router, "last_analyzer_coverage", ())
        if getattr(item, "status", None) == "blocked"
    )


def _all_mode_recon_seeds(
    base_url: str,
    *,
    include_ssti: bool,
    access_control_object_id: str | None = None,
) -> tuple[str, ...]:
    """전체 모드에서 SPA와 별도로 방문해야 하는 인증 Surface를 반환한다."""

    seeds: list[str] = []
    if include_ssti:
        profile_path = _VULN_TARGETS["ssti"].seed_path
        assert profile_path is not None
        seeds.append(urljoin(base_url, profile_path))
    if access_control_object_id is not None:
        if _OBJECT_ID.fullmatch(access_control_object_id) is None:
            raise ValueError("Access Control Recon seed requires a numeric object ID")
        seeds.append(urljoin(base_url, f"rest/basket/{access_control_object_id}"))
    return tuple(seeds)


def _recon_entry_points(
    base_url: str,
    target_url: str,
    seed_urls: tuple[str, ...],
    *,
    mode: str,
) -> tuple[str, tuple[str, ...]]:
    """Apply the auditable Recon start policy after all credential setup.

    ``base-url`` deliberately discards target-specific entry points, including ones
    learned during account preparation. Credentials remain execution authority only.
    """

    if mode == "base-url":
        return base_url, ()
    if mode == "targeted":
        return target_url, tuple(dict.fromkeys(seed_urls))
    raise ValueError("unsupported recon entry mode")


def _response_json(result, *, operation: str, statuses: tuple[int, ...]) -> dict:
    status = result.observation.get("status")
    body = result.observation.get("body")
    if status not in statuses or not isinstance(body, str):
        raise RuntimeError(
            f"Juice Shop {operation} 응답이 예상한 형식이 아닙니다. "
            f"(type={result.evidence_type!r}, status={status!r}, "
            f"error_kind={result.observation.get('error_kind')!r}, "
            f"body_type={type(body).__name__})"
        )
    try:
        payload = json.loads(body)
    except (TypeError, ValueError) as error:
        raise RuntimeError(f"Juice Shop {operation} 응답이 JSON이 아닙니다.") from error
    if not isinstance(payload, dict):
        raise RuntimeError(f"Juice Shop {operation} 응답이 객체가 아닙니다.")
    return payload


def _resolve_juice_shop_db(explicit_path: str | None) -> Path:
    """자동 정리가 가능한 정확한 Juice Shop SQLite 파일을 검증한다."""

    if explicit_path:
        candidates = (Path(explicit_path),)
    else:
        project_parent = Path(__file__).resolve().parents[3]
        candidates = (
            project_parent / "juice-shop" / "data" / "juiceshop.sqlite",
            Path.cwd().resolve().parents[1]
            / "juice-shop"
            / "data"
            / "juiceshop.sqlite",
        )
    for candidate in dict.fromkeys(path.resolve() for path in candidates):
        if not candidate.is_file():
            continue
        try:
            connection = sqlite3.connect(f"file:{candidate}?mode=ro", uri=True)
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        except sqlite3.Error:
            continue
        finally:
            if "connection" in locals():
                connection.close()
                del connection
        if {"Users", "Baskets", "Wallets"}.issubset(tables):
            return candidate
    raise RuntimeError(
        "Juice Shop SQLite DB를 찾지 못했습니다. 계정을 만들지 않았습니다. "
        "--juice-shop-db로 juiceshop.sqlite 경로를 지정하세요."
    )


def _cleanup_provisioned_accounts(
    database_path: Path, accounts: list[_ProvisionedAccount]
) -> None:
    """이번 실행에서 만든 계정과 직접 연결 데이터만 트랜잭션으로 삭제한다."""

    if not accounts:
        return
    user_ids = tuple(account.user_id for account in accounts)
    placeholders = ",".join("?" for _ in user_ids)
    connection = sqlite3.connect(database_path, timeout=10)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("BEGIN IMMEDIATE")
        rows = connection.execute(
            f"SELECT id,email FROM Users WHERE id IN ({placeholders})", user_ids
        ).fetchall()
        actual = {int(user_id): str(email) for user_id, email in rows}
        expected = {account.user_id: account.email for account in accounts}
        if actual != expected:
            raise RuntimeError(
                "임시 계정 DB 좌표가 생성 기록과 달라 자동 삭제를 중단했습니다."
            )

        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }

        basket_rows = connection.execute(
            f"SELECT id FROM Baskets WHERE UserId IN ({placeholders})", user_ids
        ).fetchall()
        basket_ids = tuple(int(row[0]) for row in basket_rows)
        if basket_ids and "BasketItems" in tables:
            basket_placeholders = ",".join("?" for _ in basket_ids)
            connection.execute(
                f"DELETE FROM BasketItems WHERE BasketId IN ({basket_placeholders})",
                basket_ids,
            )

        # Juice Shop의 Users 외래키 테이블 중 자동 생성·검증 중 생길 수 있는 행을
        # 명시적으로 제거한다. WHERE는 이번 실행의 user_id로만 제한한다.
        for table in (
            "Addresses",
            "Cards",
            "Complaints",
            "Feedbacks",
            "ImageCaptchas",
            "Memories",
            "PrivacyRequests",
            "Recycles",
            "SecurityAnswers",
            "Wallets",
        ):
            if table not in tables:
                continue
            connection.execute(
                f"DELETE FROM {table} WHERE UserId IN ({placeholders})", user_ids
            )
        connection.execute(
            f"DELETE FROM Baskets WHERE UserId IN ({placeholders})", user_ids
        )
        deleted = connection.execute(
            f"DELETE FROM Users WHERE id IN ({placeholders})", user_ids
        ).rowcount
        if deleted != len(accounts):
            raise RuntimeError("생성한 임시 계정을 모두 삭제하지 못했습니다.")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _prompt_access_control_accounts(
    *, input_fn=None, password_fn=None
) -> tuple[_AccessAccountInput, _AccessAccountInput]:
    """두 전용 테스트 계정을 대화형으로 입력받되 비밀번호를 화면에 표시하지 않는다."""

    input_fn = input if input_fn is None else input_fn
    password_fn = getpass.getpass if password_fn is None else password_fn
    accounts: list[_AccessAccountInput] = []
    for role, label, credential_ref in (
        ("actor", "Actor(비소유자)", _ACTOR_CREDENTIAL_REF),
        ("owner", "Owner(소유자)", _OWNER_CREDENTIAL_REF),
    ):
        email = input_fn(f"{label} 테스트 계정 이메일: ").strip()
        password = password_fn(f"{label} 테스트 계정 비밀번호 (숨김 입력): ")
        if not email or not password:
            raise ValueError(f"{label} 테스트 계정 정보가 비어 있습니다.")
        accounts.append(_AccessAccountInput(role, credential_ref, email, password))
    actor, owner = accounts
    if actor.email.casefold() == owner.email.casefold():
        raise ValueError("Actor와 Owner는 서로 다른 테스트 계정이어야 합니다.")
    return actor, owner


def _authenticate_access_control_accounts(
    app,
    resolver: InMemoryCredentialResolver,
    accounts: tuple[_AccessAccountInput, _AccessAccountInput],
    *,
    base_url: str,
    host: str,
    allowed_path_prefix: str,
) -> tuple[str, str, str]:
    """입력받은 계정을 로그인하고 token과 각 계정의 basket ID만 메모리에 둔다."""

    authentication_run_id = f"run-access-login-{uuid4()}"
    app.stores.runs.add(
        Run(
            run_id=authentication_run_id,
            target_url=urljoin(base_url, "rest/user/login"),
            scope=RunScope(
                allowed_hosts=frozenset({host}),
                allowed_path_prefixes=(allowed_path_prefix,),
            ),
            policy_profile="safe",
            request_budget=len(accounts),
        )
    )
    app.budget_manager.open_run(authentication_run_id, len(accounts))

    object_ids: list[str] = []
    try:
        for account in accounts:
            login_body = json.dumps(
                {"email": account.email, "password": account.password},
                separators=(",", ":"),
            )
            _, login = app.collector.collect_with_result(
                authentication_run_id,
                urljoin(base_url, "rest/user/login"),
                EvidenceRequest(
                    evidence_type="account_authentication",
                    surface_id="juice-shop-access-login",
                    reason=f"log in supplied Juice Shop {account.role} test account",
                    suggested_tool="http_post",
                    http_request=HttpRequestSpec(
                        method="POST",
                        headers=(("Content-Type", "application/json"),),
                        body=login_body,
                    ),
                    approval_ref=_ACCESS_LOGIN_APPROVAL_REF,
                ),
                task_id=f"access-login-{account.role}",
                approval_ref=_ACCESS_LOGIN_APPROVAL_REF,
            )
            payload = _response_json(login, operation="로그인", statuses=(200,))
            authentication = payload.get("authentication")
            if not isinstance(authentication, dict):
                raise RuntimeError("로그인 응답에 authentication이 없습니다.")
            token = authentication.get("token")
            basket_id = str(authentication.get("bid", ""))
            if (
                not isinstance(token, str)
                or not token
                or _OBJECT_ID.fullmatch(basket_id) is None
            ):
                raise RuntimeError("로그인 응답에 token 또는 basket ID가 없습니다.")
            resolver.add(
                account.credential_ref,
                ResolvedHttpCredential(authorization=f"Bearer {token}"),
                allowed_origins=(base_url,),
            )
            object_ids.append(basket_id)
    except Exception:
        for account in accounts:
            resolver.revoke(account.credential_ref)
        raise

    actor_id, owner_id = object_ids
    if actor_id == owner_id:
        for account in accounts:
            resolver.revoke(account.credential_ref)
        raise RuntimeError("두 테스트 계정의 basket ID가 같아 대조할 수 없습니다.")
    return actor_id, owner_id, authentication_run_id


def _provision_path_traversal_account(
    app,
    resolver: InMemoryCredentialResolver,
    *,
    base_url: str,
    host: str,
    allowed_path_prefix: str,
    cleanup_database: Path,
) -> tuple[_ProvisionedAccount, str]:
    """서버 렌더링 폼을 탐색·검증할 폐기용 계정과 보안 답변을 만든다."""

    provision_run_id = f"run-provision-{uuid4()}"
    app.stores.runs.add(
        Run(
            run_id=provision_run_id,
            target_url=urljoin(base_url, "api/Users"),
            scope=RunScope(
                allowed_hosts=frozenset({host}),
                allowed_path_prefixes=(allowed_path_prefix,),
            ),
            policy_profile="safe",
            request_budget=3,
        )
    )
    app.budget_manager.open_run(provision_run_id, 3)

    suffix = uuid4().hex
    email = f"hacklipse-path-{suffix}@example.invalid"
    password = secrets.token_urlsafe(18)
    account: _ProvisionedAccount | None = None
    try:
        _, registration = app.collector.collect_with_result(
            provision_run_id,
            urljoin(base_url, "api/Users"),
            EvidenceRequest(
                evidence_type="account_provisioning",
                surface_id="juice-shop-account-provisioning",
                reason="create disposable local Juice Shop path traversal account",
                suggested_tool="http_post",
                http_request=HttpRequestSpec(
                    method="POST",
                    headers=(("Content-Type", "application/json"),),
                    body=json.dumps(
                        {"email": email, "password": password},
                        separators=(",", ":"),
                    ),
                ),
                approval_ref=_PROVISION_APPROVAL_REF,
            ),
            task_id="provision-path-register",
            approval_ref=_PROVISION_APPROVAL_REF,
        )
        registration_payload = _response_json(
            registration, operation="생성", statuses=(201,)
        )
        registration_data = registration_payload.get("data")
        user_id = (
            registration_data.get("id")
            if isinstance(registration_data, dict)
            else registration_payload.get("id")
        )
        if not isinstance(user_id, int) or user_id <= 0:
            raise RuntimeError("임시 계정 생성 응답에 user ID가 없습니다.")
        account = _ProvisionedAccount(
            "path_traversal",
            _PATH_TRAVERSAL_CREDENTIAL_REF,
            user_id,
            email,
        )

        _, login = app.collector.collect_with_result(
            provision_run_id,
            urljoin(base_url, "rest/user/login"),
            EvidenceRequest(
                evidence_type="account_authentication",
                surface_id="juice-shop-account-provisioning",
                reason="log in disposable local Juice Shop path traversal account",
                suggested_tool="http_post",
                http_request=HttpRequestSpec(
                    method="POST",
                    headers=(("Content-Type", "application/json"),),
                    body=json.dumps(
                        {"email": email, "password": password},
                        separators=(",", ":"),
                    ),
                ),
                approval_ref=_PROVISION_APPROVAL_REF,
            ),
            task_id="provision-path-login",
            approval_ref=_PROVISION_APPROVAL_REF,
        )
        payload = _response_json(login, operation="로그인", statuses=(200,))
        authentication = payload.get("authentication")
        token = (
            authentication.get("token")
            if isinstance(authentication, dict)
            else None
        )
        basket_id = str(
            authentication.get("bid", "")
            if isinstance(authentication, dict)
            else ""
        )
        if not isinstance(token, str) or not token:
            raise RuntimeError("임시 계정 로그인 응답에 token이 없습니다.")
        account.basket_id = basket_id if _OBJECT_ID.fullmatch(basket_id) else None

        credential = ResolvedHttpCredential(
            authorization=f"Bearer {token}", cookies=(("token", token),)
        )
        resolver.add(_PROVISION_SESSION_REF, credential)
        app.stores.runs.save(
            app.stores.runs.get(provision_run_id).with_updates(
                credential_ref=_PROVISION_SESSION_REF
            )
        )
        _, answer = app.collector.collect_with_result(
            provision_run_id,
            urljoin(base_url, "api/SecurityAnswers"),
            EvidenceRequest(
                evidence_type="account_provisioning",
                surface_id="juice-shop-account-provisioning",
                reason="add a security answer to the disposable local account",
                suggested_tool="http_post",
                http_request=HttpRequestSpec(
                    method="POST",
                    headers=(("Content-Type", "application/json"),),
                    body=json.dumps(
                        {
                            "UserId": user_id,
                            "SecurityQuestionId": 1,
                            "answer": secrets.token_urlsafe(12),
                        },
                        separators=(",", ":"),
                    ),
                ),
                approval_ref=_PROVISION_APPROVAL_REF,
            ),
            task_id="provision-path-security-answer",
            approval_ref=_PROVISION_APPROVAL_REF,
            credential_ref=_PROVISION_SESSION_REF,
        )
        _response_json(answer, operation="보안 답변 생성", statuses=(201,))

        # 같은 token을 서로 다른 참조로 등록해 Recon/Analysis 유형별 CookieJar를
        # 격리한다. data-erasure 응답의 로그아웃 Cookie가 SSTI 세션을 지우지 않는다.
        for credential_ref in (
            _RECON_CREDENTIAL_REF,
            _PATH_TRAVERSAL_CREDENTIAL_REF,
            _TEMP_SSTI_CREDENTIAL_REF,
        ):
            resolver.add(credential_ref, credential)
        return account, provision_run_id
    except Exception:
        if account is not None:
            _cleanup_provisioned_accounts(cleanup_database, [account])
        raise


def main(
    argv: list[str], *, auto_runner_name: str | None = None,
    artifact_directory: Path | None = None,
    configure_parser: Callable[[argparse.ArgumentParser], None] | None = None,
    validate_args: Callable[[argparse.Namespace], str | None] | None = None,
    on_completed: Callable[[argparse.Namespace, object, Run], None] | None = None,
) -> int:
    # 다른 로컬 대상 실행기는 auto 경로만 공유한다. 대상별 준비/seed 선택은 금지한다.
    auto_only = auto_runner_name is not None
    runner_name = auto_runner_name or "Juice Shop"
    parser = argparse.ArgumentParser(
        description=(
            f"{runner_name} 로컬 웹앱을 base URL에서 자동 탐색한다. "
            "대상별 seed·계정 준비 없이 공용 Recon/Router/Analysis/Validation을 실행한다. "
            "기본값: auto/base-url, 브라우저 Recon 켬, heuristic, 요청 상한 80."
            if auto_only else __doc__
        )
    )
    add_routing_arguments(parser, artifact_directory=artifact_directory)
    parser.add_argument(
        "--recon-entry",
        choices=("base-url",) if auto_only else ("targeted", "base-url"),
        default="base-url" if auto_only else "targeted",
        help=(
            "starts Recon only from the supplied base URL" if auto_only else
            "targeted keeps the existing vulnerability-specific start URL/seeds; "
            "base-url starts Recon only from the supplied base URL"
        ),
    )
    parser.add_argument("base_url", help=f"localhost/127.0.0.1 {runner_name} base URL")
    parser.add_argument(
        "--vuln",
        choices=("auto",) if auto_only else (*_VULN_TARGETS, "auto", "all"),
        default="auto" if auto_only else "ssti",
        help="취약점 유형 자동 판별" if auto_only else "취약점 유형 (default: ssti)",
    )
    parser.add_argument(
        "--profile",
        choices=("heuristic", "llm"),
        default="heuristic",
        help="analysis profile (default: heuristic)",
    )
    parser.add_argument(
        "--orchestrator",
        choices=("heuristic", "hybrid"),
        default="heuristic",
        help="optional LLM choice of one already discovered page for extra Recon",
    )
    parser.add_argument(
        "--budget-allocation",
        choices=("off", "heuristic", "hybrid"),
        default="off",
        help="protect validation requests and order candidates; hybrid asks the LLM",
    )
    parser.add_argument(
        "--router-advisor",
        action="store_true",
        help=(
            "Router가 규칙으로 분류하지 못한 표면을 LLM에게 물어본다. "
            "--profile과 독립적인 축이라 heuristic 프로필에서도 켤 수 있다"
        ),
    )
    parser.add_argument(
        "--llm-provider",
        choices=("gemini", "anthropic"),
        default="gemini",
        help="LLM provider for Analysis, Recon, Router, Orchestrator, allocation or Report (default: gemini)",
    )
    parser.add_argument("--llm-model", help="provider model id")
    if not auto_only:
        parser.add_argument(
            "--juice-shop-db",
            help=(
                "Path Traversal용 임시 계정 정리에 사용할 Juice Shop "
                "juiceshop.sqlite 경로"
            ),
        )
    if auto_only:
        parser.add_argument(
            "--no-browser-recon", dest="browser_recon", action="store_false",
            help="브라우저 Recon을 끄고 정적 HTML/JS 수집만 사용한다",
        )
        parser.set_defaults(browser_recon=True)
    parser.add_argument("--browser-executable", metavar="PATH",
                        help="설치된 Chromium 실행 파일의 명시적 경로")
    parser.add_argument(
        "--knowledge-db",
        help=(
            "과거 KnowledgeCase를 Analysis 참고용으로 검색하고 확정 Finding을 "
            "발행할 SQLite 경로. 파일명만 주면 knowledge/ 아래에 저장하며, "
            "주지 않으면 검색·발행하지 않는다"
        ),
    )
    parser.add_argument(
        "--request-budget",
        type=int,
        help=(f"Run 전체 HTTP 요청 상한 (기본: {_ALL_MODE_BUDGET})" if auto_only else
              "Run 전체 HTTP 요청 상한 (기본: 단일 유형 %d, 전체 모드 %d)"
              % (_DEFAULT_BUDGET, _ALL_MODE_BUDGET)),
    )
    parser.add_argument(
        "--ssrf-local-callback", action="store_true",
        help="로컬 대상 실험용 loopback HTTP callback 수신기를 실행한다(원격 대상에는 사용 불가)",
    )
    parser.add_argument(
        "--ssrf-owned-local-receiver", action="store_true",
        help=(
            "격리된 로컬 연구에서만 운영자 소유 Receiver를 별도 "
            "실행한다(--ssrf-review의 Surface 단위 승인 필수)"
        ),
    )
    parser.add_argument(
        "--ssrf-review", action="store_true",
        help=(
            "Recon 후 URL 입력 좌표의 callback/Owned Receiver를 먼저 "
            "독립 재현하고, 성공 시 별도 승인으로 내부 확인을 진행한다(기본 off)"
        ),
    )
    parser.add_argument(
        "--ssrf-local-callback-host",
        choices=("127.0.0.1", "host.docker.internal"), default="127.0.0.1",
        help="Docker 대상에는 host.docker.internal을 광고한다(기본 수신 주소는 loopback)",
    )
    parser.add_argument(
        "--ssrf-local-callback-bind-host", default="127.0.0.1",
        help="로컬 Docker bridge 실험에서만 수신기를 결합할 사설 IPv4 주소",
    )
    parser.add_argument(
        "--ssrf-oast", choices=("off", "public_interactsh", "private_interactsh"),
        default="off", help="명시적으로 선택한 Interactsh callback Provider (기본 off)",
    )
    parser.add_argument(
        "--ssrf-public-oast-consent", action="store_true",
        help="공개 Interactsh에 대상 callback 메타데이터를 보내는 데 동의한다",
    )
    parser.add_argument("--ssrf-interactsh-server", help="사설 Interactsh HTTPS 서버 주소")
    parser.add_argument("--ssrf-interactsh-callback-domain", help="사설 서버의 callback DNS 도메인")
    parser.add_argument(
        "--ssrf-canary-url",
        help="이전 옵션: 내부 확인 주소는 --ssrf-review의 Recon 후 비표시 입력을 사용",
    )
    parser.add_argument(
        "--ssrf-canary-policy-ref",
        help="이전 옵션: 목적지 규칙은 --ssrf-review에서 선택한 좌표에 확인",
    )
    parser.add_argument(
        "--ssrf-canary-consent", action="store_true",
        help="이전 옵션: 실행 승인은 --ssrf-review에서 별도로 확인",
    )
    parser.add_argument(
        "--recon-max-pages",
        type=int,
        help=(
            "maximum documents/scripts Recon may fetch; defaults to the profile's "
            "bounded discovery limit"
        ),
    )
    parser.add_argument(
        "--approve-state-changing",
        action="store_true",
        help=(
            "현재 로컬 Run에서 상태 변경 가능성이 있는 요청을 명시적으로 승인한다. "
            "호스트·경로·도구·요청 예산 제한은 그대로 적용된다"
        ),
    )
    parser.add_argument(
        "--redirect-origin-alias",
        action="append",
        default=[],
        metavar="HOST:PORT",
        help=(
            "treat an explicitly named upstream authority in Location headers as "
            "the supplied local target origin (repeatable; useful behind a local proxy)"
        ),
    )
    parser.add_argument(
        "--validation-review",
        action="store_true",
        help="비확정 Validation 결과에 LLM 분류 Claim을 남긴다(--profile llm 전용, 판정 불변)",
    )
    parser.add_argument("--debug", action="store_true", help="안전한 진행 로그 출력")
    parser.add_argument(
        "--debug-llm-content",
        action="store_true",
        help="LLM prompt와 구조화 응답 출력",
    )
    if configure_parser is not None:
        configure_parser(parser)
    args = parser.parse_args(argv[1:])
    if validate_args is not None:
        rejection = validate_args(args)
        if rejection is not None:
            print(f"거부: {rejection}")
            return 2
    if artifact_directory is not None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        stem = artifact_directory / f"dynast-{stamp}-{uuid4().hex[:8]}"
        args.report_out = args.report_out or f"{stem}.md"
        args.routing_log = args.routing_log or f"{stem}.jsonl"
    if args.request_budget is not None and args.request_budget <= 0:
        print("거부: --request-budget는 양수여야 합니다.")
        return 2
    if args.browser_executable:
        browser_path = Path(args.browser_executable).expanduser()
        if not browser_path.is_file() or not os.access(browser_path, os.X_OK):
            print("거부: --browser-executable은 실행 가능한 로컬 파일이어야 합니다.")
            return 2
        args.browser_executable = str(browser_path.resolve())
    if args.recon_max_pages is not None and args.recon_max_pages <= 0:
        print("거부: --recon-max-pages는 양수여야 합니다.")
        return 2
    if args.validation_review and args.profile != "llm":
        print("거부: --validation-review는 --profile llm과 함께 사용해야 합니다.")
        return 2
    if args.router == "agentic" and args.compare_routers:
        print("거부: --router agentic은 현재 --compare-routers와 함께 사용할 수 없습니다.")
        return 2
    if args.vuln == "auto" and args.recon_entry != "base-url":
        print("거부: --vuln auto는 --recon-entry base-url과 함께 사용해야 합니다.")
        return 2
    if args.ssrf_local_callback and args.vuln not in {"auto", "all"}:
        print("거부: --ssrf-local-callback은 auto/all 통합 검사에서만 사용합니다.")
        return 2
    if args.ssrf_owned_local_receiver and args.vuln not in {"auto", "all"}:
        print("거부: --ssrf-owned-local-receiver는 auto/all 통합 검사에서만 사용합니다.")
        return 2
    if args.ssrf_owned_local_receiver and not args.ssrf_review:
        print("거부: 운영자 소유 Receiver는 --ssrf-review 승인 절차가 필요합니다.")
        return 2
    if args.ssrf_local_callback and args.ssrf_oast != "off":
        print("거부: 로컬 callback과 Interactsh는 동시에 선택할 수 없습니다.")
        return 2
    if (
        args.ssrf_local_callback_host != "127.0.0.1"
        and not (args.ssrf_local_callback or args.ssrf_owned_local_receiver)
    ):
        print("거부: Docker callback 주소에는 명시적인 로컬 SSRF 수신기가 필요합니다.")
        return 2
    if (
        args.ssrf_local_callback_bind_host != "127.0.0.1"
        and (
            args.ssrf_local_callback_host != "host.docker.internal"
            or not (args.ssrf_local_callback or args.ssrf_owned_local_receiver)
        )
    ):
        print("거부: Docker bridge 수신 주소에는 host.docker.internal 수신기가 필요합니다.")
        return 2
    if args.ssrf_oast != "off" and args.vuln not in {"auto", "all"}:
        print("거부: Interactsh SSRF는 auto/all 통합 검사에서만 사용합니다.")
        return 2
    if args.ssrf_oast == "public_interactsh" and not args.ssrf_public_oast_consent:
        print("거부: 공개 OAST는 --ssrf-public-oast-consent가 필요합니다.")
        return 2
    if args.ssrf_oast == "private_interactsh" and not args.ssrf_interactsh_server:
        print("거부: 사설 OAST에는 서버 주소가 필요합니다.")
        return 2
    if args.ssrf_canary_url or args.ssrf_canary_policy_ref or args.ssrf_canary_consent:
        print(
            "거부: --ssrf-canary-* 옵션은 더 이상 사용하지 않습니다. "
            "--ssrf-review에서 Recon 후 좌표를 선택하고 내부 확인 주소와 "
            "목적지 규칙을 별도로 승인하세요."
        )
        return 2
    if args.router_advisor:
        # 팀원 PR에서 사용하던 옵션을 새 실험 축의 명칭으로 호환한다.
        args.router = "hybrid"

    base_url = args.base_url.rstrip("/") + "/"
    parsed = urlsplit(base_url)
    host = (parsed.hostname or "").casefold()
    if parsed.scheme not in {"http", "https"} or host not in _LOCAL_HOSTS:
        print(f"거부: 이 실행기는 localhost/127.0.0.1의 {runner_name} 대상만 허용합니다.")
        return 2
    run_all = args.vuln == "all"
    auto_scan = args.vuln == "auto"
    broad_scan = run_all or auto_scan
    vuln = None if broad_scan else _VULN_TARGETS[args.vuln]
    access_control = args.vuln in {"access_control", "all"}
    needs_path_account = args.vuln in {"path_traversal", "all"}
    target_label = "전체" if run_all else "자동 탐색" if auto_scan else vuln.label
    cleanup_database: Path | None = None
    if needs_path_account:
        try:
            cleanup_database = _resolve_juice_shop_db(args.juice_shop_db)
        except RuntimeError as error:
            print(f"거부: {error}")
            return 2
    if args.recon_entry == "base-url":
        target_url = base_url
    elif broad_scan:
        # 전체 모드는 Recon이 시작 페이지에서 Surface를 찾아 유형별로 라우팅한다.
        target_url = base_url
    elif access_control:
        # 시작 Surface가 입력받은 Actor 계정의 basket ID에 달려 있어 로그인 후 정해진다.
        pass
    else:
        assert vuln is not None
        # seed_path 가 없는 유형은 Recon 이 번들에서 표면을 찾아낸다(SPA 라우트, /ftp).
        target_url = (
            base_url
            if vuln.seed_path is None
            else urljoin(base_url, vuln.seed_path)
        )

    debug_enabled = args.debug or args.debug_llm_content
    progress = _DebugProgress(debug_enabled)
    llm_client = None
    llm_meter: _LlmUsageMeter | None = None
    selected_model = ""
    rpm_limit: int | None = None
    if needs_llm(args):
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
        rpm_limit = args.llm_rpm_limit
        if rpm_limit is None and args.llm_provider == "gemini":
            rpm_limit = _DEFAULT_GEMINI_RPM_LIMIT
        if rpm_limit is not None:
            llm_client = SlidingWindowLlmClient(
                llm_client,
                max_calls=rpm_limit,
            )
            progress.log(f"LLM 호출 제한 적용: {rpm_limit}회/60초")
        if debug_enabled:
            llm_client = _ProgressLlmClient(
                llm_client,
                provider=args.llm_provider,
                model=selected_model,
                progress=progress,
                show_content=args.debug_llm_content,
            )
        llm_meter = _LlmUsageMeter(llm_client)
        llm_client = llm_meter
        progress.log(
            f"LLM 구성 완료: provider={_safe_log_value(args.llm_provider)}, "
            f"model={_safe_log_value(selected_model)}"
        )

    # 기존 계약: 기록 경로가 쓰기 불가면 확인 질문이나 대상 준비 전에 중단한다.
    try:
        JsonlRoutingAuditLog(args.routing_log).prepare()
    except OSError as error:
        print(f"Router 기록을 시작하지 못했습니다: {error}")
        return 2

    _print_execution_preview(
        args,
        target_label=target_label,
        selected_model=selected_model,
        rpm_limit=rpm_limit,
        runner_name=runner_name,
    )
    if broad_scan:
        print("참고: 검증된 정상 요청 템플릿이 없어 POST Path Traversal 탐침은 차단됩니다.")

    agent_credentials: tuple[tuple[str, str], ...] = ()
    recon_seed_urls: tuple[str, ...] = ()
    access_accounts: tuple[_AccessAccountInput, _AccessAccountInput] | None = None
    if auto_scan:
        if args.approve_state_changing:
            print(
                "이 검증은 알려진 취약점 유형·endpoint·대상별 계정 준비 없이 루트 URL에서\n"
                "지원되는 Analyzer 후보를 자동 분류합니다. 상태 변경 가능 요청을 명시적으로\n"
                "승인했으므로 대상 데이터나 세션이 변경될 수 있습니다."
            )
        else:
            print(
                "이 검증은 알려진 취약점 유형·endpoint·대상별 계정 준비 없이 루트 URL에서\n"
                "지원되는 Analyzer 후보를 자동 분류합니다. 인증과 상태 변경 승인은 제공하지 않습니다."
            )
        confirmation = f"로컬 {runner_name} 자동 탐색을 시작할까요? [y/N] "
        credentials = {}
        approvals = ()
        run_credential_ref = None
        principal_credentials = ()
        actor_object_id = None
        owner_object_id = None
    elif run_all:
        credentials = {}
        approvals = (
            _PROVISION_APPROVAL_REF,
            _ACCESS_LOGIN_APPROVAL_REF,
            PATH_TRAVERSAL_POST_APPROVAL_REF,
            SSTI_APPROVAL_REF,
        )
        run_credential_ref = None
        recon_seed_urls = (
            ()
            if args.recon_entry == "base-url"
            else _all_mode_recon_seeds(base_url, include_ssti=True)
        )
        confirmation = "위 구성으로 로컬 Juice Shop 통합 검사를 시작할까요? [y/N] "
        principal_credentials = ()
        actor_object_id = None
        owner_object_id = None
    elif access_control:
        print(
            "이 검증은 사용자가 제공한 Juice Shop 전용 테스트 계정 두 개로 로그인하고\n"
            "각 계정의 token과 basket ID를 메모리에서만 사용합니다. 계정을 생성·삭제하거나\n"
            "입력한 이메일·비밀번호를 Run, Evidence, SQLite, JSONL에 저장하지 않습니다."
        )
        confirmation = "테스트 계정 두 개로 Access Control 검증을 실행할까요? [y/N] "
        credentials = {}
        approvals: tuple[str, ...] = (_ACCESS_LOGIN_APPROVAL_REF,)
        run_credential_ref = None
        principal_credentials = ()
        actor_object_id = None
        owner_object_id = None
    elif args.vuln in ("xss", "path_traversal"):
        if args.vuln == "xss":
            print(
                "이 검증은 헤드리스 브라우저로 SPA 라우트를 열어 값이 DOM에 반사되는지 봅니다.\n"
                "요청은 읽기 전용 GET이며 대상 상태를 바꾸지 않습니다."
            )
        else:
            print(
                "이 검증은 폐기 가능한 임시 계정으로 보호 페이지를 관측합니다.\n"
                "정상 요청 템플릿이 검증되지 않은 POST Path Traversal 탐침은 보내지\n"
                "않으며, 발견된 안전한 GET Surface만 검사합니다. 검증 종료 시\n"
                "임시 계정과 연결 데이터를 직접 정리합니다."
            )
        confirmation = f"로컬 Juice Shop {vuln.label} 검증을 실행할까요? [y/N] "
        credentials = {}
        run_credential_ref = None
        principal_credentials = ()
        actor_object_id = None
        owner_object_id = None
        approvals = (
            (_PROVISION_APPROVAL_REF, PATH_TRAVERSAL_POST_APPROVAL_REF)
            if args.vuln == "path_traversal"
            else ()
        )
    elif args.vuln == "sqli":
        if args.approve_state_changing:
            print(
                "이 검증은 인증 없이 GET과 발견된 HTML POST 폼에 최소 SQL 구문 탐침을 "
                "보냅니다. 상태 변경 가능 요청을 명시적으로 승인한 구성입니다."
            )
        else:
            print(
                "이 검증은 인증 없이 읽기 전용 GET 탐침을 보냅니다. 발견된 POST 폼은 "
                "후보로 기록하지만 중앙 정책에서 실행을 차단합니다."
            )
        confirmation = "로컬 Juice Shop SQLi 검증을 실행할까요? [y/N] "
        credentials = {}
        run_credential_ref = None
        principal_credentials = ()
        actor_object_id = None
        owner_object_id = None
        approvals = ()
    else:
        print("브라우저 개발자 도구에서 로컬 Juice Shop의 token Cookie 값을 확인하세요.")
        token = getpass.getpass("Juice Shop token Cookie (숨김 입력): ").strip()
        if not token:
            print("취소: token Cookie가 비어 있습니다.")
            return 2
        print(
            "이 검증은 전용 실습 계정의 username을 control/산술식으로 변경한 뒤 "
            f"{SSTI_CLEANUP_VALUE!r}(으)로 정리합니다."
        )
        confirmation = "로컬 Juice Shop SSTI 검증을 실행할까요? [y/N] "
        credentials = {
            _CREDENTIAL_REF: ResolvedHttpCredential(cookies=(("token", token),))
        }
        run_credential_ref = _CREDENTIAL_REF
        principal_credentials = ()
        actor_object_id = None
        owner_object_id = None
        approvals = (SSTI_APPROVAL_REF,)
    if args.approve_state_changing:
        approvals = tuple(
            dict.fromkeys((
                *approvals,
                _STATE_CHANGING_APPROVAL_REF,
                SSTI_APPROVAL_REF,
                PATH_TRAVERSAL_POST_APPROVAL_REF,
            ))
        )
    if input(confirmation).strip().casefold() != "y":
        print("취소했습니다.")
        return 2
    if auto_scan:
        try:
            if getattr(args, "anonymous", False):
                session_credential = None
            elif getattr(args, "session_cookie_stdin", False):
                session_credential = _read_session_cookie_stdin()
            elif getattr(args, "session_authorization_stdin", False):
                session_credential = _read_session_authorization_stdin()
            else:
                session_credential = _prompt_optional_session_cookie()
        except ValueError as error:
            print(f"취소: {error}")
            return 2
        if session_credential is not None:
            credentials[_AUTO_SESSION_CREDENTIAL_REF] = session_credential
            run_credential_ref = _AUTO_SESSION_CREDENTIAL_REF
            print("로그인 세션을 이 Run에 적용합니다. 인증정보 원문은 저장하지 않습니다.")
            if getattr(args, "owner_session_cookie_stdin", False):
                try:
                    owner_credential = _read_session_cookie_stdin()
                except ValueError as error:
                    print(f"취소: 두 번째 세션이 유효하지 않습니다: {error}")
                    return 2
                credentials[_AUTO_OWNER_CREDENTIAL_REF] = owner_credential
                principal_credentials = (
                    ("actor", _AUTO_SESSION_CREDENTIAL_REF),
                    ("owner", _AUTO_OWNER_CREDENTIAL_REF),
                )
                actor_object_id = args.access_actor_object_id
                owner_object_id = args.access_owner_object_id
        else:
            print("로그인 세션 없이 익명 탐색을 진행합니다.")
    if access_control:
        try:
            access_accounts = _prompt_access_control_accounts()
        except ValueError as error:
            print(f"취소: {error}")
            return 2

    progress_view = None if debug_enabled else RunProgressView()
    resolver = InMemoryCredentialResolver({})
    for credential_ref, credential in credentials.items():
        resolver.add(
            credential_ref,
            credential,
            allowed_origins=(base_url,),
        )
    http_runtime = HttpExecutionRuntime(
        credential_resolver=resolver,
        redirect_origin_aliases=tuple(args.redirect_origin_alias),
    )
    # SPA 의 DOM sink 는 브라우저로만 관측된다. 필요할 때만 감싸 다른 유형의
    # 실행 비용을 늘리지 않는다.
    needs_browser = args.vuln in _BROWSER_VULNS
    runtime = (
        PlaywrightBrowserRuntime(
            http_runtime=http_runtime, executable_path=args.browser_executable,
        )
        if needs_browser
        else http_runtime
    )
    audit = _DebugAuditLog(progress) if debug_enabled else InMemoryExecutionAuditLog()
    # 대상 Evidence 와 분리된 Knowledge Plane 이다. 경로를 주지 않으면
    # 과거 Case 검색과 새 Finding 발행을 모두 사용하지 않는다.
    knowledge_base = None
    if args.knowledge_db:
        knowledge_path = _knowledge_database_path(args.knowledge_db)
        knowledge_path.parent.mkdir(parents=True, exist_ok=True)
        knowledge_base = SQLiteKnowledgeBase(knowledge_path)
    ssrf_callback = None
    ssrf_owned_receiver = None
    try:
        if args.ssrf_local_callback:
            ssrf_callback = LocalSsrfCallbackService(
                advertised_host=args.ssrf_local_callback_host,
                bind_host=args.ssrf_local_callback_bind_host,
            )
        elif args.ssrf_oast != "off":
            ssrf_callback = InteractshCliCallbackService(
                server=("oast.pro" if args.ssrf_oast == "public_interactsh"
                        else args.ssrf_interactsh_server),
                public_oast=args.ssrf_oast == "public_interactsh",
                public_oast_consent=args.ssrf_public_oast_consent,
                callback_domain=args.ssrf_interactsh_callback_domain,
                token=(os.environ.get("HACKLIPSE_INTERACTSH_TOKEN", "")
                       if args.ssrf_oast == "private_interactsh" else ""),
            )
    except (OSError, TimeoutError, ValueError) as error:
        close_ssrf_services(ssrf_callback)
        ssrf_callback = None
        print(
            "SSRF callback Provider를 시작하지 못해 callback 전략만 "
            f"비활성화합니다: {error}"
        )
    try:
        if args.ssrf_owned_local_receiver:
            # Public callback Provider와 신뢰 경계를 공유하지 않는 별도 인스턴스다.
            ssrf_owned_receiver = LocalSsrfCallbackService(
                advertised_host=args.ssrf_local_callback_host,
                bind_host=args.ssrf_local_callback_bind_host,
            )
    except (OSError, TimeoutError, ValueError) as error:
        close_ssrf_services(ssrf_owned_receiver)
        ssrf_owned_receiver = None
        print(
            "운영자 소유 SSRF Receiver를 시작하지 못해 "
            f"Receiver 전략만 비활성화합니다: {error}"
        )
    try:
        router = build_run_router(
            args, vulnerability_types=None if broad_scan else (target_label,),
            llm_client=llm_client, selected_model=selected_model,
            # With review enabled, only the post-Recon selected coordinate is routed.
            ssrf_callback_service=None if args.ssrf_review else ssrf_callback,
        )
    except (OSError, TimeoutError, ValueError) as error:
        close_ssrf_services(ssrf_callback, ssrf_owned_receiver)
        print(f"Router 기록을 시작하지 못했습니다: {error}")
        return 2
    app = None
    reviewed_ssrf_run_ids: set[str] = set()

    def post_recon_ssrf_review(run: Run) -> None:
        # The callback runs only after assembly/start, so this late binding is resolved.
        if app is None:
            raise RuntimeError("SSRF review application is not assembled")
        if run.run_id in reviewed_ssrf_run_ids:
            return
        callback_mode = (
            "off" if ssrf_callback is None else
            "local_callback" if args.ssrf_local_callback else args.ssrf_oast
        )
        if _run_ssrf_review_gate(
            app, run, callback_mode=callback_mode,
            owned_receiver_mode=ssrf_owned_receiver is not None,
            allow_initial_internal=False,
        ):
            reviewed_ssrf_run_ids.add(run.run_id)

    def post_ssrf_callback_review(run: Run) -> bool:
        # Eligibility (independent A/B proof and four-request floor) is owned by
        # the Orchestrator. This hook only gathers an explicit second approval.
        if app is None:
            raise RuntimeError("SSRF review application is not assembled")
        return _run_ssrf_internal_followup_gate(app, run)

    app = assemble_with_ssrf_cleanup(
        build_local_application, ssrf_callback,
        {},
        ssrf_cleanup_services=(ssrf_owned_receiver,),
        runtime=runtime,
        knowledge_base=knowledge_base,
        orchestration_advisor=(
            LlmOrchestrationAdvisor(llm_client=llm_client)
            if args.orchestrator == "hybrid" and llm_client is not None
            else None
        ),
        budget_allocation_advisor=(
            LlmBudgetAllocationAdvisor(llm_client=llm_client)
            if args.budget_allocation == "hybrid" and llm_client is not None
            else None
        ),
        report_format_version="v2",
        report_mode=args.report,
        report_llm_client=llm_client,
        report_llm_model=selected_model,
        # 살아 있는 계측기를 넘긴다. 조립 시점에는 아직 0이고, Report가 만들어질 때
        # 그 Run이 실제로 쓴 누적값을 읽는다. client를 만들지 않았다면 사용량을 모르는
        # 것이 아니라 0회다 - 모른다고 적으면 요약 on/off의 사실이 서로 달라진다.
        report_llm_usage=llm_meter if llm_meter is not None else NoLlmUsage(),
        # 전체 모드는 유형을 제한하지 않는다. Router가 Surface별로 관련 Candidate만 만든다.
        router=router,
        ssrf_callback_service=ssrf_callback,
        ssrf_owned_receiver_service=ssrf_owned_receiver,
        ssrf_local_test_mode=isinstance(ssrf_callback, LocalSsrfCallbackService),
        credential_resolver=resolver,
        approval_gate=StaticApprovalGate(approvals),
        default_approval_ref=(
            _STATE_CHANGING_APPROVAL_REF
            if args.approve_state_changing
            else None
        ),
        audit_log=audit,
        task_progress_callback=progress.task_event if debug_enabled else None,
        # 진행 화면과 상세 로그 중 하나만 붙인다. 상세 로그가 중간에 끼면 화면을
        # 다시 그릴 때 앞서 출력한 줄과 어긋나 둘 다 읽을 수 없게 된다.
        progress_sink=None if debug_enabled else progress_view,
        config=OrchestratorConfig(
            browser_xss_validation=needs_browser,
            budget_allocation_enabled=args.budget_allocation != "off",
            post_recon_gate=(post_recon_ssrf_review if args.ssrf_review else None),
            post_ssrf_callback_gate=(
                post_ssrf_callback_review if args.ssrf_review else None
            ),
        ),
    )
    base_path = parsed.path if parsed.path.endswith("/") else f"{parsed.path}/"
    preparation_run_ids: list[str] = []
    provisioned_accounts: list[_ProvisionedAccount] = []
    if access_control:
        assert access_accounts is not None
        try:
            actor_object_id, owner_object_id, authentication_run_id = (
                _authenticate_access_control_accounts(
                    app,
                    resolver,
                    access_accounts,
                    base_url=base_url,
                    host=host,
                    allowed_path_prefix=base_path or "/",
                )
            )
        except (RuntimeError, ValueError) as error:
            access_accounts = None
            resolver.clear()
            close_ssrf_services(ssrf_callback, ssrf_owned_receiver)
            print(f"Access Control 테스트 계정 로그인 실패: {error}")
            return 1
        access_accounts = None
        preparation_run_ids.append(authentication_run_id)
        access_surface_url = urljoin(base_url, f"rest/basket/{actor_object_id}")
        principal_credentials = (
            ("actor", _ACTOR_CREDENTIAL_REF),
            ("owner", _OWNER_CREDENTIAL_REF),
        )
        if args.recon_entry == "base-url":
            target_url = base_url
            run_credential_ref = _ACTOR_CREDENTIAL_REF
        elif run_all:
            recon_seed_urls = _all_mode_recon_seeds(
                base_url,
                include_ssti=True,
                access_control_object_id=actor_object_id,
            )
        else:
            target_url = access_surface_url
            run_credential_ref = _ACTOR_CREDENTIAL_REF
        progress.log("입력받은 ACTOR/OWNER 테스트 계정 로그인 완료")

    if needs_path_account:
        assert cleanup_database is not None
        try:
            path_account, path_provision_run_id = _provision_path_traversal_account(
                app,
                resolver,
                base_url=base_url,
                host=host,
                allowed_path_prefix=base_path or "/",
                cleanup_database=cleanup_database,
            )
        except (RuntimeError, ValueError) as error:
            for run_id in preparation_run_ids:
                http_runtime.close_session(run_id)
            resolver.clear()
            close_ssrf_services(ssrf_callback, ssrf_owned_receiver)
            print(f"임시 계정 준비 실패: {error}")
            return 1
        preparation_run_ids.append(path_provision_run_id)
        provisioned_accounts = [path_account]
        run_credential_ref = _RECON_CREDENTIAL_REF
        agent_credentials = (("Path Traversal", _PATH_TRAVERSAL_CREDENTIAL_REF),)
        if run_all:
            agent_credentials += (("SSTI", _TEMP_SSTI_CREDENTIAL_REF),)
        progress.log("Path Traversal용 임시 계정 생성 및 보안 답변 등록 완료")

    target_url, recon_seed_urls = _recon_entry_points(
        base_url,
        target_url,
        recon_seed_urls,
        mode=args.recon_entry,
    )
    needs_discovery = (
        args.recon_entry == "base-url"
        or args.vuln in _BUNDLE_DISCOVERY_VULNS
    )
    request_budget = (
        args.request_budget if args.request_budget is not None
        else _ALL_MODE_BUDGET if broad_scan else _DEFAULT_BUDGET
    )
    run = None
    workflow_error: WorkflowExecutionError | None = None
    cleanup_error: Exception | None = None
    try:
        profile = register_standard_agents(
            app,
            llm_client=llm_client if args.profile == "llm" else None,
            recon_planner=standard_recon_planner(mode=args.recon, llm_client=llm_client),
            recon_max_pages=(
                args.recon_max_pages
                if args.recon_max_pages is not None
                else (_ALL_MODE_RECON_PAGES if needs_discovery else 1)
            ),
            recon_surface_collection_mode=args.surface_collection,
            recon_browser_enabled=args.browser_recon,
            recon_browser_executable_path=args.browser_executable,
            recon_seed_urls=recon_seed_urls,
            recon_infer_unlinked_render_parameters=args.recon_entry == "targeted",
            actor_object_id=actor_object_id,
            owner_object_id=owner_object_id,
            validation_review=args.validation_review,
            agentic_probe_enabled=args.router == "agentic",
        )
        if profile == "llm":
            profile = f"llm/{args.llm_provider} ({_safe_log_value(selected_model)})"
        try:
            progress.log(
                f"Run 시작: vuln={target_label}, profile={profile}, "
                f"router={args.router}, request_budget={request_budget}"
            )
            run = app.orchestrator.start(
                RunRequest(
                    target_url=target_url,
                    scope=RunScope(
                        allowed_hosts=frozenset({host}),
                        allowed_path_prefixes=(base_path or "/",),
                    ),
                    request_budget=request_budget,
                    credential_ref=run_credential_ref,
                    principal_credentials=principal_credentials,
                    agent_credentials=agent_credentials,
                    execution_profile=execution_profile_from_args(
                        args,
                        selected_model=selected_model,
                        llm_rpm_limit=rpm_limit,
                    ),
                )
            )
        except WorkflowExecutionError as error:
            workflow_error = error
    finally:
        if provisioned_accounts and cleanup_database is not None:
            try:
                _cleanup_provisioned_accounts(cleanup_database, provisioned_accounts)
                progress.log("임시 계정 및 연결 데이터 삭제 완료")
            except Exception as error:
                cleanup_error = error
        if run is not None:
            http_runtime.close_session(run.run_id)
        for preparation_run_id in preparation_run_ids:
            http_runtime.close_session(preparation_run_id)
        resolver.clear()
        close_ssrf_services(ssrf_callback, ssrf_owned_receiver)
        if access_control:
            progress.log("입력받은 Access Control credential 메모리 참조 폐기 완료")

    if workflow_error is not None:
        append_run_result(args, app, app.stores.runs.get(workflow_error.run_id))
        print(f"Run 실패: {workflow_error}")
        if cleanup_error is not None:
            print(f"임시 계정 정리 실패: {cleanup_error}")
        return 1
    if run is not None:
        append_run_result(args, app, run)
        write_report_artifact(app, run, args.report_out)
    if cleanup_error is not None:
        print(f"Run은 완료됐지만 임시 계정 정리에 실패했습니다: {cleanup_error}")
        return 1
    assert run is not None
    if on_completed is not None:
        try:
            on_completed(args, app, run)
        except (OSError, ValueError) as error:
            print(f"Run은 완료됐지만 추가 산출물을 저장하지 못했습니다: {error}")
            return 1
    progress.log(f"Run 완료: phase={_safe_log_value(run.phase.value)}")

    # 진행 상태 집계는 Store를 다시 세는 공용 계산을 쓴다. 실행기마다 따로 세면
    # 같은 Run을 두 화면이 다르게 보고할 수 있다.
    snapshot = build_progress_snapshot(
        run,
        stores=app.stores,
        budget=app.budget_manager,
        llm_calls=llm_meter.calls if llm_meter else 0,
        llm_input_tokens=llm_meter.input_tokens if llm_meter else 0,
        llm_output_tokens=llm_meter.output_tokens if llm_meter else 0,
    )
    if progress_view is not None:
        progress_view.close(
            surfaces=snapshot.surface_count, parameters=snapshot.parameter_count
        )
    candidate_counts = Counter(dict(snapshot.candidates_by_type))
    finding_counts = Counter(dict(snapshot.findings_by_type))
    # Observation type을 실행기 표시 문구로 옮긴다. 스냅샷은 원본 type만 담는다.
    labels = {target.signal: target.signal_label for target in _VULN_TARGETS.values()}
    signal_counts = Counter(
        {labels[name]: count for name, count in snapshot.signals_by_type if name in labels}
    )
    ssrf_review = build_ssrf_review_fact(
        profile=run.execution_profile,
        candidates=app.stores.candidates.list_by_run(run.run_id),
        findings=app.stores.findings.list_by_run(run.run_id),
        run_evidence=app.stores.evidence.list_by_run(run.run_id),
    )
    execution_signals = 0 if vuln is None else signal_counts[vuln.signal_label]
    verdict = (
        "CONFIRMED (취약점 확인)"
        if (snapshot.finding_count if broad_scan else finding_counts[target_label])
        else "미확정"
    )

    print()
    print("=" * 54)
    print(f"  {runner_name} {target_label} 실행 결과")
    print("=" * 54)
    print()
    print("[실행 정보]")
    print(f"  상태            완료 ({run.phase.value})")
    print(f"  분석 대상       {target_label}")
    print(f"  Analysis 구성   {profile}")
    if auto_scan:
        print(
            "  로그인 세션     "
            f"{'사용' if run.credential_ref == _AUTO_SESSION_CREDENTIAL_REF else '미사용'}"
        )
    print(f"  추가 Recon      {run.extra_recon_rounds}회")
    if args.browser_recon:
        for item in app.stores.evidence.list_by_run(run.run_id):
            if item.observation.get("type") == "browser_recon_summary":
                print(f"  브라우저 Recon  {item.observation.get('status')} · "
                      f"요청 {item.observation.get('request_count', 0)}회 · "
                      f"UI 동작 {item.observation.get('action_count', 0)}회 · "
                      f"해시 확인 {item.observation.get('hash_probe_count', 0)}회/"
                      f"반사 {item.observation.get('hash_reflection_count', 0)}개 · "
                      f"중단 {item.observation.get('stop_reason', 'unknown')}")
    if run.budget_candidate_order:
        print(
            "  예산 배분       "
            f"{run.budget_allocation_source} · "
            f"검증 예약 {run.budget_validation_reserve}회/Candidate"
        )
    print(
        f"  감사된 실행     {len(audit.list_by_run(run.run_id))}회 / "
        f"예산 {snapshot.budget_used}회 사용, 상한 {snapshot.budget_total}회"
    )
    if ssrf_callback is not None:
        issued, polled = ssrf_callback.usage
        print(f"  SSRF callback   발급 호출 {issued}회 · 조회 호출 {polled}회")
    if llm_meter is not None:
        print(f"  LLM 사용량      {llm_meter.summary()}")
    recon_planner_summary = _recon_planner_summary(
        app.stores.evidence.list_by_run(run.run_id)
    )
    if recon_planner_summary is not None:
        print(f"  Recon Planner: {recon_planner_summary}")
    if preparation_run_ids:
        preparation_executions = sum(
            len(audit.list_by_run(run_id)) for run_id in preparation_run_ids
        )
        print(f"  계정 준비 실행  {preparation_executions}회")
    print()
    print("[분석 신호]")
    print(f"  Candidate       {_format_counts(candidate_counts)}")
    if broad_scan:
        print(
            f"  Surface         {snapshot.surface_count}개 "
            f"(파라미터 {snapshot.parameter_count}종)"
        )
        print(f"  탐지 신호       {_format_counts(signal_counts)}")
        print(
            f"  검증 완료       {snapshot.validated_count} / {snapshot.candidate_count}"
        )
    else:
        assert vuln is not None
        print(f"  {vuln.signal_label:<14} {execution_signals}개")
    if ssrf_review is not None:
        print()
        print("[SSRF URL 처리 검토]")
        for line in _ssrf_review_summary_lines(ssrf_review):
            print(line)
    if ssrf_callback is not None:
        ssrf_evidence = app.stores.evidence.list_by_run(run.run_id)
        ssrf_results = [item for item in ssrf_evidence
                        if item.observation.get("type") == "ssrf_probe_result"]
        ssrf_hits = [item for item in ssrf_evidence
                     if item.observation.get("type") == "ssrf_callback_http"]
        print()
        print("[SSRF callback 검증]")
        print(f"  Analysis 좌표   {len(ssrf_results)}개 "
              f"(HTTP {sum(item.observation.get('status') == 'http' for item in ssrf_results)}, "
              f"DNS {sum(item.observation.get('status') == 'dns' for item in ssrf_results)}, "
              f"무반응 {sum(item.observation.get('status') == 'no_hit' for item in ssrf_results)}, "
              f"Provider 오류 {sum(item.observation.get('status') == 'provider_error' for item in ssrf_results)})")
        print(f"  HTTP 수신      Analysis {sum(item.validation_id is None for item in ssrf_hits)}개 · "
              f"Validation {sum(item.validation_id is not None for item in ssrf_hits)}개")
        if finding_counts["SSRF"]:
            print("  확정 근거       운영자 금지 규칙 + 독립 canary marker 재현 "
                  "(callback 단독 판정 아님)")
        else:
            print("  확정 기준       목적지 규칙·금지 canary 접근 미입증 — "
                  "callback만으로 CONFIRMED 불가")
    if snapshot.unchecked:
        print()
        print("[검사하지 못한 Candidate]")
        # 검사했는데 없었다 / 검사하다 실패했다 / 시작조차 못 했다를 구분해서 보여준다.
        marks = {
            CandidateStatus.FAILED.value: "실패",
            CandidateStatus.BLOCKED.value: "승인필요",
            CandidateStatus.SKIPPED_BUDGET.value: "예산부족",
        }
        for item in snapshot.unchecked:
            mark = marks.get(item.status, item.status)
            print(f"  {mark:<8} {item.vulnerability_type:<14} {item.reason}")
    analyzer_gaps = _blocked_analyzer_gaps(router)
    if broad_scan and analyzer_gaps:
        requirement_labels = {
            "method": "HTTP 메서드",
            "surface_kind": "Surface 종류",
            "state_changing_input": "상태 변경 입력",
            "input_parameter": "입력 파라미터",
            "parameter_hint": "필수 파라미터",
            "object_identifier": "객체 식별자",
            "required_observation": "필수 관측",
            "observation_parameter": "관측 기반 파라미터",
            "surface": "Surface",
        }
        print()
        print("[실행하지 못한 Analyzer 계약]")
        for item in analyzer_gaps:
            missing = ", ".join(
                requirement_labels.get(value, value)
                for value in item.missing_requirements
            ) or "실행 가능한 Surface"
            print(
                f"  {item.vulnerability_type:<14} "
                f"{item.capability_id} · 부족: {missing}"
            )
    print()
    print("[최종 판정]")
    print(f"  결과            {verdict}")
    print(f"  Finding         {snapshot.finding_count}개")
    print(f"  취약점 유형     {_format_counts(finding_counts)}")
    if not snapshot.candidate_count:
        print()
        if access_control:
            print(
                "  참고: Candidate가 없으면 token이 만료됐거나 "
                "/rest/basket/{id} 응답을 읽지 못했을 수 있습니다."
            )
        elif broad_scan:
            if snapshot.surface_count and analyzer_gaps and len(analyzer_gaps) == len(getattr(router, "last_analyzer_coverage", ())):
                print("  참고: Surface는 발견했지만 현재 Analyzer 실행 조건을 만족하는 입력 좌표가 없습니다.")
            elif snapshot.surface_count:
                print("  참고: 발견한 Surface가 Router에서 Candidate로 채택되지 않았습니다.")
            else:
                print("  참고: Recon에서 Surface를 발견하지 못했습니다.")
        elif args.vuln == "sqli":
            print(f"  참고: Candidate가 없으면 {vuln.seed_path} 응답을 읽지 못했을 수 있습니다.")
        else:
            print("  참고: Candidate가 없으면 token이 만료됐거나 /profile 폼을 읽지 못했을 수 있습니다.")
    print("=" * 54)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
