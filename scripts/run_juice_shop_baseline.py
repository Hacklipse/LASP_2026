"""로컬 OWASP Juice Shop에서 SQLi·SSTI·Access Control 검증을 실행한다.

취약점마다 인증과 정리 요구가 다르다.

    SQLi            인증 없음. 읽기 전용 GET. 정리할 상태가 없다.
    SSTI            실습 계정 token Cookie. username을 바꾸므로 고정값으로 되돌린다.
    Access Control  임시 계정 두 개를 만들고 검증 후 연결 데이터까지 삭제한다.
    all             한 Run에서 여러 유형을 함께 검사한다. 유형별 자격증명은 Run에
                    따로 등록되고, 등록하지 않은 유형은 자격증명 없이 실행된다.

비밀은 Task·Evidence·감사 로그·LLM prompt에 들어가지 않는다. SSTI는 username을 일시적으로
변경하므로 개인 계정이 아닌 실습 계정을 사용한다.

    py scripts/run_juice_shop_baseline.py http://127.0.0.1:3000/
    py scripts/run_juice_shop_baseline.py http://127.0.0.1:3000/ --vuln sqli
    py scripts/run_juice_shop_baseline.py http://127.0.0.1:3000/ --vuln access_control
    py scripts/run_juice_shop_baseline.py http://127.0.0.1:3000/ --vuln all
    py scripts/run_juice_shop_baseline.py http://127.0.0.1:3000/ --profile llm --debug-llm-content
"""

from __future__ import annotations

import argparse
import getpass
import json
import re
import secrets
import sqlite3
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from uuid import uuid4

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
from hacklipse.application import build_progress_snapshot  # noqa: E402
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
from hacklipse.domain import (  # noqa: E402
    CANDIDATE_SKIPPED_BUDGET,
    EvidenceRequest,
    HttpRequestSpec,
    Run,
    RunRequest,
    RunScope,
)
from hacklipse.ports import ResolvedHttpCredential  # noqa: E402
from hacklipse.ports.errors import LlmCredentialsMissing  # noqa: E402

# 기존 DVWA 실행기와 같은 안전한 디버그 출력 구현을 재사용한다. 이 모듈은 main guard가
# 있어 import만으로 실행되지 않는다.
from run_dvwa_baseline import (  # noqa: E402
    _DebugAuditLog,
    _DebugProgress,
    _LlmUsageMeter,
    _ProgressLlmClient,
    _safe_log_value,
)

_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1"})
_CREDENTIAL_REF = "interactive-local-juice-shop"
_ACTOR_CREDENTIAL_REF = "interactive-local-juice-shop-actor"
_OWNER_CREDENTIAL_REF = "interactive-local-juice-shop-owner"
_PROVISION_APPROVAL_REF = "interactive-local-juice-shop-account-provisioning"
_DEFAULT_BUDGET = 20
# 전체 모드는 Recon 크롤링과 여러 Candidate 분석을 한 Run에서 감당해야 한다. 정확한
# 배분은 Task 3(Budget·스케줄링)에서 다루고, 여기서는 우선 상한만 넉넉히 잡는다.
_ALL_MODE_BUDGET = 80
_ALL_MODE_RECON_PAGES = 12
_OBJECT_ID = re.compile(r"^[0-9]{1,10}$")


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
    "access_control": _VulnTarget(
        "Access Control", None, "object_id_auth", "객체 권한 우회"
    ),
}


@dataclass(slots=True)
class _ProvisionedAccount:
    role: str
    credential_ref: str
    user_id: int
    email: str
    basket_id: str | None = None


def _format_counts(counts: Counter[str]) -> str:
    if not counts:
        return "없음"
    return ", ".join(f"{name} {count}개" for name, count in counts.items())


def _response_json(result, *, operation: str, statuses: tuple[int, ...]) -> dict:
    status = result.observation.get("status")
    body = result.observation.get("body")
    if status not in statuses or not isinstance(body, str):
        raise RuntimeError(f"임시 계정 {operation} 응답이 예상한 형식이 아닙니다.")
    try:
        payload = json.loads(body)
    except (TypeError, ValueError) as error:
        raise RuntimeError(f"임시 계정 {operation} 응답이 JSON이 아닙니다.") from error
    if not isinstance(payload, dict):
        raise RuntimeError(f"임시 계정 {operation} 응답이 객체가 아닙니다.")
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


def _provision_access_control_accounts(
    app,
    resolver: InMemoryCredentialResolver,
    *,
    base_url: str,
    host: str,
    allowed_path_prefix: str,
    cleanup_database: Path,
) -> tuple[list[_ProvisionedAccount], str]:
    """두 폐기 가능한 계정을 중앙 Runtime으로 생성·로그인하고 basket ID를 반환한다."""

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
            request_budget=4,
        )
    )
    app.budget_manager.open_run(provision_run_id, 4)

    accounts: list[_ProvisionedAccount] = []
    try:
        for role, credential_ref in (
            ("actor", _ACTOR_CREDENTIAL_REF),
            ("owner", _OWNER_CREDENTIAL_REF),
        ):
            suffix = uuid4().hex
            email = f"hacklipse-{role}-{suffix}@example.invalid"
            password = secrets.token_urlsafe(18)
            register_body = json.dumps(
                {"email": email, "password": password}, separators=(",", ":")
            )
            _, registration = app.collector.collect_with_result(
            provision_run_id,
            urljoin(base_url, "api/Users"),
            EvidenceRequest(
                evidence_type="account_provisioning",
                surface_id="juice-shop-account-provisioning",
                reason=f"create disposable local Juice Shop {role} account",
                suggested_tool="http_post",
                http_request=HttpRequestSpec(
                    method="POST",
                    headers=(("Content-Type", "application/json"),),
                    body=register_body,
                ),
                approval_ref=_PROVISION_APPROVAL_REF,
            ),
            task_id=f"provision-{role}-register",
            approval_ref=_PROVISION_APPROVAL_REF,
        )
            registration_payload = _response_json(
                registration, operation="생성", statuses=(201,)
            )
            registration_data = registration_payload.get("data")
            user_id = (
                registration_data.get("id")
                if isinstance(registration_data, dict)
                else None
            )
            if not isinstance(user_id, int) or user_id <= 0:
                raise RuntimeError("임시 계정 생성 응답에 user ID가 없습니다.")
            account = _ProvisionedAccount(role, credential_ref, user_id, email)
            accounts.append(account)

            login_body = json.dumps(
                {"email": email, "password": password}, separators=(",", ":")
            )
            _, login = app.collector.collect_with_result(
            provision_run_id,
            urljoin(base_url, "rest/user/login"),
            EvidenceRequest(
                evidence_type="account_authentication",
                surface_id="juice-shop-account-provisioning",
                reason=f"log in disposable local Juice Shop {role} account",
                suggested_tool="http_post",
                http_request=HttpRequestSpec(
                    method="POST",
                    headers=(("Content-Type", "application/json"),),
                    body=login_body,
                ),
                approval_ref=_PROVISION_APPROVAL_REF,
            ),
            task_id=f"provision-{role}-login",
            approval_ref=_PROVISION_APPROVAL_REF,
        )
            payload = _response_json(login, operation="로그인", statuses=(200,))
            authentication = payload.get("authentication")
            if not isinstance(authentication, dict):
                raise RuntimeError("임시 계정 로그인 응답에 authentication이 없습니다.")
            token = authentication.get("token")
            basket_id = str(authentication.get("bid", ""))
            if (
                not isinstance(token, str)
                or not token
                or _OBJECT_ID.fullmatch(basket_id) is None
            ):
                raise RuntimeError(
                    "임시 계정 로그인 응답에 token 또는 basket ID가 없습니다."
                )
            account.basket_id = basket_id
            resolver.add(
                credential_ref,
                ResolvedHttpCredential(authorization=f"Bearer {token}"),
            )
    except Exception:
        _cleanup_provisioned_accounts(cleanup_database, accounts)
        raise

    actor_id, owner_id = (account.basket_id for account in accounts)
    if actor_id == owner_id:
        _cleanup_provisioned_accounts(cleanup_database, accounts)
        raise RuntimeError("자동 생성된 두 계정의 basket ID가 같아 대조할 수 없습니다.")
    return accounts, provision_run_id


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_url", help="localhost/127.0.0.1 Juice Shop base URL")
    parser.add_argument(
        "--vuln",
        choices=(*_VULN_TARGETS, "all"),
        default="ssti",
        help="취약점 유형 (default: ssti)",
    )
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
    parser.add_argument(
        "--juice-shop-db",
        help="Access Control 임시 계정 정리에 사용할 juiceshop.sqlite 경로",
    )
    parser.add_argument(
        "--request-budget",
        type=int,
        help="Run 전체 HTTP 요청 상한 (기본: 단일 유형 %d, 전체 모드 %d)"
        % (_DEFAULT_BUDGET, _ALL_MODE_BUDGET),
    )
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
    run_all = args.vuln == "all"
    vuln = None if run_all else _VULN_TARGETS[args.vuln]
    access_control = args.vuln == "access_control"
    target_label = "전체" if run_all else vuln.label
    if run_all:
        # 전체 모드는 Recon이 시작 페이지에서 Surface를 찾아 유형별로 라우팅한다.
        target_url = base_url
    elif access_control:
        # 시작 Surface가 임시 계정의 basket ID에 달려 있어 계정 준비 후에 정해진다.
        try:
            cleanup_database = _resolve_juice_shop_db(args.juice_shop_db)
        except RuntimeError as error:
            print(f"거부: {error}")
            return 2
    else:
        assert vuln is not None and vuln.seed_path is not None
        target_url = urljoin(base_url, vuln.seed_path)

    debug_enabled = args.debug or args.debug_llm_content
    progress = _DebugProgress(debug_enabled)
    llm_client = None
    llm_meter: _LlmUsageMeter | None = None
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
        llm_meter = _LlmUsageMeter(llm_client)
        llm_client = llm_meter
        progress.log(
            f"LLM 구성 완료: provider={_safe_log_value(args.llm_provider)}, "
            f"model={_safe_log_value(selected_model)}"
        )

    agent_credentials: tuple[tuple[str, str], ...] = ()
    if run_all:
        # 전체 모드가 다루는 것은 Recon이 시작 페이지에서 찾아낼 수 있는 유형뿐이다.
        # Access Control은 /rest/basket/{id}처럼 구체적인 객체 ID가 있어야 성립하는데,
        # 그 ID는 크롤링으로 나오지 않고 임의로 만들어내면 열거가 된다. 그래서 전용
        # Run(--vuln access_control)으로 남긴다.
        print(
            "전체 모드는 한 Run에서 Recon이 찾아낸 Surface를 유형별로 라우팅합니다.\n"
            "SQLi와 XSS는 인증 없이 실행됩니다. SSTI는 token Cookie가 있어야 /profile\n"
            "폼을 읽을 수 있습니다.\n"
            "Access Control은 객체 ID가 필요해 크롤링으로 찾을 수 없으므로 "
            "--vuln access_control로 따로 실행하세요."
        )
        token = getpass.getpass(
            "SSTI용 Juice Shop token Cookie (건너뛰려면 Enter, 숨김 입력): "
        ).strip()
        credentials = {}
        approvals = ()
        run_credential_ref = None
        if token:
            credentials[_CREDENTIAL_REF] = ResolvedHttpCredential(
                cookies=(("token", token),)
            )
            approvals = (SSTI_APPROVAL_REF,)
            # Recon은 Run 기본 세션으로 돈다. 인증되지 않으면 /profile 폼을 못 읽어
            # SSTI Surface 자체가 만들어지지 않는다.
            run_credential_ref = _CREDENTIAL_REF
            # 유형별 등록. SQLi·XSS는 여기 없으므로 자격증명 없이 실행된다.
            agent_credentials = (("SSTI", _CREDENTIAL_REF),)
            print(
                "  SSTI 포함: username을 control/산술식으로 바꾼 뒤 "
                f"{SSTI_CLEANUP_VALUE!r}(으)로 정리합니다."
            )
        else:
            print("  SSTI 건너뜀: token이 없어 /profile 폼을 읽을 수 없습니다.")
        confirmation = "로컬 Juice Shop 전체 취약점 검사를 실행할까요? [y/N] "
        principal_credentials = ()
        actor_object_id = None
        owner_object_id = None
    elif access_control:
        print(
            "이 검증은 로컬 Juice Shop에 폐기 가능한 임시 계정 두 개를 생성하고 "
            "각 계정의 token과 basket ID를 메모리에서만 사용합니다.\n"
            "계정 생성·로그인은 상태 변경 요청이며, 검증 종료 시 연결 데이터와 함께 삭제합니다."
        )
        confirmation = "임시 계정 두 개를 생성하고 Access Control 검증을 실행할까요? [y/N] "
        credentials = {}
        approvals: tuple[str, ...] = (_PROVISION_APPROVAL_REF,)
    elif args.vuln == "sqli":
        # 인증도 정리도 필요 없는 유일한 유형이다. 읽기 전용 GET에 메타문자 하나를
        # 실어 control과의 오류 차이만 본다.
        print(
            "이 검증은 인증 없이 읽기 전용 GET만 보냅니다. "
            "대상 상태를 바꾸지 않으므로 정리할 데이터도 없습니다."
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
    if input(confirmation).strip().casefold() != "y":
        print("취소했습니다.")
        return 2

    resolver = InMemoryCredentialResolver(credentials)
    runtime = HttpExecutionRuntime(credential_resolver=resolver)
    audit = _DebugAuditLog(progress) if debug_enabled else InMemoryExecutionAuditLog()
    app = build_local_application(
        {},
        runtime=runtime,
        # 전체 모드는 유형을 제한하지 않는다. Router가 Surface별로 관련 Candidate만 만든다.
        router=standard_router(None if run_all else (target_label,)),
        credential_resolver=resolver,
        approval_gate=StaticApprovalGate(approvals),
        audit_log=audit,
        task_progress_callback=progress.task_event if debug_enabled else None,
    )
    base_path = parsed.path if parsed.path.endswith("/") else f"{parsed.path}/"
    provision_run_id: str | None = None
    provisioned_accounts: list[_ProvisionedAccount] = []
    if access_control:
        try:
            provisioned_accounts, provision_run_id = _provision_access_control_accounts(
                app,
                resolver,
                base_url=base_url,
                host=host,
                allowed_path_prefix=base_path or "/",
                cleanup_database=cleanup_database,
            )
        except (RuntimeError, ValueError) as error:
            print(f"임시 계정 준비 실패: {error}")
            return 1
        actor_object_id = provisioned_accounts[0].basket_id
        owner_object_id = provisioned_accounts[1].basket_id
        assert actor_object_id is not None and owner_object_id is not None
        target_url = urljoin(base_url, f"rest/basket/{actor_object_id}")
        run_credential_ref = _ACTOR_CREDENTIAL_REF
        principal_credentials = (
            ("actor", _ACTOR_CREDENTIAL_REF),
            ("owner", _OWNER_CREDENTIAL_REF),
        )
        progress.log("임시 ACTOR/OWNER 계정 생성 및 로그인 완료")

    request_budget = args.request_budget or (
        _ALL_MODE_BUDGET if run_all else _DEFAULT_BUDGET
    )
    run = None
    workflow_error: WorkflowExecutionError | None = None
    cleanup_error: Exception | None = None
    try:
        profile = register_standard_agents(
            app,
            llm_client=llm_client,
            recon_max_pages=_ALL_MODE_RECON_PAGES if run_all else 1,
            actor_object_id=actor_object_id,
            owner_object_id=owner_object_id,
        )
        if profile == "llm":
            profile = f"llm/{args.llm_provider} ({_safe_log_value(selected_model)})"
        try:
            progress.log(
                f"Run 시작: vuln={target_label}, profile={profile}, "
                f"request_budget={request_budget}"
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
                )
            )
        except WorkflowExecutionError as error:
            workflow_error = error
    finally:
        if access_control and provisioned_accounts:
            try:
                _cleanup_provisioned_accounts(cleanup_database, provisioned_accounts)
                progress.log("임시 ACTOR/OWNER 계정 및 연결 데이터 삭제 완료")
            except Exception as error:
                cleanup_error = error

    if workflow_error is not None:
        print(f"Run 실패: {workflow_error}")
        if cleanup_error is not None:
            print(f"임시 계정 정리 실패: {cleanup_error}")
        return 1
    if cleanup_error is not None:
        print(f"Run은 완료됐지만 임시 계정 정리에 실패했습니다: {cleanup_error}")
        return 1
    assert run is not None
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
    candidate_counts = Counter(dict(snapshot.candidates_by_type))
    finding_counts = Counter(dict(snapshot.findings_by_type))
    # Observation type을 실행기 표시 문구로 옮긴다. 스냅샷은 원본 type만 담는다.
    labels = {target.signal: target.signal_label for target in _VULN_TARGETS.values()}
    signal_counts = Counter(
        {labels[name]: count for name, count in snapshot.signals_by_type if name in labels}
    )
    execution_signals = 0 if vuln is None else signal_counts[vuln.signal_label]
    verdict = (
        "CONFIRMED (취약점 확인)"
        if (snapshot.finding_count if run_all else finding_counts[target_label])
        else "미확정"
    )

    print()
    print("=" * 54)
    print(f"  Juice Shop {target_label} 실행 결과")
    print("=" * 54)
    print()
    print("[실행 정보]")
    print(f"  상태            완료 ({run.phase.value})")
    print(f"  분석 대상       {target_label}")
    print(f"  Agent 구성      {profile}")
    print(
        f"  감사된 실행     {len(audit.list_by_run(run.run_id))}회 / "
        f"예산 {snapshot.budget_used}회 사용, 상한 {snapshot.budget_total}회"
    )
    if llm_meter is not None:
        print(f"  LLM 사용량      {llm_meter.summary()}")
    if provision_run_id is not None:
        print(f"  계정 준비 실행  {len(audit.list_by_run(provision_run_id))}회")
    print()
    print("[분석 신호]")
    print(f"  Candidate       {_format_counts(candidate_counts)}")
    if run_all:
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
    if snapshot.unchecked:
        print()
        print("[검사하지 못한 Candidate]")
        # 검사했는데 없었다 / 검사하다 실패했다 / 시작조차 못 했다를 구분해서 보여준다.
        marks = {"failed": "실패", CANDIDATE_SKIPPED_BUDGET: "예산부족"}
        for item in snapshot.unchecked:
            mark = marks.get(item.status, item.status)
            print(f"  {mark:<8} {item.vulnerability_type:<14} {item.reason}")
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
        elif run_all:
            print("  참고: Candidate가 없으면 Recon이 Surface를 찾지 못했을 수 있습니다.")
        elif args.vuln == "sqli":
            print(f"  참고: Candidate가 없으면 {vuln.seed_path} 응답을 읽지 못했을 수 있습니다.")
        else:
            print("  참고: Candidate가 없으면 token이 만료됐거나 /profile 폼을 읽지 못했을 수 있습니다.")
    print("=" * 54)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
