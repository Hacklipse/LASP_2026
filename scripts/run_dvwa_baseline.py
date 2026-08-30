"""로컬 DVWA에 로그인한 뒤 reflected-XSS 결정적 baseline을 실행한다.

인증정보는 명령행 인자나 환경변수로 받지 않고 현재 프로세스에서만 입력받는다.
Task/Evidence/Audit에는 credential_ref와 마스킹된 응답만 남는다.

    python3 scripts/run_dvwa_baseline.py http://127.0.0.1:8080/
    python3 scripts/run_dvwa_baseline.py http://127.0.0.1:8080/DVWA/
"""

from __future__ import annotations

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
from hacklipse.application.errors import WorkflowExecutionError  # noqa: E402
from hacklipse.bootstrap import (  # noqa: E402
    build_local_application,
    register_standard_agents,
    standard_router,
)
from hacklipse.domain import RunRequest, RunScope  # noqa: E402
from hacklipse.ports import FormLoginSpec, ResolvedHttpCredential  # noqa: E402

_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1"})
_CREDENTIAL_REF = "interactive-local-dvwa"
_APPROVAL_REF = "interactive-local-dvwa-login"
_DEFAULT_BUDGET = 20


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2

    base_url = argv[1].rstrip("/") + "/"
    parsed = urlsplit(base_url)
    host = (parsed.hostname or "").casefold()
    if parsed.scheme not in {"http", "https"} or host not in _LOCAL_HOSTS:
        print("거부: 이 실행기는 localhost/127.0.0.1의 HTTP(S) DVWA만 허용한다.")
        return 2

    username = input("DVWA username: ")
    password = getpass.getpass("DVWA password: ")
    if input("로컬 DVWA에 로그인 POST를 실행할까요? [y/N] ").strip().casefold() != "y":
        print("취소했습니다.")
        return 2

    login_url = urljoin(base_url, "login.php")
    target_url = urljoin(base_url, "vulnerabilities/xss_r/?name=seed")
    resolver = InMemoryCredentialResolver(
        {
            _CREDENTIAL_REF: ResolvedHttpCredential(
                # DVWA의 보안 단계가 reflected-XSS 실습 동작을 가리지 않게 고정한다.
                cookies=(("security", "low"),),
                form_login=FormLoginSpec(
                    login_url=login_url,
                    username=username,
                    password=password,
                    csrf_field="user_token",
                    extra_fields=(("Login", "Login"),),
                    failure_marker="Login failed",
                    approval_ref=_APPROVAL_REF,
                ),
            )
        }
    )
    runtime = HttpExecutionRuntime(credential_resolver=resolver)
    audit = InMemoryExecutionAuditLog()
    app = build_local_application(
        {},
        runtime=runtime,
        router=standard_router(),
        credential_resolver=resolver,
        approval_gate=StaticApprovalGate((_APPROVAL_REF,)),
        audit_log=audit,
    )
    profile = register_standard_agents(app)
    base_path = parsed.path if parsed.path.endswith("/") else f"{parsed.path}/"

    try:
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

    candidates = app.stores.candidates.list_by_run(run.run_id)
    reflections = tuple(
        item
        for item in app.stores.evidence.list_by_run(run.run_id)
        if item.observation.get("type") == "reflection"
    )
    events = audit.list_by_run(run.run_id)
    print(f"구성              {profile}")
    print(f"phase             {run.phase.value}")
    print(f"Candidate         {dict(Counter(c.vulnerability_type for c in candidates))}")
    print(f"reflection 신호  {len(reflections)}")
    print(f"감사된 HTTP 실행 {len(events)}")
    print(f"Finding           {len(app.stores.findings.list_by_run(run.run_id))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
