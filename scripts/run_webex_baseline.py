"""WebExploitBench 타깃에 LASP를 돌려 탐지와 채점 결과를 같이 남긴다.

두 가지를 따로 기록한다. 섞으면 다음 개선 대상을 고를 수 없다.

- **탐지** — 기대 클래스로 CONFIRMED Finding이 나왔는가. LASP 어휘로 판정하므로
  채점기가 없어도 나오고, 커버리지(탐색)와 오라클(확정) 중 어디서 잃는지 보인다.
- **채점** — `vulnerability/<id>/verify/verify.py`가 통과시켰는가. 이게 벤치마크의
  공식 숫자다. `challenge.json`이 `scoring`에 `verifier`를 넣은 건만 해당하고,
  `LLM_judge` 전용 건은 로컬에서 채점할 수단이 없어 `unscored`로 남긴다.

채점기는 컨테이너 안의 원본 파일을 `docker exec`로 읽어 agent 출력과 비교한다. 그래서
compose가 실제로 붙인 컨테이너 이름을 넘겨야 한다 — 서비스 키를 그대로 쓰면 "컨테이너
없음"으로 실패해 탐지 실패와 구분되지 않는다.

    python3 scripts/run_webex_baseline.py --targets openmetadata
    python3 scripts/run_webex_baseline.py --targets openmetadata --keep-up
    python3 scripts/run_webex_baseline.py --no-up --targets openmetadata   # 이미 떠 있음
    python3 scripts/run_webex_baseline.py --budget 120                     # 할당 5개 전부
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT / "scripts"))

from webex_inventory import (  # noqa: E402
    ASSIGNED,
    WEBEX_ROOT,
    Target,
    Vulnerability,
    load_targets,
)

from hacklipse.adapters import HttpExecutionRuntime  # noqa: E402
from hacklipse.adapters.benchmark_report import (  # noqa: E402
    verifier_input,
    webexploitbench_agent_output,
)
from hacklipse.application.errors import WorkflowExecutionError  # noqa: E402
from hacklipse.bootstrap import (  # noqa: E402
    build_local_application,
    register_standard_agents,
    standard_router,
)
from hacklipse.domain import RunRequest, RunScope  # noqa: E402

DEFAULT_BUDGET = 80
READY_TIMEOUT = 600
_URL = re.compile(r"https?://[^\s,)]+")


def _project_name(target: str) -> str:
    """targetctl의 project 이름 규칙을 그대로 따른다 (`sanitize_project_part`)."""

    return "web_" + re.sub(r"[^a-z0-9]", "_", target.casefold())


def _targetctl(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(root / "scripts" / "targetctl"), *args],
        cwd=root, text=True, capture_output=True, check=check,
    )


def _resolve_url(root: Path, target: Target) -> str | None:
    """컨테이너 내부 주소를 호스트에서 접근 가능한 URL로 바꾼다.

    `application_targets`에는 설명 문장이 붙어 있는 타깃이 있어(dataease) 치환 후
    첫 URL 토큰만 떼어 쓴다. bind host는 `0.0.0.0`으로 적히는데 그건 수신 주소라
    클라이언트가 붙을 주소가 아니다 — loopback으로 바꾼다.
    """

    ports_file = root / ".targetctl" / "ports" / f"{_project_name(target.name)}.ports"
    if not ports_file.exists():
        return None
    rendered = target.application_targets
    for line in ports_file.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        if len(parts) != 4:
            continue
        service, internal, host, published = parts
        if host in {"0.0.0.0", "::", ""}:
            host = "127.0.0.1"
        for scheme in ("http", "https"):
            rendered = rendered.replace(
                f"{scheme}://{service}:{internal}", f"{scheme}://{host}:{published}"
            )
    match = _URL.search(rendered)
    return match.group(0).rstrip("/") if match else None


def _container_names(root: Path, target: Target) -> dict[str, str]:
    """compose 서비스 키 -> 실제 컨테이너 이름.

    규칙(`<project>-<service>-1`)을 가정하지 않고 compose에 직접 묻는다. 타깃이
    `container_name`을 지정하면 규칙이 어긋난다.
    """

    project = _project_name(target.name)
    result = subprocess.run(
        ["docker", "compose", "-p", project, "ps", "--format", "json", "--all"],
        cwd=root / target.name, text=True, capture_output=True, check=False,
    )
    names: dict[str, str] = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        entries = item if isinstance(item, list) else [item]
        for entry in entries:
            service, name = entry.get("Service"), entry.get("Name")
            if isinstance(service, str) and isinstance(name, str):
                names[service] = name
    return names


def _wait_ready(url: str, timeout: int) -> bool:
    """어떤 HTTP 응답이라도 오면 준비된 것으로 본다.

    401·403·404도 서버가 살아 있다는 신호다. 200만 기다리면 인증을 요구하는 타깃에서
    영원히 대기한다.
    """

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(url, timeout=5)
            return True
        except urllib.error.HTTPError:
            return True
        except Exception:
            time.sleep(3)
    return False


@dataclass
class TargetResult:
    target: str
    url: str | None = None
    status: str = "pending"
    detail: str = ""
    surfaces: int = 0
    candidates: dict[str, int] = field(default_factory=dict)
    confirmed: dict[str, int] = field(default_factory=dict)
    requests_used: int = 0
    seconds: float = 0.0
    detected_ids: list[str] = field(default_factory=list)
    pre_verdicts: dict[str, str] = field(default_factory=dict)
    verdicts: dict[str, str] = field(default_factory=dict)


def _run_lasp(url: str, budget: int) -> tuple[object, object]:
    """LASP를 한 번 돌리고 (app, run)을 돌려준다. 대조군이므로 LLM 없이 돈다."""

    app = build_local_application(
        {}, runtime=HttpExecutionRuntime(), router=standard_router()
    )
    register_standard_agents(app)
    run = app.orchestrator.start(
        RunRequest(
            target_url=url,
            scope=RunScope(allowed_hosts=frozenset({"127.0.0.1", "localhost"})),
            request_budget=budget,
        )
    )
    return app, run


def _score(
    root: Path, target: Target, agent_output: dict, dockers: dict[str, str]
) -> dict[str, str]:
    """verifier가 있는 건만 실제로 채점한다.

    채점기 상당수가 agent 출력이 아니라 **컨테이너에 남은 효과**를 본다(RCE canary,
    SSRF listener 로그). 그 효과는 지워지지 않으므로, 앞선 실행이나 수동 익스플로잇이
    남긴 흔적이 있으면 LASP가 아무것도 못 해도 pass가 나온다. 호출자가 LASP 실행
    전후로 두 번 불러 그 차이만 인정해야 한다.
    """

    verdicts: dict[str, str] = {}
    payload = verifier_input(agent_output, urls={}, dockers=dockers)
    for vuln in target.vulnerabilities:
        if "verifier" not in vuln.scoring:
            verdicts[vuln.vuln_id] = "unscored"
            continue
        script = (
            root / target.name / "vulnerability" / vuln.vuln_id / "verify" / "verify.py"
        )
        if not script.exists():
            verdicts[vuln.vuln_id] = "missing_verifier"
            continue
        try:
            done = subprocess.run(
                [sys.executable, str(script), payload],
                text=True, capture_output=True, timeout=180, check=False,
            )
        except subprocess.TimeoutExpired:
            verdicts[vuln.vuln_id] = "timeout"
            continue
        verdicts[vuln.vuln_id] = _verdict(done.stdout)
    return verdicts


def _verdict(stdout: str) -> str:
    for line in reversed(stdout.splitlines()):
        try:
            value = json.loads(line.strip())
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(value, dict) and "status" in value:
            return "pass" if value["status"] else "fail"
    return "error"


def _detected(expected: tuple[Vulnerability, ...], confirmed: Counter) -> list[str]:
    """기대 클래스로 CONFIRMED가 나온 취약점 id.

    유형 단위 매칭이라 같은 유형이 여러 건이면 건수만큼 인정하지는 않는다 — 가진
    증거가 "그 유형을 하나 확정했다"까지이므로 더 주장하면 과대평가다.
    """

    remaining = Counter(confirmed)
    hit: list[str] = []
    for vuln in expected:
        if vuln.lasp_type and remaining.get(vuln.lasp_type, 0) > 0:
            remaining[vuln.lasp_type] -= 1
            hit.append(vuln.vuln_id)
    return hit


def _measure(root: Path, target: Target, args) -> TargetResult:
    result = TargetResult(target=target.name)
    if not args.no_up:
        print(f"[{target.name}] 기동 중 ...", flush=True)
        try:
            _targetctl(root, "up", target.name)
        except subprocess.CalledProcessError as error:
            result.status = "up_failed"
            result.detail = (error.stderr or "")[-400:]
            return result

    url = _resolve_url(root, target)
    if url is None:
        result.status = "no_url"
        result.detail = "ports 파일이 없거나 application_targets에 URL이 없다"
        return result
    result.url = url

    print(f"[{target.name}] {url} 준비 대기 ...", flush=True)
    if not _wait_ready(url, args.ready_timeout):
        result.status = "not_ready"
        result.detail = f"{args.ready_timeout}s 안에 응답하지 않았다"
        return result

    dockers = _container_names(root, target)
    # LASP 를 돌리기 전에 한 번 채점한다. 여기서 이미 pass 가 나오는 건은 컨테이너에
    # 남은 흔적 때문이지 이번 실행의 성과가 아니다.
    result.pre_verdicts = _score(root, target, {"output": "", "_reports": []}, dockers)
    contaminated = sorted(k for k, v in result.pre_verdicts.items() if v == "pass")
    if contaminated:
        print(
            f"[{target.name}] 경고: 측정 전에 이미 통과하는 건이 있다 "
            f"({', '.join(contaminated)}). 컨테이너를 새로 띄워야 한다.",
            flush=True,
        )

    started = time.monotonic()
    try:
        app, run = _run_lasp(url, args.budget)
    except WorkflowExecutionError as error:
        result.status = "run_failed"
        result.detail = str(error)[-400:]
        return result
    result.seconds = round(time.monotonic() - started, 1)

    surfaces = app.stores.surfaces.list_by_run(run.run_id)
    candidates = app.stores.candidates.list_by_run(run.run_id)
    findings = app.stores.findings.list_by_run(run.run_id)
    evidence = app.stores.evidence.list_by_run(run.run_id)

    result.surfaces = len(surfaces)
    result.candidates = dict(Counter(c.vulnerability_type for c in candidates))
    confirmed = Counter(f.vulnerability_type for f in findings)
    result.confirmed = dict(confirmed)
    result.requests_used = args.budget - app.budget_manager.remaining(run.run_id)
    result.detected_ids = _detected(target.vulnerabilities, confirmed)

    agent_output = webexploitbench_agent_output(
        findings,
        {s.surface_id: s for s in surfaces},
        {e.evidence_id: e for e in evidence},
    )
    post = _score(root, target, agent_output, dockers)
    # 측정 전에 이미 통과하던 건은 이번 실행의 성과로 셀 수 없다. 차이만 인정한다.
    result.verdicts = {
        vuln_id: (
            "pre_contaminated"
            if result.pre_verdicts.get(vuln_id) == "pass"
            else verdict
        )
        for vuln_id, verdict in post.items()
    }
    result.status = "ok"
    return result


def _print_summary(results: list[TargetResult], targets: tuple[Target, ...]) -> None:
    by_name = {t.name: t for t in targets}
    total_vulns = sum(len(t.vulnerabilities) for t in targets)
    print("\n" + "=" * 72)
    print(f"{'타깃':<14}{'표면':>5}{'확정':>5}{'탐지':>7}{'채점pass':>10}{'요청':>6}{'초':>7}")
    print("-" * 72)
    detected_all = scored_all = 0
    for result in results:
        expected = len(by_name[result.target].vulnerabilities)
        passed = sum(1 for v in result.verdicts.values() if v == "pass")
        detected_all += len(result.detected_ids)
        scored_all += passed
        confirmed = sum(result.confirmed.values())
        mark = "" if result.status == "ok" else f"  <- {result.status}"
        print(
            f"{result.target:<14}{result.surfaces:>5}{confirmed:>5}"
            f"{len(result.detected_ids):>4}/{expected:<3}{passed:>7}/{expected:<3}"
            f"{result.requests_used:>5}{result.seconds:>7.1f}{mark}"
        )
    print("-" * 72)
    print(f"{'합계':<14}{'':>5}{'':>5}{detected_all:>4}/{total_vulns:<3}{scored_all:>7}/{total_vulns:<3}")

    unscored = Counter(
        v for r in results for v in r.verdicts.values() if v != "pass"
    )
    if unscored:
        print("\n미통과 내역: " + ", ".join(f"{k} {n}" for k, n in unscored.most_common()))

    # 미탐의 원인을 두 갈래로 갈라 적는다. 둘을 합치면 다음 작업이 "탐지를 고치는 일"인지
    # "보고·채점을 고치는 일"인지 결정할 수 없다.
    print("\n미탐 원인 구분")
    for result in results:
        if result.status != "ok":
            print(f"  {result.target:<14} 측정 못 함 ({result.status}) {result.detail[:60]}")
            continue
        confirmed = sum(result.confirmed.values())
        passed = sum(1 for v in result.verdicts.values() if v == "pass")
        if confirmed == 0:
            print(
                f"  {result.target:<14} 탐지 0건 — CONFIRMED Finding 자체가 없다"
                f" (표면 {result.surfaces}, Candidate {sum(result.candidates.values())})"
            )
        elif passed == 0:
            print(
                f"  {result.target:<14} 탐지 {confirmed}건인데 채점 0 — 하네스/보고 쪽 문제일 수 있다"
                f" {result.confirmed}"
            )
        else:
            print(f"  {result.target:<14} 탐지 {confirmed}건, 채점 {passed}건 통과")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", nargs="*", default=list(ASSIGNED))
    parser.add_argument("--budget", type=int, default=DEFAULT_BUDGET)
    parser.add_argument("--ready-timeout", type=int, default=READY_TIMEOUT)
    parser.add_argument("--keep-up", action="store_true", help="측정 후 내리지 않는다")
    parser.add_argument("--no-up", action="store_true", help="이미 떠 있다고 가정한다")
    parser.add_argument("--output-dir", default=str(_ROOT / "artifacts" / "webex"))
    args = parser.parse_args(argv[1:])

    root = WEBEX_ROOT
    targets = load_targets(root=root, names=tuple(args.targets))
    if not targets:
        print(f"해제된 타깃이 없다 (WEBEX_ROOT={root})")
        return 2

    results: list[TargetResult] = []
    for target in targets:
        try:
            results.append(_measure(root, target, args))
        except Exception as error:  # noqa: BLE001 - 한 타깃이 죽어도 나머지는 재야 한다
            print(f"[{target.name}] 중단: {type(error).__name__}: {error}", flush=True)
            results.append(
                TargetResult(
                    target=target.name,
                    status="crashed",
                    detail=f"{type(error).__name__}: {error}"[-400:],
                )
            )
        finally:
            if not args.keep_up and not args.no_up:
                _targetctl(root, "down", target.name, check=False)

    _print_summary(results, targets)

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"webex-{stamp}.json"
    out_path.write_text(
        json.dumps(
            {
                "measured_at": stamp,
                "webex_root": str(root),
                "budget": args.budget,
                "targets": [asdict(r) for r in results],
            },
            ensure_ascii=False, indent=2,
        ),
        encoding="utf-8",
    )
    print(f"\n기록 {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
