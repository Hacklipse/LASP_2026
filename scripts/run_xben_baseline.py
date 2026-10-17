"""XBEN 랩에 LASP를 돌려 **취약점 탐지** 성능을 클래스 균등으로 채점한다.

채점축은 플래그 획득이 아니다. 각 랩의 `benchmark.json` tags가 정답이고, 성공은
"기대 클래스로 CONFIRMED Finding이 나왔는가"다. 플래그는 랩이 정상 기동했는지
확인하는 보조 신호로만 쓴다.

헤드라인은 **macro-average** — 클래스별 탐지율의 비가중 평균이다. 랩 수로 가중하면
XSS(23랩)가 Path Traversal(9랩)의 2.5배 무게를 갖고, 한 클래스만 손봐도 전체 숫자가
올라가 "균등하게 좋아졌다"를 가려낼 수 없다.

미탐은 원인별로 분류한다. 커버리지(탐색)와 오라클(확정) 중 어디서 잃는지 분리하지
않으면 다음 개선 대상을 고를 수 없다.

    python3 scripts/run_xben_baseline.py --per-class 3            # 클래스당 3랩
    python3 scripts/run_xben_baseline.py --labs XBEN-013-24       # 특정 랩만
    python3 scripts/run_xben_baseline.py --per-class 6 --budget 200
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT / "scripts"))

from xben_inventory import (  # noqa: E402
    SUPPORTED,
    XBEN_ROOT,
    Lab,
    load_labs,
    stratified_plan,
)

from hacklipse.adapters import (  # noqa: E402
    HttpExecutionRuntime,
    PlaywrightBrowserRuntime,
    SlidingWindowLlmClient,
)
from hacklipse.adapters.analyzer_capabilities import (  # noqa: E402
    DEFAULT_ANALYZER_CAPABILITIES,
    capability_missing_requirements,
)
from hacklipse.application.errors import WorkflowExecutionError  # noqa: E402
from hacklipse.application.orchestrator import OrchestratorConfig  # noqa: E402
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

ALLOWED_HOSTS = frozenset({"localhost", "127.0.0.1"})
DEFAULT_BUDGET = 150
# 무료 티어는 분당 호출이 제한된다. 기존 러너와 같은 값을 쓴다.
DEFAULT_GEMINI_RPM_LIMIT = 14
UP_TIMEOUT = 420          # 빌드 포함. 이미지 캐시가 비면 여기서 대부분을 쓴다.
READY_TIMEOUT = 60
RUN_TIMEOUT = 900

# 미탐 원인. 우선순위 순서대로 판정한다.
CAUSE_CONFIRMED = "confirmed"
CAUSE_WRONG_CLASS = "wrong_class"
CAUSE_NO_CONFIRM = "probe_ran_no_confirm"
CAUSE_NO_CANDIDATE = "no_candidate"
CAUSE_NO_SURFACE = "no_surface"
CAUSE_ENV = "env_failure"
CAUSE_RUN_ERROR = "run_error"

CAUSE_MEANING = {
    CAUSE_CONFIRMED: "기대 클래스 확정",
    CAUSE_WRONG_CLASS: "다른 클래스를 확정해 기대 클래스를 가림",
    CAUSE_NO_CONFIRM: "후보는 섰으나 오라클이 확정 못 함 ← 오라클 문제",
    CAUSE_NO_CANDIDATE: "기대 클래스 후보 자체가 안 섬 ← capability/라우팅 문제",
    CAUSE_NO_SURFACE: "Surface 0개 ← 정찰 문제",
    CAUSE_ENV: "랩 기동 실패 ← 측정 환경 문제, 분모에서 제외",
    CAUSE_RUN_ERROR: "LASP 실행 예외",
}


@dataclass
class LabResult:
    lab_id: str
    expected_class: str
    level: str
    tags: list[str]
    cause: str
    confirmed_types: list[str] = field(default_factory=list)
    candidate_types: list[str] = field(default_factory=list)
    candidate_statuses: dict[str, int] = field(default_factory=dict)
    surfaces: int = 0
    findings: int = 0
    gate_blocks: dict[str, int] = field(default_factory=dict)
    near_miss: list = field(default_factory=list)
    requests_used: int = 0
    phase: str = ""
    target_url: str = ""
    duration_s: float = 0.0
    detail: str = ""

    @property
    def detected(self) -> bool:
        return self.cause == CAUSE_CONFIRMED

    @property
    def scorable(self) -> bool:
        """분모에 들어가는가. 환경 실패는 LASP 성능이 아니므로 뺀다."""
        return self.cause != CAUSE_ENV


def load_dotenv(path: Path = _ROOT / ".env") -> list[str]:
    """.env를 os.environ에 넣는다. 이미 셸에 있는 값은 덮지 않는다.

    이 프로젝트에는 python-dotenv가 없고 .env를 읽는 건 docker compose뿐이다.
    스크립트를 직접 돌리면 키가 환경에 없어 LlmCredentialsMissing으로 죽는다.
    """
    if not path.is_file():
        return []
    loaded: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if not key or not value or os.environ.get(key):
            continue
        os.environ[key] = value
        loaded.append(key)
    return loaded


def build_llm(provider: str, model: str, rpm: int | None):
    """LLM Client를 만든다. 랩 루프 밖에서 **한 번만** 부른다.

    랩마다 새로 만들면 SlidingWindowLlmClient의 호출 윈도우가 리셋돼
    무료 티어 분당 한도를 그대로 넘긴다.
    """
    if provider == "none":
        return None, ""
    if provider == "gemini":
        client = build_gemini_llm_client_from_env(model=model)
    else:
        client = build_llm_client_from_env(model=model)
    if rpm:
        client = SlidingWindowLlmClient(client, max_calls=rpm)
    return client, model


def _sh(
    args: list[str],
    cwd: Path | None = None,
    timeout: int = 120,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env={**os.environ, **env} if env else None,
    )


def _compose_down(lab: Lab) -> None:
    """포트를 반납해야 다음 랩이 뜬다. make에는 down이 없어 compose를 직접 쓴다."""
    _sh(["docker", "compose", "down", "-v", "--remove-orphans"], cwd=lab.path, timeout=180)


def _discover_url(lab: Lab) -> str | None:
    """compose가 실제로 매핑한 호스트 포트를 조회한다.

    대부분의 랩이 `ports: - 80`으로 에페메랄 포트를 쓴다. 고정 포트를 하드코딩하면
    랩마다 틀리고, 호스트에서 이미 점유된 포트(8080=Burp, 5000=AirPlay 등)와
    충돌한다. compose에 직접 물어보는 게 유일하게 맞는 방법이다.
    """
    probe = _sh(["docker", "compose", "ps", "--format", "json"], cwd=lab.path, timeout=60)
    if probe.returncode != 0:
        return None

    entries = []
    raw = probe.stdout.strip()
    if raw.startswith("["):
        try:
            entries = json.loads(raw)
        except json.JSONDecodeError:
            entries = []
    else:
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    # HTTP 포트를 고른다. DB(3306/5432)는 LASP의 대상이 아니다.
    best: tuple[int, int] | None = None
    for entry in entries:
        for mapping in (entry.get("Publishers") or []):
            published = mapping.get("PublishedPort") or 0
            target = mapping.get("TargetPort") or 0
            if not published or target in (3306, 5432, 27017):
                continue
            rank = 0 if target in (80, 8080, 8000, 5000, 3000, 5003) else 1
            if best is None or rank < best[0]:
                best = (rank, int(published))
    if best is None:
        return None
    return f"http://127.0.0.1:{best[1]}/"


def _wait_ready(url: str, timeout: int = READY_TIMEOUT) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                if response.status < 500:
                    return True
        except urllib.error.HTTPError as error:
            # 401/403/404도 서버가 살아있다는 증거다.
            if error.code < 500:
                return True
        except (urllib.error.URLError, TimeoutError, OSError):
            pass
        time.sleep(2)
    return False


def bring_up(lab: Lab) -> tuple[str | None, str]:
    """랩을 띄우고 (URL, 실패이유)를 반환한다.

    플랫폼은 여기서 건드리지 않는다. 전역 DOCKER_DEFAULT_PLATFORM=linux/amd64로
    폴백하면 네이티브로 잘 빌드되던 서비스까지 깨진다(php:7.4-apache가 amd64 매니페스트
    해석에 실패한다). arm64 매니페스트가 없는 이미지는 scripts/xben_env_repair.py가
    해당 서비스에만 platform을 박아 해결한다.
    """
    _compose_down(lab)
    try:
        built = _sh(
            ["make", "-C", str(lab.path), "run"], cwd=XBEN_ROOT, timeout=UP_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        return None, f"기동 타임아웃 {UP_TIMEOUT}s"
    if built.returncode != 0:
        tail = (built.stderr or built.stdout or "").strip().splitlines()
        # 빌드 가드가 남으면 다음 실행이 재빌드를 건너뛰어 같은 실패를 반복한다.
        _sh(["make", "-C", str(lab.path), "clean"], cwd=XBEN_ROOT, timeout=60)
        return None, "기동 실패: " + (tail[-1] if tail else "원인 미상")

    url = _discover_url(lab)
    if url is None:
        return None, "호스트 포트 매핑을 찾지 못함"
    if not _wait_ready(url):
        return None, f"{url} 응답 없음 ({READY_TIMEOUT}s)"
    return url, ""


class _RunTimeout(Exception):
    pass


@contextmanager
def _deadline(seconds: int):
    """Run 하나가 배치 전체를 영구 대기시키지 못하게 막는다.

    run_lasp는 subprocess가 아니라 같은 프로세스의 호출이므로 subprocess timeout이
    걸리지 않는다. 브라우저 런타임이 멈추면 무인 실행이 밤새 한 랩에 묶인다.
    """
    if not hasattr(signal, "SIGALRM"):
        yield
        return

    def _fire(signum, frame):  # noqa: ARG001
        raise _RunTimeout(f"run exceeded {seconds}s")

    previous = signal.signal(signal.SIGALRM, _fire)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def _gate_diagnosis(expected: str, surfaces, evidence) -> dict:
    """기대 클래스의 capability가 각 Surface에서 **어느 게이트에** 막혔는지 센다.

    no_candidate만으로는 다음에 뭘 고칠지 알 수 없다. capability 선언의 어느 조건이
    Surface를 떨어뜨렸는지가 실제로 손댈 지점이다. Router가 쓰는 것과 같은 함수를
    불러 진단과 실행이 어긋나지 않게 한다.

    near_miss는 막힌 이유가 가장 적은 (capability, 이유) 쌍이다. 게이트 하나만 풀면
    후보가 설 수 있는 경우를 가려낸다.
    """
    wanted = [c for c in DEFAULT_ANALYZER_CAPABILITIES if c.vulnerability_type == expected]
    if not wanted or not surfaces:
        return {"gate_blocks": {}, "near_miss": []}

    blocks: Counter[str] = Counter()
    best: tuple[int, str, tuple[str, ...]] | None = None
    for capability in wanted:
        for surface in surfaces:
            reasons = capability_missing_requirements(capability, surface, evidence)
            if not reasons:
                continue  # 매칭됨 — 후보가 섰어야 한다
            for reason in reasons:
                blocks[reason] += 1
            if best is None or len(reasons) < best[0]:
                best = (len(reasons), capability.capability_id, reasons)
    return {
        "gate_blocks": dict(blocks.most_common()),
        "near_miss": [best[1], list(best[2])] if best else [],
    }


def run_lasp(
    target: str,
    budget: int,
    llm_client=None,
    expected: str = "",
    browser: bool = True,
) -> tuple[dict, str]:
    """1회 Run. llm_client가 None이면 결정론적 대조군. (지표, 오류) 반환.

    브라우저 런타임과 browser_xss_validation을 켜는 것은 성능 튜닝이 아니라 하네스
    정확성이다. 이 프로젝트의 다른 러너(run_dvwa_baseline, run_juice_shop_baseline)는
    XSS 대상에 둘 다 켠다. 끄고 재면 최우선 capability(xss.browser.fragment, 0.40)의
    확정 경로가 닫힌 채로 측정돼 XSS만 구조적으로 과소평가된다.
    """
    http_runtime = HttpExecutionRuntime()
    runtime = PlaywrightBrowserRuntime(http_runtime=http_runtime) if browser else http_runtime
    app = build_local_application(
        {},
        runtime=runtime,
        router=standard_router(),
        config=OrchestratorConfig(browser_xss_validation=browser),
    )
    register_standard_agents(app, llm_client=llm_client)
    try:
        with _deadline(RUN_TIMEOUT):
            run = app.orchestrator.start(
                RunRequest(
                    target_url=target,
                    scope=RunScope(allowed_hosts=ALLOWED_HOSTS),
                    request_budget=budget,
                )
            )
    except _RunTimeout as error:
        return {}, str(error)
    except WorkflowExecutionError as error:
        return {}, f"WorkflowExecutionError: {error}"
    except Exception as error:  # noqa: BLE001 — 한 랩의 예외로 배치를 끊지 않는다
        return {}, f"{type(error).__name__}: {error}"

    surfaces = app.stores.surfaces.list_by_run(run.run_id)
    candidates = app.stores.candidates.list_by_run(run.run_id)
    findings = app.stores.findings.list_by_run(run.run_id)
    return {
        **_gate_diagnosis(expected, surfaces, app.stores.evidence.list_by_run(run.run_id)),
        "phase": run.phase.value,
        "surfaces": len(surfaces),
        "findings": len(findings),
        "requests_used": budget - app.budget_manager.remaining(run.run_id),
        "candidate_types": sorted({c.vulnerability_type for c in candidates}),
        "candidate_statuses": dict(
            Counter(
                getattr(c.status, "value", str(c.status)) for c in candidates
            )
        ),
        "confirmed_types": sorted(
            {
                f.vulnerability_type
                for f in findings
                if str(getattr(f, "status", "")).casefold()
                in ("confirmed", "candidatestatus.confirmed")
                or f.proof_type is not None
            }
        ),
    }, ""


def classify(expected: str, metrics: dict) -> tuple[str, str]:
    """미탐 원인을 하나로 귀속한다. 우선순위: 확정 > 오분류 > 미확정 > 후보없음 > 표면없음."""
    confirmed = set(metrics.get("confirmed_types") or ())
    candidates = set(metrics.get("candidate_types") or ())
    if expected in confirmed:
        return CAUSE_CONFIRMED, ""
    if confirmed:
        return CAUSE_WRONG_CLASS, f"확정={sorted(confirmed)}"
    if expected in candidates:
        statuses = metrics.get("candidate_statuses") or {}
        return CAUSE_NO_CONFIRM, f"후보상태={statuses}"
    if metrics.get("surfaces"):
        return CAUSE_NO_CANDIDATE, f"후보클래스={sorted(candidates) or '없음'}"
    return CAUSE_NO_SURFACE, f"phase={metrics.get('phase')}"


def measure(
    lab: Lab,
    expected: str,
    budget: int,
    keep_up: bool,
    llm_client=None,
    browser: bool = True,
) -> LabResult:
    started = time.monotonic()
    result = LabResult(
        lab_id=lab.lab_id,
        expected_class=expected,
        level=lab.level,
        tags=list(lab.tags),
        cause=CAUSE_ENV,
    )
    url, reason = bring_up(lab)
    if url is None:
        result.detail = reason
        result.duration_s = round(time.monotonic() - started, 1)
        return result

    result.target_url = url
    metrics, error = run_lasp(url, budget, llm_client, expected, browser)
    if error:
        result.cause = CAUSE_RUN_ERROR
        result.detail = error
    else:
        result.phase = metrics["phase"]
        result.surfaces = metrics["surfaces"]
        result.findings = metrics["findings"]
        result.requests_used = metrics["requests_used"]
        result.candidate_types = metrics["candidate_types"]
        result.candidate_statuses = metrics["candidate_statuses"]
        result.confirmed_types = metrics["confirmed_types"]
        result.gate_blocks = metrics.get("gate_blocks", {})
        result.near_miss = metrics.get("near_miss", [])
        result.cause, result.detail = classify(expected, metrics)

    if not keep_up:
        _compose_down(lab)
    result.duration_s = round(time.monotonic() - started, 1)
    return result


def report(results: list[LabResult]) -> None:
    print("\n" + "=" * 86)
    print("클래스별 탐지율 — 랩 수로 가중하지 않는다")
    print("=" * 86)

    per_class: dict[str, list[LabResult]] = {cls: [] for cls in SUPPORTED}
    for item in results:
        per_class.setdefault(item.expected_class, []).append(item)

    rates: list[float] = []
    print(f"\n{'클래스':<16}{'탐지':>8}{'분모':>6}{'탐지율':>9}   주요 미탐 원인")
    print("-" * 86)
    for cls in SUPPORTED:
        items = per_class.get(cls, [])
        scorable = [i for i in items if i.scorable]
        hit = [i for i in scorable if i.detected]
        if not scorable:
            print(f"{cls:<16}{'-':>8}{0:>6}{'n/a':>9}   측정 랩 없음")
            continue
        rate = len(hit) / len(scorable)
        rates.append(rate)
        causes = Counter(i.cause for i in scorable if not i.detected)
        top = ", ".join(f"{c}×{n}" for c, n in causes.most_common(2)) or "-"
        print(f"{cls:<16}{len(hit):>8}{len(scorable):>6}{rate * 100:>8.1f}%   {top}")

    print("-" * 86)
    if rates:
        macro = sum(rates) / len(rates)
        all_scorable = [i for i in results if i.scorable]
        micro = (
            sum(1 for i in all_scorable if i.detected) / len(all_scorable)
            if all_scorable
            else 0.0
        )
        print(f"{'macro-average':<16}{'':>8}{len(rates):>6}{macro * 100:>8.1f}%   ← 헤드라인")
        print(f"{'(micro 참고용)':<16}{'':>8}{len(all_scorable):>6}{micro * 100:>8.1f}%   클래스 쏠림에 취약")
        spread = max(rates) - min(rates)
        print(f"\n클래스간 격차 {spread * 100:.1f}%p  (최고 {max(rates) * 100:.1f}% / 최저 {min(rates) * 100:.1f}%)")
        if spread > 0.3:
            print("  ⚠ 격차 30%p 초과 — 균등 개선 원칙에 따라 최저 클래스를 먼저 본다")

    print("\n" + "=" * 86)
    print("미탐 원인 분포 — 탐색(커버리지) vs 오라클(확정) 중 어디서 잃는가")
    print("=" * 86)
    causes = Counter(i.cause for i in results)
    total = len(results)
    for cause, n in causes.most_common():
        print(f"  {cause:<22}{n:>3}랩  {n / total * 100:>5.1f}%   {CAUSE_MEANING.get(cause, '')}")

    blocked = [i for i in results if i.cause == CAUSE_NO_CANDIDATE and i.gate_blocks]
    if blocked:
        print("\n" + "=" * 86)
        print("no_candidate 하위원인 — capability 선언의 어느 게이트가 Surface를 떨어뜨렸는가")
        print("=" * 86)
        totals: Counter[str] = Counter()
        for item in blocked:
            for reason, count in item.gate_blocks.items():
                totals[reason] += count
        for reason, count in totals.most_common():
            labs = sum(1 for i in blocked if reason in i.gate_blocks)
            print(f"  {reason:<24}{labs:>3}랩  (Surface×capability {count}건)")
        print("\n  게이트 하나만 풀면 후보가 설 수 있는 랩 (near miss):")
        for item in sorted(blocked, key=lambda i: len(i.near_miss[1]) if i.near_miss else 99):
            if not item.near_miss:
                continue
            capability_id, reasons = item.near_miss
            print(
                f"    {item.lab_id}  {item.expected_class:<16}{capability_id:<36}"
                f"막힘={','.join(reasons)}"
            )

    env = [i for i in results if i.cause == CAUSE_ENV]
    if env:
        print(f"\n  환경 실패 {len(env)}랩은 분모에서 제외됨:")
        for item in env:
            print(f"    {item.lab_id}  {item.detail}")

    print("\n" + "=" * 86)
    print("랩별 상세")
    print("=" * 86)
    print(f"{'랩':<16}{'기대클래스':<16}{'결과':<22}{'표면':>5}{'요청':>6}{'초':>7}")
    print("-" * 86)
    for item in sorted(results, key=lambda i: (i.expected_class, i.lab_id)):
        mark = "✅" if item.detected else ("⚙" if item.cause == CAUSE_ENV else "❌")
        print(
            f"{item.lab_id:<16}{item.expected_class:<16}{mark + ' ' + item.cause:<22}"
            f"{item.surfaces:>5}{item.requests_used:>6}{item.duration_s:>7.0f}"
        )
        if item.detail:
            print(f"{'':<16}  └ {item.detail}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--per-class", type=int, default=3, help="클래스당 랩 수 (기본 3)"
    )
    parser.add_argument("--budget", type=int, default=DEFAULT_BUDGET, help="랩당 요청 예산")
    parser.add_argument("--labs", nargs="+", metavar="LAB", help="특정 랩만 (XBEN-013-24)")
    parser.add_argument("--keep-up", action="store_true", help="측정 후 컨테이너 유지")
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="브라우저 런타임과 browser_xss_validation을 끈다 (XSS 확정 경로가 닫힌다)",
    )
    parser.add_argument("--out", type=Path, help="결과 JSON 경로")
    parser.add_argument(
        "--llm",
        choices=("gemini", "anthropic", "none"),
        default="gemini",
        help="LLM 공급자. none이면 결정론적 대조군 (기본: gemini)",
    )
    parser.add_argument("--model", help="모델 id 고정. 생략하면 공급자 기본값")
    parser.add_argument(
        "--llm-rpm",
        type=int,
        help=f"분당 LLM 호출 상한 (gemini 기본 {DEFAULT_GEMINI_RPM_LIMIT})",
    )
    args = parser.parse_args()

    if _sh(["docker", "info"], timeout=60).returncode != 0:
        print("docker를 쓸 수 없다. Docker Desktop이 떠 있는지 확인해라.")
        return 2

    loaded = load_dotenv()
    model = args.model or (
        DEFAULT_GEMINI_LLM_MODEL if args.llm == "gemini" else DEFAULT_ANTHROPIC_LLM_MODEL
    )
    rpm = args.llm_rpm
    if rpm is None and args.llm == "gemini":
        rpm = DEFAULT_GEMINI_RPM_LIMIT
    try:
        llm_client, model_used = build_llm(args.llm, model, rpm)
    except Exception as error:  # noqa: BLE001 — 키 부재를 사용자 메시지로 바꾼다
        print(f"LLM 구성 실패: {error}")
        print("  .env의 GEMINI_API_KEY를 확인하거나 --llm none으로 대조군을 돌려라.")
        return 2

    labs = {lab.lab_id: lab for lab in load_labs()}
    targets: list[tuple[Lab, str]] = []

    if args.labs:
        for lab_id in args.labs:
            lab = labs.get(lab_id)
            if lab is None:
                print(f"없는 랩: {lab_id}")
                return 2
            if not lab.expected_classes:
                print(f"건너뜀 {lab_id}: 지원 클래스 태그가 없다 ({','.join(lab.tags)})")
                continue
            targets.append((lab, lab.expected_classes[0]))
    else:
        plan = stratified_plan(list(labs.values()), args.per_class)
        for cls in SUPPORTED:
            for lab in plan.get(cls, []):
                targets.append((lab, cls))

    if not targets:
        print("측정할 랩이 없다.")
        return 2

    stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H%M%SZ")
    out_path = args.out or _ROOT / "runs" / f"xben_{stamp}" / "results.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    config = {
        "stamp": stamp,
        "per_class": args.per_class,
        "budget": args.budget,
        "llm_provider": args.llm,
        "llm_model": model_used,
        "llm_rpm_limit": rpm,
        "browser_xss_validation": not args.no_browser,
        "labs": len(targets),
    }
    print(f"XBEN 베이스라인  랩 {len(targets)}개 / 클래스당 {args.per_class} / 예산 {args.budget}")
    if llm_client is None:
        print("구성  LLM 없음 (결정론적 대조군)")
    else:
        print(f"구성  {args.llm} / {model_used}" + (f" / {rpm}회per60초" if rpm else ""))
    if loaded:
        print(f".env  {', '.join(loaded)} 로드")
    print(f"결과  {out_path}\n")

    results: list[LabResult] = []
    for index, (lab, expected) in enumerate(targets, start=1):
        print(f"[{index}/{len(targets)}] {lab.lab_id}  기대={expected}  L{lab.level}", flush=True)
        result = measure(
            lab, expected, args.budget, args.keep_up, llm_client, not args.no_browser
        )
        results.append(result)
        print(
            f"        → {result.cause}"
            + (f"  ({result.detail})" if result.detail else "")
            + f"  {result.duration_s:.0f}s",
            flush=True,
        )
        out_path.write_text(
            json.dumps(
                {"config": config, "results": [asdict(r) for r in results]},
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

    report(results)
    print(f"\n구성  {config['llm_provider']} / {config['llm_model'] or '대조군'}")
    print(f"결과 저장  {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
