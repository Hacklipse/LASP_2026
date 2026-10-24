"""WebExploitBench 인벤토리와 LASP 취약점 어휘 매핑.

채점 단위는 앱이 아니라 **취약점 1건**이다. 각 타깃의 `challenge.json`이 vuln_id와
채점 방식을 선언하고, `vulnerability/<id>/metadata.json`이 유형과 Location을 준다.
정답은 그 metadata의 유형을 LASP `vulnerability_type`으로 옮긴 것이고, 탐지 성공은
"기대 클래스로 CONFIRMED Finding이 나왔는가"다.

매핑은 추정이 섞이므로 등급을 같이 들고 다닌다. `exact`만 "지원한다"고 셀 수 있고,
`partial`·`none`을 지원으로 합치면 before 수치가 실제보다 좋아 보인다. 특히
Stored XSS는 쓰기→읽기 2단계라 반사형 XSS capability로 덮이지 않는다.

    python3 scripts/webex_inventory.py                  # 커버리지 요약
    python3 scripts/webex_inventory.py --targets dataease comfyui
    python3 scripts/webex_inventory.py --json           # 러너가 읽을 형태
"""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

WEBEX_ROOT = Path(
    os.environ.get("WEBEX_ROOT", str(Path.home() / "hf" / "WebExploitBench"))
)

# 중간발표 전까지 본인이 맡은 타깃. PM 분배 기준이다.
ASSIGNED = ("dataease", "white-jotter", "comfyui", "openmetadata", "ofbiz")

# WebExploitBench 유형 -> (LASP vulnerability_type, 매핑 등급, 근거)
#
# exact   : LASP가 같은 것을 증명한다
# partial : 같은 이름이지만 증명 전략이 다르다. 그대로 세면 과대평가다
# none    : 대응하는 capability가 없다
_MAPPING: dict[str, tuple[str | None, str, str]] = {
    "SQL Injection": ("SQLi", "exact", "sqli capability 3종"),
    "Arbitrary File Read": ("Arbitrary File Read", "exact", "AFR capability 4종"),
    "Restricted Sensitive Information Read": (
        "Sensitive Data Exposure", "exact", "sensitive_data capability 2종",
    ),
    "Access Control Bypass / Unauthorized Read or Write": (
        "Access Control", "exact", "access_control.object_identifier",
    ),
    "IDOR / Unauthorized Write or Overwrite": (
        "Access Control", "exact", "access_control.object_identifier",
    ),
    "Weak or Default Credentials": (
        "Exposed Working Credentials", "exact", "credentials.public_login_pair",
    ),
    "SSRF": (
        "SSRF", "partial",
        "capability가 opt-in이다. callback receiver 없이는 등록되지 않는다",
    ),
    "Stored XSS": (
        "XSS", "partial",
        "XSS capability는 반사·DOM 기준이다. 저장형은 쓰기→읽기 2단계가 따로 필요하다",
    ),
    "Arbitrary File Write": (
        "File Upload", "partial",
        "업로드 정책 분석이지 임의 경로 쓰기 증명이 아니다",
    ),
    "Remote Code Execution": (
        None, "none", "대응 capability 없음. SSTI가 인접하지만 RCE 증명은 아니다",
    ),
}


@dataclass(frozen=True)
class Vulnerability:
    """채점 단위 1건."""

    target: str
    vuln_id: str
    webex_type: str
    lasp_type: str | None
    coverage: str
    note: str
    location: str
    scoring: tuple[str, ...]


@dataclass(frozen=True)
class Target:
    """타깃 앱 하나와 그 안의 채점 단위들."""

    name: str
    challenge_id: str
    internal_port: int | None
    application_targets: str
    vulnerabilities: tuple[Vulnerability, ...]


def _read_json(path: Path) -> dict:
    try:
        with path.open(encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _vulnerability_type(metadata: dict) -> str:
    """metadata의 유형 키를 읽는다.

    타깃마다 대소문자가 다르다 — comfyui는 ``Vulnerability Type``, dataease는
    ``vulnerability Type``이다. 한쪽만 읽으면 14건이 조용히 미분류로 빠진다.
    """

    lowered = {key.casefold(): value for key, value in metadata.items()}
    value = lowered.get("vulnerability type")
    return value if isinstance(value, str) and value else "(미상)"


def load_targets(
    root: Path = WEBEX_ROOT, names: tuple[str, ...] = ASSIGNED
) -> tuple[Target, ...]:
    """해제된 타깃 디렉터리에서 인벤토리를 읽는다.

    pack이 아직 안 풀린 타깃은 조용히 건너뛰지 않고 호출자가 알 수 있게 제외한다.
    """

    targets: list[Target] = []
    for name in names:
        directory = root / name
        challenge = _read_json(directory / "challenge.json")
        if not challenge:
            continue
        scoring_by_id = {
            item.get("vuln_id"): tuple(item.get("scoring") or ())
            for item in challenge.get("vulnerabilities", ())
            if isinstance(item, dict)
        }
        found: list[Vulnerability] = []
        for vuln_dir in sorted((directory / "vulnerability").glob("*")):
            metadata = _read_json(vuln_dir / "metadata.json")
            if not metadata:
                continue
            webex_type = _vulnerability_type(metadata)
            lasp_type, coverage, note = _MAPPING.get(
                webex_type, (None, "none", "매핑 미정의")
            )
            found.append(
                Vulnerability(
                    target=name,
                    vuln_id=vuln_dir.name,
                    webex_type=webex_type,
                    lasp_type=lasp_type,
                    coverage=coverage,
                    note=note,
                    location=str(metadata.get("Location", "")),
                    scoring=scoring_by_id.get(vuln_dir.name, ()),
                )
            )
        agent_input = challenge.get("agent_input")
        targets.append(
            Target(
                name=name,
                challenge_id=str(challenge.get("id", name)),
                internal_port=challenge.get("internal_port"),
                application_targets=str(
                    (agent_input or {}).get("application_targets", "")
                    if isinstance(agent_input, dict)
                    else ""
                ),
                vulnerabilities=tuple(found),
            )
        )
    return tuple(targets)


def _summary(targets: tuple[Target, ...]) -> None:
    rows = [v for target in targets for v in target.vulnerabilities]
    if not rows:
        print(f"해제된 타깃이 없다. pack을 먼저 풀어야 한다 (WEBEX_ROOT={WEBEX_ROOT})")
        return

    print(f"WEBEX_ROOT = {WEBEX_ROOT}")
    print(f"타깃 {len(targets)}개 / 채점 단위 {len(rows)}건\n")

    print("타깃별")
    for target in targets:
        print(
            f"  {target.name:<14} {len(target.vulnerabilities):>2}건"
            f"   {target.application_targets}"
        )

    print("\n유형별 (LASP 커버리지 등급)")
    by_type = Counter((v.webex_type, v.coverage) for v in rows)
    for (webex_type, coverage), count in sorted(
        by_type.items(), key=lambda item: (-item[1], item[0][0])
    ):
        mark = {"exact": "O", "partial": "△", "none": "X"}[coverage]
        print(f"  {mark} {count:>2}  {webex_type}")

    print("\n커버리지 요약")
    by_coverage = Counter(v.coverage for v in rows)
    total = len(rows)
    for coverage, label in (
        ("exact", "O 그대로 지원"),
        ("partial", "△ 부분 — 전략이 다르다"),
        ("none", "X 미지원"),
    ):
        count = by_coverage.get(coverage, 0)
        print(f"  {label:<24} {count:>2}/{total}")

    print("\n주의")
    for coverage in ("partial", "none"):
        for webex_type, (_, grade, note) in _MAPPING.items():
            if grade != coverage:
                continue
            count = sum(1 for v in rows if v.webex_type == webex_type)
            if count:
                print(f"  {webex_type} ({count}건) — {note}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--targets", nargs="*", default=list(ASSIGNED),
        help="조사할 타깃 이름 (기본: 본인 할당 5개)",
    )
    parser.add_argument("--json", action="store_true", help="러너가 읽을 JSON 출력")
    args = parser.parse_args()

    targets = load_targets(names=tuple(args.targets))
    if args.json:
        print(json.dumps([asdict(t) for t in targets], ensure_ascii=False, indent=2))
        return 0
    _summary(targets)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
