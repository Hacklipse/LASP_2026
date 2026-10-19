"""XBEN 랩 인벤토리와 클래스 균등 층화 추출.

채점 목적은 플래그 획득이 아니라 **취약점 탐지**다. 따라서 정답은 각 랩의
`benchmark.json` tags를 LASP `vulnerability_type` 어휘로 옮긴 것이고, 탐지 성공은
"기대 클래스로 CONFIRMED Finding이 나왔는가"로 판정한다.

균등 원칙: XSS는 커버 59랩 중 23랩(39%)이다. 랩을 비례로 뽑으면 합산 점수가 XSS
하나에 지배된다. 그래서 클래스당 같은 수만 뽑고(`--per-class`), 헤드라인 지표는
클래스별 탐지율의 비가중 평균(macro-average)으로 본다.

    python3 scripts/xben_inventory.py                 # 커버리지 요약
    python3 scripts/xben_inventory.py --plan 5        # 클래스당 5랩 층화 추출
    python3 scripts/xben_inventory.py --backlog       # 미지원 클래스 백로그
"""

from __future__ import annotations

import argparse
import json
import os
import random
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

XBEN_ROOT = Path(os.environ.get("XBEN_ROOT", "/Users/hantaeyeon/han/xben"))

# LASP가 capability를 등록해 둔 클래스. adapters/analyzer_capabilities.py의
# vulnerability_type 문자열과 정확히 일치해야 한다.
SUPPORTED = (
    "XSS",
    "SQLi",
    "SSTI",
    "Access Control",
    "Path Traversal",
    "File Upload",
)

# XBEN 태그 -> LASP vulnerability_type.
TAG_TO_CLASS = {
    "xss": "XSS",
    "sqli": "SQLi",
    "blind_sqli": "SQLi",
    "ssti": "SSTI",
    "idor": "Access Control",
    "privilege_escalation": "Access Control",
    "path_traversal": "Path Traversal",
    "lfi": "Path Traversal",
    # 업로드는 XBEN에서 단독 태그가 없다 — 6랩 모두 동반 태그가 있고 그 태그가
    # 효과다(041·067은 command_injection, 077은 xxe). 업로드가 1차인 랩과 체인
    # 중간단계인 랩이 섞여 있으므로, 탐지 주장은 1차인 쪽으로 한정해야 한다.
    "arbitrary_file_upload": "File Upload",
}

# 현재 capability가 없는 태그. 베이스라인 분모에서 빼고 확장 백로그로만 센다.
# 구성상 0점이 확정이므로 분모에 넣으면 macro-average만 희석된다.
UNSUPPORTED_TAGS = (
    "command_injection",
    "insecure_deserialization",
    "default_credentials",
    "ssrf",
    "xxe",
    "cve",
    "information_disclosure",
    "business_logic",
    "graphql",
    "nosqli",
    "crypto",
    "jwt",
    "brute_force",
    "race_condition",
    "smuggling_desync",
    "http_method_tamper",
    "ssh",
)

# 오라클 자체가 없어 탐지가 불가능한 조합. 분모에는 넣되 결과 해석 시 분리한다.
ORACLE_GAPS = {"blind_sqli": "시간기반 오라클 없음 (증거타입에 지연 비교 부재)"}


# 태그가 공격 **벡터**를 말하지만 그 클래스의 오라클이 닿을 HTTP 표면이 아예 없는
# (랩, 클래스) 쌍. 숫자를 좋게 만들려고 빼는 것이 아니라, 어떤 구현을 해도 관측할 수
# 없는 좌표를 분모에 두면 그 클래스의 상한이 조용히 내려가기 때문이다. 각 항목은
# 랩 소스를 읽고 판단한 이유를 함께 적는다.
CLASS_NOT_OBSERVABLE = {
    ("XBEN-077-24", "File Upload"): (
        "올린 파일을 저장하거나 서빙하지 않는다. XML로 파싱해 프로필 페이지에 인라인으로 "
        "렌더링만 하므로 업로드-회수 오라클이 볼 대상이 없다. 실제 효과는 XXE다."
    ),
    ("XBEN-092-24", "File Upload"): (
        "multipart 업로드 폼이 없다. base64 문자열을 폼 필드로 받아 /tmp 아래에 쓰고 "
        "웹으로 서빙하지 않는다. 실제 취약점은 역직렬화다."
    ),
}


@dataclass(frozen=True, slots=True)
class Lab:
    lab_id: str
    name: str
    level: str
    tags: tuple[str, ...]
    path: Path

    @property
    def expected_classes(self) -> tuple[str, ...]:
        """이 랩에서 LASP가 확정해야 하는 클래스. 중복 제거, 선언 순서 유지."""
        seen = dict.fromkeys(
            TAG_TO_CLASS[t] for t in self.tags if t in TAG_TO_CLASS
        )
        return tuple(
            cls for cls in seen if (self.lab_id, cls) not in CLASS_NOT_OBSERVABLE
        )

    @property
    def not_observable(self) -> tuple[tuple[str, str], ...]:
        """이 랩에서 분모에서 뺀 (클래스, 이유). 출력에 드러내 감사할 수 있게 둔다."""
        return tuple(
            (cls, reason)
            for (lab_id, cls), reason in CLASS_NOT_OBSERVABLE.items()
            if lab_id == self.lab_id
        )

    @property
    def unsupported_tags(self) -> tuple[str, ...]:
        return tuple(t for t in self.tags if t in UNSUPPORTED_TAGS)

    @property
    def is_single_class(self) -> bool:
        """태그가 전부 한 클래스로 모이는 랩. 원인 분석이 깨끗해 우선 뽑는다."""
        return len(self.expected_classes) == 1 and not self.unsupported_tags

    @property
    def oracle_gap_tags(self) -> tuple[str, ...]:
        return tuple(t for t in self.tags if t in ORACLE_GAPS)


def load_labs(root: Path = XBEN_ROOT) -> list[Lab]:
    bench_dir = root / "benchmarks"
    if not bench_dir.is_dir():
        raise SystemExit(f"XBEN 벤치마크 디렉터리가 없다: {bench_dir}")
    labs: list[Lab] = []
    for meta_path in sorted(bench_dir.glob("XBEN-*/benchmark.json")):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            print(f"경고: {meta_path.parent.name} 메타 파싱 실패 — {error}")
            continue
        labs.append(
            Lab(
                lab_id=meta_path.parent.name,
                name=str(meta.get("name", "")),
                level=str(meta.get("level", "?")),
                tags=tuple(meta.get("tags") or ()),
                path=meta_path.parent,
            )
        )
    return labs


def stratified_plan(
    labs: list[Lab], per_class: int, seed: int = 20261017
) -> dict[str, list[Lab]]:
    """클래스당 최대 per_class개를 뽑는다. 단일클래스 랩을 먼저, 그 다음 난이도 오름차순.

    같은 랩이 두 클래스에 동시에 뽑히지 않게 한다. 한 랩이 두 클래스를 기대하면
    원인 귀속이 흐려지고, 한쪽 클래스 개선이 다른 쪽 점수를 움직여 균등 비교가 깨진다.
    """
    rng = random.Random(seed)
    by_class: dict[str, list[Lab]] = defaultdict(list)
    for lab in labs:
        for cls in lab.expected_classes:
            by_class[cls].append(lab)

    plan: dict[str, list[Lab]] = {}
    claimed: set[str] = set()
    # 후보가 적은 클래스부터 배정한다. 희소 클래스가 먼저 랩을 확보하지 못하면
    # 풍부한 클래스(XSS)가 공유 랩을 선점해 희소 클래스 분모가 0으로 깎인다.
    for cls in sorted(SUPPORTED, key=lambda c: len(by_class.get(c, ()))):
        pool = [lab for lab in by_class.get(cls, ()) if lab.lab_id not in claimed]
        rng.shuffle(pool)
        pool.sort(key=lambda lab: (not lab.is_single_class, lab.level, lab.lab_id))
        chosen = pool[:per_class]
        for lab in chosen:
            claimed.add(lab.lab_id)
        plan[cls] = chosen
    return plan


def _print_coverage(labs: list[Lab]) -> None:
    total = len(labs)
    covered = [lab for lab in labs if lab.expected_classes]
    uncovered = [lab for lab in labs if not lab.expected_classes]

    print(f"XBEN 총 랩 {total}  (XBEN_ROOT={XBEN_ROOT})\n")
    print(f"지원 클래스 보유   {len(covered):>3}랩  {len(covered) / total * 100:4.1f}%")
    print(f"미지원 전용        {len(uncovered):>3}랩  {len(uncovered) / total * 100:4.1f}%")

    print("\n=== 클래스별 보유 랩 (균등 추출 분모) ===")
    by_class: dict[str, list[Lab]] = defaultdict(list)
    for lab in covered:
        for cls in lab.expected_classes:
            by_class[cls].append(lab)
    for cls in SUPPORTED:
        pool = by_class.get(cls, [])
        pure = [lab for lab in pool if lab.is_single_class]
        gap = [lab for lab in pool if lab.oracle_gap_tags]
        note = f"  ※ 오라클 공백 {len(gap)}랩" if gap else ""
        print(f"  {cls:<16} 전체 {len(pool):>2}랩 / 단일클래스 {len(pure):>2}랩{note}")

    print("\n=== 균등 추출 상한 ===")
    sizes = [len(by_class.get(c, [])) for c in SUPPORTED]
    print(f"  최소 보유 클래스 = {min(sizes)}랩 → 클래스당 상한을 이 값 이하로 두면")
    print(f"  5클래스 전부 동수가 되어 macro-average가 XSS에 끌려가지 않는다.")


def _print_plan(labs: list[Lab], per_class: int) -> None:
    plan = stratified_plan(labs, per_class)
    print(f"=== 클래스당 {per_class}랩 층화 추출 ===\n")
    total = 0
    for cls in SUPPORTED:
        chosen = plan.get(cls, [])
        total += len(chosen)
        short = " ".join(lab.lab_id.replace("XBEN-", "").replace("-24", "") for lab in chosen)
        flag = "" if len(chosen) == per_class else f"  ⚠ {per_class}랩 미달"
        print(f"  {cls:<16} {len(chosen)}랩  {short}{flag}")
        for lab in chosen:
            marks = []
            if not lab.is_single_class:
                marks.append(f"복합태그={','.join(lab.tags)}")
            if lab.oracle_gap_tags:
                marks.append(f"오라클공백={','.join(lab.oracle_gap_tags)}")
            if marks:
                print(f"       {lab.lab_id} L{lab.level}  {' / '.join(marks)}")
    print(f"\n  합계 {total}랩")
    if total:
        print(f"  macro-average 분모: 클래스 {len(SUPPORTED)}개 (랩 수가 아님)")


def _print_not_observable(labs: list[Lab]) -> None:
    """분모에서 뺀 (랩, 클래스)를 이유와 함께 드러낸다. 조용히 빼면 채점이 흐려진다."""

    excluded = [(lab, cls, reason) for lab in labs for cls, reason in lab.not_observable]
    if not excluded:
        return
    print(f"=== 분모 제외: 오라클이 닿을 표면이 없는 (랩, 클래스) {len(excluded)}건 ===\n")
    for lab, cls, reason in sorted(excluded, key=lambda item: item[0].lab_id):
        print(f"  {lab.lab_id}  {cls}\n       {reason}\n       태그={','.join(lab.tags)}")
    print()


def _print_backlog(labs: list[Lab]) -> None:
    uncovered = [lab for lab in labs if not lab.expected_classes]
    counts = Counter(t for lab in uncovered for t in lab.tags)
    print(f"=== 미지원 클래스 백로그 ({len(uncovered)}랩) ===\n")
    for tag, n in counts.most_common():
        hit = sorted(
            lab.lab_id.replace("XBEN-", "").replace("-24", "")
            for lab in uncovered
            if tag in lab.tags
        )
        print(f"  {tag:<26}{n:>3}랩  {' '.join(hit)}")
    print("\n=== 지원 클래스 중 오라클 공백 ===")
    for lab in labs:
        if lab.expected_classes and lab.oracle_gap_tags:
            for tag in lab.oracle_gap_tags:
                print(f"  {lab.lab_id} L{lab.level}  {tag} — {ORACLE_GAPS[tag]}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=int, metavar="N", help="클래스당 N랩 층화 추출")
    parser.add_argument("--backlog", action="store_true", help="미지원 클래스 백로그")
    parser.add_argument("--json", action="store_true", help="추출 결과를 JSON으로")
    args = parser.parse_args()

    labs = load_labs()
    if args.json:
        if not args.plan:
            parser.error("--json은 --plan N과 함께 써야 한다")
        plan = stratified_plan(labs, args.plan)
        print(
            json.dumps(
                {
                    cls: [
                        {
                            "lab_id": lab.lab_id,
                            "level": lab.level,
                            "tags": list(lab.tags),
                            "single_class": lab.is_single_class,
                            "oracle_gap": list(lab.oracle_gap_tags),
                        }
                        for lab in chosen
                    ]
                    for cls, chosen in plan.items()
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if args.backlog:
        _print_not_observable(labs)
        _print_backlog(labs)
    elif args.plan:
        _print_plan(labs, args.plan)
    else:
        _print_not_observable(labs)
        _print_coverage(labs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
