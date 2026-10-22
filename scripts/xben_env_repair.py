"""XBEN 랩이 현대 Docker/Apple Silicon에서 기동하지 못하는 원인을 수리한다.

측정 전제: 분모가 깨진 클래스는 탐지율을 읽을 수 없다. 베이스라인에서 SQLi는
3랩 중 2랩이 환경 실패로 빠져 분모가 1이 됐다. 이건 LASP 성능이 아니라 측정 환경이
만든 손실이므로 먼저 걷어낸다.

수리는 세 종류다. 모두 **멱등**이고, 원본을 `.orig`로 남긴다. 취약점·플래그·앱 로직은
건드리지 않는다 — 기동을 막는 문법과 플랫폼만 고친다.

  1. `expose: - 3306:3306`  → `expose: - 3306`
     expose는 단일 포트만 받는다. 매핑 문법은 Compose v2가 거부한다.
  2. `ports: - "3000:3000"` → `ports: - "3000"`
     호스트 포트를 고정하면 다른 무언가가 점유한 순간 랩이 안 뜬다. 하네스는
     compose에 실제 매핑을 물어보므로 호스트 쪽을 고정할 이유가 없다.
  3. arm64 매니페스트가 없는 이미지를 쓰는 서비스에 `platform: linux/amd64`
     전역 DOCKER_DEFAULT_PLATFORM으로 강제하면 네이티브로 잘 빌드되던 서비스까지
     깨진다(php:7.4-apache가 그렇다). 문제 서비스에만 붙인다.
  4. `composer install` 앞에 `policy.advisories.block=false`
     취약한 의존성을 일부러 핀한 랩이 있는데, 그 핀이 바로 시험 대상 취약점이다.
     요즘 Composer는 보안권고가 붙은 패키지 설치를 거부해 빌드 자체가 막힌다.

    python3 scripts/xben_env_repair.py            # 바꿀 내용만 보여준다
    python3 scripts/xben_env_repair.py --apply
    python3 scripts/xben_env_repair.py --revert    # .orig로 되돌린다
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from xben_inventory import XBEN_ROOT  # noqa: E402

# arm64 매니페스트가 없어 Apple Silicon에서 pull이 실패하는 이미지.
# 여기 없는 이미지가 같은 증상을 보이면 추가한다.
NO_ARM64_IMAGES = ("mysql:5.7",)

_EXPOSE_REASON = (
    "      # Was a host:container mapping. `expose` takes a single container port and\n"
    "      # Compose v2 rejects the mapping form, so the lab could not start at all.\n"
)
_PORTS_REASON = (
    "      # Was a fixed host:container mapping. A pinned host port makes the lab\n"
    "      # unstartable whenever anything else holds it, and the harness asks Compose\n"
    "      # for the real mapping anyway.\n"
)
_PLATFORM_REASON = (
    "    # This image publishes no linux/arm64 manifest, so it cannot be pulled on Apple\n"
    "    # Silicon. Pinning the platform here (not globally) keeps the other services\n"
    "    # building natively - a global override breaks those that have no amd64 manifest.\n"
)

_BLOCK_RE = re.compile(r"^(\s*)([a-zA-Z_][\w-]*):\s*(.*)$")
_LIST_PORT_RE = re.compile(r'^(\s*-\s*)"?(\d+):(\d+)"?\s*$')

_COMPOSER_RE = re.compile(r"^RUN composer install.*$", re.M)
_COMPOSER_REASON = (
    "# Modern Composer refuses to install packages carrying security advisories. Some labs\n"
    "# pin a deliberately vulnerable dependency - that pin IS the vulnerability under test -\n"
    "# so the image could not build at all. Disabling the policy restores the intended app\n"
    "# and does not change the vulnerability.\n"
)


def _repair_dockerfiles(root: Path, apply: bool) -> int:
    """composer 정책 때문에 빌드가 막히는 Dockerfile을 수리한다."""
    changed = 0
    for path in sorted(root.glob("XBEN-*/app/Dockerfile")):
        text = path.read_text(encoding="utf-8")
        if "policy.advisories.block" in text:
            continue
        match = _COMPOSER_RE.search(text)
        if match is None:
            continue
        changed += 1
        print(f"{path.parent.parent.name}")
        print("  composer: policy.advisories.block=false 추가")
        if apply:
            backup = path.with_suffix(".orig")
            if not backup.is_file():
                shutil.copy2(path, backup)
            patched = match.group(0).replace(
                "composer install",
                "composer config policy.advisories.block false && composer install",
                1,
            )
            path.write_text(
                text[: match.start()] + _COMPOSER_REASON + patched + text[match.end() :],
                encoding="utf-8",
            )
    return changed


def _service_has_platform(lines: list[str], image_index: int, indent: int) -> bool:
    """image 줄이 속한 서비스 블록에 platform 키가 이미 있는지 본다.

    image 줄 전후를 같은 들여쓰기 안에서만 훑는다. 들여쓰기가 얕아지면 다른 서비스로
    넘어간 것이므로 멈춘다.
    """
    for step in (1, -1):
        cursor = image_index + step
        while 0 <= cursor < len(lines):
            line = lines[cursor].rstrip("\n")
            if line.strip():
                current = len(line) - len(line.lstrip())
                if current < indent:
                    break
                if current == indent and line.strip().startswith("platform:"):
                    return True
            cursor += step
    return False


def _repair_compose(text: str) -> tuple[str, list[str]]:
    """compose 본문을 수리하고 (새 본문, 변경 설명 목록)을 반환한다."""
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    notes: list[str] = []
    block: str | None = None          # 지금 어떤 키의 리스트 안인지
    service: str | None = None
    service_indent = 0
    pending_platform: list[int] = []  # platform을 넣어야 하는 out 인덱스

    for position, raw in enumerate(lines):
        stripped = raw.strip()
        match = _BLOCK_RE.match(raw.rstrip("\n"))

        if match and not stripped.startswith("-"):
            indent, key, rest = len(match.group(1)), match.group(2), match.group(3)
            if key in ("expose", "ports"):
                block = key
            else:
                block = None
                # services 바로 아래 2칸 들여쓰기가 서비스 이름이다.
                if indent == 2 and not rest:
                    service = key
                    service_indent = indent
                elif indent <= service_indent and key == "services":
                    service = None
            if key == "image" and any(img in rest for img in NO_ARM64_IMAGES):
                # 이미 platform이 박힌 서비스는 건드리지 않는다. 안 그러면 재실행마다
                # 같은 줄이 또 끼어들어 멱등성이 깨진다.
                if not _service_has_platform(lines, position, indent):
                    pending_platform.append(len(out))
                    notes.append(
                        f"{service or '?'}: platform=linux/amd64 ({rest.strip()})"
                    )
            out.append(raw)
            continue

        if block and stripped.startswith("-"):
            port = _LIST_PORT_RE.match(raw.rstrip("\n"))
            if port:
                lead, host, container = port.groups()
                if block == "expose":
                    out.append(_EXPOSE_REASON)
                    out.append(f"{lead}{container}\n")
                    notes.append(f"{service or '?'}: expose {host}:{container} -> {container}")
                    continue
                out.append(_PORTS_REASON)
                out.append(f'{lead}"{container}"\n')
                notes.append(f"{service or '?'}: ports {host}:{container} -> {container}")
                continue
        out.append(raw)

    # image 줄 바로 다음에 platform을 끼운다. 뒤에서부터 넣어 인덱스가 밀리지 않게 한다.
    for index in reversed(pending_platform):
        out.insert(index + 1, _PLATFORM_REASON + "    platform: linux/amd64\n")

    return "".join(out), notes


def _already_patched(text: str) -> bool:
    return "platform: linux/amd64" in text or "the harness asks Compose" in text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="실제로 파일을 고친다")
    parser.add_argument("--revert", action="store_true", help=".orig로 되돌린다")
    args = parser.parse_args()

    composes = sorted((XBEN_ROOT / "benchmarks").glob("XBEN-*/docker-compose.yml"))
    if not composes:
        print(f"compose 파일을 찾지 못했다: {XBEN_ROOT}")
        return 2

    if args.revert:
        count = 0
        targets = [(p, p.with_suffix(".yml.orig")) for p in composes]
        targets += [
            (p, p.with_suffix(".orig"))
            for p in sorted((XBEN_ROOT / "benchmarks").glob("XBEN-*/app/Dockerfile"))
        ]
        for path, backup in targets:
            if backup.is_file():
                shutil.copy2(backup, path)
                backup.unlink()
                print(f"되돌림  {path.parent.name}/{path.name}")
                count += 1
        print(f"\n{count}개 복원")
        return 0

    changed = 0
    for path in composes:
        text = path.read_text(encoding="utf-8")
        new_text, notes = _repair_compose(text)
        if new_text == text or not notes:
            continue
        changed += 1
        print(f"{path.parent.name}")
        for note in notes:
            print(f"  {note}")
        if args.apply:
            backup = path.with_suffix(".yml.orig")
            if not backup.is_file():
                shutil.copy2(path, backup)
            path.write_text(new_text, encoding="utf-8")

    changed += _repair_dockerfiles(XBEN_ROOT / "benchmarks", args.apply)

    verb = "수리함" if args.apply else "수리 대상 (적용하려면 --apply)"
    print(f"\n{changed}랩 {verb}")
    if not args.apply and changed:
        print("원본은 docker-compose.yml.orig 로 보존된다. --revert 로 되돌릴 수 있다.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
