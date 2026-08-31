"""핵심 계층이 외부 구현 계층을 역참조하지 않는지 정적으로 검사한다."""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path


# 테스트 파일 위치와 무관하게 실제 패키지 루트를 계산한다.
PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "src" / "hacklipse"


class DependencyDirectionTests(unittest.TestCase):
    """AST import 목록을 이용해 단방향 의존 규칙을 검증한다."""

    def test_core_layers_do_not_import_outer_layers(self) -> None:
        """domain·ports·application이 자신보다 바깥 계층을 import하지 않아야 한다."""

        # 각 핵심 계층이 절대 알아서는 안 되는 외부 모듈 접두사다.
        forbidden = {
            "domain": ("hacklipse.ports", "hacklipse.application", "hacklipse.adapters"),
            "ports": ("hacklipse.application", "hacklipse.adapters", "hacklipse.bootstrap"),
            "application": ("hacklipse.adapters", "hacklipse.bootstrap"),
        }

        violations: list[str] = []
        for layer, prefixes in forbidden.items():
            for path in (PACKAGE_ROOT / layer).rglob("*.py"):
                # 문자열 검색이 아닌 AST를 사용해 실제 import 문만 판별한다.
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        names = [alias.name for alias in node.names]
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        names = [node.module]
                    else:
                        continue
                    for name in names:
                        if any(
                            name == prefix or name.startswith(prefix + ".")
                            for prefix in prefixes
                        ):
                            violations.append(f"{path.relative_to(PACKAGE_ROOT)} imports {name}")

        self.assertEqual(violations, [])

    def test_core_layers_use_only_the_standard_library(self) -> None:
        """domain·ports·application은 외부 패키지에 의존하지 않아야 한다.

        불변식과 중재 로직이 사는 계층이라 감사 대상이고, 외부 패키지에 묶이면
        검증과 이식이 어려워진다. adapters는 바깥세상과 붙는 곳이므로 예외다.
        """

        violations: list[str] = []
        for layer in ("domain", "ports", "application"):
            for path in (PACKAGE_ROOT / layer).rglob("*.py"):
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        names = [alias.name for alias in node.names]
                    elif isinstance(node, ast.ImportFrom):
                        # 상대 import는 같은 패키지 안이므로 검사 대상이 아니다.
                        names = [node.module] if node.level == 0 and node.module else []
                    else:
                        continue
                    for name in names:
                        root = name.split(".")[0]
                        if root == "hacklipse" or root in sys.stdlib_module_names:
                            continue
                        violations.append(f"{path.relative_to(PACKAGE_ROOT)} imports {name}")

        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
