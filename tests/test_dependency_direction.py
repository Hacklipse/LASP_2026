"""핵심 계층이 외부 구현 계층을 역참조하지 않는지 정적으로 검사한다."""

from __future__ import annotations

import ast
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


if __name__ == "__main__":
    unittest.main()
