"""Juice Shop 임시 계정 정리가 이번 실행의 데이터만 삭제하는지 검증한다."""

from __future__ import annotations

import contextlib
import io
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS))

from run_juice_shop_baseline import (  # noqa: E402
    _ProvisionedAccount,
    _all_mode_recon_seeds,
    _cleanup_provisioned_accounts,
    _knowledge_database_path,
    _print_execution_preview,
    _recon_planner_summary,
    _resolve_juice_shop_db,
)
from hacklipse.domain import Evidence


class JuiceShopAllModeTests(unittest.TestCase):
    def test_execution_preview_groups_configuration_scope_and_cleanup(self) -> None:
        args = SimpleNamespace(
            vuln="all",
            profile="llm",
            llm_provider="gemini",
            recon="hybrid",
            router="hybrid",
            router_review="weak",
            compare_routers=False,
            knowledge_db="knowledge.sqlite",
            routing_log="artifacts/routing-decisions.jsonl",
        )
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            _print_execution_preview(
                args,
                target_label="전체",
                selected_model="gemini-3.5-flash-lite",
                rpm_limit=14,
            )

        rendered = output.getvalue()
        self.assertIn("[실행 구성]", rendered)
        self.assertIn("검사 대상       통합 검사 (4종)", rendered)
        self.assertIn("Router          hybrid · review weak", rendered)
        self.assertIn("Router 비교     끔", rendered)
        self.assertIn("LLM 호출 제한   14회 / rolling 60초", rendered)
        self.assertIn("Knowledge       knowledge/knowledge.sqlite", rendered)
        self.assertIn("[검사 범위]", rendered)
        self.assertIn("XSS · SQLi · Path Traversal · SSTI", rendered)
        self.assertIn("Access Control (--vuln access_control)", rendered)
        self.assertIn("[계정 및 정리]", rendered)
        self.assertIn("종료 처리       임시 계정과 연결 데이터를 삭제", rendered)
        self.assertNotIn("비교: False", rendered)

    def test_bare_knowledge_database_name_uses_dedicated_directory(self) -> None:
        self.assertEqual(
            _knowledge_database_path("knowledge.sqlite"),
            Path("knowledge/knowledge.sqlite"),
        )
        self.assertEqual(
            _knowledge_database_path("var/cases.sqlite"),
            Path("var/cases.sqlite"),
        )

    def test_authenticated_all_mode_adds_the_profile_as_a_recon_seed(self) -> None:
        self.assertEqual(
            _all_mode_recon_seeds(
                "http://127.0.0.1:3000/", include_ssti=True
            ),
            ("http://127.0.0.1:3000/profile",),
        )
        self.assertEqual(
            _all_mode_recon_seeds(
                "http://127.0.0.1:3000/", include_ssti=False
            ),
            (),
        )

    def test_recon_planner_summary_reports_success_and_fallback(self) -> None:
        def evidence(source: str, reason: str) -> Evidence:
            return Evidence(
                evidence_id=f"evi-{source}",
                run_id="run-1",
                surface_id=None,
                created_by="llm_recon_planner",
                evidence_type="observation",
                observation={
                    "type": "recon_plan",
                    "selection_source": source,
                    "reason": reason,
                },
            )

        self.assertEqual(
            _recon_planner_summary((evidence("llm", "ranked"),)), "LLM 성공"
        )
        self.assertEqual(
            _recon_planner_summary(
                (evidence("deterministic_fallback", "llm_call_failed:LlmTimeout"),)
            ),
            "fallback 사용 (timeout)",
        )


class JuiceShopTemporaryAccountCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "juiceshop.sqlite"
        connection = sqlite3.connect(self.database)
        connection.executescript(
            """
            CREATE TABLE Users (id INTEGER PRIMARY KEY, email TEXT UNIQUE);
            CREATE TABLE Baskets (id INTEGER PRIMARY KEY, UserId INTEGER);
            CREATE TABLE BasketItems (id INTEGER PRIMARY KEY, BasketId INTEGER);
            CREATE TABLE Wallets (id INTEGER PRIMARY KEY, UserId INTEGER);
            INSERT INTO Users VALUES (1, 'real-user@example.test');
            INSERT INTO Users VALUES (26, 'hacklipse-actor-run@example.invalid');
            INSERT INTO Users VALUES (27, 'hacklipse-owner-run@example.invalid');
            INSERT INTO Baskets VALUES (1, 1), (7, 26), (8, 27);
            INSERT INTO BasketItems VALUES (1, 1), (2, 7);
            INSERT INTO Wallets VALUES (1, 1), (2, 26), (3, 27);
            """
        )
        connection.commit()
        connection.close()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _accounts() -> list[_ProvisionedAccount]:
        return [
            _ProvisionedAccount(
                "actor",
                "actor-ref",
                26,
                "hacklipse-actor-run@example.invalid",
                "7",
            ),
            _ProvisionedAccount(
                "owner",
                "owner-ref",
                27,
                "hacklipse-owner-run@example.invalid",
                "8",
            ),
        ]

    def test_cleanup_removes_only_the_current_temporary_accounts(self) -> None:
        # macOS의 임시 디렉터리(/var)는 /private/var 심볼릭 링크다. resolver가 경로를
        # 정규화하므로 기대값도 같은 기준으로 맞춘다.
        self.assertEqual(_resolve_juice_shop_db(str(self.database)), self.database.resolve())

        _cleanup_provisioned_accounts(self.database, self._accounts())

        connection = sqlite3.connect(self.database)
        self.assertEqual(connection.execute("SELECT * FROM Users").fetchall(), [(1, "real-user@example.test")])
        self.assertEqual(connection.execute("SELECT * FROM Baskets").fetchall(), [(1, 1)])
        self.assertEqual(connection.execute("SELECT * FROM BasketItems").fetchall(), [(1, 1)])
        self.assertEqual(connection.execute("SELECT * FROM Wallets").fetchall(), [(1, 1)])
        connection.close()

    def test_mismatched_identity_rolls_back_without_deleting_anything(self) -> None:
        accounts = self._accounts()
        accounts[0].email = "unexpected@example.invalid"

        with self.assertRaises(RuntimeError):
            _cleanup_provisioned_accounts(self.database, accounts)

        connection = sqlite3.connect(self.database)
        self.assertEqual(connection.execute("SELECT COUNT(*) FROM Users").fetchone()[0], 3)
        self.assertEqual(connection.execute("SELECT COUNT(*) FROM Baskets").fetchone()[0], 3)
        connection.close()


if __name__ == "__main__":
    unittest.main()
