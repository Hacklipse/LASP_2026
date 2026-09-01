"""Juice Shop 임시 계정 정리가 이번 실행의 데이터만 삭제하는지 검증한다."""

from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS))

from run_juice_shop_baseline import (  # noqa: E402
    _ProvisionedAccount,
    _cleanup_provisioned_accounts,
    _resolve_juice_shop_db,
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
        self.assertEqual(_resolve_juice_shop_db(str(self.database)), self.database)

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
