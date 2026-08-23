"""Run별 요청 예산을 재시작 후에도 보존하는 SQLite Adapter."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from threading import RLock

from hacklipse.domain import TaskEnvelope
from hacklipse.ports.errors import BudgetExceeded, DuplicateRecord, RecordNotFound


class SQLiteBudgetManager:
    """기존 요청 단위 BudgetManager 계약을 SQLite로 영속화한다."""

    def __init__(self, database_path: str | Path) -> None:
        self._path = str(database_path)
        self._lock = RLock()
        self._closed = False
        self._connection = sqlite3.connect(self._path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        with self._lock:
            self._connection.execute("PRAGMA busy_timeout = 5000")
            if self._path != ":memory:":
                self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS budgets (
                    run_id TEXT PRIMARY KEY,
                    total_units INTEGER NOT NULL CHECK(total_units >= 0),
                    used_units INTEGER NOT NULL CHECK(used_units >= 0),
                    CHECK(used_units <= total_units)
                )
                """
            )
            self._connection.commit()

    def open_run(self, run_id: str, total_units: int) -> None:
        if total_units < 0:
            raise ValueError("budget total cannot be negative")
        with self._lock:
            try:
                self._connection.execute(
                    "INSERT INTO budgets(run_id, total_units, used_units) VALUES (?, ?, 0)",
                    (run_id, total_units),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as error:
                self._connection.rollback()
                raise DuplicateRecord(run_id) from error

    def ensure_available(self, task: TaskEnvelope) -> None:
        if task.request_budget > 0 and self.remaining(task.run_id) <= 0:
            raise BudgetExceeded(f"request budget exhausted for {task.run_id}")

    def consume(self, run_id: str, units: int) -> None:
        if units < 0:
            raise ValueError("budget consumption cannot be negative")
        with self._lock:
            try:
                # 잔량 확인과 차감을 하나의 write transaction으로 묶는다.
                self._connection.execute("BEGIN IMMEDIATE")
                row = self._connection.execute(
                    "SELECT total_units, used_units FROM budgets WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
                if row is None:
                    raise RecordNotFound(run_id)
                remaining = row["total_units"] - row["used_units"]
                if units > remaining:
                    raise BudgetExceeded(f"request budget exceeded for {run_id}")
                self._connection.execute(
                    "UPDATE budgets SET used_units = used_units + ? WHERE run_id = ?",
                    (units, run_id),
                )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

    def remaining(self, run_id: str) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT total_units, used_units FROM budgets WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        if row is None:
            raise RecordNotFound(run_id)
        return row["total_units"] - row["used_units"]

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._connection.close()
            self._closed = True

    def __enter__(self) -> SQLiteBudgetManager:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
