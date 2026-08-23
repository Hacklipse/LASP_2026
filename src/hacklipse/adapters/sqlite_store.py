"""도메인 객체를 JSON으로 보존하는 SQLite 저장소 Adapter."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from threading import RLock
from typing import Any

from hacklipse.domain import (
    Candidate,
    Evidence,
    EvidenceRequest,
    Finding,
    ReportArtifact,
    Run,
    RunPhase,
    RunScope,
    Surface,
    TaskEnvelope,
    TaskRecord,
    TaskStatus,
)
from hacklipse.ports.errors import DuplicateRecord, RecordNotFound


_SCHEMA_VERSION = 1


class _SQLiteDatabase:
    """한 StoreBundle 안에서 공유하는 SQLite 연결과 transaction 경계."""

    def __init__(self, database_path: str | Path) -> None:
        self.path = str(database_path)
        self._lock = RLock()
        self._closed = False
        self.connection = sqlite3.connect(self.path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        with self._lock:
            self.connection.execute("PRAGMA busy_timeout = 5000")
            if self.path != ":memory:":
                self.connection.execute("PRAGMA journal_mode = WAL")
            self.connection.execute("PRAGMA foreign_keys = ON")

    @contextmanager
    def transaction(self):
        """쓰기 전체를 직렬화하고 성공 시 commit, 실패 시 rollback한다."""

        with self._lock:
            try:
                yield self.connection
                self.connection.commit()
            except Exception:
                self.connection.rollback()
                raise

    def one(self, sql: str, parameters: tuple[object, ...]) -> sqlite3.Row | None:
        with self._lock:
            return self.connection.execute(sql, parameters).fetchone()

    def all(self, sql: str, parameters: tuple[object, ...]) -> list[sqlite3.Row]:
        with self._lock:
            return self.connection.execute(sql, parameters).fetchall()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self.connection.close()
            self._closed = True


def _initialize_schema(database: _SQLiteDatabase) -> None:
    statements = (
        "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS runs (run_id TEXT PRIMARY KEY, data TEXT NOT NULL)",
        """
        CREATE TABLE IF NOT EXISTS tasks (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT NOT NULL UNIQUE,
            run_id TEXT NOT NULL,
            data TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS evidence (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id TEXT NOT NULL UNIQUE,
            run_id TEXT NOT NULL,
            data TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS surfaces (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            surface_id TEXT NOT NULL UNIQUE,
            run_id TEXT NOT NULL,
            data TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS candidates (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            candidate_id TEXT NOT NULL UNIQUE,
            run_id TEXT NOT NULL,
            data TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS findings (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id TEXT NOT NULL UNIQUE,
            run_id TEXT NOT NULL,
            data TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS reports (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT NOT NULL UNIQUE,
            run_id TEXT NOT NULL,
            data TEXT NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_tasks_run ON tasks(run_id, seq)",
        "CREATE INDEX IF NOT EXISTS idx_evidence_run ON evidence(run_id, seq)",
        "CREATE INDEX IF NOT EXISTS idx_surfaces_run ON surfaces(run_id, seq)",
        "CREATE INDEX IF NOT EXISTS idx_candidates_run ON candidates(run_id, seq)",
        "CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id, seq)",
        "CREATE INDEX IF NOT EXISTS idx_reports_run ON reports(run_id, seq)",
    )
    with database.transaction() as connection:
        for statement in statements:
            connection.execute(statement)
        versions = connection.execute("SELECT version FROM schema_version").fetchall()
        if not versions:
            connection.execute(
                "INSERT INTO schema_version(version) VALUES (?)", (_SCHEMA_VERSION,)
            )
        elif len(versions) != 1 or versions[0]["version"] != _SCHEMA_VERSION:
            raise RuntimeError("unsupported SQLite store schema version")


def _json_default(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise TypeError("naive datetime cannot be persisted")
        return value.isoformat()
    if isinstance(value, (frozenset, set)):
        return sorted(value, key=repr)
    raise TypeError(f"unsupported persistent value: {type(value).__name__}")


def _dump(value: object) -> str:
    try:
        return json.dumps(
            asdict(value),
            default=_json_default,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise ValueError(f"domain object is not JSON serializable: {error}") from error


def _load(data: str) -> dict[str, Any]:
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("persisted domain object must be a JSON object")
    return value


def _decode_run(data: str) -> Run:
    value = _load(data)
    scope = value.pop("scope")
    value["scope"] = RunScope(
        allowed_hosts=frozenset(scope["allowed_hosts"]),
        allowed_path_prefixes=tuple(scope["allowed_path_prefixes"]),
    )
    value["phase"] = RunPhase(value["phase"])
    for name in (
        "evidence_ids",
        "surface_ids",
        "candidate_ids",
        "finding_ids",
        "report_ids",
    ):
        value[name] = tuple(value[name])
    return Run(**value)


def _decode_task(data: str) -> TaskRecord:
    value = _load(data)
    envelope = value.pop("envelope")
    request = envelope.get("evidence_request")
    envelope["evidence_request"] = EvidenceRequest(**request) if request else None
    for name in ("evidence_ids", "finding_ids", "allowed_tools"):
        envelope[name] = tuple(envelope[name])
    return TaskRecord(
        envelope=TaskEnvelope(**envelope),
        status=TaskStatus(value["status"]),
        attempts=value["attempts"],
        error=value["error"],
    )


def _decode_evidence(data: str) -> Evidence:
    value = _load(data)
    value["observation"] = dict(value["observation"])
    value["artifact_refs"] = dict(value["artifact_refs"])
    value["created_at"] = datetime.fromisoformat(value["created_at"])
    return Evidence(**value)


def _decode_surface(data: str) -> Surface:
    value = _load(data)
    value["parameters"] = tuple(value["parameters"])
    return Surface(**value)


def _decode_candidate(data: str) -> Candidate:
    value = _load(data)
    value["evidence_ids"] = tuple(value["evidence_ids"])
    return Candidate(**value)


def _decode_finding(data: str) -> Finding:
    value = _load(data)
    value["evidence_ids"] = tuple(value["evidence_ids"])
    value["remediation_refs"] = tuple(value["remediation_refs"])
    return Finding(**value)


def _decode_report(data: str) -> ReportArtifact:
    return ReportArtifact(**_load(data))


class _SQLiteStore:
    """고정된 테이블에 대한 공통 INSERT·UPDATE·조회 구현."""

    table: str
    id_column: str

    def __init__(self, database: _SQLiteDatabase, decoder: Callable[[str], object]) -> None:
        self._database = database
        self._decoder = decoder

    def _add(self, record_id: str, run_id: str, value: object) -> None:
        sql = (
            f"INSERT INTO {self.table}({self.id_column}, run_id, data) "
            "VALUES (?, ?, ?)"
        )
        try:
            with self._database.transaction() as connection:
                connection.execute(sql, (record_id, run_id, _dump(value)))
        except sqlite3.IntegrityError as error:
            raise DuplicateRecord(record_id) from error

    def _save(self, record_id: str, run_id: str, value: object) -> None:
        sql = (
            f"UPDATE {self.table} SET run_id = ?, data = ? "
            f"WHERE {self.id_column} = ?"
        )
        with self._database.transaction() as connection:
            cursor = connection.execute(sql, (run_id, _dump(value), record_id))
            if cursor.rowcount == 0:
                raise RecordNotFound(record_id)

    def _get(self, record_id: str, *, run_id: str | None = None):
        sql = f"SELECT data FROM {self.table} WHERE {self.id_column} = ?"
        parameters: tuple[object, ...] = (record_id,)
        if run_id is not None:
            sql += " AND run_id = ?"
            parameters = (record_id, run_id)
        row = self._database.one(sql, parameters)
        if row is None:
            raise RecordNotFound(record_id)
        return self._decoder(row["data"])

    def _list_by_run(self, run_id: str) -> tuple[object, ...]:
        rows = self._database.all(
            f"SELECT data FROM {self.table} WHERE run_id = ? ORDER BY seq", (run_id,)
        )
        return tuple(self._decoder(row["data"]) for row in rows)


class SQLiteRunStore:
    """Run의 현재 상태를 SQLite에 저장한다."""

    def __init__(self, database: _SQLiteDatabase) -> None:
        self._database = database

    def add(self, run: Run) -> None:
        try:
            with self._database.transaction() as connection:
                connection.execute(
                    "INSERT INTO runs(run_id, data) VALUES (?, ?)",
                    (run.run_id, _dump(run)),
                )
        except sqlite3.IntegrityError as error:
            raise DuplicateRecord(run.run_id) from error

    def save(self, run: Run) -> None:
        with self._database.transaction() as connection:
            cursor = connection.execute(
                "UPDATE runs SET data = ? WHERE run_id = ?", (_dump(run), run.run_id)
            )
            if cursor.rowcount == 0:
                raise RecordNotFound(run.run_id)

    def get(self, run_id: str) -> Run:
        row = self._database.one("SELECT data FROM runs WHERE run_id = ?", (run_id,))
        if row is None:
            raise RecordNotFound(run_id)
        return _decode_run(row["data"])


class SQLiteTaskStore(_SQLiteStore):
    table = "tasks"
    id_column = "task_id"

    def __init__(self, database: _SQLiteDatabase) -> None:
        super().__init__(database, _decode_task)

    def add(self, task: TaskRecord) -> None:
        self._add(task.envelope.task_id, task.envelope.run_id, task)

    def save(self, task: TaskRecord) -> None:
        self._save(task.envelope.task_id, task.envelope.run_id, task)

    def get(self, task_id: str) -> TaskRecord:
        return self._get(task_id)

    def list_by_run(self, run_id: str) -> tuple[TaskRecord, ...]:
        return self._list_by_run(run_id)


class SQLiteEvidenceStore(_SQLiteStore):
    table = "evidence"
    id_column = "evidence_id"

    def __init__(self, database: _SQLiteDatabase) -> None:
        super().__init__(database, _decode_evidence)

    def append(self, evidence: Evidence) -> None:
        self._add(evidence.evidence_id, evidence.run_id, evidence)

    def get(self, run_id: str, evidence_id: str) -> Evidence:
        return self._get(evidence_id, run_id=run_id)

    def get_many(self, run_id: str, evidence_ids: Sequence[str]) -> tuple[Evidence, ...]:
        return tuple(self.get(run_id, evidence_id) for evidence_id in evidence_ids)

    def list_by_run(self, run_id: str) -> tuple[Evidence, ...]:
        return self._list_by_run(run_id)


class SQLiteSurfaceStore(_SQLiteStore):
    table = "surfaces"
    id_column = "surface_id"

    def __init__(self, database: _SQLiteDatabase) -> None:
        super().__init__(database, _decode_surface)

    def add(self, surface: Surface) -> None:
        self._add(surface.surface_id, surface.run_id, surface)

    def get(self, run_id: str, surface_id: str) -> Surface:
        return self._get(surface_id, run_id=run_id)

    def list_by_run(self, run_id: str) -> tuple[Surface, ...]:
        return self._list_by_run(run_id)


class SQLiteCandidateStore(_SQLiteStore):
    table = "candidates"
    id_column = "candidate_id"

    def __init__(self, database: _SQLiteDatabase) -> None:
        super().__init__(database, _decode_candidate)

    def add(self, candidate: Candidate) -> None:
        self._add(candidate.candidate_id, candidate.run_id, candidate)

    def save(self, candidate: Candidate) -> None:
        # 소유 Run 검사와 갱신을 한 SQL로 묶어 중간 race와 Run 이동을 막는다.
        with self._database.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE candidates SET data = ?
                WHERE candidate_id = ? AND run_id = ?
                """,
                (_dump(candidate), candidate.candidate_id, candidate.run_id),
            )
            if cursor.rowcount == 0:
                raise RecordNotFound(candidate.candidate_id)

    def get(self, run_id: str, candidate_id: str) -> Candidate:
        return self._get(candidate_id, run_id=run_id)

    def list_by_run(self, run_id: str) -> tuple[Candidate, ...]:
        return self._list_by_run(run_id)


class SQLiteFindingStore(_SQLiteStore):
    table = "findings"
    id_column = "finding_id"

    def __init__(self, database: _SQLiteDatabase) -> None:
        super().__init__(database, _decode_finding)

    def add(self, finding: Finding) -> None:
        if finding.status != "confirmed":
            raise ValueError("finding store accepts confirmed findings only")
        self._add(finding.finding_id, finding.run_id, finding)

    def get(self, run_id: str, finding_id: str) -> Finding:
        return self._get(finding_id, run_id=run_id)

    def list_by_run(self, run_id: str) -> tuple[Finding, ...]:
        return self._list_by_run(run_id)


class SQLiteReportStore(_SQLiteStore):
    table = "reports"
    id_column = "report_id"

    def __init__(self, database: _SQLiteDatabase) -> None:
        super().__init__(database, _decode_report)

    def add(self, report: ReportArtifact) -> None:
        self._add(report.report_id, report.run_id, report)

    def list_by_run(self, run_id: str) -> tuple[ReportArtifact, ...]:
        return self._list_by_run(run_id)


@dataclass(slots=True)
class SQLiteStoreBundle:
    """같은 SQLite 파일과 connection을 공유하는 영속 저장소 묶음."""

    database_path: str | Path
    _database: _SQLiteDatabase = field(init=False, repr=False)
    runs: SQLiteRunStore = field(init=False)
    tasks: SQLiteTaskStore = field(init=False)
    evidence: SQLiteEvidenceStore = field(init=False)
    surfaces: SQLiteSurfaceStore = field(init=False)
    candidates: SQLiteCandidateStore = field(init=False)
    findings: SQLiteFindingStore = field(init=False)
    reports: SQLiteReportStore = field(init=False)

    def __post_init__(self) -> None:
        self._database = _SQLiteDatabase(self.database_path)
        _initialize_schema(self._database)
        self.runs = SQLiteRunStore(self._database)
        self.tasks = SQLiteTaskStore(self._database)
        self.evidence = SQLiteEvidenceStore(self._database)
        self.surfaces = SQLiteSurfaceStore(self._database)
        self.candidates = SQLiteCandidateStore(self._database)
        self.findings = SQLiteFindingStore(self._database)
        self.reports = SQLiteReportStore(self._database)

    def close(self) -> None:
        self._database.close()

    def __enter__(self) -> SQLiteStoreBundle:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
