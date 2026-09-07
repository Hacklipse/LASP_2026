"""확정 Finding을 일반화해 저장·검색하는 독립 Knowledge Plane Adapter.

Phase 9-A는 워크플로 배선보다 저장 경계를 먼저 만든다. 이 모듈은 Evidence 원문을
받지 않고, 확정 Finding과 구조화된 Candidate/Surface만 KnowledgeCase로 변환한다.
따라서 과거 대상의 응답 본문이나 인증정보가 현재 Run의 판단 자료로 복사될 경로가 없다.

KnowledgeBase는 append-only다. 같은 case_id를 다시 발행하면 덮어쓰지 않고 거부한다.
과거 사례는 Analysis 참고자료일 뿐이며, 이 Adapter에는 Finding이나 Validation을 만드는
기능이 의도적으로 없다.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict
from pathlib import Path
from threading import RLock
from urllib.parse import unquote, urlsplit
from uuid import uuid4

from hacklipse.domain import Candidate, Finding, KnowledgeCase, KnowledgeQuery, Surface
from hacklipse.ports.errors import DuplicateRecord


_CATEGORY_LIMIT = 80
_SUMMARY_LIMIT = 500
_METADATA_VALUE_LIMIT = 500
_CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_PROVENANCE_REF = re.compile(r"^[a-z][a-z0-9_]{0,31}:[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
_SAFE_PARAMETER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,63}$")
_SAFE_PATH_SEGMENT = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")
_INTEGER_SEGMENT = re.compile(r"^[0-9]{1,20}$")
_UUID_SEGMENT = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_TOKEN = re.compile(r"[A-Za-z0-9_:-]+")
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_BEARER = re.compile(r"\bBearer\s+\S+", re.IGNORECASE)
_SECRET_ASSIGNMENT = re.compile(
    r"\b(?:authorization|cookie|password|passwd|csrf|api[_-]?key|token|secret|session)"
    r"\s*[:=]\s*\S+",
    re.IGNORECASE,
)
_PHONE = re.compile(r"(?<!\d)01[016789][-. ]?\d{3,4}[-. ]?\d{4}(?!\d)")
_KOREAN_RRN = re.compile(r"(?<!\d)\d{6}[- ]?[1-4]\d{6}(?!\d)")

_ALLOWED_METADATA_KEYS = frozenset(
    {
        "parameter_count",
        "parameter_names",
        "proof_type",
        "requires_auth",
        "severity",
        "surface_kind",
        "surface_method",
        "surface_path",
    }
)

_PROOF_TYPE_BY_VULNERABILITY = {
    "XSS": "xss_execution",
    "SQLi": "sqli_effect",
    "Access Control": "unauthorized_object_access",
    "Path Traversal": "path_traversal_file_read",
    "SSTI": "ssti_execution",
}


class KnowledgeCaseFactory:
    """확정 Finding을 비밀 원문 없는 재사용 사례로 일반화한다."""

    def __init__(self, id_factory: Callable[[], str] | None = None) -> None:
        self._id_factory = id_factory or (lambda: str(uuid4()))

    def from_finding(
        self,
        finding: Finding,
        candidate: Candidate,
        surface: Surface,
    ) -> KnowledgeCase:
        """소유 관계를 확인하고 구조화된 필드만 KnowledgeCase에 복사한다.

        Candidate의 hypothesis와 Evidence 본문은 의도적으로 사용하지 않는다. 둘 다 LLM
        자유 텍스트나 대상 응답을 포함할 수 있어, 일반화 없이 Knowledge Plane에 넣으면
        다른 Run의 프롬프트로 유출될 수 있다.
        """

        _validate_source_relationships(finding, candidate, surface)
        proof_type = _PROOF_TYPE_BY_VULNERABILITY.get(finding.vulnerability_type)
        if proof_type is None:
            raise ValueError(
                "knowledge publication requires a supported vulnerability proof type"
            )

        method = surface.method.upper()
        surface_kind = _surface_kind(surface)
        auth = "authenticated" if surface.requires_auth else "unauthenticated"
        summary = (
            f"Confirmed {finding.vulnerability_type} on an {auth} {method} "
            f"{surface_kind} surface using independent {proof_type} validation."
        )
        metadata = {
            "parameter_count": str(len(tuple(dict.fromkeys(surface.parameters)))),
            "parameter_names": ",".join(_generalize_parameter_names(surface.parameters)),
            "proof_type": proof_type,
            "requires_auth": "true" if surface.requires_auth else "false",
            "severity": finding.severity,
            "surface_kind": surface_kind,
            "surface_method": method,
            "surface_path": _generalize_path(surface.url),
        }
        case = KnowledgeCase(
            case_id=f"case-{self._id_factory()}",
            category=finding.vulnerability_type,
            summary=summary,
            provenance_refs=(
                f"run:{finding.run_id}",
                f"finding:{finding.finding_id}",
                f"validation:{finding.validation_id}",
            ),
            metadata=metadata,
        )
        _validate_case(case)
        return case


class InMemoryKnowledgeBase:
    """테스트와 단일 프로세스 실행에 쓰는 append-only KnowledgeBase."""

    def __init__(self) -> None:
        self._cases: dict[str, KnowledgeCase] = {}
        self._lock = RLock()

    def publish(self, case: KnowledgeCase) -> None:
        _validate_case(case)
        with self._lock:
            if case.case_id in self._cases:
                raise DuplicateRecord(case.case_id)
            # metadata 구현체가 mutable dict여도 발행 뒤 바뀌지 않게 복사한다.
            self._cases[case.case_id] = _copy_case(case)

    def search(self, query: KnowledgeQuery) -> tuple[KnowledgeCase, ...]:
        _validate_query(query)
        with self._lock:
            cases = tuple(self._cases.values())
        return _search(cases, query)


class SQLiteKnowledgeBase:
    """기존 StoreBundle과 같은 DB 파일에도 공존할 수 있는 SQLite KnowledgeBase.

    Phase 9-A에서 기존 SQLiteStoreBundle 스키마를 수정하지 않는다. 전용 테이블만
    ``CREATE TABLE IF NOT EXISTS``로 추가하므로 팀원의 Store/Progress migration과 결합이
    필요 없고, 같은 database_path를 사용해도 별도 연결로 안전하게 동작한다.
    """

    def __init__(self, database_path: str | Path) -> None:
        self.path = str(database_path)
        self._lock = RLock()
        self._closed = False
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        with self._lock:
            self._connection.execute("PRAGMA busy_timeout = 5000")
            if self.path != ":memory:":
                self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS knowledge_cases (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL UNIQUE,
                    category TEXT NOT NULL,
                    data TEXT NOT NULL
                )
                """
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_knowledge_category "
                "ON knowledge_cases(category, seq)"
            )
            self._connection.commit()

    def publish(self, case: KnowledgeCase) -> None:
        _validate_case(case)
        data = _encode_case(case)
        with self._lock:
            self._ensure_open()
            try:
                self._connection.execute(
                    "INSERT INTO knowledge_cases(case_id, category, data) VALUES (?, ?, ?)",
                    (case.case_id, case.category.casefold(), data),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as error:
                self._connection.rollback()
                raise DuplicateRecord(case.case_id) from error
            except Exception:
                self._connection.rollback()
                raise

    def search(self, query: KnowledgeQuery) -> tuple[KnowledgeCase, ...]:
        _validate_query(query)
        with self._lock:
            self._ensure_open()
            rows = self._connection.execute(
                "SELECT data FROM knowledge_cases WHERE category = ? ORDER BY seq",
                (query.category.casefold(),),
            ).fetchall()
        return _search(tuple(_decode_case(row["data"]) for row in rows), query)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._connection.close()
            self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("SQLite knowledge base is closed")

    def __enter__(self) -> SQLiteKnowledgeBase:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        del exc_type, exc, traceback
        self.close()


def _validate_source_relationships(
    finding: Finding, candidate: Candidate, surface: Surface
) -> None:
    if finding.run_id != candidate.run_id or finding.run_id != surface.run_id:
        raise ValueError("knowledge sources must belong to the same run")
    if finding.candidate_id != candidate.candidate_id:
        raise ValueError("knowledge finding must reference its candidate")
    if finding.surface_id != surface.surface_id or candidate.surface_id != surface.surface_id:
        raise ValueError("knowledge sources must reference the same surface")
    if finding.vulnerability_type != candidate.vulnerability_type:
        raise ValueError("knowledge sources must agree on vulnerability type")
    if candidate.status != "confirmed":
        raise ValueError("only a confirmed candidate can be published as knowledge")


def _validate_case(case: KnowledgeCase) -> None:
    if not _CASE_ID.fullmatch(case.case_id):
        raise ValueError("knowledge case_id has an invalid format")
    if not case.category.strip() or len(case.category) > _CATEGORY_LIMIT:
        raise ValueError("knowledge category must be non-blank and bounded")
    if not case.summary.strip() or len(case.summary) > _SUMMARY_LIMIT:
        raise ValueError("knowledge summary must be non-blank and bounded")
    if _contains_sensitive_text(case.summary):
        raise ValueError("knowledge summary contains target-specific or sensitive text")
    if not case.provenance_refs:
        raise ValueError("knowledge case requires provenance references")
    if len(set(case.provenance_refs)) != len(case.provenance_refs):
        raise ValueError("knowledge provenance references cannot be duplicated")
    if any(_PROVENANCE_REF.fullmatch(item) is None for item in case.provenance_refs):
        raise ValueError("knowledge provenance reference has an invalid format")
    if not {"run", "finding", "validation"}.issubset(
        item.partition(":")[0] for item in case.provenance_refs
    ):
        raise ValueError("knowledge provenance must include run, finding, and validation")

    metadata = dict(case.metadata)
    unknown = set(metadata) - _ALLOWED_METADATA_KEYS
    if unknown:
        raise ValueError(f"knowledge metadata contains unsupported keys: {sorted(unknown)}")
    for key, value in metadata.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("knowledge metadata keys and values must be strings")
        if len(value) > _METADATA_VALUE_LIMIT or _contains_sensitive_text(value):
            raise ValueError("knowledge metadata contains target-specific or sensitive text")
    path = metadata.get("surface_path")
    if path is not None and (not path.startswith("/") or "?" in path or "#" in path):
        raise ValueError("knowledge surface_path must be a generalized path without query")


def _validate_query(query: KnowledgeQuery) -> None:
    if not query.category.strip() or len(query.category) > _CATEGORY_LIMIT:
        raise ValueError("knowledge query category must be non-blank and bounded")
    if query.limit <= 0:
        raise ValueError("knowledge query limit must be positive")
    if query.limit > 100:
        raise ValueError("knowledge query limit cannot exceed 100")
    if len(query.text) > 2_000:
        raise ValueError("knowledge query text is too long")


def _search(
    cases: Sequence[KnowledgeCase], query: KnowledgeQuery
) -> tuple[KnowledgeCase, ...]:
    wanted = query.category.casefold()
    tokens = _tokens(query.text)
    ranked: list[tuple[int, int, KnowledgeCase]] = []
    for index, case in enumerate(cases):
        if case.category.casefold() != wanted:
            continue
        haystack = " ".join((case.summary, *case.metadata.values())).casefold()
        score = sum(1 for token in tokens if token in haystack)
        # 검색어가 있으면 하나도 맞지 않는 사례는 관련 사례로 반환하지 않는다.
        if tokens and score == 0:
            continue
        ranked.append((-score, index, _copy_case(case)))
    ranked.sort(key=lambda item: (item[0], item[1]))
    return tuple(item[2] for item in ranked[: query.limit])


def _tokens(text: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(item.casefold() for item in _TOKEN.findall(text)))


def _surface_kind(surface: Surface) -> str:
    if surface.path_identifier is not None:
        return "path-identified"
    if surface.parameters:
        return "parameterized"
    return "static"


def _generalize_parameter_names(parameters: Sequence[str]) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            name if _SAFE_PARAMETER.fullmatch(name) is not None else "{parameter}"
            for name in parameters
        )
    )


def _generalize_path(url: str) -> str:
    """호스트·query·사용자 값을 제거한 경로 모양만 반환한다."""

    path = unquote(urlsplit(url).path or "/")
    segments = path.split("/")
    generalized: list[str] = []
    for segment in segments:
        if not segment:
            generalized.append("")
        elif _INTEGER_SEGMENT.fullmatch(segment) or _UUID_SEGMENT.fullmatch(segment):
            generalized.append("{id}")
        elif segment.startswith("{") and segment.endswith("}"):
            generalized.append("{id}")
        elif _SAFE_PATH_SEGMENT.fullmatch(segment):
            generalized.append(segment.casefold())
        else:
            generalized.append("{value}")
    value = "/".join(generalized)
    return value if value.startswith("/") else f"/{value}"


def _contains_sensitive_text(value: str) -> bool:
    return bool(
        "://" in value
        or _EMAIL.search(value)
        or _JWT.search(value)
        or _BEARER.search(value)
        or _SECRET_ASSIGNMENT.search(value)
        or _PHONE.search(value)
        or _KOREAN_RRN.search(value)
    )


def _copy_case(case: KnowledgeCase) -> KnowledgeCase:
    return KnowledgeCase(
        case_id=case.case_id,
        category=case.category,
        summary=case.summary,
        provenance_refs=tuple(case.provenance_refs),
        metadata=dict(case.metadata),
    )


def _encode_case(case: KnowledgeCase) -> str:
    return json.dumps(
        asdict(_copy_case(case)),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _decode_case(data: str) -> KnowledgeCase:
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("persisted knowledge case must be a JSON object")
    case = KnowledgeCase(
        case_id=value["case_id"],
        category=value["category"],
        summary=value["summary"],
        provenance_refs=tuple(value["provenance_refs"]),
        metadata=dict(value.get("metadata", {})),
    )
    _validate_case(case)
    return case
