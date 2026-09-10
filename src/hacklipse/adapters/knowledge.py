"""확정 Finding을 일반화해 저장·검색하는 독립 Knowledge Plane Adapter.

Phase 9-A는 워크플로 배선보다 저장 경계를 먼저 만든다. 이 모듈은 Evidence 원문을
받지 않고, 확정 Finding과 구조화된 Candidate/Surface만 KnowledgeCase로 변환한다.
따라서 과거 대상의 응답 본문이나 인증정보가 현재 Run의 판단 자료로 복사될 경로가 없다.

KnowledgeBase는 append-only다. 같은 패턴의 Case는 하나만 두고, 서로 다른 Run에서
확인된 provenance는 별도 관측으로 추가한다. 같은 관측을 다시 발행하면 거부한다.
과거 사례는 Analysis 참고자료일 뿐이며, 이 Adapter에는 Finding이나 Validation을 만드는
기능이 의도적으로 없다.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from pathlib import Path
from threading import RLock
from urllib.parse import unquote, urlsplit

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


def knowledge_case_id(
    *, category: str, summary: str, metadata: Mapping[str, str]
) -> str:
    """같은 일반화 패턴은 Run이 달라도 같은 case_id를 받는다.

    Run/Finding/Validation ID는 독립 관측의 provenance일 뿐 재사용 지식의 정체성이
    아니다. 일반화된 설명과 metadata를 정규화해 해시하므로 같은 대상을 반복 실행하거나
    서로 다른 대상에서 같은 패턴을 확인해도 검색 가능한 Case는 하나만 남는다.
    """

    seed = json.dumps(
        {
            "category": category.casefold(),
            "summary": summary,
            "metadata": dict(sorted(metadata.items())),
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return "case-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


class KnowledgeCaseFactory:
    """확정 Finding을 비밀 원문 없는 재사용 사례로 일반화한다."""

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
        parameter_names = tuple(sorted(_generalize_parameter_names(surface.parameters)))
        metadata = {
            "parameter_count": str(len(parameter_names)),
            "parameter_names": ",".join(parameter_names),
            "proof_type": proof_type,
            "requires_auth": "true" if surface.requires_auth else "false",
            "severity": finding.severity,
            "surface_kind": surface_kind,
            "surface_method": method,
            "surface_path": _generalize_path(surface.url),
        }
        case = KnowledgeCase(
            case_id=knowledge_case_id(
                category=finding.vulnerability_type,
                summary=summary,
                metadata=metadata,
            ),
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
        self._observations: dict[str, list[tuple[str, ...]]] = {}
        self._lock = RLock()

    def publish(self, case: KnowledgeCase) -> None:
        _validate_case(case)
        with self._lock:
            existing = self._cases.get(case.case_id)
            observation = tuple(case.provenance_refs)
            observations = self._observations.setdefault(case.case_id, [])
            if observation in observations:
                raise DuplicateRecord(case.case_id)
            if existing is not None and not _same_pattern(existing, case):
                raise ValueError("knowledge case_id refers to a different pattern")
            if existing is None:
                # metadata 구현체가 mutable dict여도 발행 뒤 바뀌지 않게 복사한다.
                self._cases[case.case_id] = _copy_case(case)
            observations.append(observation)

    def search(self, query: KnowledgeQuery) -> tuple[KnowledgeCase, ...]:
        _validate_query(query)
        with self._lock:
            cases = tuple(
                _with_observations(case, self._observations.get(case.case_id, ()))
                for case in self._cases.values()
            )
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
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS knowledge_case_observations (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    observation_key TEXT NOT NULL,
                    provenance_data TEXT NOT NULL,
                    UNIQUE(case_id, observation_key)
                )
                """
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_knowledge_observation_case "
                "ON knowledge_case_observations(case_id, seq)"
            )
            # 기존 DB의 Case도 첫 관측으로 등록한다. INSERT OR IGNORE이므로 재개방해도
            # 관측이 중복되지 않고 기존 knowledge_cases 스키마도 그대로 사용할 수 있다.
            for row in self._connection.execute(
                "SELECT case_id, data FROM knowledge_cases ORDER BY seq"
            ).fetchall():
                stored = _decode_case(row["data"])
                self._insert_observation(self._connection, stored, ignore_duplicate=True)
            self._connection.commit()

    def publish(self, case: KnowledgeCase) -> None:
        _validate_case(case)
        with self._lock:
            self._ensure_open()
            try:
                # 같은 패턴을 두 Run이 동시에 처음 발행해도 한쪽의 case_id UNIQUE
                # 충돌로 트랜잭션 전체가 취소되지 않게 한다. canonical Case는 하나만
                # 만들고 각 Run의 provenance 관측은 아래에서 모두 추가한다.
                self._connection.execute(
                    "INSERT OR IGNORE INTO knowledge_cases(case_id, category, data) "
                    "VALUES (?, ?, ?)",
                    (case.case_id, case.category.casefold(), _encode_case(case)),
                )
                row = self._connection.execute(
                    "SELECT data FROM knowledge_cases WHERE case_id = ?", (case.case_id,)
                ).fetchone()
                if row is None:
                    raise RuntimeError("knowledge case insert did not persist")
                if not _same_pattern(_decode_case(row["data"]), case):
                    raise ValueError("knowledge case_id refers to a different pattern")
                self._insert_observation(self._connection, case)
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
            cases = tuple(
                self._case_with_stored_observations(_decode_case(row["data"]))
                for row in rows
            )
        return _search(cases, query)

    @staticmethod
    def _insert_observation(connection, case: KnowledgeCase, *, ignore_duplicate=False) -> None:
        statement = "INSERT OR IGNORE" if ignore_duplicate else "INSERT"
        connection.execute(
            f"{statement} INTO knowledge_case_observations"
            "(case_id, observation_key, provenance_data) VALUES (?, ?, ?)",
            (
                case.case_id,
                _observation_key(case.provenance_refs),
                _encode_provenance(case.provenance_refs),
            ),
        )

    def _case_with_stored_observations(self, case: KnowledgeCase) -> KnowledgeCase:
        rows = self._connection.execute(
            "SELECT provenance_data FROM knowledge_case_observations "
            "WHERE case_id = ? ORDER BY seq",
            (case.case_id,),
        ).fetchall()
        observations = tuple(_decode_provenance(row["provenance_data"]) for row in rows)
        return _with_observations(case, observations)

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


def _same_pattern(left: KnowledgeCase, right: KnowledgeCase) -> bool:
    """provenance를 제외한 재사용 지식의 내용이 같은지 확인한다."""

    return (
        left.category.casefold() == right.category.casefold()
        and left.summary == right.summary
        and dict(left.metadata) == dict(right.metadata)
    )


def _with_observations(
    case: KnowledgeCase, observations: Sequence[Sequence[str]]
) -> KnowledgeCase:
    """append-only 관측을 검색 결과의 provenance로 합쳐 반환한다."""

    groups = tuple(tuple(group) for group in observations) or (case.provenance_refs,)
    provenance = tuple(dict.fromkeys(ref for group in groups for ref in group))
    combined = KnowledgeCase(
        case_id=case.case_id,
        category=case.category,
        summary=case.summary,
        provenance_refs=provenance,
        metadata=dict(case.metadata),
    )
    _validate_case(combined)
    return combined


def _observation_key(provenance_refs: Sequence[str]) -> str:
    normalized = "\0".join(sorted(provenance_refs))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _encode_provenance(provenance_refs: Sequence[str]) -> str:
    return json.dumps(
        list(provenance_refs),
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _decode_provenance(data: str) -> tuple[str, ...]:
    value = json.loads(data)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("persisted knowledge provenance must be a string array")
    return tuple(value)


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
