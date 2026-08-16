"""개발·테스트용 메모리 저장소 Adapter 모음."""

from __future__ import annotations

from collections.abc import Sequence
from copy import deepcopy
from dataclasses import dataclass, field

from hacklipse.domain import Candidate, Evidence, Finding, ReportArtifact, Run, TaskRecord
from hacklipse.ports.errors import DuplicateRecord, RecordNotFound


class InMemoryRunStore:
    """Run 상태를 프로세스 메모리에 보관한다."""

    def __init__(self) -> None:
        self._items: dict[str, Run] = {}

    def add(self, run: Run) -> None:
        _add(self._items, run.run_id, run)

    def save(self, run: Run) -> None:
        _save(self._items, run.run_id, run)

    def get(self, run_id: str) -> Run:
        return _get(self._items, run_id)


class InMemoryTaskStore:
    """Task 생명주기와 시도 이력을 입력 순서대로 보관한다."""

    def __init__(self) -> None:
        self._items: dict[str, TaskRecord] = {}

    def add(self, task: TaskRecord) -> None:
        _add(self._items, task.envelope.task_id, task)

    def save(self, task: TaskRecord) -> None:
        _save(self._items, task.envelope.task_id, task)

    def get(self, task_id: str) -> TaskRecord:
        return _get(self._items, task_id)

    def list_by_run(self, run_id: str) -> tuple[TaskRecord, ...]:
        """특정 Run에 속한 Task만 등록 순서대로 반환한다."""

        return tuple(
            deepcopy(item) for item in self._items.values() if item.envelope.run_id == run_id
        )


class InMemoryEvidenceStore:
    """Evidence를 덮어쓰지 않고 추가하며 Run 범위로만 읽게 한다."""

    def __init__(self) -> None:
        self._items: dict[str, Evidence] = {}

    def append(self, evidence: Evidence) -> None:
        """새 Evidence ID만 추가하고 기존 Evidence 수정은 허용하지 않는다."""

        _add(self._items, evidence.evidence_id, evidence)

    def get(self, run_id: str, evidence_id: str) -> Evidence:
        """Evidence가 요청한 Run에 속할 때만 반환한다."""

        evidence = _get(self._items, evidence_id)
        if evidence.run_id != run_id:
            raise RecordNotFound(f"evidence not found in run {run_id}: {evidence_id}")
        return evidence

    def get_many(self, run_id: str, evidence_ids: Sequence[str]) -> tuple[Evidence, ...]:
        return tuple(self.get(run_id, evidence_id) for evidence_id in evidence_ids)

    def list_by_run(self, run_id: str) -> tuple[Evidence, ...]:
        return tuple(deepcopy(item) for item in self._items.values() if item.run_id == run_id)


class InMemoryCandidateStore:
    """Candidate의 분석·검증 진행 상태를 메모리에 보관한다."""

    def __init__(self) -> None:
        self._items: dict[str, Candidate] = {}

    def add(self, candidate: Candidate) -> None:
        _add(self._items, candidate.candidate_id, candidate)

    def save(self, candidate: Candidate) -> None:
        current = self._items.get(candidate.candidate_id)
        if current is not None and current.run_id != candidate.run_id:
            raise RecordNotFound(candidate.candidate_id)
        _save(self._items, candidate.candidate_id, candidate)

    def get(self, run_id: str, candidate_id: str) -> Candidate:
        candidate = _get(self._items, candidate_id)
        if candidate.run_id != run_id:
            raise RecordNotFound(f"candidate not found in run {run_id}: {candidate_id}")
        return candidate

    def list_by_run(self, run_id: str) -> tuple[Candidate, ...]:
        return tuple(deepcopy(item) for item in self._items.values() if item.run_id == run_id)


class InMemoryFindingStore:
    """confirmed 상태의 Finding만 보관하는 메모리 저장소."""

    def __init__(self) -> None:
        self._items: dict[str, Finding] = {}

    def add(self, finding: Finding) -> None:
        # Adapter에서도 confirmed 조건을 재검사해 잘못된 직접 저장을 방지한다.
        if finding.status != "confirmed":
            raise ValueError("finding store accepts confirmed findings only")
        _add(self._items, finding.finding_id, finding)

    def get(self, run_id: str, finding_id: str) -> Finding:
        finding = _get(self._items, finding_id)
        if finding.run_id != run_id:
            raise RecordNotFound(f"finding not found in run {run_id}: {finding_id}")
        return finding

    def list_by_run(self, run_id: str) -> tuple[Finding, ...]:
        return tuple(deepcopy(item) for item in self._items.values() if item.run_id == run_id)


class InMemoryReportStore:
    """Run별 ReportArtifact를 메모리에 보관한다."""

    def __init__(self) -> None:
        self._items: dict[str, ReportArtifact] = {}

    def add(self, report: ReportArtifact) -> None:
        _add(self._items, report.report_id, report)

    def list_by_run(self, run_id: str) -> tuple[ReportArtifact, ...]:
        return tuple(deepcopy(item) for item in self._items.values() if item.run_id == run_id)


@dataclass(slots=True)
class MemoryStoreBundle:
    """로컬 조립 시 필요한 개별 메모리 저장소를 한 묶음으로 제공한다."""

    runs: InMemoryRunStore = field(default_factory=InMemoryRunStore)
    tasks: InMemoryTaskStore = field(default_factory=InMemoryTaskStore)
    evidence: InMemoryEvidenceStore = field(default_factory=InMemoryEvidenceStore)
    candidates: InMemoryCandidateStore = field(default_factory=InMemoryCandidateStore)
    findings: InMemoryFindingStore = field(default_factory=InMemoryFindingStore)
    reports: InMemoryReportStore = field(default_factory=InMemoryReportStore)


def _add(items: dict[str, object], key: str, value: object) -> None:
    """중복 ID를 거부하고 외부 변경을 막기 위해 복사본을 저장한다."""

    if key in items:
        raise DuplicateRecord(key)
    items[key] = deepcopy(value)


def _save(items: dict[str, object], key: str, value: object) -> None:
    """기존 레코드만 복사본으로 갱신한다."""

    if key not in items:
        raise RecordNotFound(key)
    items[key] = deepcopy(value)


def _get(items: dict[str, object], key: str):
    """저장된 객체가 호출자에게서 변경되지 않도록 복사본을 반환한다."""

    try:
        return deepcopy(items[key])
    except KeyError as error:
        raise RecordNotFound(key) from error
