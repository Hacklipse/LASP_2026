"""도메인 객체별 저장소가 제공해야 하는 최소 동작 계약."""

from __future__ import annotations

from typing import Protocol, Sequence

from hacklipse.domain import (
    Candidate,
    Evidence,
    Finding,
    ReportArtifact,
    Run,
    TaskRecord,
)


class RunStore(Protocol):
    """Run의 현재 상태를 생성·갱신·조회하는 저장소 계약."""

    def add(self, run: Run) -> None: ...

    def save(self, run: Run) -> None: ...

    def get(self, run_id: str) -> Run: ...


class TaskStore(Protocol):
    """Task 실행 이력과 시도 상태를 관리하는 저장소 계약."""

    def add(self, task: TaskRecord) -> None: ...

    def save(self, task: TaskRecord) -> None: ...

    def get(self, task_id: str) -> TaskRecord: ...

    def list_by_run(self, run_id: str) -> Sequence[TaskRecord]: ...


class EvidenceStore(Protocol):
    """Evidence를 append-only로 저장하고 Run 범위로 조회하는 계약."""

    def append(self, evidence: Evidence) -> None: ...

    def get(self, run_id: str, evidence_id: str) -> Evidence: ...

    def get_many(self, run_id: str, evidence_ids: Sequence[str]) -> Sequence[Evidence]: ...

    def list_by_run(self, run_id: str) -> Sequence[Evidence]: ...


class CandidateStore(Protocol):
    """검증 전 Candidate의 분석·판정 상태를 관리하는 계약."""

    def add(self, candidate: Candidate) -> None: ...

    def save(self, candidate: Candidate) -> None: ...

    def get(self, run_id: str, candidate_id: str) -> Candidate: ...

    def list_by_run(self, run_id: str) -> Sequence[Candidate]: ...


class FindingStore(Protocol):
    """독립 검증을 통과한 Finding만 저장하는 계약."""

    def add(self, finding: Finding) -> None: ...

    def get(self, run_id: str, finding_id: str) -> Finding: ...

    def list_by_run(self, run_id: str) -> Sequence[Finding]: ...


class ReportStore(Protocol):
    """Run별 보고서 산출물을 저장하고 조회하는 계약."""

    def add(self, report: ReportArtifact) -> None: ...

    def list_by_run(self, run_id: str) -> Sequence[ReportArtifact]: ...
