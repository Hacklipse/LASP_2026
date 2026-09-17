"""확정 Finding을 사람이 읽을 수 있는 Markdown으로 변환한다."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from html import escape
from typing import Literal
from uuid import uuid4

from hacklipse.domain import (
    AgentResult, AgentResultStatus, CandidateStatus, Finding, ReportArtifact, TaskEnvelope,
)
from hacklipse.ports import (
    BudgetManager, CandidateStore, EvidenceStore, FindingStore, RunStore, SurfaceStore,
)
from hacklipse.ports.errors import RecordNotFound

from .report_contract import (
    CONTRACT_VERSION, FindingReportFact, RunReportFacts, finding_fact_id,
    report_facts_hash, surface_path_hint,
)


@dataclass(frozen=True, slots=True)
class FindingReportReferences:
    """보고서에만 표시하는 추적 ID. Narrator facts에는 포함하지 않는다."""

    finding_id: str
    surface_id: str
    validation_id: str
    evidence_ids: tuple[str, ...]


def _code(value: str) -> str:
    # 내부 참조 ID도 Markdown/HTML 구조를 삽입하지 못하게 표시한다.
    text = escape(value, quote=True).replace("`", "&#96;")
    text = "".join(character if character.isprintable() else " " for character in text)
    return f"`{text}`"


def render_report_v2(
    facts: RunReportFacts, *, references: tuple[FindingReportReferences, ...] = (),
) -> str:
    """같은 facts/참조에서 같은 bytes를 생성하는 offline renderer."""

    by_id = {reference.finding_id: reference for reference in references}
    if len(by_id) != len(references) or not set(by_id) <= {f.finding_id for f in facts.findings}:
        raise ValueError("report references must belong to unique offered findings")
    counts = dict(facts.candidate_counts)
    number = lambda value: "정보 없음" if value is None else str(value)
    lines = [
        "# Security assessment report (v2)", "",
        f"Run: {_code(facts.run_id)}", "",
        "- 보고서 버전: `v2`",
        f"- Facts 계약: `{CONTRACT_VERSION}`",
        f"- Facts SHA-256: `{report_facts_hash(facts)}`", "",
        "## 검사 범위 및 요청 예산", "",
        f"- 발견 Surface: {number(facts.surface_count)}",
        f"- 발견 파라미터 수 (Surface별 중복 제거): {number(facts.parameter_count)}",
        f"- 전체 Candidate: {sum(counts.values())}",
        f"- 확정 Finding: {len(facts.findings)}",
        f"- 총 요청 예산: {number(facts.request_budget_total)}",
        f"- 사용 요청 예산: {number(facts.request_budget_used)}", "",
        "발견된 범위의 집계이며, 대상 전체를 빠짐없이 검사했다는 의미는 아닙니다.", "",
        "## Candidate 상태", "",
        "| 상태 | 개수 |", "|---|---:|",
        *(f"| {status.value} | {count} |" for status, count in facts.candidate_counts), "",
    ]
    if not facts.findings:
        lines.append("확정 Finding이 없습니다.")
    if counts[CandidateStatus.SKIPPED_BUDGET]:
        lines.append(f"예산 부족으로 검사를 완료하지 못한 Candidate: {counts[CandidateStatus.SKIPPED_BUDGET]}개.")
    explanations = (
        (CandidateStatus.ROUTED, "분석 대기"),
        (CandidateStatus.ANALYZED, "독립 검증 대기"),
        (CandidateStatus.SUSPECTED, "의심 상태이며 미확정"),
        (CandidateStatus.REJECTED, "검증에서 기각"),
        (CandidateStatus.BLOCKED, "검증 차단"),
        (CandidateStatus.FAILED, "검사 실패"),
    )
    for status, explanation in explanations:
        if counts[status]:
            lines.append(f"- {explanation}: {counts[status]}개")
    lines.extend(["", "## 확정 Finding", ""])
    if not facts.findings:
        lines.append("해당 없음.")
    for finding in facts.findings:
        lines.extend([
            f"### {finding.vulnerability_type}", "",
            f"- Finding: {_code(finding.finding_id)}",
            f"- Fact: {_code(finding.fact_id)}",
            f"- 경로 (일반화): {_code(finding.surface_path_hint)}",
            f"- 검증: {finding.proof_description}",
        ])
        if finding.proof_type is not None:
            lines.extend([
                f"- Proof type: `{finding.proof_type.value}`",
                f"- 재현 횟수: {finding.reproduction_count}",
            ])
        else:
            lines.append("- 재현 횟수: 정보 없음")
        reference = by_id.get(finding.finding_id)
        if reference is not None:
            lines.extend([
                f"- Surface: {_code(reference.surface_id)}",
                f"- Validation: {_code(reference.validation_id)}",
                f"- Evidence: {', '.join(_code(item) for item in sorted(set(reference.evidence_ids)))}",
            ])
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


class MarkdownReportAgent:
    """판정 변경이나 외부 요청 없이 confirmed Finding만 렌더링한다."""

    def __init__(
        self,
        *,
        finding_store: FindingStore,
        evidence_store: EvidenceStore,
        id_factory: Callable[[], str] | None = None,
        format_version: Literal["v1", "v2"] = "v1",
        candidate_store: CandidateStore | None = None,
        surface_store: SurfaceStore | None = None,
        run_store: RunStore | None = None,
        budget_manager: BudgetManager | None = None,
    ) -> None:
        if format_version not in ("v1", "v2"):
            raise ValueError("unsupported report format version")
        if format_version == "v2" and any(
            store is None for store in (candidate_store, surface_store, run_store)
        ):
            raise ValueError("report v2 requires candidate, surface and run stores")
        self._findings = finding_store
        self._evidence = evidence_store
        self._id_factory = id_factory or (lambda: str(uuid4()))
        self._format_version = format_version
        self._candidates = candidate_store
        self._surfaces = surface_store
        self._runs = run_store
        self._budget = budget_manager

    def collect_facts(self, task: TaskEnvelope) -> RunReportFacts:
        """Store 사실을 수집한다. Evidence 본문은 facts로 복사하지 않는다."""
        return self._collect_facts(task, self._load_findings(task))

    def _load_findings(self, task: TaskEnvelope) -> list[Finding]:
        findings = [self._findings.get(task.run_id, item) for item in task.finding_ids]
        for finding in findings:
            self._evidence.get_many(task.run_id, finding.evidence_ids)
        return findings

    def _collect_facts(self, task: TaskEnvelope, findings: Sequence[Finding]) -> RunReportFacts:
        if self._candidates is None or self._surfaces is None or self._runs is None:
            raise ValueError("collecting report facts requires candidate, surface and run stores")
        run = self._runs.get(task.run_id)
        surfaces = self._surfaces.list_by_run(task.run_id)
        counts = Counter(candidate.status for candidate in self._candidates.list_by_run(task.run_id))
        used = None
        if self._budget is not None:
            try:
                # Report Task의 request_budget=0은 실행 사용량이 아니다.
                used = run.request_budget - self._budget.remaining(task.run_id)
            except RecordNotFound:
                # 예전 Run에 계측 기록이 없으면 0으로 추정하지 않는다.
                pass
        return RunReportFacts(
            run_id=task.run_id,
            format_version="v2",
            candidate_counts=tuple((status, counts[status]) for status in CandidateStatus),
            findings=tuple(
                FindingReportFact(
                    fact_id=finding_fact_id(finding.finding_id),
                    finding_id=finding.finding_id,
                    vulnerability_type=finding.vulnerability_type,
                    surface_path_hint=surface_path_hint(
                        self._surfaces.get(task.run_id, finding.surface_id).url
                    ),
                    proof_type=finding.proof_type,
                    reproduction_count=finding.reproduction_count,
                )
                for finding in findings
            ),
            request_budget_total=run.request_budget,
            request_budget_used=used,
            surface_count=len(surfaces),
            parameter_count=sum(len(set(surface.parameters)) for surface in surfaces),
        )

    def handle(self, task: TaskEnvelope) -> AgentResult:
        """Task에 지정된 Finding을 조회해 하나의 Markdown 산출물을 만든다."""

        findings = self._load_findings(task)
        if self._format_version == "v2":
            content = render_report_v2(
                self._collect_facts(task, findings),
                references=tuple(
                    FindingReportReferences(
                        finding_id=f.finding_id, surface_id=f.surface_id,
                        validation_id=f.validation_id, evidence_ids=f.evidence_ids,
                    ) for f in findings
                ),
            )
        else:
            content = self._render_v1(task, findings)
        report = ReportArtifact(
            report_id=f"report-{self._id_factory()}",
            run_id=task.run_id,
            format="markdown",
            content=content,
        )
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            reports=(report,),
        )

    @staticmethod
    def _render_v1(task: TaskEnvelope, findings: Sequence[Finding]) -> str:
        """기존 v1 본문과 순서/개행을 그대로 유지한다."""
        lines = ["# Security assessment report", "", f"Run: `{task.run_id}`", ""]
        if not findings:
            lines.append("No confirmed findings were produced.")
        for finding in findings:
            lines.extend(
                [
                    f"## {finding.vulnerability_type} ({finding.severity})",
                    "",
                    f"- Finding: `{finding.finding_id}`",
                    f"- Surface: `{finding.surface_id}`",
                    f"- Validation: `{finding.validation_id}`",
                    f"- Evidence: {', '.join(f'`{item}`' for item in finding.evidence_ids)}",
                    "",
                ]
            )
        return "\n".join(lines).rstrip() + "\n"
