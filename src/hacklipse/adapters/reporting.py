"""확정 Finding을 사람이 읽을 수 있는 Markdown으로 변환한다."""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from html import escape
from typing import Literal
from uuid import uuid4

from hacklipse.domain import (
    AgentResult, AgentResultStatus, CandidateStatus, Evidence, Finding, ReportArtifact,
    TaskEnvelope,
)
from hacklipse.ports import (
    BudgetManager, CandidateStore, EvidenceStore, FindingStore, RunStore, SurfaceStore,
)
from hacklipse.ports.errors import LlmCredentialsMissing, RecordNotFound

from .llm_report_narrative import ReportNarrative, ReportNarrator, deterministic_fallback
from .report_contract import (
    CONTRACT_VERSION, FindingReportFact, NarratorFingerprintConfig, RunReportFacts,
    finding_fact_id, report_facts_hash, report_input_fingerprint, surface_path_hint,
)


_LOG = logging.getLogger(__name__)


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
    narrative: ReportNarrative | None = None,
) -> str:
    """같은 facts/참조에서 같은 bytes를 생성하는 offline renderer.

    narrative는 맨 아래에만 덧붙는다. narrative=None이면 위 사실 블록과 완전히 같은
    bytes가 나온다 — LLM을 껐을 때와 붙였을 때의 사실이 같은지 비교하는 근거다.
    """

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
    lines.extend(_narrative_lines(facts, narrative))
    return "\n".join(lines).rstrip() + "\n"


def _narrative_lines(
    facts: RunReportFacts, narrative: ReportNarrative | None,
) -> list[str]:
    """LLM 문장은 위 사실을 대체하지 않는다. 항상 비권위적이라고 먼저 밝힌다."""

    if narrative is None:
        return []
    lines = [
        "## 요약 (비권위적)", "",
        "아래 문장은 위 사실 블록을 LLM이 요약한 것입니다. 판정·증명·심각도의 근거가 아니며,",
        "위 사실과 다르면 위 사실이 우선합니다.", "",
        f"- 생성 상태: `{narrative.status}`",
        f"- 출처: `{narrative.source}`", "",
    ]
    if narrative.source != "llm":
        lines.extend([narrative.run_summary, ""])
        return lines
    if narrative.run_summary:
        lines.extend([narrative.run_summary, ""])
    labels = {fact.finding_id: fact.vulnerability_type for fact in facts.findings}
    for finding_id, summary in narrative.finding_summaries:
        lines.extend([f"### {labels[finding_id]} — 요약", "", summary, ""])
    if narrative.rejected:
        lines.append(f"검증을 통과하지 못해 제외한 문장: {len(narrative.rejected)}개.")
    return lines


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
        narrator: ReportNarrator | None = None,
        narrator_config: NarratorFingerprintConfig | None = None,
    ) -> None:
        if format_version not in ("v1", "v2"):
            raise ValueError("unsupported report format version")
        if narrator is not None and format_version != "v2":
            # v1에는 사실 블록이 없어서 요약이 무엇을 근거로 했는지 보일 수 없다.
            raise ValueError("report narrator requires format v2")
        if (narrator is None) != (narrator_config is None):
            raise ValueError("report narrator and fingerprint config must be provided together")
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
        self._narrator = narrator
        self._narrator_config = narrator_config

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

        report_id = f"report-{self._id_factory()}"
        new_evidence_ids: tuple[str, ...] = ()
        findings = self._load_findings(task)
        if self._format_version == "v2":
            facts = self._collect_facts(task, findings)
            narrative = self._narrate(facts)
            content = render_report_v2(
                facts,
                references=tuple(
                    FindingReportReferences(
                        finding_id=f.finding_id, surface_id=f.surface_id,
                        validation_id=f.validation_id, evidence_ids=f.evidence_ids,
                    ) for f in findings
                ),
                narrative=narrative,
            )
            if narrative is not None:
                claim_id = self._record_narrative(
                    task, report_id=report_id, facts=facts, narrative=narrative,
                )
                if claim_id is not None:
                    new_evidence_ids = (claim_id,)
        else:
            content = self._render_v1(task, findings)
        report = ReportArtifact(
            report_id=report_id,
            run_id=task.run_id,
            format="markdown",
            content=content,
        )
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=new_evidence_ids,
            reports=(report,),
        )

    def _record_narrative(
        self,
        task: TaskEnvelope,
        *,
        report_id: str,
        facts: RunReportFacts,
        narrative: ReportNarrative,
    ) -> str | None:
        """본문 없이 Narrator 선택·비용 trace만 Claim으로 남긴다."""

        assert self._narrator_config is not None
        claim = Evidence(
            evidence_id=f"{report_id}-narrative",
            run_id=task.run_id,
            surface_id=None,
            source_task_id=task.task_id,
            created_by="llm_report_narrator",
            evidence_type="claim",
            observation={
                "type": "llm_report_narrative",
                "contract_version": CONTRACT_VERSION,
                "input_fingerprint": report_input_fingerprint(
                    facts, self._narrator_config,
                ),
                "offered_finding_ids": [item.finding_id for item in facts.findings],
                "offered_fact_ids": list(facts.fact_ids),
                "accepted_fact_ids": list(narrative.accepted_fact_ids),
                "rejected": [
                    {"index": index, "reason": reason}
                    for index, reason in narrative.rejected
                ],
                "selection_source": narrative.source,
                "status": narrative.status,
                "llm_calls": narrative.llm_calls,
                "usage": {
                    "input_tokens": narrative.usage.input_tokens,
                    "output_tokens": narrative.usage.output_tokens,
                    "cache_read_input_tokens": narrative.usage.cache_read_input_tokens,
                    "cache_creation_input_tokens": narrative.usage.cache_creation_input_tokens,
                },
                "usage_available": narrative.usage_available,
                "model": narrative.model,
                "elapsed_ms": narrative.elapsed_ms,
            },
        )
        try:
            self._evidence.append(claim)
        except Exception as error:  # noqa: BLE001 - 보고서는 Claim 저장 실패와 무관하게 생성한다
            _LOG.warning(
                "report narrative claim storage failed: %s", type(error).__name__,
            )
            return None
        return claim.evidence_id

    def _narrate(self, facts: RunReportFacts) -> ReportNarrative | None:
        """Narrator가 어떻게 실패하든 v2 보고서 자체는 반드시 생성한다."""

        if self._narrator is None:
            return None
        try:
            return self._narrator.narrate(facts)
        except LlmCredentialsMissing:
            # 배선 실수는 숨기지 않는다. 켠 줄 알고 결정적 보고서를 받는 편이 더 나쁘다.
            raise
        except Exception:  # noqa: BLE001 - Report 실패는 Run 전체를 FAILED로 만든다
            _LOG.warning("report narrator internal fallback")
            return deterministic_fallback("internal_error")

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
