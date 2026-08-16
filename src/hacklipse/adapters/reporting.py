"""확정 Finding을 사람이 읽을 수 있는 Markdown으로 변환한다."""

from __future__ import annotations

from collections.abc import Callable
from uuid import uuid4

from hacklipse.domain import AgentResult, AgentResultStatus, ReportArtifact, TaskEnvelope
from hacklipse.ports import EvidenceStore, FindingStore


class MarkdownReportAgent:
    """판정 변경이나 외부 요청 없이 confirmed Finding만 렌더링한다."""

    def __init__(
        self,
        *,
        finding_store: FindingStore,
        evidence_store: EvidenceStore,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._findings = finding_store
        self._evidence = evidence_store
        self._id_factory = id_factory or (lambda: str(uuid4()))

    def handle(self, task: TaskEnvelope) -> AgentResult:
        """Task에 지정된 Finding을 조회해 하나의 Markdown 산출물을 만든다."""

        # Report Agent는 Candidate를 다시 판단하지 않고 Finding Store만 읽는다.
        findings = [
            self._findings.get(task.run_id, finding_id) for finding_id in task.finding_ids
        ]
        lines = ["# Security assessment report", "", f"Run: `{task.run_id}`", ""]
        if not findings:
            lines.append("No confirmed findings were produced.")
        for finding in findings:
            # 보고 전에 Finding이 참조하는 Evidence가 실제 Run에 존재하는지 확인한다.
            self._evidence.get_many(task.run_id, finding.evidence_ids)
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
        report = ReportArtifact(
            report_id=f"report-{self._id_factory()}",
            run_id=task.run_id,
            format="markdown",
            content="\n".join(lines).rstrip() + "\n",
        )
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            reports=(report,),
        )
