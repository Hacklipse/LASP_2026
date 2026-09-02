"""진행 이벤트를 터미널 화면으로 그린다.

두 실행기가 같은 화면을 쓴다. 표시 규칙은 여기에만 두고 Domain·Application 에는
넣지 않는다. 같은 이벤트를 나중에 웹 UI 가 다르게 그릴 수 있어야 한다.

터미널 호환성
    TTY         같은 블록을 지우고 다시 그린다
    non-TTY     한 줄씩 덧붙인다 (CI, 파일 redirect, 파이프)

`--debug` 와 함께 쓰지 않는다. 상세 로그가 중간에 끼면 다시 그리기가 화면을 망가뜨린다.
실행기가 둘 중 하나만 선택해 붙인다.

색을 쓰지 않는다. 기호만으로는 구분이 안 되는 환경이 있어 기호와 한국어 상태를 함께
적는다.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from hacklipse.domain import ProgressEvent, ProgressEventKind

# 기호는 보조 표시다. 옆의 낱말이 같은 정보를 담는다.
_WAITING = "·"
_RUNNING = "▶"
_DONE = "✓"
_BROKEN = "✗"

_PHASE_LABELS = {
    "init": "준비",
    "recon": "탐색",
    "route": "분류",
    "analyze": "분석",
    "validate": "검증",
    "report": "보고",
    "done": "완료",
    "failed": "실패",
}


@dataclass
class _TypeState:
    """취약점 유형 하나의 진행 상태."""

    candidates: int = 0
    running: int = 0
    analyzed: int = 0
    validated: int = 0
    findings: int = 0
    unchecked: int = 0
    surface: str | None = None
    note: str | None = None

    def mark(self) -> str:
        if self.validated and self.validated >= self.candidates:
            return _DONE
        if self.unchecked:
            return _BROKEN
        if self.running:
            return _RUNNING
        return _WAITING

    def label(self) -> str:
        """분석과 검증을 구분해서 보여준다.

        분석만 끝난 상태를 "대기"로 적으면 아무것도 안 한 것처럼 보인다. 실제로는
        요청을 보내고 신호까지 남긴 뒤 독립 검증을 기다리는 중이다.
        """

        if self.validated and self.validated >= self.candidates:
            return "완료" if not self.findings else f"완료 (Finding {self.findings})"
        if self.unchecked:
            return f"중단 ({self.note})" if self.note else "중단"
        if self.running:
            return f"검사 중 {self.surface}" if self.surface else "검사 중"
        if self.analyzed:
            return "검증 대기"
        return "대기"


class RunProgressView:
    """ProgressEvent 를 접어 실행 중 화면을 만든다.

    Orchestrator 에 ProgressSink 로 꽂힌다. 이벤트에는 이미 민감정보가 제거돼 있으므로
    여기서는 다시 거르지 않는다. 거꾸로 말하면 이 화면의 안전성은 이벤트 계층이 책임진다.
    """

    def __init__(self, *, stream=None, tty: bool | None = None) -> None:
        self._stream = stream if stream is not None else sys.stdout
        if tty is None:
            tty = bool(getattr(self._stream, "isatty", lambda: False)())
        self._tty = tty
        self._lines_drawn = 0
        self._phase = "init"
        self._types: dict[str, _TypeState] = {}
        self._surfaces = 0
        self._parameters = 0
        self._budget_used = 0
        self._budget_total = 0
        self._closed = False

    # --- ProgressSink ---
    def emit(self, event: ProgressEvent) -> None:
        self._fold(event)
        if self._tty:
            self._draw()
        else:
            # append-only 에서는 매 이벤트마다 전체 상태를 반복하지 않는다. 로그가
            # 뒤덮여 무엇이 바뀌었는지 읽을 수 없다. 바뀐 것만 한 줄로 남긴다.
            line = self._event_line(event)
            if line:
                self._write(line)

    def close(self, *, surfaces: int = 0, parameters: int = 0) -> None:
        """Run 이 끝난 뒤 마지막 화면을 확정한다.

        Surface 수는 이벤트에 실리지 않으므로 완료 후 스냅샷 값을 받아 채운다.
        """

        if self._closed:
            return
        self._surfaces = surfaces or self._surfaces
        self._parameters = parameters or self._parameters
        # 마지막 화면은 두 방식 모두 전체 블록으로 한 번 남긴다.
        self._draw()
        self._stream.write("\n")
        self._closed = True

    # --- 상태 접기 ---
    def _fold(self, event: ProgressEvent) -> None:
        self._phase = event.phase
        self._budget_used = event.budget_used
        self._budget_total = event.budget_total
        name = event.vulnerability_type
        if name is None:
            return
        state = self._types.setdefault(name, _TypeState())
        kind = event.kind

        if kind is ProgressEventKind.CANDIDATE_QUEUED:
            state.candidates += 1
        elif kind is ProgressEventKind.AGENT_STARTED:
            state.running += 1
            state.surface = event.surface_path or state.surface
        elif kind is ProgressEventKind.EVIDENCE_COLLECTED:
            state.surface = event.surface_path or state.surface
        elif kind is ProgressEventKind.AGENT_COMPLETED:
            state.running = max(0, state.running - 1)
            # 분석과 검증이 각각 완료를 알린다. 검증 완료에는 verdict가 실린다.
            if event.detail:
                state.validated += 1
            else:
                state.analyzed += 1
        elif kind is ProgressEventKind.FINDING_CREATED:
            state.findings += 1
        elif kind in (
            ProgressEventKind.CANDIDATE_FAILED,
            ProgressEventKind.CANDIDATE_SKIPPED,
        ):
            state.running = max(0, state.running - 1)
            state.unchecked += 1
            state.note = "예산 부족" if kind is ProgressEventKind.CANDIDATE_SKIPPED else event.detail

    # --- 그리기 ---
    def _render(self) -> list[str]:
        phase = _PHASE_LABELS.get(self._phase, self._phase)
        lines = [f"[진행] {phase}"]
        recon_mark = _DONE if self._phase not in ("init", "recon") else _RUNNING
        detail = (
            f"Surface {self._surfaces} · 파라미터 {self._parameters}"
            if self._surfaces
            else "수집 중"
        )
        lines.append(f"  {recon_mark} 탐색      {detail}")
        for name in sorted(self._types):
            state = self._types[name]
            lines.append(
                f"  {state.mark()} {name:<9} {state.label():<40}"
                f" Candidate {state.candidates}"
            )
        validated = sum(item.validated for item in self._types.values())
        total = sum(item.candidates for item in self._types.values())
        findings = sum(item.findings for item in self._types.values())
        lines.append(f"  {_WAITING} 검증      {validated} / {total}")
        lines.append(f"  {_WAITING} Finding   {findings}")
        lines.append(f"  {_WAITING} 예산      {self._budget_used} / {self._budget_total}")
        return lines

    _QUIET_KINDS = frozenset({ProgressEventKind.EVIDENCE_COLLECTED})

    def _event_line(self, event: ProgressEvent) -> str | None:
        """append-only 로그에 남길 한 줄. 조용한 종류는 건너뛴다."""

        if event.kind in self._QUIET_KINDS:
            return None
        phase = _PHASE_LABELS.get(event.phase, event.phase)
        parts = [f"[{phase}]"]
        if event.vulnerability_type:
            state = self._types.get(event.vulnerability_type, _TypeState())
            parts.append(f"{event.vulnerability_type} {state.label()}")
        else:
            parts.append(event.kind.value)
        parts.append(f"예산 {event.budget_used}/{event.budget_total}")
        return " ".join(parts)

    def _write(self, text: str) -> None:
        self._stream.write(text + "\n")
        flush = getattr(self._stream, "flush", None)
        if flush:
            flush()

    def _draw(self) -> None:
        lines = self._render()
        if self._tty and self._lines_drawn:
            # 앞서 그린 블록만 지운다. 그 위의 출력은 건드리지 않는다.
            self._stream.write(f"\033[{self._lines_drawn}A\033[J")
        self._stream.write("\n".join(lines) + "\n")
        if self._tty:
            self._lines_drawn = len(lines)
        flush = getattr(self._stream, "flush", None)
        if flush:
            flush()
