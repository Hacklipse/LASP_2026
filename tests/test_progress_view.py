"""진행 화면이 상태를 정확히 접고 터미널 환경에 맞게 출력하는지 검증한다.

화면의 안전성은 이벤트 계층이 책임진다. 여기서 확인하는 것은 "무엇이 일어나는지가
읽히는가"와 "TTY가 아닌 곳에서 출력이 깨지지 않는가"다.
"""

from __future__ import annotations

import io
import unittest

from hacklipse.domain import ProgressEvent, ProgressEventKind
from scripts.progress_view import RunProgressView


def _view(tty: bool) -> tuple[RunProgressView, io.StringIO]:
    stream = io.StringIO()
    return RunProgressView(stream=stream, tty=tty), stream


class _Emitter:
    def __init__(self, view: RunProgressView) -> None:
        self._view = view
        self._sequence = 0

    def __call__(self, kind: ProgressEventKind, **changes) -> None:
        self._sequence += 1
        self._view.emit(
            ProgressEvent(
                run_id="run-1",
                sequence=self._sequence,
                kind=kind,
                phase=changes.pop("phase", "analyze"),
                budget_total=changes.pop("budget_total", 30),
                **changes,
            )
        )


class ProgressFoldingTests(unittest.TestCase):
    """이벤트를 접어 만든 상태가 실제 진행을 설명해야 한다."""

    def test_analysis_done_is_not_shown_as_waiting(self) -> None:
        """분석만 끝난 상태를 대기로 적으면 아무것도 안 한 것처럼 보인다."""

        view, stream = _view(tty=False)
        emit = _Emitter(view)
        emit(ProgressEventKind.CANDIDATE_QUEUED, phase="route", vulnerability_type="SQLi")
        emit(
            ProgressEventKind.AGENT_STARTED,
            vulnerability_type="SQLi",
            surface_path="/rest/products/search",
        )
        # 분석 완료에는 verdict 가 실리지 않는다. 검증 완료에만 실린다.
        emit(ProgressEventKind.AGENT_COMPLETED, vulnerability_type="SQLi")

        # 등록 직후의 "대기"는 맞다. 분석이 끝난 뒤의 줄이 그대로면 안 된다.
        last = stream.getvalue().strip().splitlines()[-1]
        self.assertIn("검증 대기", last)
        self.assertNotIn("SQLi 대기", last)

    def test_validation_verdict_completes_the_type(self) -> None:
        view, stream = _view(tty=False)
        emit = _Emitter(view)
        emit(ProgressEventKind.CANDIDATE_QUEUED, phase="route", vulnerability_type="SQLi")
        emit(ProgressEventKind.AGENT_STARTED, vulnerability_type="SQLi")
        emit(ProgressEventKind.AGENT_COMPLETED, vulnerability_type="SQLi")
        emit(
            ProgressEventKind.FINDING_CREATED, phase="validate", vulnerability_type="SQLi"
        )
        emit(
            ProgressEventKind.AGENT_COMPLETED,
            phase="validate",
            vulnerability_type="SQLi",
            detail="confirmed",
        )

        view.close(surfaces=45, parameters=2)
        output = stream.getvalue()

        self.assertIn("완료 (Finding 1)", output)
        self.assertIn("Surface 45", output)

    def test_budget_skip_is_shown_as_interrupted_not_finished(self) -> None:
        """검사하지 못한 것을 완료로 보여주면 검사 범위를 오해한다."""

        view, stream = _view(tty=False)
        emit = _Emitter(view)
        emit(ProgressEventKind.CANDIDATE_QUEUED, phase="route", vulnerability_type="XSS")
        emit(
            ProgressEventKind.CANDIDATE_SKIPPED,
            phase="validate",
            vulnerability_type="XSS",
            detail="budget",
        )
        view.close()

        output = stream.getvalue()
        self.assertIn("중단 (예산 부족)", output)
        self.assertNotIn("XSS       완료", output)


class TerminalCompatibilityTests(unittest.TestCase):
    """TTY 와 non-TTY 에서 출력이 서로 다르게, 그러나 둘 다 온전해야 한다."""

    def test_non_tty_appends_one_line_per_event(self) -> None:
        """CI 나 파일 redirect 에서는 화면 갱신 제어문자를 쓰면 안 된다."""

        view, stream = _view(tty=False)
        emit = _Emitter(view)
        emit(ProgressEventKind.RUN_STARTED, phase="init")
        emit(ProgressEventKind.PHASE_CHANGED, phase="recon")
        emit(ProgressEventKind.CANDIDATE_QUEUED, phase="route", vulnerability_type="SQLi")

        output = stream.getvalue()
        self.assertNotIn("\033[", output)
        self.assertEqual(len(output.strip().splitlines()), 3)

    def test_tty_redraws_the_same_block(self) -> None:
        view, stream = _view(tty=True)
        emit = _Emitter(view)
        emit(ProgressEventKind.RUN_STARTED, phase="init")
        first = stream.getvalue()
        emit(ProgressEventKind.PHASE_CHANGED, phase="recon")

        # 두 번째 출력은 앞서 그린 줄 수만큼 커서를 올리고 지운 뒤 다시 그린다.
        redrawn = stream.getvalue()[len(first) :]
        self.assertTrue(redrawn.startswith("\033["))
        self.assertIn("A\033[J", redrawn)

    def test_evidence_collection_is_quiet_in_the_append_log(self) -> None:
        """증적 수집은 요청마다 발생한다. 로그를 뒤덮으면 흐름이 안 보인다."""

        view, stream = _view(tty=False)
        emit = _Emitter(view)
        emit(ProgressEventKind.CANDIDATE_QUEUED, phase="route", vulnerability_type="SQLi")
        before = stream.getvalue()
        emit(
            ProgressEventKind.EVIDENCE_COLLECTED,
            vulnerability_type="SQLi",
            surface_path="/rest/products/search",
        )

        self.assertEqual(stream.getvalue(), before)

    def test_close_is_idempotent(self) -> None:
        view, stream = _view(tty=False)
        view.close(surfaces=3, parameters=1)
        once = stream.getvalue()
        view.close(surfaces=3, parameters=1)

        self.assertEqual(stream.getvalue(), once)


if __name__ == "__main__":
    unittest.main()
