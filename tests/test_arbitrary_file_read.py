"""경로를 그대로 여는 표면에서 고정 절대 경로 파일 읽기를 증명하는지 검증한다."""

from __future__ import annotations

import unittest

from hacklipse.adapters.arbitrary_file_read import (
    ARBITRARY_FILE_READ_OBSERVATION,
    ARBITRARY_FILE_READ_PROBE_PATH,
    ARBITRARY_FILE_READ_PROOF_MARKERS,
    ARBITRARY_FILE_READ_TOOL,
    arbitrary_file_read_signal,
    build_arbitrary_file_read_requests,
    looks_like_file_parameter,
    validate_arbitrary_file_read_request,
)
from hacklipse.domain import (
    ARBITRARY_FILE_READ_SAFE_PROBE_PATH,
    Evidence,
    ExecutionRequest,
    HttpRequestKind,
    Surface,
)


def _surface(url: str = "http://localhost/view", parameters=("file",)) -> Surface:
    return Surface(
        surface_id="surface-1", run_id="run-1", url=url,
        method="GET", parameters=parameters,
    )


def _response(evidence_id: str, body: str, status: int = 200) -> Evidence:
    return Evidence(
        evidence_id=evidence_id, run_id="run-1", surface_id="surface-1",
        created_by="execution_runtime:arbitrary_file_read_probe",
        evidence_type="http_response",
        observation={"status": status, "method": "GET", "body": body},
    )


def _request(**overrides) -> ExecutionRequest:
    fields = dict(
        execution_id="exec-1", run_id="run-1", task_id="task-1",
        tool=ARBITRARY_FILE_READ_TOOL, target_url="http://localhost/view",
        surface_id="surface-1", purpose="probe", method="GET",
        request_kind=HttpRequestKind.ARBITRARY_FILE_READ_PROBE,
        query_parameters=(("file", ARBITRARY_FILE_READ_PROBE_PATH),),
    )
    fields.update(overrides)
    return ExecutionRequest(**fields)


class ProbeShapeTests(unittest.TestCase):
    def test_probe_sends_the_fixed_absolute_path(self) -> None:
        control, probe = build_arbitrary_file_read_requests(
            _surface(), ("file",), ("file",), purpose="probe"
        )
        self.assertEqual(
            dict(probe.http_request.query_parameters)["file"],
            ARBITRARY_FILE_READ_SAFE_PROBE_PATH,
        )
        self.assertIs(
            probe.http_request.request_kind,
            HttpRequestKind.ARBITRARY_FILE_READ_PROBE,
        )
        self.assertIs(control.http_request.request_kind, HttpRequestKind.CONTROL)

    def test_only_the_selected_parameter_carries_the_probe(self) -> None:
        """한 요청에서 바뀌는 자리가 둘이면 무엇이 신호를 만들었는지 말할 수 없다."""

        _, probe = build_arbitrary_file_read_requests(
            _surface(parameters=("file", "lang")), ("file", "lang"), ("file",),
            purpose="probe",
        )
        values = dict(probe.http_request.query_parameters)
        self.assertEqual(values["file"], ARBITRARY_FILE_READ_SAFE_PROBE_PATH)
        self.assertNotEqual(values["lang"], ARBITRARY_FILE_READ_SAFE_PROBE_PATH)


class FileParameterNameTests(unittest.TestCase):
    """라우팅 관측이 파일 이름과 URL 이름을 한데 묶으므로 분석기가 좁힌다."""

    def test_file_like_names_are_accepted(self) -> None:
        for name in ("file", "filepath", "page", "template", "download", "doc"):
            with self.subTest(name=name):
                self.assertTrue(looks_like_file_parameter(name))

    def test_url_like_names_are_rejected(self) -> None:
        """URL 자리에 절대 경로를 보내도 파일이 나오지 않는다. 요청 낭비다."""

        for name in ("url", "redirect", "dest", "target", "src", "link", "uri"):
            with self.subTest(name=name):
                self.assertFalse(looks_like_file_parameter(name))

    def test_mixed_names_are_treated_as_url(self) -> None:
        self.assertFalse(looks_like_file_parameter("file_url"))
        self.assertFalse(looks_like_file_parameter("doc_src"))

    def test_unrelated_names_are_rejected(self) -> None:
        for name in ("q", "lang", "sort", "id"):
            with self.subTest(name=name):
                self.assertFalse(looks_like_file_parameter(name))


class ValidatorTests(unittest.TestCase):
    def test_fixed_absolute_path_is_accepted(self) -> None:
        validate_arbitrary_file_read_request(_request())

    def test_other_files_are_rejected(self) -> None:
        for value in ("/etc/passwd", "/etc/shadow", "../../../../../etc/os-release"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_arbitrary_file_read_request(
                        _request(query_parameters=(("file", value),))
                    )

    def test_exactly_one_parameter_may_carry_the_probe(self) -> None:
        with self.assertRaises(ValueError):
            validate_arbitrary_file_read_request(
                _request(query_parameters=(
                    ("file", ARBITRARY_FILE_READ_PROBE_PATH),
                    ("other", ARBITRARY_FILE_READ_PROBE_PATH),
                ))
            )

    def test_the_dedicated_tool_is_required(self) -> None:
        with self.assertRaises(ValueError):
            validate_arbitrary_file_read_request(_request(tool="http_get"))

    def test_body_and_headers_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_arbitrary_file_read_request(_request(method="POST", body="x=1"))


class SignalTests(unittest.TestCase):
    _PROOF = "PRETTY_NAME=\"Debian GNU/Linux 12\"\nVERSION_ID=\"12\"\n"

    def test_markers_only_in_the_probe_are_a_signal(self) -> None:
        self.assertTrue(
            arbitrary_file_read_signal(
                _response("evi-control", "<html>home</html>"),
                _response("evi-probe", self._PROOF),
            )
        )

    def test_markers_already_in_the_control_are_not_a_signal(self) -> None:
        """대조 응답에도 있으면 그 표식은 파일을 읽어서 생긴 것이 아니다."""

        self.assertFalse(
            arbitrary_file_read_signal(
                _response("evi-control", self._PROOF),
                _response("evi-probe", self._PROOF),
            )
        )

    def test_error_status_is_not_a_signal(self) -> None:
        self.assertFalse(
            arbitrary_file_read_signal(
                _response("evi-control", "<html>home</html>"),
                _response("evi-probe", self._PROOF, status=500),
            )
        )

    def test_partial_markers_are_not_a_signal(self) -> None:
        self.assertFalse(
            arbitrary_file_read_signal(
                _response("evi-control", "<html>home</html>"),
                _response("evi-probe", 'PRETTY_NAME="Debian"'),
            )
        )

    def test_proof_markers_identify_the_fixed_file(self) -> None:
        self.assertEqual(
            ARBITRARY_FILE_READ_PROOF_MARKERS, ("PRETTY_NAME=", "VERSION_ID=")
        )
        self.assertEqual(ARBITRARY_FILE_READ_OBSERVATION, "arbitrary_file_read")


if __name__ == "__main__":
    unittest.main()
