"""WebExploitBench 채점기 payload가 경로 원문과 증거를 보존하는지 검증한다."""

import json
import unittest

from hacklipse.adapters.benchmark_report import (
    MAX_OBSERVATION_CHARS,
    finding_report,
    verifier_input,
    webexploitbench_agent_output,
)
from hacklipse.adapters.report_contract import surface_path_hint
from hacklipse.domain import Evidence, Finding, Surface, ValidationProofType


def example_surface(surface_id: str = "surface-1", url: str = "http://web:80/manager/channel_url_list") -> Surface:
    return Surface(
        surface_id=surface_id, run_id="run-1", url=url, method="POST",
        parameters=("payload",), requires_auth=False,
    )


def example_finding(surface_id: str = "surface-1", finding_id: str = "finding-1") -> Finding:
    return Finding(
        finding_id=finding_id, run_id="run-1", candidate_id="candidate-1",
        validation_id="validation-1", vulnerability_type="XSS", surface_id=surface_id,
        evidence_ids=("evi-1",), proof_type=ValidationProofType.XSS_EXECUTION,
        reproduction_count=2,
    )


def example_evidence(evidence_id: str = "evi-1", body: str = "secret-file-content") -> Evidence:
    return Evidence(
        evidence_id=evidence_id, run_id="run-1", surface_id="surface-1",
        created_by="execution_runtime:http", evidence_type="mutated_input_response",
        observation={"status": 200, "method": "POST", "body": body},
    )


class FindingReportTest(unittest.TestCase):
    def test_report_carries_the_raw_url(self) -> None:
        surface = example_surface()
        report = finding_report(example_finding(), surface)
        self.assertEqual(report["source_url"], surface.url)
        self.assertEqual(report["sink_api"], surface.url)

    def test_identifier_paths_survive_here_but_not_in_the_report_contract(self) -> None:
        """식별자가 섞인 경로는 v2 계약에서 ``{value}``로 가려져 채점에 못 쓴다.

        고정 세그먼트만 있는 경로는 계약을 거쳐도 살아남는다. 두 경로가 갈리는 지점이
        이 채널이 따로 필요한 이유이므로, 회귀로 고정한다.
        """

        with_identifier = "http://web:80/api/users/1234"
        static_only = "http://web:80/manager/channel_url_list"
        self.assertEqual(surface_path_hint(with_identifier), "/api/users/{value}")
        self.assertEqual(surface_path_hint(static_only), "/manager/channel_url_list")

        surface = example_surface(url=with_identifier)
        report = finding_report(example_finding(), surface)
        self.assertEqual(report["source_url"], with_identifier)

    def test_report_records_proof_and_surface_shape(self) -> None:
        report = finding_report(example_finding(), example_surface())
        specific = report["Vulnerability Specific Information"]
        self.assertEqual(specific["proof_type"], "xss_execution")
        self.assertEqual(specific["method"], "POST")
        self.assertEqual(specific["parameters"], ["payload"])
        self.assertEqual(specific["reproduction_count"], 2)

    def test_missing_proof_omits_the_key(self) -> None:
        finding = Finding(
            finding_id="finding-2", run_id="run-1", candidate_id="candidate-1",
            validation_id="validation-1", vulnerability_type="XSS", surface_id="surface-1",
            evidence_ids=("evi-1",),
        )
        specific = finding_report(finding, example_surface())["Vulnerability Specific Information"]
        self.assertNotIn("proof_type", specific)

    def test_response_body_is_preserved_for_file_content_scoring(self) -> None:
        """파일 읽기 채점은 읽은 원문이 출력에 있어야 통과한다."""

        report = finding_report(example_finding(), example_surface(), (example_evidence(),))
        specific = report["Vulnerability Specific Information"]
        self.assertEqual(specific["response_bodies"], ["secret-file-content"])
        self.assertEqual(specific["status_codes"], [200])

    def test_long_body_is_clipped_from_the_front(self) -> None:
        body = "A" * (MAX_OBSERVATION_CHARS + 100)
        report = finding_report(example_finding(), example_surface(), (example_evidence(body=body),))
        preserved = report["Vulnerability Specific Information"]["response_bodies"][0]
        self.assertEqual(len(preserved), MAX_OBSERVATION_CHARS)
        self.assertTrue(body.startswith(preserved))

    def test_mismatched_surface_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            finding_report(example_finding(), example_surface(surface_id="surface-other"))


class AgentOutputTest(unittest.TestCase):
    def test_reports_are_readable_from_both_scoring_paths(self) -> None:
        """채점기는 ``_reports``를 먼저 보고, 없으면 ``output`` 안의 JSON을 찾는다."""

        output = webexploitbench_agent_output(
            (example_finding(),), {"surface-1": example_surface()}, {"evi-1": example_evidence()},
        )
        self.assertEqual(len(output["_reports"]), 1)
        embedded = json.loads(output["output"])
        self.assertEqual(embedded["_reports"], output["_reports"])

    def test_specific_information_is_not_flattened_to_the_top_level(self) -> None:
        """Finding이 여럿일 때 값이 섞이지 않도록 평탄화하지 않는다."""

        output = webexploitbench_agent_output(
            (example_finding(),), {"surface-1": example_surface()},
        )
        self.assertNotIn("Vulnerability Specific Information", output)
        self.assertNotIn("proof_type", output)

    def test_each_finding_keeps_its_own_surface_url(self) -> None:
        surfaces = {
            "surface-1": example_surface(),
            "surface-2": example_surface("surface-2", "http://web:80/upload/image"),
        }
        findings = (example_finding(), example_finding("surface-2", "finding-2"))
        reports = webexploitbench_agent_output(findings, surfaces)["_reports"]
        self.assertEqual(
            [report["source_url"] for report in reports],
            ["http://web:80/manager/channel_url_list", "http://web:80/upload/image"],
        )

    def test_unknown_surface_is_reported_not_silently_dropped(self) -> None:
        with self.assertRaises(KeyError):
            webexploitbench_agent_output((example_finding(),), {})

    def test_unlinked_evidence_is_skipped_without_failing(self) -> None:
        output = webexploitbench_agent_output(
            (example_finding(),), {"surface-1": example_surface()}, {},
        )
        specific = output["_reports"][0]["Vulnerability Specific Information"]
        self.assertNotIn("response_bodies", specific)


class VerifierInputTest(unittest.TestCase):
    def test_payload_matches_the_verifier_contract(self) -> None:
        output = webexploitbench_agent_output(
            (example_finding(),), {"surface-1": example_surface()},
        )
        data = json.loads(verifier_input(output, {"target": "http://web:80"}))
        self.assertEqual(data["urls"]["target"], "http://web:80")
        self.assertEqual(data["agent_output"]["_reports"], output["_reports"])

    def test_urls_are_optional(self) -> None:
        data = json.loads(verifier_input({"output": "", "_reports": []}))
        self.assertNotIn("urls", data)

    def test_container_names_reach_the_verifier(self) -> None:
        """compose 이름 규칙이 서비스 키와 달라 매핑을 실어야 한다.

        verifier 다수가 ``docker exec``로 원본 파일을 읽어 비교한다. 매핑이 없으면
        서비스 키를 컨테이너 이름으로 쓰다가 "컨테이너 없음"으로 실패한다 — 탐지
        실패와 구분되지 않는 가짜 미탐이 된다.
        """

        data = json.loads(
            verifier_input(
                {"output": "", "_reports": []},
                dockers={"openmetadata-server": "web_openmetadata-openmetadata-server-1"},
            )
        )
        self.assertEqual(
            data["dockers"]["openmetadata-server"],
            "web_openmetadata-openmetadata-server-1",
        )

    def test_container_names_are_optional(self) -> None:
        data = json.loads(verifier_input({"output": "", "_reports": []}))
        self.assertNotIn("dockers", data)

    def test_the_target_url_reaches_the_verifier(self) -> None:
        """주소가 없으면 verifier 가 탐지 여부와 무관하게 즉시 false 를 낸다.

        comfyui-002·003·005 는 `configured_url(data, "manager", data["url"])` 로
        주소를 찾고, 비면 `emit(False)` 로 끝낸다. 그 실패는 `error` 가 아니라
        `fail` 로 나오므로 "error 0건이면 배선 정상" 식 점검에 걸리지 않는다.
        """

        data = json.loads(
            verifier_input(
                {"output": "", "_reports": []},
                url="http://127.0.0.1:39759",
                urls={"manager": "http://127.0.0.1:39759"},
            )
        )
        self.assertEqual(data["url"], "http://127.0.0.1:39759")
        self.assertEqual(data["urls"]["manager"], "http://127.0.0.1:39759")

    def test_the_url_is_optional(self) -> None:
        data = json.loads(verifier_input({"output": "", "_reports": []}))
        self.assertNotIn("url", data)
        self.assertNotIn("urls", data)


if __name__ == "__main__":
    unittest.main()
