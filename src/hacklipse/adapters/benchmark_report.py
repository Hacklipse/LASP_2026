"""WebExploitBench 채점기가 읽는 보고 payload를 Finding에서 직접 만든다.

v2 보고서 계약(``RunReportFacts``)으로는 채점에 필요한 사실을 실을 수 없다. 세 가지가
빠진다.

1. 파라미터·요청 본문·응답 원문이 없다. 계약이 "URL/파라미터 원문은 넣지 않는다"로
   명시해 제외한 값들인데, 채점기의 용어 매칭과 파일 내용 일치는 이 값을 요구한다.
2. ``Vulnerability Specific Information``에 해당하는 자리가 없다. 크레덴셜 보고 채점은
   이 필드만 본다.
3. ``surface_path_hint``가 식별자 세그먼트를 ``{value}``로 가린다. 고정 세그먼트만 있는
   경로는 살아남지만, ID·UUID·토큰이 섞인 경로는 채점기의 경로 **정확 일치**를 통과하지
   못한다. 접근 제어 계열 Finding이 대부분 여기 해당한다.

그 일반화 자체는 LLM 내레이터에게 원문이 새지 않게 하는 안전장치이므로 유지한다.

그래서 이 모듈은 보고서 계약을 거치지 않고 저장소 객체(Finding·Surface·Evidence)에서
직접 payload를 만드는 **별도 출력 채널**이다. 계약과 내레이터 경로는 그대로 두므로
기존 불변식이 깨지지 않는다.

이 채널은 벤치마크 실행에서만 쓴다. 내레이터의 허용 입력은 닫힌 목록이며 원문 URL은
거기에 포함되지 않는다. 이 payload를 LLM 입력으로 연결하면 그 불변식이 깨진다.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence

from hacklipse.domain import Evidence, Finding, Surface

# 채점기는 report의 모든 문자열을 평탄화해 용어를 비교한다. 응답 본문을 통째로 실으면
# payload가 argv 한도를 넘길 수 있으므로 상한을 둔다. 파일 읽기 증명은 보통 본문 앞부분에
# 드러나므로 선두를 보존한다.
MAX_OBSERVATION_CHARS = 4096

# Finding이 참조하는 Evidence 중 payload에 담을 관측 키. Runtime이 남기는 공통 키만
# 쓴다. Analyzer 전용 키는 유형마다 달라서 일반 계약으로 삼을 수 없다.
_OBSERVATION_KEYS = ("status", "method", "body")

_VSI_KEY = "Vulnerability Specific Information"


def _clip(value: str) -> str:
    if len(value) <= MAX_OBSERVATION_CHARS:
        return value
    return value[:MAX_OBSERVATION_CHARS]


def _observation_fields(evidences: Sequence[Evidence]) -> dict[str, object]:
    """Finding의 Evidence에서 채점에 쓰일 수 있는 관측만 추린다.

    ``output_matches_file_content``처럼 읽은 파일 원문을 요구하는 채점이 있으므로 본문을
    버리지 않는다. 다만 Evidence는 이미 ``SensitiveDataSanitizer``를 거친 값이라,
    비밀로 분류된 문자열은 ``<redacted>``로 치환돼 있을 수 있다.
    """

    bodies: list[str] = []
    statuses: list[int] = []
    for evidence in evidences:
        observation = evidence.observation
        for key in _OBSERVATION_KEYS:
            value = observation.get(key)
            if key == "body" and isinstance(value, str) and value:
                bodies.append(_clip(value))
            elif key == "status" and isinstance(value, int):
                statuses.append(value)
    fields: dict[str, object] = {}
    if statuses:
        fields["status_codes"] = statuses
    if bodies:
        # 채점기가 원문 일치를 보므로 합치지 않고 관측 단위를 유지한다.
        fields["response_bodies"] = bodies
    return fields


def finding_report(
    finding: Finding,
    surface: Surface,
    evidences: Sequence[Evidence] = (),
) -> dict[str, object]:
    """Finding 하나를 채점기가 읽는 report 한 건으로 만든다.

    ``source_url``과 ``sink_api``에는 Surface의 **원문 URL**을 그대로 싣는다. 채점기가
    URL에서 경로만 떼어 소문자로 정규화해 비교하므로 일반화된 경로로는 매칭되지 않는다.
    """

    if finding.surface_id != surface.surface_id:
        raise ValueError("finding and surface must refer to the same surface")

    specific: dict[str, object] = {
        "method": surface.method,
        "parameters": list(surface.parameters),
        "requires_auth": surface.requires_auth,
        "reproduction_count": finding.reproduction_count,
    }
    if finding.proof_type is not None:
        specific["proof_type"] = finding.proof_type.value
    specific.update(_observation_fields(evidences))

    return {
        "source_url": surface.url,
        "sink_api": surface.url,
        "vulnerability_type": finding.vulnerability_type,
        "finding_id": finding.finding_id,
        _VSI_KEY: specific,
    }


def webexploitbench_agent_output(
    findings: Sequence[Finding],
    surfaces: Mapping[str, Surface],
    evidence: Mapping[str, Evidence] | None = None,
) -> dict[str, object]:
    """Run의 Finding 전체를 채점기의 ``agent_output`` 형태로 만든다.

    채점기는 ``agent_output["_reports"]``를 먼저 보고, 없으면 ``agent_output["output"]``
    안의 JSON을 찾는다. 두 경로 모두 성립하도록 같은 내용을 양쪽에 싣는다.

    개별 Finding의 ``Vulnerability Specific Information``을 최상위로 평탄화하지는 않는다.
    채점기 자신이 "서로 다른 report의 값이 섞이지 않도록 ``_reports``를 우선한다"고
    명시하고 있어, 평탄화는 Finding이 여럿일 때 오히려 오판을 만든다.
    """

    evidence_by_id = evidence or {}
    reports: list[dict[str, object]] = []
    for finding in findings:
        surface = surfaces.get(finding.surface_id)
        if surface is None:
            # Surface를 복원하지 못한 Finding은 경로를 주장할 수 없다. 조용히 빼면
            # 보고 누락이 되므로 호출자가 알 수 있게 올린다.
            raise KeyError(f"surface is missing for finding: {finding.finding_id}")
        linked = tuple(
            evidence_by_id[evidence_id]
            for evidence_id in finding.evidence_ids
            if evidence_id in evidence_by_id
        )
        reports.append(finding_report(finding, surface, linked))

    payload: dict[str, object] = {"_reports": reports}
    return {
        "output": json.dumps(payload, ensure_ascii=False, sort_keys=True),
        "_reports": reports,
    }


def verifier_input(
    agent_output: Mapping[str, object],
    urls: Mapping[str, str] | None = None,
    dockers: Mapping[str, str] | None = None,
    url: str | None = None,
) -> str:
    """``verify.py``가 ``argv[1]``로 받는 JSON 문자열을 만든다.

    벤치마크의 evaluator 서비스가 verifier 에게 넘기는 것과 같은 네 필드를 채운다
    (``{"dockers", "url", "urls", "agent_output"}``). 호스트에서 ``verify.py``를
    직접 부를 때는 그 서비스를 거치지 않으므로 호출자가 직접 채워야 한다.

    ``dockers``는 compose 서비스 키에서 실제 컨테이너 이름으로 가는 매핑이다.
    verifier 다수가 ``docker exec``로 컨테이너 안의 원본 파일을 읽어 agent 출력과
    비교하는데, 넘기지 않으면 서비스 키를 그대로 컨테이너 이름으로 쓴다
    (``verify_helpers.docker_container``의 ``default``). compose는 실제로는
    ``<project>-<service>-1``로 이름을 붙이므로 그 기본값은 맞지 않고, 채점이
    "읽지 못했다"가 아니라 "컨테이너가 없다"로 실패한다.

    ``url``·``urls``는 verifier 가 대상에 직접 요청할 때 쓰는 주소다. 둘 다 빠지면
    ``verify_helpers.configured_url``이 기본값으로 떨어지고 그 기본값도 비어
    **탐지 여부와 무관하게 즉시 false**가 된다 — comfyui-002·003·005 가 그 경로다.
    실패가 ``error`` 가 아니라 ``fail`` 로 나오므로 배선 점검에 걸리지 않는다.
    """

    data: dict[str, object] = {"agent_output": dict(agent_output)}
    if url:
        data["url"] = url
    if urls:
        data["urls"] = dict(urls)
    if dockers:
        data["dockers"] = dict(dockers)
    return json.dumps(data, ensure_ascii=False, sort_keys=True)
