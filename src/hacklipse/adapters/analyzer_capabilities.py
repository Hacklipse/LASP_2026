"""표준 Analysis Agent capability 선언과 범용 Surface matcher."""

from __future__ import annotations

from collections.abc import Sequence
from urllib.parse import urlsplit

from hacklipse.domain import Evidence, Surface
from hacklipse.ports import AnalyzerCapability, ObservationRequirement

from .request_safety import has_state_changing_parameters, object_identifier_parameters


DEFAULT_ANALYZER_CAPABILITIES = (
    AnalyzerCapability(
        capability_id="xss.http.query",
        agent_type="xss_analyzer",
        vulnerability_type="XSS",
        methods=("GET",),
        surface_kind="server",
        exploration_parameter_source="surface",
        supported_evidence_types=("control_response", "mutated_input_response"),
        strategy_ids=("reflect_each_parameter",),
        default_priority=0.30,
    ),
    AnalyzerCapability(
        capability_id="xss.browser.fragment",
        agent_type="browser_xss_analyzer",
        vulnerability_type="XSS",
        methods=("GET",),
        surface_kind="client",
        exploration_parameter_source="surface",
        supported_evidence_types=("browser_execution",),
        strategy_ids=("execute_fragment_in_browser",),
        default_priority=0.40,
    ),
    AnalyzerCapability(
        capability_id="sqli.http.query",
        agent_type="sqli_analyzer",
        vulnerability_type="SQLi",
        methods=("GET",),
        surface_kind="server",
        exploration_parameter_source="surface",
        supported_evidence_types=(
            "control_response",
            "mutated_input_response",
            "server_error_delta",
        ),
        strategy_ids=("compare_query_mutations",),
        default_priority=0.30,
    ),
    AnalyzerCapability(
        capability_id="path_traversal.http.query",
        agent_type="path_traversal_analyzer",
        vulnerability_type="Path Traversal",
        methods=("GET",),
        surface_kind="server",
        exploration_parameter_source="surface",
        supported_evidence_types=("control_response", "file_read_marker"),
        strategy_ids=("probe_file_parameter",),
        default_priority=0.25,
    ),
    AnalyzerCapability(
        capability_id="path_traversal.bounded_render_form",
        agent_type="path_traversal_analyzer",
        vulnerability_type="Path Traversal",
        methods=("POST",),
        surface_kind="server",
        observation_requirements=(
            ObservationRequirement(
                "unlinked_render_parameter_candidate",
                "bounded_unlinked_render_parameter",
            ),
        ),
        exploration_parameter_source="observation",
        supported_evidence_types=("control_response", "file_read_marker"),
        strategy_ids=("probe_bounded_render_parameter",),
        default_priority=0.25,
    ),
    AnalyzerCapability(
        capability_id="ssti.form.username",
        agent_type="ssti_analyzer",
        vulnerability_type="SSTI",
        methods=("POST",),
        surface_kind="server",
        parameter_hints=("username",),
        exploration_parameter_source="surface",
        supported_evidence_types=(
            "control_response",
            "template_execution_marker",
        ),
        strategy_ids=("compare_template_expressions",),
        default_priority=0.20,
    ),
    AnalyzerCapability(
        capability_id="access_control.object_identifier",
        agent_type="access_control_analyzer",
        vulnerability_type="Access Control",
        methods=("GET",),
        surface_kind="server",
        requires_parameters=False,
        requires_object_identifier=True,
        exploration_parameter_source="surface",
        supported_evidence_types=("cross_principal_response",),
        strategy_ids=("compare_object_ownership",),
        default_priority=0.35,
    ),
)


def observation_parameters(
    capability: AnalyzerCapability,
    surface: Surface,
    evidence: Sequence[Evidence],
) -> tuple[str, ...]:
    """Capability requirement를 만족한 관측에서 실행 입력 이름을 추출한다."""

    requirements = set(capability.observation_requirements)
    return tuple(
        dict.fromkeys(
            parameter
            for item in evidence
            if item.run_id == surface.run_id
            and item.surface_id == surface.surface_id
            and item.evidence_type == "observation"
            and any(
                item.observation.get("type") == requirement.observation_type
                and (
                    requirement.source is None
                    or item.observation.get("source") == requirement.source
                )
                for requirement in requirements
            )
            and isinstance((parameter := item.observation.get("parameter")), str)
            and parameter
        )
    )


def capability_matches(
    capability: AnalyzerCapability,
    surface: Surface,
    evidence: Sequence[Evidence] = (),
) -> bool:
    """Agent 이름과 취약점 유형을 분기하지 않는 범용 capability matcher."""

    return not capability_missing_requirements(capability, surface, evidence)


def capability_missing_requirements(
    capability: AnalyzerCapability,
    surface: Surface,
    evidence: Sequence[Evidence] = (),
) -> tuple[str, ...]:
    """Surface가 capability를 만족하지 못한 이유를 안정된 코드로 반환한다.

    Router의 실행 여부와 진단 결과가 서로 달라지지 않도록
    :func:`capability_matches`와 같은 조건을 한 곳에서 계산한다. 반환값은 감사 로그와
    CLI에 노출되므로 URL, 파라미터 값, 응답 본문은 포함하지 않는다.
    """

    missing: list[str] = []

    if surface.method.upper() not in capability.methods:
        missing.append("method")
    is_client = bool(urlsplit(surface.url).fragment)
    if is_client != (capability.surface_kind == "client"):
        missing.append("surface_kind")
    if has_state_changing_parameters(surface.parameters):
        missing.append("state_changing_input")
    if capability.requires_parameters and not surface.parameters:
        missing.append("input_parameter")
    if capability.parameter_hints:
        offered = {name.casefold() for name in surface.parameters}
        if not offered.intersection(
            hint.casefold() for hint in capability.parameter_hints
        ):
            missing.append("parameter_hint")
    if capability.requires_object_identifier and not (
        object_identifier_parameters(surface.parameters)
        or surface.path_identifier is not None
    ):
        missing.append("object_identifier")
    for requirement in capability.observation_requirements:
        if not any(
            item.run_id == surface.run_id
            and item.surface_id == surface.surface_id
            and item.evidence_type == "observation"
            and item.observation.get("type") == requirement.observation_type
            and (
                requirement.source is None
                or item.observation.get("source") == requirement.source
            )
            for item in evidence
        ):
            missing.append("required_observation")
    if (
        capability.exploration_parameter_source == "observation"
        and not observation_parameters(capability, surface, evidence)
    ):
        missing.append("observation_parameter")
    return tuple(dict.fromkeys(missing))


def exploration_parameters(
    capability: AnalyzerCapability,
    surface: Surface,
    evidence: Sequence[Evidence],
) -> tuple[str, ...]:
    if capability.exploration_parameter_source == "surface":
        return tuple(dict.fromkeys(surface.parameters))
    if capability.exploration_parameter_source == "observation":
        return observation_parameters(capability, surface, evidence)
    return ()
