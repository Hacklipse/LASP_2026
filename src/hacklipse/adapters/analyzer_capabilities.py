"""표준 Analysis Agent capability 선언과 범용 Surface matcher."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

from hacklipse.domain import Evidence, Run, Surface
from hacklipse.ports import AnalyzerCapability, ObservationRequirement

from .request_safety import has_state_changing_parameters, object_identifier_parameters
from .cors_analysis import CORS_SEARCH_INPUT_NAMES
from .graphql_introspection import INTROSPECTION_TYPE, INTROSPECTION_RECON_OBSERVATION
from .graphql_suggestions import SUGGESTION_TYPE, SUGGESTION_PLAN
from .error_disclosure import (
    ERROR_DISCLOSURE_TYPE, ERROR_ROUTE_OBSERVATION, ERROR_GRAPHQL_OBSERVATION,
)
from .sensitive_exposure import CONFIG_ROUTE_OBSERVATION
from .public_login_credentials import PUBLIC_LOGIN_OBSERVATION, PUBLIC_LOGIN_TYPE
from .open_redirect_analysis import REDIRECT_PARAMETER_HINTS
from .postmessage_plan import POSTMESSAGE_ANALYZER, POSTMESSAGE_CAPABILITY, POSTMESSAGE_PLAN
from .file_upload_analysis import UPLOAD_TYPE, UPLOAD_ANALYZER, UPLOAD_FORM


OPTIONAL_SOURCE_MAP_CAPABILITIES = (
    AnalyzerCapability(
        capability_id="source_map.public_reference",
        agent_type="source_map_exposure_analyzer",
        vulnerability_type="Source Map Exposure",
        methods=("GET",), surface_kind="server", requires_parameters=False,
        observation_requirements=(ObservationRequirement("source_map_reference"),),
        exploration_parameter_source="none",
        supported_evidence_types=("http_response",),
        strategy_ids=("independent_source_content_fetch",), default_priority=0.50,
    ),
)


DEFAULT_ANALYZER_CAPABILITIES = (
    AnalyzerCapability(
        capability_id="file_upload.multipart.extension_policy",
        agent_type=UPLOAD_ANALYZER, vulnerability_type=UPLOAD_TYPE,
        methods=("POST",), surface_kind="server",
        observation_requirements=(ObservationRequirement(UPLOAD_FORM, "html_form"),),
        exploration_parameter_source="observation",
        supported_evidence_types=("http_response",),
        strategy_ids=("compare_inert_file_extensions",), default_priority=0.25,
    ),
    AnalyzerCapability(
        capability_id=POSTMESSAGE_CAPABILITY,
        agent_type=POSTMESSAGE_ANALYZER,
        vulnerability_type="XSS",
        methods=("GET",), surface_kind="server", requires_parameters=False,
        observation_requirements=(ObservationRequirement(POSTMESSAGE_PLAN),),
        exploration_parameter_source="none",
        supported_evidence_types=("browser_execution",),
        strategy_ids=("independent_foreign_origin_message_execution",),
        default_priority=0.47,
    ),
    AnalyzerCapability(
        capability_id="credentials.public_login_pair",
        agent_type="public_login_credentials_analyzer",
        vulnerability_type=PUBLIC_LOGIN_TYPE,
        methods=("GET",), surface_kind="server", requires_parameters=False,
        observation_requirements=(ObservationRequirement(PUBLIC_LOGIN_OBSERVATION),),
        exploration_parameter_source="none",
        supported_evidence_types=("http_response",),
        strategy_ids=("approved_observed_login_replay",), default_priority=0.55,
    ),
    AnalyzerCapability(
        capability_id="sensitive_data.observed_config_route",
        agent_type="sensitive_exposure_analyzer",
        vulnerability_type="Sensitive Data Exposure",
        methods=("GET",), surface_kind="server", requires_parameters=False,
        observation_requirements=(ObservationRequirement(CONFIG_ROUTE_OBSERVATION),),
        exploration_parameter_source="none",
        supported_evidence_types=("http_response",),
        strategy_ids=("independent_config_credential_fetch",), default_priority=0.38,
    ),
    AnalyzerCapability(
        capability_id="error_details.diagnostic_get",
        agent_type="error_disclosure_analyzer",
        vulnerability_type=ERROR_DISCLOSURE_TYPE,
        methods=("GET",), surface_kind="server", requires_parameters=False,
        observation_requirements=(ObservationRequirement(ERROR_ROUTE_OBSERVATION),),
        exploration_parameter_source="none",
        supported_evidence_types=("http_response",),
        strategy_ids=("independent_error_stack_fetch",), default_priority=0.41,
    ),
    AnalyzerCapability(
        capability_id="error_details.graphql_syntax",
        agent_type="error_disclosure_analyzer",
        vulnerability_type=ERROR_DISCLOSURE_TYPE,
        methods=("GET",), surface_kind="server", requires_parameters=False,
        observation_requirements=(ObservationRequirement(ERROR_GRAPHQL_OBSERVATION),),
        exploration_parameter_source="none",
        supported_evidence_types=("http_response",),
        strategy_ids=("independent_anonymous_parser_errors",), default_priority=0.41,
    ),
    AnalyzerCapability(
        capability_id="graphql.field_suggestion", agent_type="graphql_suggestion_analyzer",
        vulnerability_type=SUGGESTION_TYPE, methods=("GET",),
        surface_kind="server", requires_parameters=False,
        observation_requirements=(ObservationRequirement(SUGGESTION_PLAN),),
        exploration_parameter_source="none", supported_evidence_types=("http_response",),
        strategy_ids=("independent_anonymous_field_typo",), default_priority=0.42,
    ),
    AnalyzerCapability(
        capability_id="graphql.schema_read", agent_type="graphql_introspection_analyzer",
        vulnerability_type=INTROSPECTION_TYPE, methods=("GET",),
        surface_kind="server", requires_parameters=False,
        observation_requirements=(ObservationRequirement(INTROSPECTION_RECON_OBSERVATION),),
        exploration_parameter_source="none", supported_evidence_types=("http_response",),
        strategy_ids=("independent_read_only_schema_fetch",), default_priority=0.44,
    ),
    AnalyzerCapability(
        capability_id="cors.http.search_sample", agent_type="cors_analyzer",
        vulnerability_type="CORS", methods=("GET",), surface_kind="server",
        parameter_hints=tuple(sorted(CORS_SEARCH_INPUT_NAMES)),
        exploration_parameter_source="none", supported_evidence_types=("http_response",),
        strategy_ids=("compare_fixed_origin_headers",), default_priority=0.43,
    ),
    AnalyzerCapability(
        capability_id="cors.graphql.operation", agent_type="cors_analyzer",
        vulnerability_type="CORS", methods=("GET",), surface_kind="server",
        requires_parameters=False,
        observation_requirements=(ObservationRequirement("graphql_schema_operation"),),
        exploration_parameter_source="none", supported_evidence_types=("http_response",),
        strategy_ids=("compare_fixed_origin_headers",), default_priority=0.43,
    ),
    AnalyzerCapability(
        capability_id="open_redirect.http.query",
        agent_type="open_redirect_analyzer",
        vulnerability_type="Open Redirect",
        methods=("GET",), surface_kind="server",
        parameter_hints=REDIRECT_PARAMETER_HINTS,
        exploration_parameter_source="surface",
        supported_evidence_types=("http_redirect",),
        strategy_ids=("compare_redirect_locations",), default_priority=0.50,
    ),
    AnalyzerCapability(
        capability_id="sensitive_data.embedded_json",
        agent_type="sensitive_exposure_analyzer",
        vulnerability_type="Sensitive Data Exposure",
        methods=("GET",), surface_kind="server",
        requires_parameters=False, exploration_parameter_source="none",
        observation_requirements=(ObservationRequirement("sensitive_json_exposure"),),
        supported_evidence_types=("http_response",),
        strategy_ids=("recheck_public_json_fields",), default_priority=0.45,
    ),
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
        capability_id="sqli.graphql.read_query",
        agent_type="sqli_analyzer", vulnerability_type="SQLi",
        methods=("GET",), surface_kind="server", requires_parameters=False,
        observation_requirements=(ObservationRequirement("graphql_read_query_plan"),),
        exploration_parameter_source="none",
        supported_evidence_types=("control_response", "mutated_input_response"),
        strategy_ids=("compare_graphql_query_argument",), default_priority=0.30,
    ),
    AnalyzerCapability(
        capability_id="sqli.http.form",
        agent_type="sqli_analyzer",
        vulnerability_type="SQLi",
        methods=("POST",),
        surface_kind="server",
        exploration_parameter_source="surface",
        supported_evidence_types=(
            "control_response",
            "mutated_input_response",
            "server_error_delta",
        ),
        strategy_ids=("compare_form_mutations",),
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
            ObservationRequirement("valid_post_request_template", "trusted_template_store"),
        ),
        exploration_parameter_source="observation",
        supported_evidence_types=("control_response", "file_read_marker"),
        strategy_ids=("probe_bounded_render_parameter",),
        default_priority=0.25,
    ),
    AnalyzerCapability(
        capability_id="path_traversal.hidden_body_parameter",
        agent_type="path_traversal_analyzer",
        vulnerability_type="Path Traversal",
        methods=("POST",),
        surface_kind="server",
        observation_requirements=(
            ObservationRequirement("post_form_body_structure", "html_form"),
            # A field-name-only HTML form cannot justify a POST probe. No standard
            # adapter publishes this observation until a verified request template
            # and session/token refresh are implemented.
            ObservationRequirement("valid_post_request_template", "trusted_template_store"),
        ),
        exploration_parameter_source="none",
        supported_evidence_types=("control_response", "file_read_marker"),
        strategy_ids=("hidden_parameter_differential_probe",),
        default_priority=0.20,
    ),
    AnalyzerCapability(
        capability_id="ssti.http.query",
        agent_type="ssti_analyzer",
        vulnerability_type="SSTI",
        methods=("GET",),
        surface_kind="server",
        # username 힌트를 걸지 않는다. 템플릿에 렌더링되는 좌표의 이름은 대상마다 달라
        # name·message·template 등으로 나타나며, heuristic_ssti_parameters가 이미
        # SSTI_PARAMETER_HINTS로 한 번 좁힌다. 여기서 또 좁히면 선언과 분석기의
        # 좁힘 기준이 두 곳으로 갈라진다.
        exploration_parameter_source="surface",
        supported_evidence_types=(
            "control_response",
            "template_execution_marker",
        ),
        strategy_ids=("compare_query_template_expressions",),
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


@dataclass(frozen=True, slots=True)
class AnalyzerCapabilityCoverage:
    """등록된 Analyzer capability의 현재 Run 실행 가능 여부."""

    capability_id: str
    vulnerability_type: str
    agent_type: str
    status: Literal["routable", "blocked"]
    matched_surface_count: int = 0
    missing_requirements: tuple[str, ...] = ()


def analyzer_capability_coverage(
    capabilities: Sequence[AnalyzerCapability],
    run: Run,
    surfaces: Sequence[Surface],
    evidence: Sequence[Evidence],
) -> tuple[AnalyzerCapabilityCoverage, ...]:
    """Router 모드와 무관하게 capability별 가장 작은 계약 gap을 계산한다."""

    run_surfaces = tuple(surface for surface in surfaces if surface.run_id == run.run_id)
    evidence_by_surface: dict[str, list[Evidence]] = {}
    for item in evidence:
        if item.run_id == run.run_id and item.surface_id is not None:
            evidence_by_surface.setdefault(item.surface_id, []).append(item)
    coverage: list[AnalyzerCapabilityCoverage] = []
    for capability in capabilities:
        gaps = tuple(
            capability_missing_requirements(
                capability, surface, evidence_by_surface.get(surface.surface_id, ())
            )
            for surface in run_surfaces
        )
        matched = sum(not gap for gap in gaps)
        if matched:
            coverage.append(AnalyzerCapabilityCoverage(
                capability_id=capability.capability_id,
                vulnerability_type=capability.vulnerability_type,
                agent_type=capability.agent_type,
                status="routable",
                matched_surface_count=matched,
            ))
        else:
            coverage.append(AnalyzerCapabilityCoverage(
                capability_id=capability.capability_id,
                vulnerability_type=capability.vulnerability_type,
                agent_type=capability.agent_type,
                status="blocked",
                missing_requirements=(
                    min(gaps, key=lambda gap: (
                        len(gap), "method" in gap, "surface_kind" in gap, gap
                    )) if gaps else ("surface",)
                ),
            ))
    return tuple(coverage)


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
