"""규칙이 분류하지 못한 Surface만 LLM으로 해석해 라우팅 제안을 만드는 Advisor.

역할은 구조적으로 분리한다.

    Rule    설명 가능한 Observation·Surface 규칙으로 Candidate를 만든다 (routing.py, 결정적)
    LLM     그 규칙이 비워 둔 자리에 한해 "이 표면은 어떤 유형으로 볼 만한가"만 제안 (이 파일)

LLM은 Candidate를 만들지 않고, 담당 Agent도 고르지 않는다. 고르는 것은 이미 존재하는
``surface_id``와 취약점 유형 두 가지뿐이며, ``agent_type`` 해석은 표면 모양(fragment 여부)을
보고 Python이 결정한다. 실제 Candidate 생성·priority 부여·저장은 여전히
``RuleBasedVulnerabilityRouter``와 Orchestrator가 수행한다.

``probing.py``의 ``validate_probe_selection()``은 참고하지 않는다. 그 함수는 Analysis Agent가
실행 대상(파라미터 값)을 확정하는 계약이라 존재하지 않는 선택을 ``AgentContractError``로
올리는 것이 맞다. 여기 선택은 실행 값이 아니라 "무엇을 검사 대상으로 볼지"에 대한 제안일
뿐이라, 잘못된 개별 항목 때문에 나머지 유효한 제안까지 버릴 이유가 없다. 그래서
``llm_recon_planner``와 같은 방식으로 구조 위반과 항목 위반을 나눠 다룬다.

    구조 위반(응답이 객체가 아님, suggestions가 배열이 아님) → 전체를 버리고 빈 제안 반환
    항목 위반(없는 surface_id, 해석 불가 유형, 중복)         → 그 항목만 버리고 계속

프롬프트 위생 — Surface 메타데이터와 구조화된 Observation 유형만 싣는다. 응답 본문,
관측된 query 값(``observed_query``), 자격증명은 어느 것도 프롬프트에 들어가지 않는다.
``observed_query``에는 token 같은 값이 실제로 담기므로 이름만 골라 쓴다.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

from hacklipse.domain import Evidence, Run, Surface
from hacklipse.ports.errors import (
    LlmRefused,
    LlmResponseFormatError,
    LlmTimeout,
    LlmTransportError,
)
from hacklipse.ports.llm import LlmClient, LlmMessage, LlmRequest

from .request_safety import has_state_changing_parameters
from .routing import RouteSuggestion

# Evidence.created_by에 쓸 고정 식별자. selection_source(llm/rule)와 별개로 "이 판단을
# 만든 컴포넌트가 무엇인가"는 항상 이 값으로 고정한다.
ROUTER_ADVISOR = "llm_router_advisor"

# 한 Run에서 LLM에게 보여 줄 Surface 상한. Juice Shop 실측 Surface가 140개라 전부 실으면
# 프롬프트가 비대해지고 비용이 표면 수에 비례해 늘어난다. Router는 Run당 한 번만 부르므로
# 이 상한이 곧 이 기능의 비용 상한이다.
DEFAULT_MAX_SURFACES = 40

_SUGGESTION_SCHEMA = {
    "type": "object",
    "properties": {
        "suggestions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "surface_id": {"type": "string"},
                    "vulnerability_type": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "required": ["surface_id", "vulnerability_type", "reason"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["suggestions"],
    "additionalProperties": False,
}

_SYSTEM = (
    "You review endpoints of a single authorized security assessment that the "
    "deterministic rules could not classify, and say which vulnerability type is worth "
    "investigating on each. You never invent endpoints, parameters, or payloads: you only "
    "pair a surface_id that was offered to you with one of the vulnerability types that "
    "was offered to you. Judge from the endpoint path, the parameter names, and the "
    "structured observation types. A surface whose name and inputs suggest the server "
    "fetches, reads, renders, or looks up something on behalf of the caller is worth a "
    "suggestion; a plain navigation link is not. Return an empty list when none of the "
    "offered surfaces are worth spending analysis budget on. Do not repeat a pairing that "
    "is already listed as covered."
)


@dataclass(frozen=True, slots=True)
class AnalyzerChoice:
    """제안 가능한 취약점 유형 하나와 그것을 맡을 Agent.

    ``client_route``는 이 Agent가 SPA fragment 표면(``/#/search``)을 다룰 수 있는지다.
    fragment는 서버로 전송되지 않으므로 HTTP 기반 Analyzer가 받으면 매번 같은 루트
    문서만 받아 신호 없이 예산만 쓴다. Router의 ``SurfaceRoutingRule``과 같은 기준이다.
    """

    vulnerability_type: str
    agent_type: str
    client_route: bool = False


@dataclass(frozen=True, slots=True)
class _OfferedSurface:
    """LLM에게 보여 줄 Surface 하나. 값이 아니라 이름과 구조만 담는다."""

    surface_id: str
    method: str
    path: str
    client_route: bool
    parameter_names: tuple[str, ...]
    observation_types: tuple[str, ...]
    covered_types: tuple[str, ...]


class LlmRouterAdvisor:
    """LLM 제안을 검증해 ``RouteSuggestion``으로만 돌려주는 ``RouterAdvisor`` 구현.

    Store에 쓰지 않고, Candidate를 만들지 않으며, 외부 요청도 하지 않는다.
    """

    def __init__(
        self,
        *,
        llm_client: LlmClient,
        analyzers: Sequence[AnalyzerChoice],
        max_surfaces: int = DEFAULT_MAX_SURFACES,
        timeout_seconds: float = 60.0,
    ) -> None:
        self._llm = llm_client
        self._analyzers = tuple(analyzers)
        self._max_surfaces = max_surfaces
        self._timeout_seconds = timeout_seconds

    def advise(
        self,
        run: Run,
        surfaces: Sequence[Surface],
        evidence: Sequence[Evidence],
        routed: frozenset[tuple[str, str]],
    ) -> Sequence[RouteSuggestion]:
        offered = self._offer(run, surfaces, evidence, routed)
        if not offered or not self._analyzers:
            # 보여 줄 표면이 없거나 제안 가능한 유형이 없다는 사실은 결정적이다.
            # LLM을 부를 이유가 없다.
            return ()

        try:
            response = self._llm.complete(
                LlmRequest(
                    messages=(
                        LlmMessage(role="user", content=self._prompt(offered)),
                    ),
                    system=_SYSTEM,
                    response_schema=_SUGGESTION_SCHEMA,
                    timeout_seconds=self._timeout_seconds,
                )
            )
        except (LlmTimeout, LlmTransportError, LlmResponseFormatError, LlmRefused):
            # 호출 실패는 규칙 결과를 그대로 두는 것으로 흡수한다. Router가 예외를 다시
            # 잡아 주지만, 여기서 먼저 처리해야 "왜 빈 제안인가"가 이 계층에 남는다.
            #
            # LlmCredentialsMissing은 일부러 잡지 않는다 - 키 없이 Advisor를 배선한 것은
            # 실행 중 장애가 아니라 구성 오류이며, 조용히 규칙만 돌면 "LLM을 켰는데
            # 규칙 결과가 나왔다"는 오독을 만든다. 다만 Router가 모든 예외를 흡수하므로
            # 이 구분이 실제로 살아나려면 bootstrap이 배선 시점에 키를 확인해야 한다.
            return ()

        return self._parse(response.payload, offered, routed)

    # ------------------------------------------------------------------
    # 제안 대상 선정
    # ------------------------------------------------------------------

    def _offer(
        self,
        run: Run,
        surfaces: Sequence[Surface],
        evidence: Sequence[Evidence],
        routed: frozenset[tuple[str, str]],
    ) -> tuple[_OfferedSurface, ...]:
        """규칙이 다 채우지 못한 Surface만 골라 안전한 메타데이터로 바꾼다."""

        observations = self._observations_by_surface(run, evidence)
        offered: list[_OfferedSurface] = []
        for surface in surfaces:
            if surface.run_id != run.run_id:
                continue
            # 상태를 바꾸는 폼은 규칙이 후보로 만들지 않는다. LLM에게 물어볼 대상도 아니다.
            if has_state_changing_parameters(surface.parameters):
                continue
            client_route = bool(urlsplit(surface.url).fragment)
            # 이 표면 모양에서 실제로 배정 가능한 유형만 후보로 센다.
            assignable = {
                choice.vulnerability_type
                for choice in self._analyzers
                if choice.client_route is client_route
            }
            covered = {
                vulnerability_type
                for surface_id, vulnerability_type in routed
                if surface_id == surface.surface_id
            }
            if not assignable - covered:
                # 배정 가능한 유형을 규칙이 이미 전부 채웠다. 물어볼 것이 없다.
                continue
            offered.append(
                _OfferedSurface(
                    surface_id=surface.surface_id,
                    method=surface.method.upper(),
                    path=urlsplit(surface.url).path or "/",
                    client_route=client_route,
                    parameter_names=tuple(surface.parameters),
                    observation_types=observations.get(surface.surface_id, ()),
                    covered_types=tuple(sorted(covered)),
                )
            )

        # 규칙이 아무것도 만들지 못한 표면이 이 기능의 본래 대상이다. 조용히 검사에서
        # 빠지는 쪽을 먼저 보여 주고, 남는 자리에 일부만 채워진 표면을 싣는다.
        offered.sort(key=lambda item: (bool(item.covered_types), item.surface_id))
        return tuple(offered[: self._max_surfaces])

    @staticmethod
    def _observations_by_surface(
        run: Run, evidence: Sequence[Evidence]
    ) -> dict[str, tuple[str, ...]]:
        """Surface별 관측 유형 목록. 관측 '값'이 아니라 유형 이름만 모은다."""

        collected: dict[str, list[str]] = {}
        for item in evidence:
            if item.run_id != run.run_id or item.surface_id is None:
                continue
            observation_type = item.observation.get("type")
            if not isinstance(observation_type, str) or not observation_type:
                continue
            seen = collected.setdefault(item.surface_id, [])
            if observation_type not in seen:
                seen.append(observation_type)
        return {key: tuple(value) for key, value in collected.items()}

    # ------------------------------------------------------------------
    # 프롬프트
    # ------------------------------------------------------------------

    def _prompt(self, offered: tuple[_OfferedSurface, ...]) -> str:
        types = sorted({choice.vulnerability_type for choice in self._analyzers})
        lines = [
            "Vulnerability types you may suggest: " + ", ".join(types),
            "",
            "Surfaces:",
        ]
        for item in offered:
            parameters = ", ".join(item.parameter_names) or "(none)"
            observations = ", ".join(item.observation_types) or "(none)"
            covered = ", ".join(item.covered_types) or "(none)"
            location = "client_route" if item.client_route else "server_route"
            lines.append(
                f"- surface_id={item.surface_id} method={item.method} "
                f"path={item.path} kind={location} parameters=[{parameters}] "
                f"observations=[{observations}] already_covered=[{covered}]"
            )
        lines.append("")
        lines.append(
            "Pair each surface_id worth investigating with one vulnerability type "
            "from the list above."
        )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 응답 검증
    # ------------------------------------------------------------------

    def _parse(
        self,
        payload: object,
        offered: tuple[_OfferedSurface, ...],
        routed: frozenset[tuple[str, str]],
    ) -> tuple[RouteSuggestion, ...]:
        """구조 위반은 전체를 버리고, 항목 위반은 해당 항목만 버린다."""

        if not isinstance(payload, dict):
            return ()
        raw = payload.get("suggestions")
        if not isinstance(raw, list):
            return ()

        by_id = {item.surface_id: item for item in offered}
        accepted: list[RouteSuggestion] = []
        taken: set[tuple[str, str]] = set()
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            surface_id = entry.get("surface_id")
            vulnerability_type = entry.get("vulnerability_type")
            if not isinstance(surface_id, str) or not isinstance(vulnerability_type, str):
                continue
            # 보여 주지 않은 표면은 제안 대상이 아니다. 다른 Run의 Surface도 여기서 걸린다.
            surface = by_id.get(surface_id)
            if surface is None:
                continue
            key = (surface_id, vulnerability_type)
            # 규칙이 이미 정한 자리와 같은 응답 안의 중복은 만들지 않는다. Router도
            # 같은 검사를 하지만, 쓸모없는 제안을 여기서 걸러야 무엇이 실제로 새로
            # 제안됐는지가 이 계층의 결과로 남는다.
            if key in routed or key in taken:
                continue
            agent_type = self._resolve_agent(vulnerability_type, surface.client_route)
            if agent_type is None:
                continue
            reason = entry.get("reason")
            accepted.append(
                RouteSuggestion(
                    surface_id=surface_id,
                    vulnerability_type=vulnerability_type,
                    agent_type=agent_type,
                    reason=reason if isinstance(reason, str) else "",
                )
            )
            taken.add(key)
        return tuple(accepted)

    def _resolve_agent(self, vulnerability_type: str, client_route: bool) -> str | None:
        """유형과 표면 모양으로 담당 Agent를 결정한다. LLM은 이 선택에 관여하지 않는다.

        XSS처럼 담당 Analyzer가 둘인 유형이 있으므로 이름만으로는 정할 수 없다.
        서버 반사는 ``xss_analyzer``, SPA의 DOM sink는 ``browser_xss_analyzer``가 맡는
        것과 같은 기준을 여기서도 표면 모양으로 적용한다.
        """

        for choice in self._analyzers:
            if (
                choice.vulnerability_type == vulnerability_type
                and choice.client_route is client_route
            ):
                return choice.agent_type
        return None
