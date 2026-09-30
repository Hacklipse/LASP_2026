"""Analysis Agent가 Router에 공개하는 실행 capability 계약."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal


SurfaceKind = Literal["server", "client"]
ParameterSource = Literal["none", "surface", "observation"]


@dataclass(frozen=True, slots=True)
class ObservationRequirement:
    """Capability 실행 전에 현재 Surface에서 확인해야 하는 구조화 관측."""

    observation_type: str
    source: str | None = None


@dataclass(frozen=True, slots=True)
class AnalyzerCapability:
    """Router가 Agent 구현을 모르고도 Surface를 연결할 수 있게 하는 선언.

    새 Analysis Agent는 이 계약만 등록하면 된다. Router에는 Agent 이름이나 취약점별
    분기를 추가하지 않는다.
    """

    capability_id: str
    agent_type: str
    vulnerability_type: str
    methods: tuple[str, ...] = ("GET",)
    surface_kind: SurfaceKind = "server"
    requires_parameters: bool = True
    parameter_hints: tuple[str, ...] = ()
    requires_object_identifier: bool = False
    observation_requirements: tuple[ObservationRequirement, ...] = ()
    exploration_parameter_source: ParameterSource = "none"
    supported_evidence_types: tuple[str, ...] = ()
    strategy_ids: tuple[str, ...] = ("default",)
    default_priority: float = 0.15

    def __post_init__(self) -> None:
        if not self.capability_id or not self.agent_type or not self.vulnerability_type:
            raise ValueError("analyzer capability identifiers must be non-empty")
        if not self.methods or any(not method for method in self.methods):
            raise ValueError("analyzer capability methods must be non-empty")
        object.__setattr__(
            self, "methods", tuple(dict.fromkeys(method.upper() for method in self.methods))
        )
        if not self.strategy_ids or len(set(self.strategy_ids)) != len(self.strategy_ids):
            raise ValueError("analyzer capability strategy ids must be unique and non-empty")
        if any(not value for value in self.strategy_ids):
            raise ValueError("analyzer capability strategy ids must be non-empty")
        if not 0.0 <= self.default_priority <= 1.0:
            raise ValueError("analyzer capability priority must be between zero and one")


class AnalyzerCapabilityRegistry:
    """Agent plugin이 capability를 등록하고 Router가 immutable snapshot을 얻는 registry."""

    def __init__(self, capabilities: Iterable[AnalyzerCapability] = ()) -> None:
        self._items: dict[str, AnalyzerCapability] = {}
        self.register_many(capabilities)

    def register(self, capability: AnalyzerCapability) -> None:
        if capability.capability_id in self._items:
            raise ValueError(
                f"analyzer capability already registered: {capability.capability_id}"
            )
        self._items[capability.capability_id] = capability

    def register_many(self, capabilities: Iterable[AnalyzerCapability]) -> None:
        for capability in capabilities:
            self.register(capability)

    def snapshot(self) -> tuple[AnalyzerCapability, ...]:
        return tuple(self._items.values())

