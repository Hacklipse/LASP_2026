"""Answer-blind contracts for iterative reconnaissance decisions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal, Protocol

from hacklipse.domain import TaskEnvelope


ReconObservationState = Literal["discovered", "fetched"]
ReconActionName = Literal["visit_surface", "stop"]
ReconActionSource = Literal["llm", "deterministic_fallback"]
ReconReasonCode = Literal[
    "inspect_input_surface",
    "inspect_document",
    "inspect_api_surface",
    "expand_coverage",
    "insufficient_signal",
    "budget_conservation",
    "no_available_surface",
    "planner_failure",
]

_SAFE_PARAMETER_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,63}$")
_DISCOVERY_TYPES = {
    "seed",
    "html_link",
    "html_form",
    "browser_navigation",
    "script_literal",
    "discovered",
}
_ACTION_STATUSES = {
    "llm_success",
    "fallback:no_available_surface",
    "fallback:timeout",
    "fallback:transport_error",
    "fallback:refused",
    "fallback:invalid_response",
    "fallback:deterministic_collection",
}


@dataclass(frozen=True, slots=True)
class ReconObservation:
    """Sanitized facts an iterative planner may use.

    Response bodies, header values, cookies, credentials, observed parameter values,
    vulnerability labels, payloads, and ground truth deliberately have no field in this
    contract. ``path`` and parameter names are target observations, not supplied answers.
    """

    observation_id: str
    surface_id: str
    path: str
    method: str
    parameter_names: tuple[str, ...]
    discovery_types: tuple[str, ...]
    state: ReconObservationState
    status_code: int | None = None
    content_type: str | None = None

    def __post_init__(self) -> None:
        if not self.observation_id or not self.surface_id:
            raise ValueError("recon observation ids must not be empty")
        if any(
            len(value) > 200 or not value.isprintable()
            for value in (self.observation_id, self.surface_id)
        ):
            raise ValueError("recon observation ids must be bounded printable strings")
        if (
            not self.path.startswith("/")
            or len(self.path) > 512
            or not self.path.isprintable()
        ):
            raise ValueError("recon observation path must be a bounded absolute path")
        if self.method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
            raise ValueError("unsupported recon observation method")
        if self.state not in {"discovered", "fetched"}:
            raise ValueError("unsupported recon observation state")
        if self.status_code is not None and not 100 <= self.status_code <= 599:
            raise ValueError("invalid recon observation status code")
        if self.content_type is not None and len(self.content_type) > 100:
            raise ValueError("recon observation content type is too long")
        if self.content_type is not None and not self.content_type.isprintable():
            raise ValueError("recon observation content type must be printable")
        if len(set(self.parameter_names)) != len(self.parameter_names) or any(
            _SAFE_PARAMETER_NAME.fullmatch(name) is None
            for name in self.parameter_names
        ):
            raise ValueError("recon parameter names must be unique safe aliases")
        if len(set(self.discovery_types)) != len(self.discovery_types) or any(
            value not in _DISCOVERY_TYPES for value in self.discovery_types
        ):
            raise ValueError("recon discovery types must use the generic allowlist")


@dataclass(frozen=True, slots=True)
class ReconAction:
    """One allowlisted next action proposed by an iterative Recon planner."""

    action: ReconActionName
    surface_id: str | None
    basis_observation_ids: tuple[str, ...]
    reason_code: ReconReasonCode
    source: ReconActionSource
    status: str
    rejected_surface_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.action not in {"visit_surface", "stop"}:
            raise ValueError("unsupported recon action")
        if self.action == "visit_surface" and not self.surface_id:
            raise ValueError("visit_surface requires a surface id")
        if self.action == "stop" and self.surface_id is not None:
            raise ValueError("stop must not carry a surface id")
        if self.reason_code not in {
            "inspect_input_surface",
            "inspect_document",
            "inspect_api_surface",
            "expand_coverage",
            "insufficient_signal",
            "budget_conservation",
            "no_available_surface",
            "planner_failure",
        }:
            raise ValueError("unsupported recon reason code")
        if self.source not in {"llm", "deterministic_fallback"}:
            raise ValueError("unsupported recon action source")
        if self.status not in _ACTION_STATUSES:
            raise ValueError("unsupported recon action status")
        if len(set(self.basis_observation_ids)) != len(self.basis_observation_ids):
            raise ValueError("recon action basis ids must be unique")
        if len(set(self.rejected_surface_ids)) != len(self.rejected_surface_ids):
            raise ValueError("rejected recon surface ids must be unique")


class IterativeReconPlanner(Protocol):
    """Choose one next visit from the current run, or stop."""

    def decide(
        self,
        *,
        task: TaskEnvelope,
        observations: tuple[ReconObservation, ...],
        selectable_surface_ids: tuple[str, ...],
        remaining_budget: int,
        round_index: int,
    ) -> ReconAction: ...
