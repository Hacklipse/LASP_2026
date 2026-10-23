"""외부 실행을 정책·예산·Evidence 저장 경계 안에서 수행한다."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, quote, quote_plus, urlencode, urlsplit, urlunsplit
from uuid import uuid4

from hacklipse.domain import (
    AccessPrincipalRole,
    AgentResult,
    AgentResultStatus,
    Candidate,
    DomainInvariantError,
    Evidence,
    EvidenceRequest,
    ExecutionRequest,
    ExecutionResult,
    HttpRequestSpec,
    HttpRequestKind,
    Run,
    RunPhase,
    ServerRequestObservation,
    SsrfAssessment,
    SsrfCanaryProofTarget,
    SsrfDestinationPolicy,
    SsrfDestinationRule,
    SsrfExecutionApproval,
    SsrfObservationPhase,
    SsrfObservationProviderStatus,
    SsrfObservationSource,
    SsrfPolicyAssertion,
    SsrfPolicyEvidenceStatus,
    SsrfPolicySource,
    SsrfReviewRegistration,
    SsrfVerificationStrategy,
    TaskEnvelope,
)
from hacklipse.domain.url_redaction import ssrf_destination_reference_parts
from hacklipse.domain.models import ssrf_csv_upload_parameter, ssrf_request_parameters
from hacklipse.ports import (
    BudgetManager,
    EvidenceSanitizer,
    EvidenceStore,
    ExecutionAuditEvent,
    ExecutionAuditLog,
    ExecutionRuntime,
    OwnedSsrfReceiverService,
    PolicyGate,
    RunStore,
    SsrfCallbackService,
    SsrfCallbackHit,
    SsrfCallbackTicket,
    ServerRequestObservationProvider,
    SsrfReviewRegistry,
)
from hacklipse.ports.errors import (
    DuplicateRecord,
    ExternalExecutionDisabled,
    PolicyViolation,
    RecordNotFound,
)
from hacklipse.ports.ssrf_callback import callback_url_matches_origin

from .errors import AgentContractError


_SSRF_POLICY_EVIDENCE_TYPE = "ssrf_destination_policy_evidence"
_SSRF_POLICY_EVIDENCE_PRODUCERS = {
    SsrfPolicySource.CONFIG_ALLOWLIST:
        "execution_runtime:ssrf_config_policy_loader",
    SsrfPolicySource.OPENAPI_ALLOWLIST:
        "execution_runtime:ssrf_openapi_policy_loader",
}
_SSRF_SECRET_REDACTION = "<redacted-ssrf-verification>"
_SSRF_CAPABILITY_STRATEGIES = {
    "ssrf.callback_observed_url_query": SsrfVerificationStrategy.CALLBACK,
    "ssrf.callback_declared_url_query": SsrfVerificationStrategy.CALLBACK,
    "ssrf.callback_declared_url_json": SsrfVerificationStrategy.CALLBACK,
    "ssrf.callback_openapi_single_url_json": SsrfVerificationStrategy.CALLBACK,
    "ssrf.callback_graphql_url_query": SsrfVerificationStrategy.CALLBACK,
    "ssrf.callback_editor_catcher_query": SsrfVerificationStrategy.CALLBACK,
    "ssrf.internal_canary_observed_url_query": (
        SsrfVerificationStrategy.INTERNAL_CANARY
    ),
    "ssrf.internal_canary_declared_url_query": (
        SsrfVerificationStrategy.INTERNAL_CANARY
    ),
    "ssrf.internal_canary_editor_catcher_query": (
        SsrfVerificationStrategy.INTERNAL_CANARY
    ),
    "ssrf.internal_request_log_observed_url_query": (
        SsrfVerificationStrategy.OWNED_RECEIVER
    ),
    "ssrf.internal_request_log_declared_url_query": (
        SsrfVerificationStrategy.OWNED_RECEIVER
    ),
    "ssrf.internal_request_log_declared_url_json": (
        SsrfVerificationStrategy.OWNED_RECEIVER
    ),
    "ssrf.internal_request_log_openapi_single_url_json": (
        SsrfVerificationStrategy.OWNED_RECEIVER
    ),
    "ssrf.internal_request_log_graphql_url_query": (
        SsrfVerificationStrategy.OWNED_RECEIVER
    ),
    "ssrf.internal_request_log_editor_catcher_query": (
        SsrfVerificationStrategy.OWNED_RECEIVER
    ),
    "ssrf.internal_request_log_model_download_workflow": (
        SsrfVerificationStrategy.OWNED_RECEIVER
    ),
    "ssrf.internal_request_log_webhook_send_workflow": (
        SsrfVerificationStrategy.OWNED_RECEIVER
    ),
    "ssrf.internal_request_log_category_csv_workflow": (
        SsrfVerificationStrategy.OWNED_RECEIVER
    ),
}
_SSRF_ANALYSIS_STRATEGIES = {
    "observed_url_callback_probe": SsrfVerificationStrategy.CALLBACK,
    "declared_url_callback_probe": SsrfVerificationStrategy.CALLBACK,
    "declared_json_callback_probe": SsrfVerificationStrategy.CALLBACK,
    "declared_graphql_callback_probe": SsrfVerificationStrategy.CALLBACK,
    "observed_url_internal_canary_probe": (
        SsrfVerificationStrategy.INTERNAL_CANARY
    ),
    "declared_url_internal_canary_probe": (
        SsrfVerificationStrategy.INTERNAL_CANARY
    ),
    "observed_url_internal_request_log_probe": (
        SsrfVerificationStrategy.OWNED_RECEIVER
    ),
    "declared_url_internal_request_log_probe": (
        SsrfVerificationStrategy.OWNED_RECEIVER
    ),
    "declared_json_internal_request_log_probe": (
        SsrfVerificationStrategy.OWNED_RECEIVER
    ),
    "declared_graphql_internal_request_log_probe": (
        SsrfVerificationStrategy.OWNED_RECEIVER
    ),
    "declared_json_workflow_internal_request_log_probe": (
        SsrfVerificationStrategy.OWNED_RECEIVER
    ),
    "declared_json_webhook_internal_request_log_probe": (
        SsrfVerificationStrategy.OWNED_RECEIVER
    ),
    "declared_csv_image_internal_request_log_probe": (
        SsrfVerificationStrategy.OWNED_RECEIVER
    ),
}


def ssrf_candidate_verification_strategy(
    candidate: Candidate,
) -> SsrfVerificationStrategy:
    """Resolve one authoritative Candidate strategy and reject mixed contracts."""

    capability = _SSRF_CAPABILITY_STRATEGIES.get(candidate.routing_capability_id)
    analysis = _SSRF_ANALYSIS_STRATEGIES.get(candidate.analysis_strategy_id)
    if candidate.routing_capability_id and capability is None:
        raise AgentContractError("unsupported SSRF routing capability")
    if candidate.analysis_strategy_id and analysis is None:
        raise AgentContractError("unsupported SSRF analysis strategy")
    if capability is not None and analysis is not None and capability is not analysis:
        raise AgentContractError("SSRF Candidate mixes verification strategies")
    return capability or analysis or SsrfVerificationStrategy.PASSIVE


def _redact_exact_ssrf_values(value: object, secrets_to_remove: tuple[str, ...]) -> object:
    """Remove one-time callback material before general Evidence sanitization."""

    if isinstance(value, str):
        encoded_variants = {
            variant
            for secret in secrets_to_remove
            if secret
            for variant in (secret, quote(secret, safe=""), quote_plus(secret, safe=""))
        }
        for secret in sorted(encoded_variants, key=len, reverse=True):
            value = value.replace(secret, _SSRF_SECRET_REDACTION)
        return value
    if isinstance(value, dict):
        return {
            key: _redact_exact_ssrf_values(item, secrets_to_remove)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [
            _redact_exact_ssrf_values(item, secrets_to_remove)
            for item in value
        ]
    return value


def _redacted_ssrf_request_url(url: str) -> str:
    """Keep only the target coordinate shape, never callback/canary values."""

    parsed = urlsplit(url)
    query = urlencode(tuple(
        (name, _SSRF_SECRET_REDACTION)
        for name, _ in parse_qsl(parsed.query, keep_blank_values=True)
    ))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def _ssrf_marker_channel(observation: object, marker: str) -> str | None:
    """Return a closed proof channel without retaining a marker or header value."""

    if not isinstance(observation, dict):
        return None
    body = observation.get("body")
    if isinstance(body, str) and marker in body:
        return "body"
    header_values: list[str] = []
    for key in ("headers", "response_headers"):
        headers = observation.get(key)
        if isinstance(headers, dict):
            header_values.extend(
                value for value in headers.values() if isinstance(value, str)
            )
        elif isinstance(headers, (list, tuple)):
            header_values.extend(
                pair[1]
                for pair in headers
                if isinstance(pair, (list, tuple)) and len(pair) == 2
                and isinstance(pair[1], str)
            )
    location = observation.get("location")
    if isinstance(location, str):
        header_values.append(location)
    return "response_header" if any(marker in value for value in header_values) else None


class RuntimeEvidenceCollector:
    """모든 Runtime 결과를 먼저 Evidence로 바꾸는 정책 통제 Worker."""

    def __init__(
        self,
        *,
        run_store: RunStore,
        evidence_store: EvidenceStore,
        policy_gate: PolicyGate,
        budget_manager: BudgetManager,
        runtime: ExecutionRuntime,
        evidence_sanitizer: EvidenceSanitizer | None = None,
        audit_log: ExecutionAuditLog | None = None,
        id_factory: Callable[[], str] | None = None,
        default_approval_ref: str | None = None,
        evidence_projection: Callable[[ExecutionRequest, ExecutionResult], ExecutionResult] | None = None,
        ssrf_callback_service: SsrfCallbackService | None = None,
        ssrf_owned_receiver_service: OwnedSsrfReceiverService | None = None,
        ssrf_canary_proof: SsrfCanaryProofTarget | None = None,
        ssrf_observation_provider: ServerRequestObservationProvider | None = None,
        ssrf_review_registry: SsrfReviewRegistry | None = None,
    ) -> None:
        self._runs = run_store
        self._evidence = evidence_store
        self._policy = policy_gate
        self._budget = budget_manager
        self._runtime = runtime
        self._sanitizer = evidence_sanitizer
        self._audit = audit_log
        self._id_factory = id_factory or (lambda: str(uuid4()))
        self._default_approval_ref = default_approval_ref
        self._evidence_projection = evidence_projection
        self._ssrf_callback = ssrf_callback_service
        self._ssrf_owned_receiver = ssrf_owned_receiver_service
        self._ssrf_canary_proof = ssrf_canary_proof
        self._ssrf_run_canaries: dict[str, SsrfCanaryProofTarget] = {}
        self._ssrf_run_hash_keys: dict[str, bytes] = {}
        self._ssrf_observations = ssrf_observation_provider
        self._ssrf_reviews = ssrf_review_registry
        self._ssrf_issued: dict[str, SsrfCallbackTicket] = {}
        self._ssrf_issued_by_run: dict[str, set[str]] = {}
        self._ssrf_owned_issued: dict[str, SsrfCallbackTicket] = {}
        self._ssrf_owned_issued_by_run: dict[str, set[str]] = {}
        self._ssrf_issue_calls = 0
        self._ssrf_poll_calls = 0
        self._ssrf_owned_issue_calls = 0
        self._ssrf_owned_poll_calls = 0

    def _ssrf_run_hmac(self, run_id: str, *parts: str) -> str:
        """Return a retry-stable digest that cannot be guessed from public fields."""

        key = self._ssrf_run_hash_keys.setdefault(run_id, secrets.token_bytes(32))
        return hmac.new(
            key, "\0".join(parts).encode("utf-8"), hashlib.sha256,
        ).hexdigest()

    def ssrf_run_fingerprint(
        self, run_id: str, purpose: str, material: bytes,
    ) -> str:
        """HMAC private material without exposing the per-Run key."""

        if not run_id or not purpose or not isinstance(material, bytes):
            raise ValueError("SSRF Run fingerprint input is invalid")
        key = self._ssrf_run_hash_keys.setdefault(run_id, secrets.token_bytes(32))
        return hmac.new(
            key,
            purpose.encode("utf-8") + b"\0" + material,
            hashlib.sha256,
        ).hexdigest()

    @property
    def ssrf_enabled(self) -> bool:
        return self._ssrf_callback is not None

    @property
    def ssrf_owned_receiver_enabled(self) -> bool:
        return self._ssrf_owned_receiver is not None

    @property
    def ssrf_canary_proof(self) -> SsrfCanaryProofTarget | None:
        return self._ssrf_canary_proof

    def ssrf_canary_proof_for_run(self, run_id: str) -> SsrfCanaryProofTarget | None:
        return self._ssrf_run_canaries.get(run_id, self._ssrf_canary_proof)

    def ssrf_verification_endpoint_ref(self, run_id: str, url: str) -> str:
        """Return a run-local opaque approval ref, not a guessable URL digest."""

        return "endpoint-" + self._ssrf_run_hmac(
            run_id, "verification-endpoint", url,
        )[:32]

    def ssrf_owned_receiver_endpoint_ref(self, run_id: str) -> str:
        """Return the protected ref for the explicitly injected receiver origin."""

        receiver = self._ssrf_owned_receiver
        if receiver is None:
            raise ExternalExecutionDisabled("SSRF owned receiver is not configured")
        return self.ssrf_verification_endpoint_ref(run_id, receiver.origin)

    @property
    def ssrf_owned_receiver_origin(self) -> str | None:
        """Expose the configured origin only to the trusted review controller."""

        receiver = self._ssrf_owned_receiver
        return receiver.origin if receiver is not None else None

    def register_ssrf_canary_proof(
        self, run_id: str, canary: SsrfCanaryProofTarget,
    ) -> None:
        """Bind one exact approved endpoint to its reviewed Run in memory."""

        registration = self.ssrf_review_for_surface(
            run_id, canary.surface_id,
            SsrfVerificationStrategy.INTERNAL_CANARY,
        )
        if (
            registration is None
            or registration.execution_approval.verification_endpoint_ref
            != self.ssrf_verification_endpoint_ref(run_id, canary.url)
        ):
            raise AgentContractError("SSRF canary does not match the approved Run review")
        self._validate_ssrf_destination_binding(
            registration, approved_destination_url=canary.url,
        )
        existing = self._ssrf_run_canaries.get(run_id)
        if existing is not None and existing != canary:
            raise AgentContractError("SSRF canary was already bound to this Run")
        self._ssrf_run_canaries[run_id] = canary

    def discard_ssrf_run_secrets(self, run_id: str) -> None:
        """Forget exact SSRF endpoints and one-time tickets after a terminal Run."""

        if self._runs.get(run_id).phase not in {RunPhase.DONE, RunPhase.FAILED}:
            raise AgentContractError("SSRF Run secrets cannot be discarded before termination")
        self._ssrf_run_canaries.pop(run_id, None)
        self._ssrf_run_hash_keys.pop(run_id, None)
        # The constructor fallback is a legacy single-Run test hook. Once that
        # Run is terminal it must not keep the exact endpoint or marker alive.
        self._ssrf_canary_proof = None
        keys = self._ssrf_issued_by_run.pop(run_id, set())
        tickets = tuple(
            ticket
            for key in keys
            if (ticket := self._ssrf_issued.pop(key, None)) is not None
        )
        owned_keys = self._ssrf_owned_issued_by_run.pop(run_id, set())
        owned_tickets = tuple(
            ticket
            for key in owned_keys
            if (ticket := self._ssrf_owned_issued.pop(key, None)) is not None
        )
        for service, issued in (
            (self._ssrf_callback, tickets),
            (self._ssrf_owned_receiver, owned_tickets),
        ):
            discard = getattr(service, "discard", None)
            if discard is None:
                continue
            for token in dict.fromkeys(ticket.token for ticket in issued):
                try:
                    discard(token)
                except Exception:
                    # Local references are gone. Provider close() remains the
                    # lifecycle backstop for third-party adapters.
                    continue

    @property
    def ssrf_callback_usage(self) -> tuple[int, int]:
        """Provider issue/poll calls, separate from target HTTP request budget."""

        return self._ssrf_issue_calls, self._ssrf_poll_calls

    @property
    def ssrf_callback_poll_wait_seconds(self) -> float:
        """Remote OAST may need longer than the local callback receiver."""

        return min(10.0, getattr(self._ssrf_callback, "poll_wait_seconds", 2.0))

    @property
    def ssrf_owned_receiver_usage(self) -> tuple[int, int]:
        return self._ssrf_owned_issue_calls, self._ssrf_owned_poll_calls

    @property
    def ssrf_owned_receiver_poll_wait_seconds(self) -> float:
        return min(
            10.0,
            getattr(self._ssrf_owned_receiver, "poll_wait_seconds", 2.0),
        )

    @property
    def ssrf_observation_enabled(self) -> bool:
        return self._ssrf_observations is not None

    @property
    def ssrf_review_registry(self) -> SsrfReviewRegistry | None:
        return self._ssrf_reviews

    def register_ssrf_review(
        self,
        *,
        run_id: str,
        parameter: str,
        hint_evidence_id: str | None,
        approval: SsrfExecutionApproval,
        verification_strategy: SsrfVerificationStrategy,
        destination_policy: SsrfDestinationPolicy | None = None,
        hint_use_approved: bool = False,
        approved_destination_url: str | None = None,
    ) -> SsrfReviewRegistration:
        """Register one store-verified, exact post-Recon review coordinate."""

        if self._ssrf_reviews is None:
            raise ExternalExecutionDisabled("SSRF review registry is not configured")
        registration = SsrfReviewRegistration(
            run_id=run_id,
            parameter=parameter,
            hint_evidence_id=hint_evidence_id,
            execution_approval=approval,
            destination_policy=destination_policy,
            hint_use_approved=hint_use_approved,
            verification_strategy=verification_strategy,
        )
        run = self._validate_ssrf_review_registration(registration)
        self._validate_ssrf_destination_binding(
            registration, approved_destination_url=approved_destination_url,
        )
        registration_evidence_id = self._store_ssrf_review_registration(registration)
        try:
            self._ssrf_reviews.register(registration)
        except (TypeError, ValueError) as error:
            raise AgentContractError("SSRF review registration conflicts with this Run") from error
        profile = replace(
            run.execution_profile,
            ssrf_execution_approval_registered=True,
            ssrf_destination_policy_registered=(
                run.execution_profile.ssrf_destination_policy_registered
                or destination_policy is not None
            ),
            ssrf_destination_policy_source=(
                destination_policy.source_type
                if destination_policy is not None
                else run.execution_profile.ssrf_destination_policy_source
            ),
        )
        self._runs.save(run.with_updates(
            execution_profile=profile,
            evidence_ids=tuple(dict.fromkeys((
                *run.evidence_ids, registration_evidence_id,
            ))),
        ))
        return registration

    def _validate_ssrf_destination_binding(
        self,
        registration: SsrfReviewRegistration,
        *,
        approved_destination_url: str | None,
    ) -> None:
        """Bind an exact operator URL to a selected Recon hint without storing it."""

        if approved_destination_url is not None:
            expected_ref = self.ssrf_verification_endpoint_ref(
                registration.run_id, approved_destination_url,
            )
            if not hmac.compare_digest(
                registration.execution_approval.verification_endpoint_ref,
                expected_ref,
            ):
                raise AgentContractError(
                    "SSRF approved destination does not match its protected reference"
                )
        if not registration.hint_use_approved:
            return
        if approved_destination_url is None or registration.hint_evidence_id is None:
            raise AgentContractError(
                "SSRF destination hint use requires the exact approved URL"
            )
        try:
            hint = self._evidence.get(
                registration.run_id, registration.hint_evidence_id,
            )
        except RecordNotFound as error:
            raise AgentContractError("SSRF destination hint is unavailable") from error
        observation = hint.observation
        if (
            hint.created_by != "recon"
            or observation.get("type") != "ssrf_destination_hint"
            or observation.get("probe_authorized") is not False
        ):
            raise AgentContractError(
                "SSRF hint-use approval requires an unexecuted Recon destination hint"
            )
        parts = ssrf_destination_reference_parts(approved_destination_url)
        fingerprint = observation.get("destination_fingerprint")
        if parts is None or not isinstance(fingerprint, str):
            raise AgentContractError("SSRF destination hint cannot be bound safely")
        origin, path_hint, material = parts
        expected_fingerprint = self.ssrf_run_fingerprint(
            registration.run_id, "destination-hint", material,
        )
        if (
            observation.get("destination_origin") != origin
            or observation.get("path_hint") != path_hint
            or not hmac.compare_digest(fingerprint, expected_fingerprint)
        ):
            raise AgentContractError(
                "SSRF approved destination does not match the selected Recon hint"
            )

    def restore_ssrf_review(
        self, run_id: str,
        strategy: SsrfVerificationStrategy | None = None,
    ) -> SsrfReviewRegistration | None:
        """Hydrate staged registrations from sanitized central Evidence records."""

        if self._ssrf_reviews is None:
            return None
        existing = self._ssrf_reviews.get_for_run(run_id, strategy)
        if strategy is not None and existing is not None:
            return existing
        stored = tuple(
            item for item in self._evidence.list_by_run(run_id)
            if item.created_by == "execution_runtime:ssrf_review_registry"
            and item.evidence_type == "observation"
            and item.validation_id is None
            and item.observation.get("type") == "ssrf_review_registration"
        )
        if not stored:
            return existing
        restored: list[SsrfReviewRegistration] = []
        run = self._runs.get(run_id)
        evidence_ids = list(run.evidence_ids)
        profile = run.execution_profile
        for item in stored:
            registration = self._registration_from_evidence(item)
            if strategy is not None and registration.verification_strategy is not strategy:
                continue
            self._validate_ssrf_review_registration(registration)
            try:
                self._ssrf_reviews.register(registration)
            except (TypeError, ValueError) as error:
                raise AgentContractError(
                    "persisted SSRF review conflicts with this Run"
                ) from error
            policy = registration.destination_policy
            profile = replace(
                profile,
                ssrf_execution_approval_registered=True,
                ssrf_destination_policy_registered=(
                    profile.ssrf_destination_policy_registered or policy is not None
                ),
                ssrf_destination_policy_source=(
                    policy.source_type
                    if policy is not None else profile.ssrf_destination_policy_source
                ),
            )
            evidence_ids.append(item.evidence_id)
            restored.append(registration)
        if restored:
            self._runs.save(run.with_updates(
                execution_profile=profile,
                evidence_ids=tuple(dict.fromkeys(evidence_ids)),
            ))
        if strategy is not None:
            return self._ssrf_reviews.get_for_run(run_id, strategy)
        registrations = self._ssrf_reviews.list_for_run(run_id)
        return registrations[0] if len(registrations) == 1 else None

    def ssrf_review_for_surface(
        self, run_id: str, surface_id: str,
        strategy: SsrfVerificationStrategy | None = None,
    ) -> SsrfReviewRegistration | None:
        if self._ssrf_reviews is None:
            return None
        registration = self._ssrf_reviews.get_for_surface(
            run_id=run_id, surface_id=surface_id, strategy=strategy,
        )
        if registration is not None:
            return registration
        self.restore_ssrf_review(run_id, strategy)
        return self._ssrf_reviews.get_for_surface(
            run_id=run_id, surface_id=surface_id, strategy=strategy,
        )

    def _validate_ssrf_review_registration(
        self, registration: SsrfReviewRegistration,
    ) -> Run:
        approval = registration.execution_approval
        references = (
            ("approval id", approval.approval_id),
            ("verification endpoint", approval.verification_endpoint_ref),
            ("approval principal", approval.approved_by),
        )
        if registration.destination_policy is not None:
            policy = registration.destination_policy
            references = (*references,
                ("policy id", policy.policy_id),
                ("policy source", policy.source_reference),
                ("policy principal", policy.approved_by),
            )
        for label, value in references:
            lowered = value.casefold()
            if (
                "://" in value
                or "/" in value
                or "?" in value
                or "@" in value
                or lowered.startswith(("http:", "https:"))
            ):
                raise AgentContractError(
                    f"SSRF review {label} must be an opaque reference"
                )
        disallowed = registration.hint_evidence_id
        if disallowed is not None and any(
            value == disallowed for _, value in references
        ):
            raise AgentContractError(
                "SSRF review hint Evidence id cannot stand in for an approval or policy"
            )
        run = self._runs.get(registration.run_id)
        surface_id = registration.surface_id
        if surface_id not in run.surface_ids:
            raise AgentContractError("SSRF review Surface is not registered in this Run")
        review_evidence = tuple(
            item for item in self._evidence.list_by_run(registration.run_id)
            if item.surface_id == surface_id
            and item.created_by == "recon"
            and item.observation.get("type") == "ssrf_url_fetch_review"
            and isinstance(
                item.observation.get("parameter_names"), (list, tuple),
            )
            and registration.parameter in item.observation.get("parameter_names", ())
        )
        if not review_evidence:
            raise AgentContractError(
                "SSRF review parameter was not recorded by passive Recon"
            )
        if registration.hint_evidence_id is not None:
            hint = self._evidence.get(
                registration.run_id, registration.hint_evidence_id,
            )
            if (
                hint.run_id != registration.run_id
                or hint.created_by != "recon"
                or hint.observation.get("type")
                not in {"ssrf_destination_hint", "ssrf_url_fetch_review"}
            ):
                raise AgentContractError(
                    "SSRF review hint is not sanitized Recon Evidence for this Run"
                )
            if (
                registration.hint_use_approved
                and hint.observation.get("type") != "ssrf_destination_hint"
            ):
                raise AgentContractError(
                    "SSRF execution can only bind a Recon destination hint"
                )
        self._validate_ssrf_destination_policy_evidence(registration)
        return run

    def _validate_ssrf_destination_policy_evidence(
        self, registration: SsrfReviewRegistration,
    ) -> None:
        """Require config/OpenAPI policy claims to name matching trusted Evidence.

        Operator attestations are themselves the trust source. A config or
        OpenAPI label, however, is only a claim until a dedicated trusted loader
        has stored the concrete destination restriction in the current Run.
        This prevents a caller from upgrading an arbitrary prefixed string to a
        CONFIRMED SSRF policy.
        """

        policy = registration.destination_policy
        if policy is None or policy.source_type is SsrfPolicySource.OPERATOR_ATTESTATION:
            return
        expected_producer = _SSRF_POLICY_EVIDENCE_PRODUCERS.get(policy.source_type)
        prefix = {
            SsrfPolicySource.CONFIG_ALLOWLIST: "config:",
            SsrfPolicySource.OPENAPI_ALLOWLIST: "openapi:",
        }.get(policy.source_type)
        if expected_producer is None or prefix is None:
            raise AgentContractError("SSRF destination policy source is unsupported")
        evidence_id = policy.source_reference.removeprefix(prefix)
        if not evidence_id or prefix + evidence_id != policy.source_reference:
            raise AgentContractError(
                "SSRF destination policy must reference trusted source Evidence"
            )
        try:
            source = self._evidence.get(registration.run_id, evidence_id)
        except RecordNotFound as error:
            raise AgentContractError(
                "SSRF destination policy source Evidence is unavailable"
            ) from error
        observation = source.observation
        expected = {
            "type": _SSRF_POLICY_EVIDENCE_TYPE,
            "source_type": policy.source_type.value,
            "surface_ids": list(policy.surface_ids),
            "destination_origin": policy.destination_origin,
            "destination_rule": policy.destination_rule.value,
            "assertion": policy.assertion.value if policy.assertion is not None else None,
            "evidence_status": SsrfPolicyEvidenceStatus.VERIFIED.value,
        }
        if (
            source.evidence_type != "observation"
            or source.validation_id is not None
            or source.created_by != expected_producer
            or source.surface_id != registration.surface_id
            or any(observation.get(key) != value for key, value in expected.items())
        ):
            raise AgentContractError(
                "SSRF destination policy source Evidence does not match the policy"
            )

    def _store_ssrf_review_registration(
        self, registration: SsrfReviewRegistration,
    ) -> str:
        approval = registration.execution_approval
        policy = registration.destination_policy
        observation: dict[str, object] = {
            "type": "ssrf_review_registration",
            "parameter": registration.parameter,
            "hint_evidence_id": registration.hint_evidence_id,
            "hint_use_approved": registration.hint_use_approved,
            "verification_strategy": registration.verification_strategy.value,
            "approval_id": approval.approval_id,
            "verification_endpoint_ref": approval.verification_endpoint_ref,
            "approved_by": approval.approved_by,
            "approved_at": approval.approved_at.isoformat(),
            "approval_scope": approval.scope,
            "policy_id": policy.policy_id if policy is not None else None,
        }
        if policy is not None:
            observation.update({
                "policy_surface_ids": list(policy.surface_ids),
                "destination_origin": policy.destination_origin or None,
                "destination_rule": policy.destination_rule.value,
                "policy_assertion": (
                    policy.assertion.value if policy.assertion is not None else None
                ),
                "policy_source": policy.source_type.value,
                "policy_source_reference": policy.source_reference,
                "policy_approved_by": policy.approved_by,
                "policy_created_at": policy.created_at.isoformat(),
                "policy_evidence_status": (
                    policy.evidence_status.value
                    if policy.evidence_status is not None else None
                ),
            })
        digest = hashlib.sha256("\0".join((
            registration.run_id, registration.verification_strategy.value,
        )).encode()).hexdigest()
        item = Evidence(
            evidence_id=f"evi-ssrf-review-registration-{digest[:32]}",
            run_id=registration.run_id,
            surface_id=registration.surface_id,
            created_by="execution_runtime:ssrf_review_registry",
            evidence_type="observation",
            observation=observation,
        )
        return self._append_or_reuse_ssrf_evidence(item)

    def _registration_from_evidence(self, item: Evidence) -> SsrfReviewRegistration:
        data = item.observation
        try:
            approval = SsrfExecutionApproval(
                approval_id=str(data["approval_id"]),
                surface_id=str(item.surface_id),
                verification_endpoint_ref=str(data["verification_endpoint_ref"]),
                approved_by=str(data["approved_by"]),
                approved_at=datetime.fromisoformat(str(data["approved_at"])),
                scope=str(data["approval_scope"]),
            )
            policy_id = data.get("policy_id")
            policy = None
            if policy_id is not None:
                stored_surface_ids = data.get("policy_surface_ids")
                surface_ids = (
                    tuple(str(value) for value in stored_surface_ids)
                    if isinstance(stored_surface_ids, (list, tuple))
                    else (str(item.surface_id),)
                )
                assertion = data.get("policy_assertion")
                evidence_status = data.get("policy_evidence_status")
                policy = SsrfDestinationPolicy(
                    policy_id=str(policy_id),
                    surface_ids=surface_ids,
                    destination_origin=(
                        "" if data.get("destination_origin") is None
                        else str(data["destination_origin"])
                    ),
                    destination_rule=SsrfDestinationRule(
                        str(data["destination_rule"])
                    ),
                    assertion=(
                        None if assertion is None
                        else SsrfPolicyAssertion(str(assertion))
                    ),
                    source_type=SsrfPolicySource(str(data["policy_source"])),
                    source_reference=str(data["policy_source_reference"]),
                    approved_by=str(data["policy_approved_by"]),
                    created_at=datetime.fromisoformat(
                        str(data["policy_created_at"])
                    ),
                    evidence_status=(
                        None if evidence_status is None
                        else SsrfPolicyEvidenceStatus(str(evidence_status))
                    ),
                )
            hint_use_approved = data.get("hint_use_approved", False)
            if type(hint_use_approved) is not bool:
                raise TypeError("persisted SSRF hint-use approval is invalid")
            verification_strategy = (
                SsrfVerificationStrategy.PASSIVE
                if "verification_strategy" not in data
                else SsrfVerificationStrategy(str(data["verification_strategy"]))
            )
            registration = SsrfReviewRegistration(
                run_id=item.run_id,
                parameter=str(data["parameter"]),
                hint_evidence_id=(
                    None if data.get("hint_evidence_id") is None
                    else str(data["hint_evidence_id"])
                ),
                execution_approval=approval,
                destination_policy=policy,
                hint_use_approved=hint_use_approved,
                verification_strategy=verification_strategy,
            )
        except (KeyError, TypeError, ValueError, DomainInvariantError) as error:
            raise AgentContractError("persisted SSRF review Evidence is invalid") from error
        digest = hashlib.sha256("\0".join((
            item.run_id, registration.verification_strategy.value,
        )).encode()).hexdigest()
        legacy_digest = hashlib.sha256(item.run_id.encode()).hexdigest()
        if (
            item.evidence_id not in {
                f"evi-ssrf-review-registration-{digest[:32]}",
                f"evi-ssrf-review-registration-{legacy_digest[:32]}",
            }
            or item.surface_id != registration.surface_id
        ):
            raise AgentContractError("persisted SSRF review Evidence identity changed")
        return registration

    def collect_server_request_observations(
        self,
        *,
        run_id: str,
        surface_id: str,
        parameter: str,
        task_id: str,
        validation_id: str | None = None,
        strategy: SsrfVerificationStrategy = SsrfVerificationStrategy.PASSIVE,
    ) -> tuple[
        SsrfObservationProviderStatus,
        tuple[ServerRequestObservation, ...],
        dict[str, str],
    ]:
        """Import sanitized provider records through the central Evidence boundary."""

        registration = self.ssrf_review_for_surface(run_id, surface_id, strategy)
        if registration is None or registration.parameter != parameter:
            raise AgentContractError("SSRF observation import lacks an exact review registration")
        run = self._runs.get(run_id)
        if surface_id not in run.surface_ids:
            raise AgentContractError("SSRF observation Surface is not registered in this Run")
        approval = registration.execution_approval
        existing, mapping = self._stored_server_request_observations(
            run_id=run_id,
            surface_id=surface_id,
            parameter=parameter,
            approval=approval,
            validation_id=validation_id,
        )
        has_analysis = any(
            item.phase is SsrfObservationPhase.ANALYSIS for item in existing
        )
        has_validation = validation_id is None or any(
            item.phase is SsrfObservationPhase.VALIDATION
            and item.verification_session_id == validation_id
            for item in existing
        )
        if has_analysis and has_validation:
            return SsrfObservationProviderStatus.AVAILABLE, existing, mapping

        provider = self._ssrf_observations
        if provider is None:
            return SsrfObservationProviderStatus.UNAVAILABLE, existing, mapping
        status = provider.status
        if not isinstance(status, SsrfObservationProviderStatus):
            raise AgentContractError("SSRF observation provider returned an invalid status")
        if status is SsrfObservationProviderStatus.UNAVAILABLE:
            return status, existing, mapping
        supplied = tuple(provider.list_observations(
            run_id=run_id, surface_id=surface_id, parameter=parameter,
        ))
        if len(supplied) > 8:
            raise AgentContractError("SSRF observation provider exceeded the coordinate limit")
        now = datetime.now(timezone.utc)
        imported = list(existing)
        for observation in supplied:
            if not isinstance(observation, ServerRequestObservation) or (
                observation.run_id != run_id
                or observation.surface_id != surface_id
                or observation.parameter != parameter
            ):
                raise AgentContractError("SSRF provider returned a foreign observation")
            if observation.phase is SsrfObservationPhase.VALIDATION and (
                validation_id is None
                or observation.verification_session_id != validation_id
            ):
                continue
            if observation.phase is SsrfObservationPhase.ANALYSIS and validation_id is None:
                pass
            elif observation.phase is SsrfObservationPhase.ANALYSIS:
                pass
            elif validation_id is None:
                continue
            if observation.verification_endpoint_ref != approval.verification_endpoint_ref:
                raise AgentContractError("SSRF observation endpoint does not match approval")
            if not observation.source_verified:
                raise AgentContractError("SSRF observation source is not verified")
            if observation.source_type is not SsrfObservationSource.OPERATOR_OWNED_SERVICE:
                raise AgentContractError("SSRF observation source is not operator-owned")
            if (
                observation.observed_at < approval.approved_at
                or observation.observed_at > now + timedelta(seconds=5)
            ):
                raise AgentContractError("SSRF observation timestamp is outside approval")
            central_id = self._store_server_request_observation(
                observation,
                task_id=task_id,
                validation_id=(
                    validation_id
                    if observation.phase is SsrfObservationPhase.VALIDATION
                    else None
                ),
                approval_id=approval.approval_id,
            )
            protected_observation = self._protected_server_request_observation(
                observation,
            )
            previous = mapping.get(protected_observation.observation_id)
            if previous is not None and previous != central_id:
                raise AgentContractError("SSRF observation mapping changed")
            mapping[protected_observation.observation_id] = central_id
            if protected_observation not in imported:
                imported.append(protected_observation)
        return status, tuple(sorted(
            imported, key=lambda item: (item.observed_at, item.observation_id)
        )), mapping

    def record_ssrf_assessment(
        self,
        *,
        run_id: str,
        surface_id: str,
        parameter: str,
        task_id: str,
        validation_id: str,
        assessment: SsrfAssessment,
        observation_evidence_ids: dict[str, str],
        strategy: SsrfVerificationStrategy = SsrfVerificationStrategy.PASSIVE,
    ) -> str:
        """Persist policy provenance as current-session central Evidence."""

        registration = self.ssrf_review_for_surface(run_id, surface_id, strategy)
        if registration is None or registration.parameter != parameter:
            raise AgentContractError("SSRF assessment lacks an exact review registration")
        if not set(assessment.observation_ids).issubset(observation_evidence_ids):
            raise AgentContractError(
                "SSRF assessment references unmapped provider observation ids"
            )
        policy = registration.destination_policy
        if (
            assessment.policy_id is not None
            and (policy is None or assessment.policy_id != policy.policy_id)
        ):
            raise AgentContractError("SSRF assessment policy provenance changed")
        central_ids = tuple(
            observation_evidence_ids[item]
            for item in assessment.observation_ids
        )
        digest = hashlib.sha256("\0".join((
            run_id,
            surface_id,
            parameter,
            validation_id,
            assessment.verdict.value,
            assessment.reason_code.value,
            assessment.policy_id or "",
            *central_ids,
        )).encode()).hexdigest()
        evidence_id = f"evi-ssrf-assessment-{digest[:32]}"
        observation: dict[str, object] = {
            "type": "ssrf_assessment_result",
            "parameter": parameter,
            "verdict": assessment.verdict.value,
            "reason_code": assessment.reason_code.value,
            "approval_id": registration.execution_approval.approval_id,
            "verification_endpoint_ref": (
                registration.execution_approval.verification_endpoint_ref
            ),
            "observation_evidence_ids": list(central_ids),
            "policy_id": assessment.policy_id,
        }
        if policy is not None:
            observation.update({
                "destination_rule": policy.destination_rule.value,
                "policy_source": policy.source_type.value,
                "policy_source_reference": policy.source_reference,
            })
        item = Evidence(
            evidence_id=evidence_id,
            run_id=run_id,
            surface_id=surface_id,
            created_by="execution_runtime:ssrf_observation_provider",
            evidence_type="observation",
            source_task_id=task_id,
            validation_id=validation_id,
            observation=observation,
        )
        return self._append_or_reuse_ssrf_evidence(item)

    def _stored_server_request_observations(
        self,
        *,
        run_id: str,
        surface_id: str,
        parameter: str,
        approval: SsrfExecutionApproval,
        validation_id: str | None,
    ) -> tuple[tuple[ServerRequestObservation, ...], dict[str, str]]:
        restored: list[ServerRequestObservation] = []
        mapping: dict[str, str] = {}
        now = datetime.now(timezone.utc)
        for item in self._evidence.list_by_run(run_id):
            data = item.observation
            if (
                item.surface_id != surface_id
                or item.created_by != "execution_runtime:ssrf_observation_provider"
                or data.get("type") != "ssrf_server_request_observation"
                or data.get("parameter") != parameter
                or data.get("verification_endpoint_ref")
                != approval.verification_endpoint_ref
            ):
                continue
            try:
                phase = SsrfObservationPhase(str(data.get("phase")))
                observation = ServerRequestObservation(
                    observation_id=str(data["provider_observation_id"]),
                    run_id=run_id,
                    surface_id=surface_id,
                    parameter=parameter,
                    verification_endpoint_ref=str(data["verification_endpoint_ref"]),
                    verification_session_id=str(data["verification_session_id"]),
                    phase=phase,
                    observed_at=datetime.fromisoformat(str(data["observed_at"])),
                    source_verified=data.get("source_verified") is True,
                    destination_origin=str(data.get("destination_origin") or ""),
                    request_method=str(data.get("request_method")),
                    source_type=SsrfObservationSource(str(data.get("source_type"))),
                )
            except (KeyError, TypeError, ValueError, DomainInvariantError) as error:
                raise AgentContractError("stored SSRF observation Evidence is invalid") from error
            if (
                item.evidence_type != "observation"
                or item.source_task_id is None
                or data.get("approval_id") != approval.approval_id
                or observation.observed_at < approval.approved_at
                or observation.observed_at > now + timedelta(seconds=5)
                or not observation.source_verified
                or observation.source_type
                is not SsrfObservationSource.OPERATOR_OWNED_SERVICE
            ):
                raise AgentContractError(
                    "stored SSRF observation Evidence failed provenance validation"
                )
            if phase is SsrfObservationPhase.VALIDATION:
                if validation_id is None or item.validation_id != validation_id:
                    continue
                if observation.verification_session_id != validation_id:
                    raise AgentContractError(
                        "stored SSRF validation observation has another session"
                    )
            elif item.validation_id is not None:
                raise AgentContractError("analysis SSRF observation has validation provenance")
            if data.get("observation_mode") == "owned_receiver":
                probe_evidence_id = data.get("probe_evidence_id")
                if not isinstance(probe_evidence_id, str) or not probe_evidence_id:
                    raise AgentContractError(
                        "owned SSRF observation lacks its probe Evidence"
                    )
                try:
                    probe = self._evidence.get(run_id, probe_evidence_id)
                except RecordNotFound as error:
                    raise AgentContractError(
                        "owned SSRF observation probe Evidence is unavailable"
                    ) from error
                probe_started_at = probe.observation.get("execution_started_at")
                if (
                    probe.surface_id != surface_id
                    or probe.created_by not in {
                        "execution_runtime:http_get", "execution_runtime:http_post",
                    }
                    or probe.source_task_id is None
                    or probe.validation_id != item.validation_id
                    or probe.observation.get("request_kind")
                    not in {
                        HttpRequestKind.SSRF_OWNED_RECEIVER_PROBE.value,
                        HttpRequestKind.SSRF_WORKFLOW_OWNED_PROBE.value,
                        HttpRequestKind.SSRF_CSV_UPLOAD_PROBE.value,
                    }
                    or not isinstance(probe_started_at, str)
                    or datetime.fromisoformat(probe_started_at) > observation.observed_at
                ):
                    raise AgentContractError(
                        "owned SSRF observation probe provenance is invalid"
                    )
            elif data.get("observation_mode") not in {None, "manual_provider"}:
                raise AgentContractError("stored SSRF observation mode is invalid")
            if item.evidence_id != self._server_request_observation_evidence_id(observation):
                raise AgentContractError("stored SSRF observation Evidence identity changed")
            previous = mapping.get(observation.observation_id)
            if previous is not None and previous != item.evidence_id:
                raise AgentContractError("stored SSRF observation mapping is ambiguous")
            restored.append(observation)
            mapping[observation.observation_id] = item.evidence_id
        return tuple(restored), mapping

    def _store_server_request_observation(
        self,
        observation: ServerRequestObservation,
        *,
        task_id: str,
        validation_id: str | None,
        approval_id: str,
        probe_evidence_id: str | None = None,
        observation_mode: str = "manual_provider",
    ) -> str:
        if observation_mode not in {"manual_provider", "owned_receiver"}:
            raise AgentContractError("SSRF observation mode is unsupported")
        if observation_mode == "owned_receiver" and not probe_evidence_id:
            raise AgentContractError("owned SSRF observation requires probe Evidence")
        protected_observation = self._protected_server_request_observation(
            observation,
        )
        stored_observation: dict[str, object] = {
            "type": "ssrf_server_request_observation",
            "provider_observation_id": protected_observation.observation_id,
            "parameter": observation.parameter,
            "phase": observation.phase.value,
            "verification_endpoint_ref": observation.verification_endpoint_ref,
            "verification_session_id": observation.verification_session_id,
            "observed_at": observation.observed_at.isoformat(),
            "request_method": observation.request_method,
            "source_type": observation.source_type.value,
            "source_verified": True,
            "destination_origin": observation.destination_origin or None,
            "approval_id": approval_id,
        }
        if observation_mode == "owned_receiver":
            stored_observation.update({
                "observation_mode": observation_mode,
                "probe_evidence_id": probe_evidence_id,
            })
        item = Evidence(
            evidence_id=self._server_request_observation_evidence_id(
                protected_observation,
            ),
            run_id=observation.run_id,
            surface_id=observation.surface_id,
            created_by="execution_runtime:ssrf_observation_provider",
            evidence_type="observation",
            source_task_id=task_id,
            validation_id=validation_id,
            observation=stored_observation,
        )
        return self._append_or_reuse_ssrf_evidence(item)

    def _protected_server_request_observation(
        self, observation: ServerRequestObservation,
    ) -> ServerRequestObservation:
        """Replace a provider-local identifier before it crosses the collector."""

        return replace(
            observation,
            observation_id="provider:" + self._ssrf_run_hmac(
                observation.run_id,
                "provider-observation-id",
                observation.observation_id,
            )[:24],
        )

    @staticmethod
    def _server_request_observation_evidence_id(
        observation: ServerRequestObservation,
    ) -> str:
        digest = hashlib.sha256("\0".join((
            observation.run_id,
            observation.surface_id,
            observation.parameter,
            observation.verification_endpoint_ref,
            observation.verification_session_id,
            observation.phase.value,
            observation.observation_id,
        )).encode()).hexdigest()
        return f"evi-ssrf-observation-{digest[:32]}"

    def _append_or_reuse_ssrf_evidence(self, expected: Evidence) -> str:
        try:
            existing = self._evidence.get(expected.run_id, expected.evidence_id)
        except RecordNotFound:
            try:
                self._evidence.append(expected)
                return expected.evidence_id
            except DuplicateRecord:
                existing = self._evidence.get(expected.run_id, expected.evidence_id)
        if (
            existing.run_id != expected.run_id
            or existing.surface_id != expected.surface_id
            or existing.created_by != expected.created_by
            or existing.evidence_type != expected.evidence_type
            or existing.validation_id != expected.validation_id
            or dict(existing.observation) != dict(expected.observation)
        ):
            raise AgentContractError("SSRF Evidence id already has different content")
        return existing.evidence_id

    def issue_ssrf_ticket(
        self, run_id: str, candidate_id: str, parameter: str, *,
        validation_id: str | None = None,
    ) -> SsrfCallbackTicket:
        """Run/Candidate/입력 좌표/Validation에 묶인 일회성 URL을 발급한다."""

        run = self._runs.get(run_id)
        base_parameter = parameter[:-2] if parameter.endswith("[]") else parameter
        if not base_parameter or len(parameter) > 128 or not parameter.isascii() or not all(
            char.isalnum() or char in "_-" for char in base_parameter
        ):
            raise AgentContractError("SSRF ticket requires a safe observed parameter name")
        service = self._ssrf_callback
        if service is None:
            raise ExternalExecutionDisabled("SSRF callback service is not configured")
        public_oast = getattr(service, "public_oast", None)
        if type(public_oast) is not bool:
            raise AgentContractError(
                "SSRF callback service must declare whether it is a public OAST"
            )
        profile = run.execution_profile
        if public_oast and not (
            profile.recorded
            and profile.ssrf_oast_mode == "public_interactsh"
            and profile.ssrf_public_oast_consented is True
        ):
            raise ExternalExecutionDisabled(
                "public SSRF OAST requires recorded Run consent"
            )
        phase = f"validation:{validation_id}" if validation_id is not None else "analysis"
        key = hashlib.sha256(
            f"{run_id}\0{candidate_id}\0{parameter}\0{phase}".encode()
        ).hexdigest()
        self._ssrf_issue_calls += 1
        ticket = service.issue(key)
        if (
            not ticket.token or not isinstance(ticket.issued_at, datetime)
            or ticket.issued_at.tzinfo is None
            or ticket.issued_at > datetime.now(timezone.utc) + timedelta(seconds=5)
            or not callback_url_matches_origin(ticket.url, service.origin)
        ):
            raise AgentContractError("SSRF callback service issued an invalid ticket")
        previous = self._ssrf_issued.get(key)
        if previous is not None and previous != ticket:
            raise AgentContractError("SSRF callback ticket changed for the same key")
        self._ssrf_issued[key] = ticket
        self._ssrf_issued_by_run.setdefault(run_id, set()).add(key)
        if validation_id is not None:
            analysis_ticket = self.issue_ssrf_ticket(run_id, candidate_id, parameter)
            if (
                ticket.token == analysis_ticket.token
                or ticket.url == analysis_ticket.url
            ):
                raise AgentContractError(
                    "SSRF validation requires an independent callback ticket"
                )
        return ticket

    def issue_ssrf_owned_receiver_ticket(
        self,
        run_id: str,
        candidate_id: str,
        surface_id: str,
        parameter: str,
        *,
        validation_id: str | None = None,
    ) -> SsrfCallbackTicket:
        """Issue one operator-owned receiver URL bound to Run/Surface/input/phase."""

        receiver = self._ssrf_owned_receiver
        if receiver is None:
            raise ExternalExecutionDisabled("SSRF owned receiver is not configured")
        if getattr(receiver, "operator_owned", False) is not True:
            raise AgentContractError("SSRF owned receiver trust was not established")
        registration = self.ssrf_review_for_surface(
            run_id, surface_id, SsrfVerificationStrategy.OWNED_RECEIVER,
        )
        if (
            registration is None
            or registration.parameter != parameter
            or registration.execution_approval.verification_endpoint_ref
            != self.ssrf_owned_receiver_endpoint_ref(run_id)
        ):
            raise AgentContractError(
                "SSRF owned receiver does not match the approved Run coordinate"
            )
        phase = f"validation:{validation_id}" if validation_id else "analysis"
        key = self._ssrf_run_hmac(
            run_id,
            "owned-receiver-ticket",
            candidate_id,
            surface_id,
            parameter,
            phase,
        )
        analysis_ticket = None
        if validation_id is not None:
            analysis_key = self._ssrf_run_hmac(
                run_id,
                "owned-receiver-ticket",
                candidate_id,
                surface_id,
                parameter,
                "analysis",
            )
            analysis_ticket = self._ssrf_owned_issued.get(analysis_key)
            if analysis_ticket is None:
                raise AgentContractError(
                    "SSRF owned receiver Validation requires an Analysis ticket"
                )
        self._ssrf_owned_issue_calls += 1
        ticket = receiver.issue(key)
        if (
            not ticket.token
            or not isinstance(ticket.issued_at, datetime)
            or ticket.issued_at.tzinfo is None
            or ticket.issued_at > datetime.now(timezone.utc) + timedelta(seconds=5)
            or not callback_url_matches_origin(ticket.url, receiver.origin)
        ):
            raise AgentContractError("SSRF owned receiver issued an invalid ticket")
        previous = self._ssrf_owned_issued.get(key)
        if previous is not None and previous != ticket:
            raise AgentContractError("SSRF owned receiver ticket changed for the same key")
        if analysis_ticket is not None:
            if (
                ticket.token == analysis_ticket.token
                or ticket.url == analysis_ticket.url
            ):
                raise AgentContractError(
                    "SSRF owned receiver Validation requires a fresh identifier"
                )
        register = getattr(
            self._policy, "register_ssrf_owned_receiver_ticket", None,
        )
        if register is None:
            raise AgentContractError("SSRF owned receiver policy binding is unavailable")
        register(run_id, surface_id, parameter, ticket.url)
        self._ssrf_owned_issued[key] = ticket
        self._ssrf_owned_issued_by_run.setdefault(run_id, set()).add(key)
        return ticket

    def collect_ssrf_owned_receiver_observations(
        self,
        run_id: str,
        candidate_id: str,
        target_url: str,
        probe_request: EvidenceRequest,
        probe_evidence_id: str,
        *,
        task_id: str,
        validation_id: str | None = None,
        poll_timeout_seconds: float = 2.0,
    ) -> tuple[str, ...]:
        """Poll a trusted receiver and store only central, sanitized observations."""

        receiver = self._ssrf_owned_receiver
        if receiver is None:
            raise ExternalExecutionDisabled("SSRF owned receiver is not configured")
        if not 0 < poll_timeout_seconds <= self.ssrf_owned_receiver_poll_wait_seconds:
            raise ValueError("SSRF owned receiver poll timeout exceeds its limit")
        spec = probe_request.http_request
        if (
            spec is None
            or spec.request_kind not in {
                HttpRequestKind.SSRF_OWNED_RECEIVER_PROBE,
                HttpRequestKind.SSRF_WORKFLOW_OWNED_PROBE,
                HttpRequestKind.SSRF_CSV_UPLOAD_PROBE,
            }
            or probe_request.suggested_tool != (
                "http_post" if spec.method.upper() == "POST" else "http_get"
            )
        ):
            raise AgentContractError("SSRF owned receiver lookup is not a bound probe")
        if spec.request_kind is HttpRequestKind.SSRF_CSV_UPLOAD_PROBE:
            csv_pair = ssrf_csv_upload_parameter(
                spec.method, spec.headers, spec.body,
            )
            receiver_pairs = (
                (csv_pair,) if csv_pair is not None
                and callback_url_matches_origin(csv_pair[1], receiver.origin)
                else ()
            )
        else:
            receiver_pairs = tuple(
                (name, value)
                for name, value in ssrf_request_parameters(
                    spec.method, spec.query_parameters, spec.headers, spec.body,
                    allow_companions=(
                        spec.request_kind is HttpRequestKind.SSRF_WORKFLOW_OWNED_PROBE
                    ),
                )
                if callback_url_matches_origin(value, receiver.origin)
            )
        if len(receiver_pairs) != 1:
            raise AgentContractError("SSRF owned receiver lookup needs one coordinate")
        parameter, _ = receiver_pairs[0]
        ticket = self.issue_ssrf_owned_receiver_ticket(
            run_id,
            candidate_id,
            probe_request.surface_id,
            parameter,
            validation_id=validation_id,
        )
        if len(receiver_pairs) != 1 or receiver_pairs[0][1] != ticket.url:
            raise AgentContractError("SSRF owned receiver URL was not issued for this probe")
        probe = self._evidence.get(run_id, probe_evidence_id)
        probe_started_at = probe.observation.get("execution_started_at")
        if (
            probe.surface_id != probe_request.surface_id
            or probe.validation_id != validation_id
            or probe.created_by != f"execution_runtime:{probe_request.suggested_tool}"
            or probe.source_task_id is None
            or probe.observation.get("request_kind")
            != spec.request_kind.value
            or probe.observation.get("request_fingerprint")
            != probe_request.request_fingerprint(target_url)
            or not isinstance(probe_started_at, str)
        ):
            raise AgentContractError(
                "SSRF owned receiver probe Evidence provenance is invalid"
            )
        probe_time = datetime.fromisoformat(probe_started_at)
        accepted: list[SsrfCallbackHit] = []
        self._ssrf_owned_poll_calls += 1
        for hit in receiver.poll(
            ticket.token, timeout_seconds=poll_timeout_seconds,
        )[:8]:
            if (
                hit.token != ticket.token
                or not hit.event_id
                or hit.protocol != "http"
                or hit.method.upper() not in {"GET", "HEAD"}
                or not isinstance(hit.received_at, datetime)
                or hit.received_at.tzinfo is None
                or hit.received_at < ticket.issued_at
                or hit.received_at < probe_time - timedelta(seconds=5)
                or hit.received_at > datetime.now(timezone.utc) + timedelta(seconds=5)
            ):
                continue
            accepted.append(hit)
        if not accepted:
            return ()
        registration = self.ssrf_review_for_surface(
            run_id, probe_request.surface_id,
            SsrfVerificationStrategy.OWNED_RECEIVER,
        )
        assert registration is not None
        phase = (
            SsrfObservationPhase.VALIDATION
            if validation_id is not None
            else SsrfObservationPhase.ANALYSIS
        )
        session_id = (
            validation_id
            if validation_id is not None
            else "analysis:" + self._ssrf_run_hmac(
                run_id, "owned-receiver-session", candidate_id,
                probe_request.surface_id, parameter,
            )[:16]
        )
        evidence_ids: list[str] = []
        for hit in accepted:
            observation = ServerRequestObservation(
                observation_id="owned:" + self._ssrf_run_hmac(
                    run_id,
                    "owned-receiver-observation",
                    candidate_id,
                    probe_evidence_id,
                    hit.event_id,
                )[:16],
                run_id=run_id,
                surface_id=probe_request.surface_id,
                parameter=parameter,
                verification_endpoint_ref=(
                    registration.execution_approval.verification_endpoint_ref
                ),
                verification_session_id=session_id,
                phase=phase,
                observed_at=hit.received_at,
                source_verified=True,
                destination_origin=receiver.origin,
                request_method=hit.method.upper(),
                source_type=SsrfObservationSource.OPERATOR_OWNED_SERVICE,
            )
            evidence_ids.append(self._store_server_request_observation(
                observation,
                task_id=task_id,
                validation_id=validation_id,
                approval_id=registration.execution_approval.approval_id,
                probe_evidence_id=probe_evidence_id,
                observation_mode="owned_receiver",
            ))
        return tuple(dict.fromkeys(evidence_ids))

    def collect_ssrf_callbacks(
        self,
        run_id: str,
        candidate_id: str,
        target_url: str,
        probe_request: EvidenceRequest,
        probe_evidence_id: str,
        *,
        task_id: str,
        validation_id: str | None = None,
        poll_timeout_seconds: float = 2.0,
    ) -> tuple[str, ...]:
        """실행된 probe와 일치하는 callback만 중앙 provenance로 저장한다."""

        service = self._ssrf_callback
        if service is None:
            raise ExternalExecutionDisabled("SSRF callback service is not configured")
        if not 0 < poll_timeout_seconds <= self.ssrf_callback_poll_wait_seconds:
            raise ValueError("SSRF callback poll timeout exceeds the provider limit")
        spec = probe_request.http_request
        callback_pairs = (
            tuple((name, value) for name, value in ssrf_request_parameters(
                spec.method, spec.query_parameters, spec.headers, spec.body,
            )
                  if value.startswith((
                      "https://", "http://127.0.0.1:",
                      "http://host.docker.internal:",
                  ))) if spec is not None else ()
        )
        if len(callback_pairs) != 1:
            raise AgentContractError("SSRF callback lookup needs one observed coordinate")
        parameter, _ = callback_pairs[0]
        ticket = self.issue_ssrf_ticket(
            run_id, candidate_id, parameter, validation_id=validation_id,
        )
        if (
            spec is None or spec.request_kind is not HttpRequestKind.SSRF_PROBE
            or probe_request.suggested_tool != (
                "http_post" if spec.method.upper() == "POST" else "http_get"
            )
            or sum(value == ticket.url for _, value in ssrf_request_parameters(
                spec.method, spec.query_parameters, spec.headers, spec.body,
            )) != 1
        ):
            raise AgentContractError("SSRF callback lookup is not bound to its probe")
        probe = self._evidence.get(run_id, probe_evidence_id)
        probe_started_at = probe.observation.get("execution_started_at")
        if (
            probe.surface_id != probe_request.surface_id
            or probe.validation_id != validation_id
            or probe.created_by != f"execution_runtime:{probe_request.suggested_tool}"
            or probe.source_task_id is None
            or probe.observation.get("request_kind") != HttpRequestKind.SSRF_PROBE.value
            or probe.observation.get("request_fingerprint")
            != probe_request.request_fingerprint(target_url)
            or not isinstance(probe_started_at, str)
        ):
            raise AgentContractError("SSRF callback probe evidence provenance is invalid")
        probe_time = datetime.fromisoformat(probe_started_at)
        evidence_ids: list[str] = []
        # The provider must honor this deadline; in-process blocking cannot be
        # preempted here without leaving a runaway poll behind.
        self._ssrf_poll_calls += 1
        for hit in service.poll(ticket.token, timeout_seconds=poll_timeout_seconds)[:8]:
            if (
                hit.token != ticket.token or not hit.event_id
                or hit.protocol not in {"http", "dns"}
                or not isinstance(hit.received_at, datetime)
                or hit.received_at.tzinfo is None
                or hit.received_at < ticket.issued_at
                or hit.received_at < probe_time - timedelta(seconds=5)
                or hit.received_at > datetime.now(timezone.utc) + timedelta(seconds=5)
                or (hit.protocol == "http" and hit.method.upper() not in {"GET", "HEAD"})
            ):
                continue
            digest = self._ssrf_run_hmac(
                run_id, "callback-evidence", candidate_id, ticket.token,
                probe_evidence_id, hit.event_id,
            )
            evidence_id = f"evi-ssrf-{digest[:32]}"
            try:
                self._evidence.get(run_id, evidence_id)
            except RecordNotFound:
                self._evidence.append(Evidence(
                    evidence_id=evidence_id,
                    run_id=run_id,
                    surface_id=probe.surface_id,
                    created_by="execution_runtime:ssrf_callback",
                    evidence_type="observation",
                    source_task_id=task_id,
                    validation_id=validation_id,
                    observation={
                        "type": (
                            "ssrf_callback_http" if hit.protocol == "http"
                            else "ssrf_callback_dns"
                        ),
                        "method": hit.method.upper(),
                        "received_at": hit.received_at.isoformat(),
                        "probe_started_at": probe_started_at,
                        "probe_evidence_id": probe_evidence_id,
                        "attribution": "unverified",
                    },
                ))
            evidence_ids.append(evidence_id)
        return tuple(dict.fromkeys(evidence_ids))

    def collect(
        self,
        run_id: str,
        target_url: str,
        spec: EvidenceRequest,
        *,
        task_id: str,
        validation_id: str | None = None,
        timeout_seconds: float = 120.0,
        approval_ref: str | None = None,
        credential_ref: str | None = None,
        candidate_id: str | None = None,
    ) -> str:
        """정책·예산·Runtime 경계를 거쳐 Evidence를 저장하고 ID를 반환한다."""

        evidence_id, _ = self.collect_with_result(
            run_id,
            target_url,
            spec,
            task_id=task_id,
            validation_id=validation_id,
            timeout_seconds=timeout_seconds,
            approval_ref=approval_ref,
            credential_ref=credential_ref,
            candidate_id=candidate_id,
        )
        return evidence_id

    def collect_with_result(
        self,
        run_id: str,
        target_url: str,
        spec: EvidenceRequest,
        *,
        task_id: str,
        validation_id: str | None = None,
        timeout_seconds: float = 120.0,
        approval_ref: str | None = None,
        credential_ref: str | None = None,
        candidate_id: str | None = None,
    ) -> tuple[str, ExecutionResult]:
        """중앙 인증 Worker가 raw 결과를 일시적으로 읽되 저장본은 마스킹한다."""

        # 저장된 Run을 신뢰 기준으로 사용해 Task가 임의 정책을 주입하지 못하게 한다.
        run = self._runs.get(run_id)
        execution_id = f"exec-{self._id_factory()}"
        http_request = spec.http_request or HttpRequestSpec()
        request = ExecutionRequest(
            execution_id=execution_id,
            run_id=run_id,
            task_id=task_id,
            tool=spec.suggested_tool,
            target_url=target_url,
            surface_id=spec.surface_id,
            purpose=spec.reason,
            method=http_request.method,
            query_parameters=http_request.query_parameters,
            form_parameters=http_request.form_parameters,
            headers=http_request.headers,
            body=http_request.body,
            body_encoding=http_request.body_encoding,
            request_kind=http_request.request_kind,
            identifier_parameter=http_request.identifier_parameter,
            identifier_location=http_request.identifier_location,
            path_identifier_index=http_request.path_identifier_index,
            path_identifier_value=http_request.path_identifier_value,
            path_suffix=http_request.path_suffix,
            path_assignment_name=http_request.path_assignment_name,
            path_assignment_value_start=http_request.path_assignment_value_start,
            path_assignment_value_end=http_request.path_assignment_value_end,
            path_assignment_value=http_request.path_assignment_value,
            file_read_path_index=http_request.file_read_path_index,
            file_read_path_value=http_request.file_read_path_value,
            file_read_parameter=http_request.file_read_parameter,
            validation_id=validation_id,
            timeout_seconds=min(timeout_seconds, run.timeout_seconds),
            credential_ref=_credential_for(
                run, spec.principal_role, credential_ref, anonymous=spec.anonymous
            ),
            # 개별 Agent가 더 좁은 승인 참조를 지정했다면 그것을 우선한다. CLI에서
            # 사용자가 Run 전체의 상태 변경 가능 요청을 명시적으로 승인한 경우에만
            # 기본 참조를 보충하며, 실제 허용 여부는 중앙 ApprovalGate가 재검증한다.
            approval_ref=(
                approval_ref
                if approval_ref is not None
                else self._default_approval_ref
            ),
            scope=run.scope,
        )
        callback_ticket: SsrfCallbackTicket | None = None
        if request.request_kind is HttpRequestKind.SSRF_PROBE:
            if candidate_id is None:
                raise AgentContractError("SSRF probe is missing its candidate")
            callback_pairs = tuple(
                (name, value) for name, value in ssrf_request_parameters(
                    request.method, request.query_parameters, request.headers, request.body,
                )
                if value.startswith((
                    "https://", "http://127.0.0.1:",
                    "http://host.docker.internal:",
                ))
            )
            if len(callback_pairs) != 1:
                raise AgentContractError("SSRF probe needs one callback coordinate")
            parameter, _ = callback_pairs[0]
            ticket = self.issue_ssrf_ticket(
                run_id, candidate_id, parameter, validation_id=validation_id,
            )
            callback_ticket = ticket
            if sum(value == ticket.url for _, value in ssrf_request_parameters(
                request.method, request.query_parameters, request.headers, request.body,
            )) != 1:
                raise AgentContractError("SSRF probe URL was not issued for this candidate")
        if request.request_kind in {
            HttpRequestKind.SSRF_OWNED_RECEIVER_PROBE,
            HttpRequestKind.SSRF_WORKFLOW_OWNED_PROBE,
            HttpRequestKind.SSRF_CSV_UPLOAD_PROBE,
        }:
            if candidate_id is None:
                raise AgentContractError("SSRF owned receiver probe is missing its candidate")
            receiver = self._ssrf_owned_receiver
            if receiver is None:
                raise ExternalExecutionDisabled("SSRF owned receiver is not configured")
            if request.request_kind is HttpRequestKind.SSRF_CSV_UPLOAD_PROBE:
                csv_pair = ssrf_csv_upload_parameter(
                    request.method, request.headers, request.body,
                )
                receiver_pairs = (
                    (csv_pair,) if csv_pair is not None
                    and callback_url_matches_origin(csv_pair[1], receiver.origin)
                    else ()
                )
            else:
                receiver_pairs = tuple(
                    (name, value)
                    for name, value in ssrf_request_parameters(
                        request.method, request.query_parameters,
                        request.headers, request.body,
                        allow_companions=(
                            request.request_kind is HttpRequestKind.SSRF_WORKFLOW_OWNED_PROBE
                        ),
                    )
                    if callback_url_matches_origin(value, receiver.origin)
                )
            if len(receiver_pairs) != 1:
                raise AgentContractError(
                    "SSRF owned receiver probe needs one issued coordinate"
                )
            parameter, _ = receiver_pairs[0]
            ticket = self.issue_ssrf_owned_receiver_ticket(
                run_id,
                candidate_id,
                request.surface_id,
                parameter,
                validation_id=validation_id,
            )
            callback_ticket = ticket
            if receiver_pairs[0][1] != ticket.url:
                raise AgentContractError(
                    "SSRF owned receiver URL was not issued for this candidate"
                )
        if request.request_kind is HttpRequestKind.SSRF_CANARY_PROBE and candidate_id is None:
            raise AgentContractError("SSRF canary probe requires an assigned candidate")
        # 실제 호출 직전에 Scope와 예산을 검사해 우회 실행을 막는다.
        try:
            self._policy.validate_execution(run, request)
            self._budget.consume(run.run_id, 1)
            execution_started_at = datetime.now(timezone.utc).isoformat()
            result = self._runtime.execute(request)
        except Exception as error:
            self._record_audit(request, "blocked_or_failed", detail=type(error).__name__)
            raise
        if result.execution_id != execution_id:
            error = AgentContractError("runtime result does not match execution request")
            self._record_audit(request, "failed", detail=type(error).__name__)
            raise error

        try:
            if callback_ticket is not None:
                callback_secrets = (callback_ticket.url, callback_ticket.token)
                result = replace(
                    result,
                    observation=_redact_exact_ssrf_values(
                        dict(result.observation), callback_secrets,
                    ),
                    artifact_refs=_redact_exact_ssrf_values(
                        dict(result.artifact_refs), callback_secrets,
                    ),
                )
            canary_marker_seen = None
            canary_marker_channel = None
            canary = self.ssrf_canary_proof_for_run(run_id)
            if (
                canary is not None
                and request.request_kind in {
                    HttpRequestKind.SSRF_CONTROL, HttpRequestKind.SSRF_CANARY_PROBE,
                }
            ):
                marker_channel = _ssrf_marker_channel(
                    dict(result.observation), canary.marker,
                )
                canary_marker_channel = marker_channel
                canary_marker_seen = (
                    result.evidence_type == "http_response"
                    and result.observation.get("status") == 200
                    and result.observation.get("truncated") is not True
                    and marker_channel is not None
                )
                # The exact endpoint and marker are protected execution inputs. A target may
                # reflect either value in headers, errors, or artifact metadata, so redact all
                # result fields before the ordinary Evidence sanitizer sees them.
                canary_secrets = (canary.url, canary.marker)
                redacted_observation = _redact_exact_ssrf_values(
                    dict(result.observation), canary_secrets,
                )
                assert isinstance(redacted_observation, dict)
                result = replace(
                    result,
                    observation={**redacted_observation, "body": None},
                    artifact_refs=_redact_exact_ssrf_values(
                        dict(result.artifact_refs), canary_secrets,
                    ),
                )
            projected_result = (
                self._evidence_projection(request, result)
                if self._evidence_projection is not None
                else result
            )
            stored_result = (
                self._sanitizer.sanitize(request, projected_result)
                if self._sanitizer is not None
                else projected_result
            )
            # Runtime 결과는 메시지로 중계하지 않고 Evidence Store에 먼저 기록한다.
            evidence_id = f"evi-{self._id_factory()}"
            observation = dict(stored_result.observation)
            if canary_marker_seen is not None:
                observation["ssrf_canary_marker_present"] = canary_marker_seen
                if canary_marker_seen:
                    observation["ssrf_canary_marker_channel"] = canary_marker_channel
            # Runtime 구현이 바뀌어도 control/probe 출처가 Evidence에서 사라지지 않게 한다.
            observation.setdefault("request_kind", request.request_kind.value)
            observation.setdefault("requested_url", request.resolved_url)
            if request.request_kind in {
                HttpRequestKind.SSRF_PROBE,
                HttpRequestKind.SSRF_CANARY_PROBE,
                HttpRequestKind.SSRF_OWNED_RECEIVER_PROBE,
                HttpRequestKind.SSRF_WORKFLOW_OWNED_PROBE,
                HttpRequestKind.SSRF_CSV_UPLOAD_CONTROL,
                HttpRequestKind.SSRF_CSV_UPLOAD_PROBE,
                HttpRequestKind.SSRF_CSV_IMPORT_CONTROL,
                HttpRequestKind.SSRF_CSV_IMPORT_PROBE,
            }:
                observation["requested_url"] = _redacted_ssrf_request_url(
                    request.resolved_url,
                )
            observation.setdefault("method", request.method.upper())
            observation["execution_started_at"] = execution_started_at
            # requested_url과 body는 저장 전에 마스킹될 수 있다. Agent가 표시 문자열을
            # Evidence 연결 키로 쓰지 않도록, 실행 직전 명세의 비가역 fingerprint를
            # Collector가 신뢰 가능한 값으로 덮어쓴다.
            observation["request_fingerprint"] = spec.request_fingerprint(target_url)
            self._evidence.append(
                Evidence(
                    evidence_id=evidence_id,
                    run_id=run.run_id,
                    surface_id=request.surface_id,
                    created_by=f"execution_runtime:{request.tool}",
                    evidence_type=stored_result.evidence_type,
                    source_task_id=task_id,
                    validation_id=validation_id,
                    observation=observation,
                    artifact_refs=stored_result.artifact_refs,
                    content_hash=(
                        None if request.request_kind in {
                            HttpRequestKind.SSRF_CONTROL,
                            HttpRequestKind.SSRF_PROBE,
                            HttpRequestKind.SSRF_CANARY_PROBE,
                            HttpRequestKind.SSRF_OWNED_RECEIVER_PROBE,
                            HttpRequestKind.SSRF_WORKFLOW_CONTROL,
                            HttpRequestKind.SSRF_WORKFLOW_OWNED_PROBE,
                            HttpRequestKind.SSRF_WORKFLOW_SETUP,
                            HttpRequestKind.SSRF_WORKFLOW_TRIGGER,
                            HttpRequestKind.SSRF_WORKFLOW_CLEANUP,
                            HttpRequestKind.SSRF_CSV_UPLOAD_CONTROL,
                            HttpRequestKind.SSRF_CSV_UPLOAD_PROBE,
                            HttpRequestKind.SSRF_CSV_IMPORT_CONTROL,
                            HttpRequestKind.SSRF_CSV_IMPORT_PROBE,
                        }
                        else stored_result.content_hash
                    ),
                )
            )
        except Exception as error:
            self._record_audit(request, "failed", detail=type(error).__name__)
            raise
        status = observation.get("status")
        self._record_audit(
            request,
            "completed",
            status_code=status if isinstance(status, int) else None,
        )
        return evidence_id, result

    def _record_audit(
        self,
        request: ExecutionRequest,
        outcome: str,
        *,
        status_code: int | None = None,
        detail: str | None = None,
    ) -> None:
        if self._audit is None:
            return
        from urllib.parse import urlsplit, urlunsplit

        parsed = urlsplit(request.resolved_url)
        target = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
        self._audit.append(
            ExecutionAuditEvent(
                execution_id=request.execution_id,
                run_id=request.run_id,
                task_id=request.task_id,
                tool=request.tool,
                method=request.method.upper(),
                target=target,
                request_kind=request.request_kind.value,
                outcome=outcome,
                status_code=status_code,
                detail=detail,
            )
        )

    # TO DO collect 호출
    def handle(self, task: TaskEnvelope) -> AgentResult:
        """증적 요청 계약을 검증하고 공통 수집 경계에 실행을 위임한다."""

        request_spec = task.evidence_request
        if request_spec is None or task.target_url is None:
            raise AgentContractError("evidence collection task is missing its request")
        if request_spec.suggested_tool not in task.allowed_tools:
            raise AgentContractError("requested execution tool is not allowed by the task")

        evidence_id = self.collect(
            task.run_id,
            task.target_url,
            request_spec,
            task_id=task.task_id,
            validation_id=task.validation_id,
            timeout_seconds=task.timeout_seconds,
            approval_ref=request_spec.approval_ref,
            # Task에 실린 자격증명을 그대로 쓴다. 여기서 Run 기본값으로 되돌리면
            # 여러 취약점을 함께 검사할 때 유형별 세션 분리가 이 지점에서 무너진다.
            # principal_role이 붙은 요청은 _credential_for가 역할을 우선한다.
            credential_ref=task.credential_ref,
            candidate_id=task.candidate_id,
        )
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=(evidence_id,),
        )


def _credential_for(
    run: Run,
    role: AccessPrincipalRole | None,
    requested: str | None = None,
    *, anonymous: bool = False,
) -> str | None:
    """Agent가 지정한 역할을 Run에 등록된 자격증명으로만 해석한다.

    Agent와 LLM은 credential_ref를 직접 고를 수 없다. `EvidenceRequest`에는 역할만
    담을 수 있고, 그 역할이 현재 Run에 등록되어 있지 않으면 요청이 거부된다. 이 해석이
    중앙에 있어야 ACTOR/OWNER 세션이 섞이지 않는다.

    `requested`는 중앙 인증 Worker처럼 어떤 주체의 세션을 세울지 Orchestrator가 이미
    정해 둔 경우에만 쓴다. 그 경우에도 Run에 등록된 참조가 아니면 거부하므로, 임의
    자격증명을 끌어다 쓰는 경로는 되지 않는다.

    ``anonymous``는 인증된 Run에서도 공개 접근을 별도로 확인하기 위한 명시적
    선택이다. 등록된 세션을 기본값으로 되살리지 않는다.
    """

    if anonymous:
        if role is not None:
            raise PolicyViolation("anonymous request cannot select a principal role")
        return None
    if role is not None:
        registered = dict(run.principal_credentials)
        credential_ref = registered.get(role.value)
        if not credential_ref:
            raise PolicyViolation(
                f"run has no credential registered for principal role: {role.value}"
            )
        return credential_ref
    if requested is not None:
        allowed = {
            run.credential_ref,
            *(ref for _, ref in run.principal_credentials),
            *(ref for _, ref in run.agent_credentials),
        }
        if requested not in allowed:
            raise PolicyViolation(
                "execution requested a credential that is not registered for this run"
            )
        return requested
    # agent_credentials가 존재하면 유형별 인증을 명시적으로 분리한 다중 취약점
    # Run이다. 이때 requested=None은 "기본값 사용"이 아니라 "이 유형은 무인증"을
    # 뜻한다. Recon은 TaskFactory가 기본 credential_ref를 명시해서 이 분기의 영향을
    # 받지 않고, 기존 단일 취약점 Run은 아래 기본값 호환 경로를 그대로 쓴다.
    if run.agent_credentials:
        return None
    return run.credential_ref
