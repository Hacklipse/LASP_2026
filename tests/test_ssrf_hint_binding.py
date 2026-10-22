"""Run-scoped SSRF Recon hint binding regressions."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from hacklipse.adapters import MemoryStoreBundle
from hacklipse.adapters.recon import ReconAgent
from hacklipse.application.errors import AgentContractError
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    Evidence,
    ExecutionResult,
    Run,
    RunPhase,
    RunScope,
    SsrfCanaryProofTarget,
    SsrfExecutionApproval,
    SsrfVerificationStrategy,
    Surface,
    TaskEnvelope,
)
from hacklipse.domain.url_redaction import ssrf_destination_reference_parts


_TARGET_URL = "https://target.example/"
_HINT_URL = "http://mailpit.internal:8025/private/token/DEMO-SECRET"
_RECON_HINT_URL = "http://mailpit.internal:8025/health"
_MARKER = "owned-harmless-marker-2026"


class _ReconRuntime:
    def execute(self, request):
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response",
                "status": 200,
                "content_type": "text/html",
                "body": (
                    '<a href="/preview?url=old">preview</a>'
                    f'<p>{_RECON_HINT_URL}</p>'
                ),
                "truncated": False,
            },
        )


class SsrfHintBindingTests(unittest.TestCase):
    def _fixture(
        self,
        *,
        run_id: str = "run-1",
        hint_url: str = _HINT_URL,
        fingerprint_override: str | None = None,
    ):
        stores = MemoryStoreBundle()
        app = build_local_application({}, stores=stores)
        run = Run(
            run_id=run_id,
            target_url=_TARGET_URL,
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            policy_profile="safe",
            request_budget=12,
            surface_ids=("surface-1",),
        )
        surface = Surface(
            surface_id="surface-1",
            run_id=run_id,
            url="https://target.example/preview?url=old",
            method="GET",
            parameters=("url",),
        )
        stores.runs.add(run)
        stores.surfaces.add(surface)
        stores.evidence.append(Evidence(
            evidence_id="evi-review",
            run_id=run_id,
            surface_id=surface.surface_id,
            created_by="recon",
            evidence_type="observation",
            observation={
                "type": "ssrf_url_fetch_review",
                "parameter_names": ["url"],
            },
        ))
        parts = ssrf_destination_reference_parts(hint_url)
        assert parts is not None
        origin, path_hint, material = parts
        stores.evidence.append(Evidence(
            evidence_id="evi-hint",
            run_id=run_id,
            surface_id=surface.surface_id,
            created_by="recon",
            evidence_type="observation",
            observation={
                "type": "ssrf_destination_hint",
                "source": "openapi_document",
                "destination_origin": origin,
                "path_hint": path_hint,
                "destination_fingerprint": (
                    fingerprint_override
                    or app.collector.ssrf_run_fingerprint(
                        run_id, "destination-hint", material,
                    )
                ),
                "host_kind": "internal_dns",
                "observed": True,
                "probe_authorized": False,
            },
        ))
        return app, stores, run

    @staticmethod
    def _approval(app, run_id: str, url: str) -> SsrfExecutionApproval:
        return SsrfExecutionApproval(
            approval_id=f"approval-{run_id}",
            surface_id="surface-1",
            verification_endpoint_ref=app.collector.ssrf_verification_endpoint_ref(
                run_id, url,
            ),
            approved_by="operator-security",
            approved_at=datetime.now(timezone.utc),
        )

    def test_recon_uses_the_collectors_run_hmac_for_destination_hints(self) -> None:
        stores = MemoryStoreBundle()
        app = build_local_application({}, stores=stores, runtime=_ReconRuntime())
        run = Run(
            run_id="run-recon",
            target_url=_TARGET_URL,
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            policy_profile="safe",
            request_budget=8,
        )
        stores.runs.add(run)
        app.budget_manager.open_run(run.run_id, run.request_budget)
        ids = iter(str(index) for index in range(1000))
        agent = ReconAgent(
            collector=app.collector,
            evidence_store=stores.evidence,
            surface_store=stores.surfaces,
            max_pages=1,
            id_factory=ids.__next__,
        )
        agent.handle(TaskEnvelope(
            task_id="task-recon",
            run_id=run.run_id,
            agent_type="recon",
            target_url=_TARGET_URL,
            allowed_tools=("http_get",),
            request_budget=4,
        ))

        hint = next(
            item for item in stores.evidence.list_by_run(run.run_id)
            if item.observation.get("type") == "ssrf_destination_hint"
        )
        parts = ssrf_destination_reference_parts(_RECON_HINT_URL)
        assert parts is not None
        self.assertEqual(
            hint.observation["destination_fingerprint"],
            app.collector.ssrf_run_fingerprint(
                run.run_id, "destination-hint", parts[2],
            ),
        )

    def test_matching_hint_and_exact_url_bind_and_canary_rechecks(self) -> None:
        app, stores, run = self._fixture()
        registration = app.collector.register_ssrf_review(
            run_id=run.run_id,
            parameter="url",
            hint_evidence_id="evi-hint",
            hint_use_approved=True,
            approved_destination_url=_HINT_URL,
            approval=self._approval(app, run.run_id, _HINT_URL),
            verification_strategy=SsrfVerificationStrategy.INTERNAL_CANARY,
        )
        self.assertTrue(registration.hint_use_approved)

        canary = SsrfCanaryProofTarget(
            url=_HINT_URL,
            marker=_MARKER,
            surface_id="surface-1",
            operator_approved=True,
        )
        app.collector.register_ssrf_canary_proof(run.run_id, canary)
        self.assertEqual(
            app.collector.ssrf_canary_proof_for_run(run.run_id), canary,
        )

        serialized = json.dumps(
            [item.observation for item in stores.evidence.list_by_run(run.run_id)],
            sort_keys=True,
        )
        self.assertNotIn(_HINT_URL, serialized)
        self.assertNotIn("DEMO-SECRET", serialized)
        self.assertIn('"hint_use_approved": true', serialized)

    def test_different_path_and_origin_cannot_use_selected_hint(self) -> None:
        for approved_url in (
            "http://mailpit.internal:8025/health",
            "http://other.internal:8025/private/token/DEMO-SECRET",
        ):
            with self.subTest(approved_url=approved_url):
                app, _, run = self._fixture()
                with self.assertRaisesRegex(
                    AgentContractError, "does not match the selected Recon hint",
                ):
                    app.collector.register_ssrf_review(
                        run_id=run.run_id,
                        parameter="url",
                        hint_evidence_id="evi-hint",
                        hint_use_approved=True,
                        approved_destination_url=approved_url,
                        approval=self._approval(app, run.run_id, approved_url),
                        verification_strategy=SsrfVerificationStrategy.INTERNAL_CANARY,
                    )

    def test_fingerprint_from_another_run_cannot_bind(self) -> None:
        source_app, source_stores, _ = self._fixture(run_id="run-source")
        foreign_fingerprint = source_stores.evidence.get(
            "run-source", "evi-hint",
        ).observation["destination_fingerprint"]
        app, _, run = self._fixture(
            run_id="run-target", fingerprint_override=str(foreign_fingerprint),
        )

        self.assertNotEqual(
            source_app.collector.ssrf_verification_endpoint_ref(
                "run-source", _HINT_URL,
            ),
            app.collector.ssrf_verification_endpoint_ref(run.run_id, _HINT_URL),
        )
        with self.assertRaisesRegex(
            AgentContractError, "does not match the selected Recon hint",
        ):
            app.collector.register_ssrf_review(
                run_id=run.run_id,
                parameter="url",
                hint_evidence_id="evi-hint",
                hint_use_approved=True,
                approved_destination_url=_HINT_URL,
                approval=self._approval(app, run.run_id, _HINT_URL),
                verification_strategy=SsrfVerificationStrategy.INTERNAL_CANARY,
            )

    def test_unapproved_hint_is_provenance_only(self) -> None:
        app, stores, run = self._fixture()
        unrelated_url = "http://different.internal:8080/health"
        registration = app.collector.register_ssrf_review(
            run_id=run.run_id,
            parameter="url",
            hint_evidence_id="evi-hint",
            hint_use_approved=False,
            approved_destination_url=unrelated_url,
            approval=self._approval(app, run.run_id, unrelated_url),
            verification_strategy=SsrfVerificationStrategy.INTERNAL_CANARY,
        )
        self.assertFalse(registration.hint_use_approved)
        persisted = next(
            item for item in stores.evidence.list_by_run(run.run_id)
            if item.observation.get("type") == "ssrf_review_registration"
        )
        self.assertIs(persisted.observation["hint_use_approved"], False)

    def test_terminal_cleanup_discards_run_hmac_key(self) -> None:
        app, stores, run = self._fixture()
        app.collector.register_ssrf_review(
            run_id=run.run_id,
            parameter="url",
            hint_evidence_id="evi-hint",
            hint_use_approved=True,
            approved_destination_url=_HINT_URL,
            approval=self._approval(app, run.run_id, _HINT_URL),
            verification_strategy=SsrfVerificationStrategy.INTERNAL_CANARY,
        )
        self.assertIn(run.run_id, app.collector._ssrf_run_hash_keys)

        stores.runs.save(run.with_updates(phase=RunPhase.DONE))
        app.collector.discard_ssrf_run_secrets(run.run_id)

        self.assertNotIn(run.run_id, app.collector._ssrf_run_hash_keys)


if __name__ == "__main__":
    unittest.main()
