"""Persistence regressions for independently typed SSRF review stages."""

from __future__ import annotations

import hashlib
import unittest
from dataclasses import replace
from datetime import datetime, timezone

from hacklipse.adapters import InMemorySsrfReviewRegistry, MemoryStoreBundle
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    Evidence,
    Run,
    RunScope,
    SsrfExecutionApproval,
    SsrfVerificationStrategy,
    Surface,
)


class SsrfReviewStrategyPersistenceTests(unittest.TestCase):
    def test_callback_and_canary_restore_without_ambiguous_fallback(self) -> None:
        stores = MemoryStoreBundle()
        run = Run(
            run_id="run-typed-review",
            target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            policy_profile="safe",
            request_budget=20,
            surface_ids=("surface-url",),
        )
        surface = Surface(
            surface_id="surface-url",
            run_id=run.run_id,
            url="https://target.example/fetch?url=old",
            method="GET",
            parameters=("url",),
        )
        review = Evidence(
            evidence_id="evi-url-review",
            run_id=run.run_id,
            surface_id=surface.surface_id,
            created_by="recon",
            evidence_type="observation",
            observation={
                "type": "ssrf_url_fetch_review",
                "parameter_names": ["url"],
            },
        )
        stores.runs.add(run)
        stores.surfaces.add(surface)
        stores.evidence.append(review)
        app = build_local_application({}, stores=stores)

        registrations = {}
        for strategy in (
            SsrfVerificationStrategy.CALLBACK,
            SsrfVerificationStrategy.INTERNAL_CANARY,
        ):
            registrations[strategy] = app.collector.register_ssrf_review(
                run_id=run.run_id,
                parameter="url",
                hint_evidence_id=review.evidence_id,
                approval=SsrfExecutionApproval(
                    approval_id=f"approval-{strategy.value}",
                    surface_id=surface.surface_id,
                    verification_endpoint_ref=f"endpoint-{strategy.value}",
                    approved_by="operator-security",
                    approved_at=datetime.now(timezone.utc),
                ),
                verification_strategy=strategy,
            )

        persisted = tuple(
            item for item in stores.evidence.list_by_run(run.run_id)
            if item.observation.get("type") == "ssrf_review_registration"
        )
        self.assertEqual(len(persisted), 2)
        self.assertEqual(
            {item.observation["verification_strategy"] for item in persisted},
            {"callback", "internal_canary"},
        )
        self.assertEqual(len({item.evidence_id for item in persisted}), 2)

        restarted = build_local_application({}, stores=stores)
        self.assertEqual(
            restarted.collector.restore_ssrf_review(
                run.run_id, SsrfVerificationStrategy.CALLBACK,
            ),
            registrations[SsrfVerificationStrategy.CALLBACK],
        )
        self.assertEqual(len(restarted.ssrf_reviews.list_for_run(run.run_id)), 1)

        # A generic hydrate must still scan the remaining persisted stages.
        self.assertIsNone(restarted.collector.restore_ssrf_review(run.run_id))

        for strategy, expected in registrations.items():
            self.assertEqual(
                restarted.ssrf_reviews.get_for_run(run.run_id, strategy),
                expected,
            )
            self.assertEqual(
                restarted.ssrf_reviews.get(
                    run_id=run.run_id,
                    surface_id=surface.surface_id,
                    parameter="url",
                    strategy=strategy,
                ),
                expected,
            )

        self.assertIsNone(restarted.ssrf_reviews.get_for_run(run.run_id))

    def test_explicit_and_legacy_passive_never_authorize_typed_lookup(self) -> None:
        stores = MemoryStoreBundle()
        run = Run(
            run_id="run-legacy-review",
            target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            policy_profile="safe",
            request_budget=20,
            surface_ids=("surface-url",),
        )
        surface = Surface(
            surface_id="surface-url",
            run_id=run.run_id,
            url="https://target.example/fetch?url=old",
            method="GET",
            parameters=("url",),
        )
        review = Evidence(
            evidence_id="evi-url-review",
            run_id=run.run_id,
            surface_id=surface.surface_id,
            created_by="recon",
            evidence_type="observation",
            observation={
                "type": "ssrf_url_fetch_review",
                "parameter_names": ["url"],
            },
        )
        stores.runs.add(run)
        stores.surfaces.add(surface)
        stores.evidence.append(review)
        app = build_local_application({}, stores=stores)
        approval = SsrfExecutionApproval(
            approval_id="approval-legacy",
            surface_id=surface.surface_id,
            verification_endpoint_ref="endpoint-legacy",
            approved_by="operator-security",
            approved_at=datetime.now(timezone.utc),
        )

        with self.assertRaises(TypeError):
            app.collector.register_ssrf_review(
                run_id=run.run_id,
                parameter="url",
                hint_evidence_id=review.evidence_id,
                approval=approval,
            )
        passive = app.collector.register_ssrf_review(
            run_id=run.run_id,
            parameter="url",
            hint_evidence_id=review.evidence_id,
            approval=approval,
            verification_strategy=SsrfVerificationStrategy.PASSIVE,
        )
        passive_evidence = next(
            item for item in stores.evidence.list_by_run(run.run_id)
            if item.observation.get("type") == "ssrf_review_registration"
        )
        self.assertEqual(
            passive_evidence.observation["verification_strategy"], "passive",
        )
        self.assertIsNone(app.collector.ssrf_review_for_surface(
            run.run_id, surface.surface_id, SsrfVerificationStrategy.CALLBACK,
        ))

        legacy_observation = dict(passive_evidence.observation)
        legacy_observation.pop("verification_strategy")
        legacy_digest = hashlib.sha256(run.run_id.encode()).hexdigest()
        legacy_evidence = replace(
            passive_evidence,
            evidence_id=f"evi-ssrf-review-registration-{legacy_digest[:32]}",
            observation=legacy_observation,
        )

        legacy_stores = MemoryStoreBundle()
        legacy_stores.runs.add(run)
        legacy_stores.surfaces.add(surface)
        legacy_stores.evidence.append(review)
        legacy_stores.evidence.append(legacy_evidence)
        restarted = build_local_application({}, stores=legacy_stores)
        restored = restarted.collector.restore_ssrf_review(
            run.run_id, SsrfVerificationStrategy.PASSIVE,
        )
        self.assertIsNotNone(restored)
        self.assertIs(restored.verification_strategy, SsrfVerificationStrategy.PASSIVE)
        self.assertIsNone(restarted.collector.ssrf_review_for_surface(
            run.run_id, surface.surface_id, SsrfVerificationStrategy.CALLBACK,
        ))

        registry = InMemorySsrfReviewRegistry()
        registry.register(passive)
        self.assertEqual(
            registry.get_for_run(run.run_id, SsrfVerificationStrategy.PASSIVE),
            passive,
        )
        self.assertIsNone(
            registry.get_for_run(run.run_id, SsrfVerificationStrategy.CALLBACK),
        )


if __name__ == "__main__":
    unittest.main()
