"""Router 감사 기록은 판단을 설명하되 실행 결과/비밀 원문을 바꾸거나 저장하지 않는다."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from hacklipse.adapters import RuleBasedVulnerabilityRouter
from hacklipse.adapters.routing_audit import JsonlRoutingAuditLog
from hacklipse.bootstrap import standard_router
from hacklipse.domain import Evidence, Run, RunScope, Surface
from hacklipse.ports.errors import LlmCredentialsMissing, LlmTimeout
from hacklipse.ports.llm import LlmResponse, LlmUsage


_RUN = Run(
    run_id="audit-run", target_url="http://localhost/", request_budget=20,
    policy_profile="safe", scope=RunScope(allowed_hosts=frozenset({"localhost"})),
    credential_ref="private-credential-reference",
)
_SURFACE = Surface(
    surface_id="search", run_id=_RUN.run_id, url="http://localhost/render?q=private-query",
    method="GET", parameters=("q",),
)


def _item(**changes):
    return dict({
        "surface_id": "search", "vulnerability_type": "Path Traversal",
        "reason": "The input may select a server-side resource.",
    }, **changes)


class _Llm:
    def __init__(self, *items, error=None):
        self.items = list(items)
        self.error = error
        self.calls = 0

    def complete(self, request):
        self.calls += 1
        if self.error:
            raise self.error
        return LlmResponse(
            payload={"suggestions": self.items}, model="fixture-model",
            usage=LlmUsage(input_tokens=100, output_tokens=50, cache_read_input_tokens=10),
        )


class _Log:
    def __init__(self):
        self.records = []

    def append(self, record):
        self.records.append(record)


class RoutingAuditTests(unittest.TestCase):
    def test_default_bootstrap_stays_rule_based_without_llm(self):
        llm = _Llm()
        router = standard_router(llm_client=llm)
        self.assertIsInstance(router, RuleBasedVulnerabilityRouter)
        router.route(_RUN, (_SURFACE,), ())
        self.assertEqual(llm.calls, 0)

    def test_invalid_mode_and_missing_client_fail_explicitly(self):
        with self.assertRaises(ValueError):
            standard_router(mode="wrong")
        with self.assertRaises(LlmCredentialsMissing):
            standard_router(mode="hybrid")

    def test_heuristic_records_rule_decisions_and_zero_llm_calls(self):
        log = _Log()
        result = standard_router(audit_log=log).route(_RUN, (_SURFACE,), ())
        record = log.records[0]
        self.assertEqual(record["router_mode"], "heuristic")
        self.assertEqual(record["llm"]["calls"], 0)
        self.assertIn("routing_input_fingerprint", record)
        self.assertEqual(record["routing_input_manifest"]["surfaces"][0]["path"], "/render")
        self.assertEqual(record["routing_input_manifest"]["surfaces"][0]["parameter_names"], ["q"])
        self.assertNotIn("private-query", json.dumps(record))
        self.assertEqual(record["llm"]["status"], "heuristic_mode")
        self.assertEqual(record["rule_decisions"], record["final_decisions"])
        self.assertEqual([d["candidate_id"] for d in record["final_decisions"]], [d.candidate.candidate_id for d in result])

    def test_hybrid_records_rule_llm_and_merged_provenance(self):
        log = _Log()
        llm = _Llm(
            _item(),
            _item(vulnerability_type="SQLi"),
        )
        router = standard_router(mode="hybrid", llm_client=llm, audit_log=log,
                                 audit_metadata={"analysis_profile": "heuristic", "password": "never-store"})
        result = router.route(_RUN, (_SURFACE,), ())
        record = log.records[0]
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["configuration"], {"analysis_profile": "heuristic", "vulnerability_types": "*", "router_review": "weak"})
        self.assertEqual(record["surface_reviews"], [{"surface_id": "search", "reason": "advisor_review", "selected": True}])
        self.assertEqual([d["source"] for d in record["final_decisions"]], ["rule", "rule", "llm"])
        self.assertEqual([d["outcome"] for d in record["llm"]["proposals"]], ["candidate_added"])
        self.assertEqual(record["llm"]["usage"]["input_tokens"], 100)
        self.assertEqual(record["llm"]["usage"]["cache_read_input_tokens"], 10)
        self.assertEqual(record["llm"]["model"], "fixture-model")
        self.assertEqual(record["llm"]["calls"], 1)
        self.assertEqual(len(result), 3)
        self.assertGreaterEqual(record["elapsed_ms"], record["llm"]["elapsed_ms"])

    def test_parser_rejection_and_capability_rejection_are_distinguished(self):
        log = _Log()
        llm = _Llm(
            _item(vulnerability_type="RCE", reason="private-rejected-text"),
            _item(surface_id="post", vulnerability_type="SQLi"),
        )
        post = replace(_SURFACE, surface_id="post", method="POST", parameters=("blob",))
        standard_router(mode="hybrid", llm_client=llm, audit_log=log).route(_RUN, (_SURFACE, post), ())
        record = log.records[0]
        self.assertEqual(record["llm"]["rejected_items"], [{
            "index": 0, "index_scope": "raw_items", "reason": "unsupported_route",
        }])
        self.assertEqual([d["outcome"] for d in record["llm"]["proposals"]], ["incompatible_surface"])
        self.assertNotIn("private-rejected-text", json.dumps(record))

    def test_strong_rules_record_skip_reason_and_evidence_references(self):
        log = _Log()
        llm = _Llm()
        evidence = Evidence(
            evidence_id="reflection", run_id=_RUN.run_id, surface_id="search",
            created_by="recon", evidence_type="observation", observation={"type": "reflection"},
        )
        standard_router(mode="hybrid", llm_client=llm, audit_log=log).route(_RUN, (_SURFACE,), (evidence,))
        record = log.records[0]
        self.assertEqual(record["surface_reviews"][0]["reason"], "advisor_review")
        self.assertEqual(record["final_decisions"][0]["evidence_ids"], ["reflection"])
        self.assertEqual(record["llm"]["source"], "llm")
        self.assertEqual(llm.calls, 1)

    def test_timeout_records_fallback_without_claiming_zero_token_cost(self):
        log = _Log()
        standard_router(mode="hybrid", llm_client=_Llm(error=LlmTimeout("private-error")), audit_log=log).route(_RUN, (_SURFACE,), ())
        record = log.records[0]
        self.assertEqual(record["llm"]["source"], "deterministic_fallback")
        self.assertEqual(record["llm"]["status"], "timeout")
        self.assertEqual(record["llm"]["calls"], 1)
        self.assertIsNone(record["llm"]["usage"])
        self.assertEqual(record["rule_decisions"], record["final_decisions"])
        self.assertNotIn("private-error", json.dumps(record))

    def test_unexpected_exception_preserves_rules_and_is_logged(self):
        log = _Log()
        router = standard_router(mode="hybrid", llm_client=_Llm(error=RuntimeError("private-error")), audit_log=log)
        result = router.route(_RUN, (_SURFACE,), ())
        record = log.records[0]
        self.assertEqual(record["status"], "completed")
        self.assertIsNone(record["error_type"])
        self.assertEqual(len(record["rule_decisions"]), 2)
        self.assertEqual(len(result), 2)
        self.assertEqual(record["rule_decisions"], record["final_decisions"])
        self.assertIsNone(record["llm"]["calls"])
        self.assertNotIn("private-error", json.dumps(record))

    def test_sensitive_inputs_and_url_in_llm_reason_are_not_logged(self):
        log = _Log()
        llm = _Llm(_item(reason="Review https://localhost/?token=private-reason token=secret-word"))
        standard_router(mode="hybrid", llm_client=llm, audit_log=log).route(_RUN, (_SURFACE,), ())
        serialized = json.dumps(log.records[0])
        for secret in ("private-query", "private-credential-reference", "private-reason", "secret-word", "http://localhost"):
            self.assertNotIn(secret, serialized)
        self.assertIn("redacted", serialized)

    def test_jsonl_appends_distinct_run_events_and_uses_private_file_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "routing.jsonl"
            log = JsonlRoutingAuditLog(path)
            log.prepare()
            router = standard_router(audit_log=log)
            router.route(_RUN, (_SURFACE,), ())
            other = replace(_RUN, run_id="second-run")
            router.route(other, (replace(_SURFACE, run_id=other.run_id),), ())
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual([record["run_id"] for record in records], [_RUN.run_id, other.run_id])
            self.assertNotEqual(records[0]["routing_id"], records[1]["routing_id"])
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_audit_write_failure_is_not_silently_ignored(self):
        class FailingLog:
            def append(self, record):
                raise OSError("disk full")

        with self.assertRaises(OSError):
            standard_router(audit_log=FailingLog()).route(_RUN, (_SURFACE,), ())

    def test_vulnerability_filter_applies_to_both_branches(self):
        log = _Log()
        llm = _Llm(_item())
        result = standard_router(("Path Traversal",), mode="hybrid", llm_client=llm, audit_log=log).route(_RUN, (_SURFACE,), ())
        self.assertEqual([d.candidate.vulnerability_type for d in result], ["Path Traversal"])
        self.assertEqual(log.records[0]["surface_reviews"][0]["reason"], "advisor_review")


if __name__ == "__main__":
    unittest.main()
