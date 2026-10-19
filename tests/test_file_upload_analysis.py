"""Inert extension probes use central policy and never claim code execution."""

from __future__ import annotations

import hashlib
import json
import struct
import unittest
import zlib
from email import policy
from email.parser import BytesParser
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit

from hacklipse.adapters.file_upload_analysis import (
    UPLOAD_EXTENSIONS, UPLOAD_RESULT, uploaded_file_url, upload_form_plans, upload_request,
    upload_payload, upload_response_problem,
)
from hacklipse.adapters.security import SensitiveDataSanitizer, StaticApprovalGate
from hacklipse.adapters.http_runtime import HttpExecutionRuntime
from hacklipse.application import OrchestratorConfig
from hacklipse.bootstrap import build_local_application, register_standard_agents, standard_router
from hacklipse.domain import (
    CandidateStatus, ExecutionRequest, ExecutionResult, HttpRequestSpec, RunPhase, RunRequest,
    RunScope, ValidationProofType,
)
from hacklipse.domain.errors import DomainInvariantError


class _UploadRuntime:
    def __init__(self, mode="accept"):
        self.mode = mode
        self.requests = []
        self.files = {}
        self.uploads = []
        self.token = ""

    def execute(self, request):
        self.requests.append(request)
        path = urlsplit(request.resolved_url).path
        status, body, media = 200, "", "text/plain"
        if path == "/":
            media = "text/html"
            body = ('<form method="POST" action="/store" enctype="multipart/form-data">'
                    '<input type="file" name="file" accept=".jpg,.png">'
                    '<button type="submit">Send</button></form>')
            if self.mode in {"csrf", "csrf_two"}:
                self.token = "csrfValue" + str(len(self.requests)) + "Sensitive"
                body = body.replace('<button', f'<input type="hidden" name="csrf_token" value="{self.token}">'
                                    '<input type="hidden" name="nonce" value="nonceSensitiveValue">'
                                    '<select name="category"><option value="photos">Photos</option></select>'
                                    '<button')
                if self.mode == "csrf_two":
                    body += body.replace('action="/store"', 'action="/store2"')
        elif request.method == "POST":
            header = dict(request.headers)["Content-Type"]
            message = BytesParser(policy=policy.default).parsebytes(
                f"Content-Type: {header}\r\nMIME-Version: 1.0\r\n\r\n".encode()
                + request.body.encode(request.body_encoding)
            )
            parts = list(message.iter_parts())
            file_parts = [part for part in parts if part.get_filename() is not None]
            assert len(file_parts) == 1
            part = file_parts[0]
            filename, payload = part.get_filename(), part.get_payload(decode=True)
            marker = filename.split(".", 1)[0]
            assert payload in (upload_payload(marker, "text_octet"), upload_payload(marker, "png_image"))
            self.uploads.append(filename)
            denied = (self.mode == "allowlist" and not filename.endswith((".jpg", ".png"))
                      or self.mode == "blocklist" and filename.endswith(".php"))
            if self.mode == "reject" or denied:
                status, body = 415, "Unsupported file type"
            elif self.mode == "json_reject":
                body = '{"error":"File extension is not allowed"}'
            elif self.mode == "auth":
                status, body = 403, "CSRF validation failed"
            elif self.mode == "success_only":
                body = '{"success":true}'
            elif self.mode in {"rate", "size"}:
                status = 429 if self.mode == "rate" else 413
                body = "try later"
            elif self.mode == "mime" and part.get_content_type() != "image/png":
                status, body = 422, '{"errors":{"file":["Unsupported MIME type"]}}'
            elif self.mode == "magic" and not payload.startswith(b"\x89PNG"):
                status, body = 400, '{"message":"Invalid image content"}'
            else:
                fields = {part.get_param("name", header="content-disposition"): part.get_content()
                          for part in parts if part.get_filename() is None}
                if self.mode in {"csrf", "csrf_two"}:
                    assert fields == {"csrf_token": self.token, "nonce": "nonceSensitiveValue", "category": "photos"}
                    assert self.token
                    self.token = ""
                stored_name = filename
                suffix = filename[len(marker):]
                if (self.mode == "normalize_repeat" and suffix
                        and any(name.endswith(suffix) for name in self.files)):
                    # 같은 확장자를 두 번째로 올리는 쪽이 독립 재현이다. 서버가 그때
                    # 확장자를 깎으면 "임의 타입이 보관된다"가 재현되지 않는다.
                    stored_name = "normalized" + str(len(self.uploads)) + ".bin"
                if self.mode in {"rename", "rename_safe"}:
                    stored_name = "renamed" + str(len(self.uploads)) + (".bin" if self.mode == "rename_safe" else filename[len(marker):])
                self.files["/files/" + stored_name] = payload
                media = "application/json"
                origin = "http://outside.invalid" if self.mode == "external" else ""
                data = {"url": origin + "/files/" + stored_name}
                if self.mode in {"csrf", "csrf_two"}:
                    data["echo"] = fields["csrf_token"]
                    data["echo_nonce"] = fields["nonce"]
                body = json.dumps({"data": {"file": data}})
                if self.mode == "html_link":
                    # 고전 PHP 업로드 폼의 응답 모양: 저장 경로를 HTML 링크로만 알린다.
                    media = "text/html"
                    body = ("<html><body>File is valid, and was successfully uploaded "
                            f"<a href='/files/{stored_name}'>here</a>."
                            "<a href='/logout'>Log out</a></body></html>")
        elif path in self.files:
            payload = self.files[path]
            body = payload.decode() if payload.startswith(b"upload") else None
            # Binary MIME still supports verification through the raw content hash.
            media = "image/png" if body is None else "text/plain"
            if self.mode == "retrieval_rate":
                status, body, media = 429, "try later", "text/plain"
        else:
            status = 404
        return ExecutionResult(
            execution_id=request.execution_id, evidence_type="http_response",
            observation={"type": "http_response", "status": status, "body": body,
                         "content_type": media, "requested_url": request.resolved_url},
            content_hash=hashlib.sha256(self.files[path] if path in self.files else body.encode()).hexdigest(),
        )


def _scan(mode="accept", approved=True, budget=500, allocation=False):
    runtime = _UploadRuntime(mode)
    app = build_local_application(
        {}, runtime=runtime, router=standard_router(("File Upload",)),
        approval_gate=StaticApprovalGate(["approved"]) if approved else None,
        default_approval_ref="approved" if approved else None,
        config=OrchestratorConfig(budget_allocation_enabled=allocation),
    )
    register_standard_agents(app, recon_max_pages=1)
    run = app.orchestrator.start(RunRequest(
        target_url="http://local.test/",
        scope=RunScope(allowed_hosts=frozenset({"local.test"})), request_budget=budget,
    ))
    return app, runtime, run


class FileUploadAnalysisTests(unittest.TestCase):
    def test_pipeline_records_every_extension_and_confirms_retrieved_storage(self):
        app, runtime, run = _scan()
        self.assertEqual(run.phase, RunPhase.DONE)
        results = [item for item in app.stores.evidence.list_by_run(run.run_id)
                   if item.observation.get("type") == UPLOAD_RESULT]
        self.assertEqual(len(results), 1)
        rows = results[0].observation["results"]
        self.assertEqual({row["extension"] for row in rows}, set(UPLOAD_EXTENSIONS))
        self.assertTrue(all(row["outcome"] == "accepted" for row in rows))
        self.assertEqual(len(runtime.uploads), len(rows) + 1)
        self.assertEqual(len(set(runtime.uploads)), len(runtime.uploads))
        candidates = app.stores.candidates.list_by_run(run.run_id)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].status, CandidateStatus.CONFIRMED)
        findings = app.stores.findings.list_by_run(run.run_id)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vulnerability_type, "File Upload")
        self.assertEqual(findings[0].proof_type, ValidationProofType.FILE_UPLOAD_RETRIEVAL)
        reports = app.stores.reports.list_by_run(run.run_id)
        self.assertIn("파일 업로드 확장자 검사", reports[0].content)
        self.assertIn(".phtml", reports[0].content)
        self.assertIn("stored_marker_retrieved", reports[0].content)

    def test_approval_is_required_before_any_upload(self):
        app, runtime, run = _scan(approved=False)
        self.assertEqual(run.phase, RunPhase.DONE)
        self.assertFalse(runtime.uploads)
        rows = next(item.observation["results"] for item in app.stores.evidence.list_by_run(run.run_id)
                    if item.observation.get("type") == UPLOAD_RESULT)
        self.assertTrue(all(row["outcome"] == "blocked" for row in rows))

    def test_rejection_auth_and_success_without_storage_are_distinct(self):
        for mode, expected in (("json_reject", "rejected"), ("auth", "blocked"),
                               ("success_only", "inconclusive"), ("external", "inconclusive")):
            with self.subTest(mode=mode):
                app, runtime, run = _scan(mode)
                self.assertEqual(run.phase, RunPhase.DONE)
                rows = next(item.observation["results"] for item in app.stores.evidence.list_by_run(run.run_id)
                            if item.observation.get("type") == UPLOAD_RESULT)
                tested = [row for row in rows if row["outcome"] != "not_tested"]
                self.assertTrue(tested)
                self.assertTrue(all(row["outcome"] == expected for row in tested))
                self.assertTrue(all(urlsplit(request.resolved_url).hostname == "local.test"
                                    for request in runtime.requests))
                self.assertFalse(app.stores.findings.list_by_run(run.run_id))

    def test_small_budget_marks_unchecked_extensions(self):
        app, runtime, run = _scan(budget=8)
        self.assertEqual(run.phase, RunPhase.DONE)
        rows = next(item.observation["results"] for item in app.stores.evidence.list_by_run(run.run_id)
                    if item.observation.get("type") == UPLOAD_RESULT)
        self.assertTrue(any(row["outcome"] == "not_tested" for row in rows))
        self.assertLessEqual(len(runtime.requests), 8)

    def test_png_controls_are_valid_and_carry_only_a_benign_comment(self):
        marker = "upload" + "a" * 32
        png = upload_payload(marker, "png_image")
        self.assertEqual(png[:8], b"\x89PNG\r\n\x1a\n")
        offset, kinds = 8, []
        while offset < len(png):
            size = struct.unpack(">I", png[offset:offset + 4])[0]
            kind, data = png[offset + 4:offset + 8], png[offset + 8:offset + 8 + size]
            checksum = struct.unpack(">I", png[offset + 8 + size:offset + 12 + size])[0]
            self.assertEqual(checksum, zlib.crc32(kind + data))
            if kind == b"IDAT":
                self.assertEqual(zlib.decompress(data), b"\0\0\0\0\xff")
            if kind == b"tEXt":
                self.assertEqual(data, b"Comment\0" + marker.encode())
            kinds.append(kind)
            offset += size + 12
        self.assertEqual(kinds, [b"IHDR", b"tEXt", b"IDAT", b"IEND"])

    def test_content_and_mime_filters_have_distinct_comparisons(self):
        for mode, dimension in (("mime", "mime"), ("magic", "content")):
            with self.subTest(mode=mode):
                app, _, run = _scan(mode)
                self.assertEqual(run.phase, RunPhase.DONE)
                result = next(item.observation for item in app.stores.evidence.list_by_run(run.run_id)
                              if item.observation.get("type") == UPLOAD_RESULT)
                self.assertTrue(any(item["dimension"] == dimension for item in result["policy_differences"]))
                rows = {(row["extension"], row["profile"]): row for row in result["results"]}
                self.assertEqual(rows[(".png", "png_image")]["outcome"], "accepted")
                self.assertEqual(rows[(".png", "text_octet")]["outcome"], "rejected")
                # 내용만 검사하고 확장자는 통과시키는 서버다. 보관된 확장자가 위험하면
                # 내용 검사를 통과했다는 사실이 면죄가 되지 않는다.
                self.assertTrue(app.stores.findings.list_by_run(run.run_id))

    def test_renamed_files_are_verified_without_claiming_safe_suffixes_are_risky(self):
        for mode, expected in (("rename", CandidateStatus.CONFIRMED), ("rename_safe", CandidateStatus.BLOCKED)):
            with self.subTest(mode=mode):
                app, _, run = _scan(mode)
                self.assertEqual(run.phase, RunPhase.DONE)
                rows = next(item.observation["results"] for item in app.stores.evidence.list_by_run(run.run_id)
                            if item.observation.get("type") == UPLOAD_RESULT)
                self.assertTrue(all(row["outcome"] == "accepted" and row["renamed"] for row in rows))
                self.assertEqual(app.stores.candidates.list_by_run(run.run_id)[0].status, expected)

    def test_a_normalized_reproduction_stops_short_of_confirmation(self):
        app, _, run = _scan("normalize_repeat")
        self.assertEqual(run.phase, RunPhase.DONE)
        candidate = app.stores.candidates.list_by_run(run.run_id)[0]
        self.assertEqual(candidate.status, CandidateStatus.SUSPECTED)
        self.assertFalse(app.stores.findings.list_by_run(run.run_id))

    def test_an_html_link_response_locates_the_stored_file(self):
        app, runtime, run = _scan("html_link")
        self.assertEqual(run.phase, RunPhase.DONE)
        rows = next(item.observation["results"] for item in app.stores.evidence.list_by_run(run.run_id)
                    if item.observation.get("type") == UPLOAD_RESULT)
        self.assertTrue(all(row["outcome"] == "accepted" for row in rows))
        self.assertEqual(app.stores.candidates.list_by_run(run.run_id)[0].status,
                         CandidateStatus.CONFIRMED)
        # 응답에 같이 실린 무관한 링크는 따라가지 않는다. 방금 올린 파일 이름을 담은
        # 참조만 읽기 때문이다.
        self.assertFalse(any(urlsplit(request.resolved_url).path == "/logout"
                             for request in runtime.requests))

    def test_a_storage_directory_name_is_not_a_state_changing_action(self):
        marker = "upload" + "b" * 32
        def located(href, extension=".php"):
            body = f"<html><body>stored <a href='{href}'>here</a></body></html>"
            return uploaded_file_url(
                {"type": "http_response", "status": 200, "body": body, "content_type": "text/html"},
                "http://local.test/index.php", marker + extension,
            )

        # /upload/<marker>.php 를 받아오는 것은 업로드가 아니라 방금 만들어진 파일 읽기다.
        for directory in ("upload", "uploads", "media/img"):
            with self.subTest(directory=directory):
                self.assertEqual(located(f"{directory}/{marker}.php"),
                                 f"http://local.test/{directory}/{marker}.php")
        # 디렉터리 이름이 실제 동작이면 그대로 막힌다.
        self.assertIsNone(located(f"delete/{marker}.php"))
        self.assertIsNone(located(f"/logout/{marker}.php"))
        # 확장자 없는 경로는 정적 파일 읽기로 보지 않는다.
        self.assertIsNone(located(f"upload/{marker}", extension=""))

    def test_rotating_csrf_and_form_defaults_are_fresh_and_redacted(self):
        app, runtime, run = _scan("csrf")
        self.assertEqual(run.phase, RunPhase.DONE)
        evidence = app.stores.evidence.list_by_run(run.run_id)
        result = next(item.observation for item in evidence if item.observation.get("type") == UPLOAD_RESULT)
        self.assertTrue(all(row["outcome"] == "accepted" for row in result["results"]))
        self.assertGreater(len(runtime.uploads), 55)
        for item in evidence:
            self.assertNotRegex(json.dumps(dict(item.observation)), r"csrfValue[0-9]+Sensitive")
            self.assertNotIn("nonceSensitiveValue", json.dumps(dict(item.observation)))
        report = app.stores.reports.list_by_run(run.run_id)[0].content
        self.assertNotIn("csrfValue", report)

    def test_global_limits_stop_further_uploads(self):
        for mode, reason in (("rate", "rate_limited"), ("size", "size_limit")):
            with self.subTest(mode=mode):
                app, runtime, run = _scan(mode)
                self.assertEqual(run.phase, RunPhase.DONE)
                self.assertEqual(len(runtime.uploads), 1)
                rows = next(item.observation["results"] for item in app.stores.evidence.list_by_run(run.run_id)
                            if item.observation.get("type") == UPLOAD_RESULT)
                self.assertTrue(all(row["outcome"] == "blocked" and row["reason"] == reason for row in rows))

    def test_server_family_coverage_precedes_rare_php_variants(self):
        app, runtime, run = _scan(budget=32)
        rows = next(item.observation["results"] for item in app.stores.evidence.list_by_run(run.run_id)
                    if item.observation.get("type") == UPLOAD_RESULT)
        primary = {row["extension"]: row for row in rows if row["profile"] == "text_octet"}
        self.assertEqual(primary[".jsp"]["outcome"], "accepted")
        self.assertEqual(primary[".php3"]["outcome"], "not_tested")
        self.assertLessEqual(len(runtime.requests), 32)

    def test_http_runtime_preserves_binary_multipart_bytes(self):
        marker = "upload" + "b" * 32
        spec = upload_request("surface", "file", marker, ".png", profile="png_image").http_request
        request = ExecutionRequest(execution_id="exec", run_id="run", task_id="task",
            tool="http_post", target_url="http://local.test/store", surface_id="surface", purpose="test",
            method=spec.method, headers=spec.headers, body=spec.body, body_encoding=spec.body_encoding)
        opener = MagicMock()
        response = opener.open.return_value.__enter__.return_value
        response.status, response.headers = 200, {"Content-Type": "text/plain"}
        response.read.return_value = b"ok"
        runtime = HttpExecutionRuntime()
        with patch.object(runtime, "_opener_for", return_value=opener):
            runtime.execute(request)
        transmitted = opener.open.call_args.args[0].data
        self.assertEqual(transmitted, spec.body.encode("latin-1"))
        self.assertIn(upload_payload(marker, "png_image"), transmitted)
        with self.assertRaises(DomainInvariantError):
            HttpRequestSpec(body="hello", body_encoding="utf-16")
        with self.assertRaises(DomainInvariantError):
            HttpRequestSpec(body="한글", body_encoding="latin-1")

    def test_rejection_reasons_do_not_conflate_auth_and_extension(self):
        self.assertEqual(upload_response_problem({"status": 302, "location": "/login"}),
                         ("blocked", "authentication_or_permission_required"))
        for status, body, expected in (
            (403, '{"error":"Invalid CSRF token"}', ("blocked", "csrf_failed")),
            (401, "login", ("blocked", "authentication_or_permission_required")),
            (400, '<p>File extension not allowed</p>', ("rejected", "extension_rejected")),
            (422, '{"errors":{"file":["Unsupported MIME type"]}}', ("rejected", "mime_rejected")),
            (400, '{"detail":"Invalid image content"}', ("rejected", "content_rejected")),
        ):
            self.assertEqual(upload_response_problem({"status": status, "body": body}), expected)

    def test_successful_csrf_messages_do_not_stop_uploads(self):
        for message, expected in (
            ("CSRF token accepted", None),
            ("CSRF verified. Invalid file extension", ("rejected", "extension_rejected")),
            ("CSRF token missing", ("blocked", "csrf_failed")),
        ):
            self.assertEqual(upload_response_problem({"status": 200, "body": json.dumps({"message": message})}), expected)

    def test_download_rate_limit_stops_further_uploads(self):
        app, runtime, run = _scan("retrieval_rate")
        self.assertEqual(run.phase, RunPhase.DONE)
        self.assertEqual(len(runtime.uploads), 1)
        rows = next(item.observation["results"] for item in app.stores.evidence.list_by_run(run.run_id)
                    if item.observation.get("type") == UPLOAD_RESULT)
        self.assertTrue(all(row["outcome"] == "blocked" for row in rows))

    def test_csrf_input_redaction_handles_valid_attribute_spellings(self):
        for html in (
            '<input name = "csrf_token" value = "rawCsrfSecretValue">',
            '<input value=rawCsrfSecretValue name=csrf_token>',
            '<input title="a > b" value="rawCsrfSecretValue" name="csrf_token">',
            '<input name="csrf&#95;token" value="rawCsrfSecretValue">',
            '<input name="csrf_token" name="other" value="rawCsrfSecretValue">',
        ):
            sanitized = SensitiveDataSanitizer._sanitize_text(html, ())
            self.assertNotIn("rawCsrfSecretValue", sanitized)
            self.assertIn("redacted", sanitized)

    def test_form_attribute_controls_which_form_owns_the_upload(self):
        template = '<form id="upload" method="POST" action="/store" enctype="multipart/form-data">{}</form>'
        self.assertFalse(upload_form_plans(template.format('<input type="file" name="file" form="other">'),
                                          "http://local.test/"))
        body = (template.format('<input type="file" name="file">')
                + '<input form="upload" name="csrf_token" type="hidden" value="freshToken">')
        plans = upload_form_plans(body, "http://local.test/")
        self.assertEqual(plans[0].fields, (("csrf_token", "freshToken"),))

    def test_multiple_csrf_uploads_keep_three_requests_for_each_validation(self):
        for allocation in (False, True):
            with self.subTest(allocation=allocation):
                app, runtime, run = _scan("csrf_two", budget=297, allocation=allocation)
                self.assertEqual(run.phase, RunPhase.DONE)
                candidates = app.stores.candidates.list_by_run(run.run_id)
                self.assertEqual(len(candidates), 2)
                self.assertTrue(all(candidate.status == CandidateStatus.CONFIRMED for candidate in candidates))
                self.assertLessEqual(len(runtime.requests), 297)

    def test_allowlist_and_case_sensitive_blocklist_outcomes(self):
        for mode in ("allowlist", "blocklist"):
            with self.subTest(mode=mode):
                app, _, run = _scan(mode)
                self.assertEqual(run.phase, RunPhase.DONE)
                rows = next(item.observation["results"] for item in app.stores.evidence.list_by_run(run.run_id)
                            if item.observation.get("type") == UPLOAD_RESULT)
                outcomes = {row["extension"]: row["outcome"] for row in rows if row["profile"] == "text_octet"}
                self.assertEqual(outcomes[".php"], "rejected")
                self.assertEqual(outcomes[".png"], "accepted")
                self.assertEqual(outcomes[".PHP"], "rejected" if mode == "allowlist" else "accepted")
                self.assertEqual(outcomes[".php.jpg"], "accepted")

    def test_form_requires_a_single_observed_file_field(self):
        template = '<form method="POST" action="/store" enctype="multipart/form-data">{}</form>'
        field = '<input name="file" type="file" accept="image/*">'
        plans = upload_form_plans(template.format(field), "http://local.test/")
        self.assertEqual((plans[0].url, plans[0].parameter, plans[0].accept),
                         ("http://local.test/store", "file", "image/*"))
        with_hidden = upload_form_plans(template.format(field + '<input name="csrf" type="hidden" value="token">'), "http://local.test/")
        self.assertEqual(with_hidden[0].fields, (("csrf", "token"),))
        for extra in ('<input name="file2" type="file">', '<textarea name="text" required></textarea>'):
            self.assertFalse(upload_form_plans(template.format(field + extra), "http://local.test/"))
        for extra in ('<input name="file" type="hidden" value="other">',
                      '<button name="submit" formmethod="GET">send</button>'):
            self.assertFalse(upload_form_plans(template.format(field + extra), "http://local.test/"))
        for action in ("http://outside.invalid/store", "/store?token=secret", "http://local.test:bad/"):
            self.assertFalse(upload_form_plans(template.format(field).replace('/store', action),
                                               "http://local.test/"))

    def test_probe_boundary_and_retrieval_links_are_bounded(self):
        marker = "upload" + "a" * 32
        for field, extension in (("file\r\ninjected", ".php"), ("file", ".unlisted")):
            with self.assertRaises(ValueError):
                upload_request("surface", field, marker, extension)
        filename = marker + ".php"
        for reference in ("http://outside.invalid/" + filename,
                          "http://local.test:8080/" + filename, "/delete?file=" + filename,
                          "/files/" + filename + "?action=delete", "/delete/" + filename,
                          "/files/../delete/" + filename):
            self.assertIsNone(uploaded_file_url({"location": reference}, "http://local.test/store", filename))
        self.assertEqual(uploaded_file_url({"location": "/files/" + filename},
                                         "http://local.test/store", filename),
                         "http://local.test/files/" + filename)
        self.assertEqual(uploaded_file_url({"body": '{"data":{"file":{"download_url":"/download?id=42"}}}'},
                                         "http://local.test/store", filename), "http://local.test/download?id=42")


if __name__ == "__main__":
    unittest.main()
