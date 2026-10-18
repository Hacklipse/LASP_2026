"""Export a completed Hacklipse Run to DynAST's public scoring contracts.

This module knows only the scorer's input format. It never reads a benchmark
answer key, target source tree, credentials, response bodies, or proof markers.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from hacklipse.domain import RunPhase, ValidationProofType
from hacklipse.adapters.graphql_discovery import GRAPHQL_SCHEMA_OPERATION

_APP = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_PARAMETER = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
_PATH_SEGMENT = re.compile(r"[A-Za-z0-9._~-]{1,48}\Z")
_SECRET_PATH = re.compile(r"(?:token|secret|password|passwd|credential|api[-_]?key)", re.I)
_CWE = {
    ValidationProofType.CORS_ORIGIN_REFLECTION: "CWE-942",
    ValidationProofType.OPEN_REDIRECT: "CWE-601",
    ValidationProofType.SENSITIVE_DATA_EXPOSURE: "CWE-200",
    ValidationProofType.WORKING_PUBLIC_CREDENTIAL: "CWE-798",
    ValidationProofType.GRAPHQL_INTROSPECTION_EXPOSURE: "CWE-200",
    ValidationProofType.GRAPHQL_FIELD_SUGGESTION_EXPOSURE: "CWE-200",
    ValidationProofType.SOURCE_MAP_EXPOSURE: "CWE-540",
    ValidationProofType.ERROR_DETAIL_EXPOSURE: "CWE-209",
    ValidationProofType.XSS_EXECUTION: "CWE-79",
    ValidationProofType.SQLI_EFFECT: "CWE-89",
    ValidationProofType.PATH_TRAVERSAL_FILE_READ: "CWE-22",
    ValidationProofType.SSTI_EXECUTION: "CWE-1336",
}
_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})


def _safe_path(url: str) -> str:
    """Retain route identity without exporting query, fragment, or secret segments."""

    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("scoring export requires absolute HTTP surface URLs")
    parts = []
    hide_next = False
    for original in parsed.path.split("/"):
        if not original:
            parts.append("")
            continue
        sensitive = bool(_SECRET_PATH.search(original))
        safe = bool(_PATH_SEGMENT.fullmatch(original)) and not sensitive and not hide_next
        parts.append(original if safe else "{value}")
        hide_next = sensitive
    result = "/".join(parts)
    return result if result.startswith("/") else "/" + result


def _parameter_names(values) -> list[str]:
    return list(dict.fromkeys(name for name in values if _PARAMETER.fullmatch(name)))


def build_dynast_documents(app, run, *, app_name: str, variant: str) -> tuple[dict, dict]:
    """Build scorer files from one completed Run, with explicit twin identity."""

    if run.phase is not RunPhase.DONE:
        raise ValueError("incomplete runs cannot be exported for DynAST scoring")
    if _APP.fullmatch(app_name) is None or variant not in {"vuln", "safe"}:
        raise ValueError("a valid DynAST app and explicit vuln/safe variant are required")
    code_version = run.execution_profile.code_version
    if not code_version:
        raise ValueError("a code version is required for comparable scorer artifacts")

    envelope = {
        "tool": {"name": "Hacklipse", "version": code_version, "mode": "dast"},
        "run": {"app": app_name, "variant": variant},
    }
    surfaces = {item.surface_id: item for item in app.stores.surfaces.list_by_run(run.run_id)}
    observations = app.stores.evidence.list_by_run(run.run_id)
    transmitted = {
        item.surface_id for item in observations
        if item.surface_id is not None and (
            item.evidence_type == "http_response"
            and type(item.observation.get("status")) is int
            and 100 <= item.observation["status"] <= 599
            or item.observation.get("type") == "browser_request_structure"
            and item.observation.get("sent") is True
        )
    }
    # A static HTML/JS reference is discovery evidence. A browser request that
    # was blocked before transmission is only a request shape, not a reached op.
    endpoints = []
    seen_endpoints = set()
    for surface in surfaces.values():
        if surface.method not in {"GET", "HEAD", "OPTIONS"} and surface.surface_id not in transmitted:
            continue
        if surface.discovery_types == ("browser_request",) and surface.surface_id not in transmitted:
            continue
        path = _safe_path(surface.url)
        params = _parameter_names(surface.parameters)
        key = (surface.method, path, tuple(params))
        if key in seen_endpoints:
            continue
        seen_endpoints.add(key)
        endpoint = {"method": surface.method, "path": path}
        if params:
            endpoint["params"] = params
        endpoints.append(endpoint)

    # The public schema explicitly declares these GraphQL operations. Preserve
    # their protocol identity instead of misreporting each as an HTTP GET path.
    evidence_by_id = {item.evidence_id: item for item in observations}
    for item in observations:
        detail = item.observation
        if (
            item.created_by != "recon" or item.evidence_type != "observation"
            or detail.get("type") != GRAPHQL_SCHEMA_OPERATION
            or item.surface_id not in surfaces
        ):
            continue
        kind, operation = detail.get("graphql_kind"), detail.get("operation")
        source = evidence_by_id.get(detail.get("schema_evidence_id"))
        if (
            kind not in {"query", "mutation", "subscription"}
            or not isinstance(operation, str)
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,79}(?:\.[A-Za-z_][A-Za-z0-9_]{0,79})?", operation) is None
            or source is None or source.evidence_type != "http_response"
            or type(source.observation.get("status")) is not int
            or not 200 <= source.observation["status"] < 300
        ):
            continue
        key = ("graphql", kind, operation)
        if key in seen_endpoints:
            continue
        seen_endpoints.add(key)
        endpoints.append({"kind": "graphql", "graphql_kind": kind, "op": operation})

    findings = []
    for finding in app.stores.findings.list_by_run(run.run_id):
        surface = surfaces.get(finding.surface_id)
        if surface is None:
            raise ValueError("confirmed finding has no Run-owned surface")
        if finding.status != "confirmed" or finding.proof_type is None or finding.reproduction_count < 1:
            raise ValueError("unproven finding cannot be exported for scoring")
        path = _safe_path(surface.url)
        embedded_basic_header = (
            finding.proof_type is ValidationProofType.SENSITIVE_DATA_EXPOSURE
            and path.endswith((".js", ".mjs"))
            and any(
                item.surface_id == surface.surface_id
                and item.created_by == "sensitive_exposure_analyzer"
                and item.observation.get("type") == "sensitive_json_exposure"
                and "fetch.authorization" in item.observation.get("field_paths", ())
                for item in observations
            )
        )
        client_script_finding = (
            finding.proof_type is ValidationProofType.WORKING_PUBLIC_CREDENTIAL
            and path.endswith((".js", ".mjs"))
            and any(
                item.surface_id == surface.surface_id
                and item.created_by == "public_login_credentials_analyzer"
                and item.observation.get("type") == "public_login_accepted"
                for item in observations
            )
        ) or embedded_basic_header
        if client_script_finding:
            # The public document is the entry route that delivered the JS.
            # Keep the script as the core Finding surface and use an observed
            # same-origin document reference for the HTTP route scored here.
            document_paths = [
                _safe_path(document.url)
                for item in observations
                if item.surface_id == surface.surface_id
                and item.observation.get("type") == "client_script_reference"
                and (document := surfaces.get(item.observation.get("document_surface_id")))
                is not None
                and document.method == "GET"
                and urlsplit(document.url).netloc == urlsplit(surface.url).netloc
            ]
            if document_paths:
                path = sorted(document_paths, key=lambda value: (-value.count("/"), value))[0]
        http = {"method": surface.method, "path": path}
        names = _parameter_names(surface.parameters)
        if len(names) == 1:
            http["param"] = names[0]
            http["param_in"] = (
                "fragment" if urlsplit(surface.url).fragment else
                "body" if surface.method not in {"GET", "HEAD", "OPTIONS"} else
                "query"
            )
        elif surface.path_identifier:
            http["param"] = surface.path_identifier
            http["param_in"] = "path"
        record = {
            "id": finding.finding_id,
            "title": finding.vulnerability_type,
            "confidence": "certain",
            "location": {"http": http},
            "exploited": True,
        }
        cwe = _CWE.get(finding.proof_type)
        if embedded_basic_header:
            cwe = "CWE-522"
        if cwe:
            record["cwe"] = cwe
        if finding.severity.lower() in _SEVERITIES:
            record["severity"] = finding.severity.lower()
        findings.append(record)

    return (
        {"schema": "dynast-bench.findings/v1", **envelope, "findings": findings},
        {"schema": "dynast-bench.endpoints/v1", **envelope, "endpoints": endpoints},
    )


def write_dynast_documents(app, run, *, app_name: str, variant: str, report_path: str) -> tuple[Path, Path]:
    """Write unique owner-only JSON files beside this Run's Markdown report."""

    findings, endpoints = build_dynast_documents(app, run, app_name=app_name, variant=variant)
    stem = Path(report_path)
    paths = (stem.with_suffix(".findings.json"), stem.with_suffix(".endpoints.json"))
    for path, document in zip(paths, (findings, endpoints), strict=True):
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(document, output, ensure_ascii=False, sort_keys=True, indent=2)
            output.write("\n")
    return paths
