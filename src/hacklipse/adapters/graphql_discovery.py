"""Extract bounded GraphQL operation names from a public introspection response.

Only schema structure crosses the Recon boundary. Values, source documents and
credentials are never copied into operation observations.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass

from hacklipse.domain import Evidence, EvidenceRequest, HttpRequestKind, HttpRequestSpec


GRAPHQL_SCHEMA_OPERATION = "graphql_schema_operation"
INTROSPECTION_QUERY = (
    "query IntrospectionQuery { __schema { queryType { name } "
    "mutationType { name } subscriptionType { name } "
    "types { kind name fields { name "
    "args { name type { kind name ofType { kind name ofType { kind name } } } } "
    "type { kind name ofType { kind name ofType { kind name "
    "ofType { kind name } } } } "
    "} } } }"
)
GRAPHQL_READ_QUERY_PLAN = "graphql_read_query_plan"
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,79}\Z")
_MAX_SCHEMA_BYTES = 2 * 1024 * 1024
_MAX_OPERATIONS = 256
_MAX_QUERY_INPUTS = 24
_EXTERNAL_DESTINATION_TOKENS = frozenset({
    "url", "uri", "host", "domain", "callback", "webhook", "redirect", "destination",
})
_EFFECTFUL_FIELD_TOKENS = frozenset({
    "create", "delete", "disable", "enable", "execute", "fetch", "remove",
    "report", "reset", "run", "send", "trigger", "update", "upload", "write",
})


def _name_tokens(name: str) -> frozenset[str]:
    expanded = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return frozenset(part.casefold() for part in re.split(r"[^A-Za-z0-9]+", expanded) if part)


@dataclass(frozen=True, slots=True)
class GraphqlQueryInput:
    field: str
    argument: str
    select_typename: bool


def graphql_query_plans(evidence: Evidence) -> tuple[GraphqlQueryInput, ...]:
    """Read only bounded schema-derived field coordinates from Recon evidence."""

    if (
        evidence.created_by != "recon" or evidence.evidence_type != "observation"
        or evidence.observation.get("type") != GRAPHQL_READ_QUERY_PLAN
    ):
        return ()
    raw = evidence.observation.get("plans")
    if not isinstance(raw, list) or not 0 < len(raw) <= _MAX_QUERY_INPUTS:
        return ()
    plans: list[GraphqlQueryInput] = []
    for item in raw:
        if not isinstance(item, dict):
            return ()
        field, argument, selected = (
            item.get("field"), item.get("argument"), item.get("select_typename")
        )
        if (
            not isinstance(field, str) or not _NAME.fullmatch(field)
            or not isinstance(argument, str) or not _NAME.fullmatch(argument)
            or type(selected) is not bool
        ):
            return ()
        plans.append(GraphqlQueryInput(field, argument, selected))
    return tuple(dict.fromkeys(plans))


def graphql_query_requests(
    surface_id: str, plan: GraphqlQueryInput, marker: str, purpose: str,
) -> tuple[EvidenceRequest, EvidenceRequest]:
    """Create one query control and one quote probe; the domain checks both."""

    def build(value: str, kind: HttpRequestKind) -> EvidenceRequest:
        selection = " { __typename }" if plan.select_typename else ""
        document = (
            f'query {{ {plan.field}({plan.argument}: "{value}")'
            f'{selection} }}'
        )
        return EvidenceRequest(
            evidence_type="http_response", surface_id=surface_id,
            reason=f"{purpose}: {plan.field}.{plan.argument}: {kind.value}",
            suggested_tool="http_get",
            http_request=HttpRequestSpec(
                method="GET", query_parameters=(("query", document),),
                request_kind=kind,
            ),
        )

    return (
        build(marker, HttpRequestKind.GRAPHQL_QUERY_CONTROL),
        build(marker + "'", HttpRequestKind.GRAPHQL_QUERY_PROBE),
    )


def graphql_auth_blocked_response(evidence: Evidence) -> bool:
    """Recognize an explicit auth gate without treating a generic error as proof."""

    status = evidence.observation.get("status")
    if type(status) is int and status in {401, 403}:
        return True
    body = evidence.observation.get("body")
    if not isinstance(body, str) or len(body) > 65536:
        return False
    try:
        document = json.loads(body)
    except (TypeError, ValueError):
        return False
    if not isinstance(document, dict) or not isinstance(document.get("errors"), list):
        return False
    return any(
        isinstance(item, dict)
        and isinstance(item.get("extensions"), dict)
        and item["extensions"].get("code") in {"UNAUTHENTICATED", "FORBIDDEN"}
        for item in document["errors"][:20]
    )


def _schema(observation: Mapping[str, object]) -> dict | None:
    status = observation.get("status")
    media = observation.get("content_type")
    body = observation.get("body")
    if (
        type(status) is not int or not 200 <= status < 300
        or observation.get("truncated")
        or not isinstance(media, str)
        or media.split(";", 1)[0].strip().casefold() not in {
            "application/json", "application/graphql-response+json"
        }
        or not isinstance(body, str) or len(body) > _MAX_SCHEMA_BYTES
    ):
        return None
    try:
        document = json.loads(body)
    except (TypeError, ValueError):
        return None
    if not isinstance(document, dict) or not isinstance(document.get("data"), dict):
        return None
    schema = document["data"].get("__schema")
    if not isinstance(schema, dict):
        return None
    types = schema.get("types")
    if not isinstance(types, list) or not 0 < len(types) <= 500:
        return None
    return schema


def _named_type(value: object) -> tuple[str, str] | None:
    for _ in range(4):
        if not isinstance(value, dict):
            return None
        kind, name = value.get("kind"), value.get("name")
        if kind in {"SCALAR", "ENUM", "OBJECT", "INTERFACE", "UNION"}:
            if isinstance(name, str) and _NAME.fullmatch(name):
                return kind, name
            return None
        if kind not in {"NON_NULL", "LIST"}:
            return None
        value = value.get("ofType")
    return None


def graphql_schema_query_inputs(
    observation: Mapping[str, object],
) -> tuple[GraphqlQueryInput, ...]:
    """Select bounded, single-argument read queries with safe scalar inputs.

    Mutation and subscription roots are excluded. Operations needing another
    required argument cannot be replayed from this schema shape alone.
    """

    schema = _schema(observation)
    if schema is None:
        return ()
    query_type = schema.get("queryType")
    root = query_type.get("name") if isinstance(query_type, dict) else None
    if not isinstance(root, str) or not _NAME.fullmatch(root):
        return ()
    plans: list[GraphqlQueryInput] = []
    for entry in schema["types"]:
        if not isinstance(entry, dict) or entry.get("kind") != "OBJECT" or entry.get("name") != root:
            continue
        fields = entry.get("fields")
        if not isinstance(fields, list) or len(fields) > 1000:
            return ()
        for field in fields:
            if not isinstance(field, dict):
                continue
            name, args = field.get("name"), field.get("args")
            return_type = _named_type(field.get("type"))
            if (
                not isinstance(name, str) or not _NAME.fullmatch(name)
                or name.startswith("__") or not isinstance(args, list)
                or len(args) > 32 or return_type is None
                or _name_tokens(name) & _EFFECTFUL_FIELD_TOKENS
            ):
                continue
            # __typename is valid on composite objects; a scalar result needs
            # no selection. Unions and interfaces also support __typename.
            if return_type[0] not in {"SCALAR", "ENUM", "OBJECT", "INTERFACE", "UNION"}:
                continue
            for arg in args:
                if not isinstance(arg, dict):
                    continue
                arg_name, arg_type = arg.get("name"), arg.get("type")
                named = _named_type(arg_type)
                if (
                    not isinstance(arg_name, str) or not _NAME.fullmatch(arg_name)
                    or named not in {("SCALAR", "String"), ("SCALAR", "ID")}
                    or _name_tokens(arg_name) & _EXTERNAL_DESTINATION_TOKENS
                ):
                    continue
                if any(
                    other is not arg and isinstance(other, dict)
                    and isinstance(other.get("type"), dict)
                    and other["type"].get("kind") == "NON_NULL"
                    and other.get("defaultValue") is None
                    for other in args
                ):
                    continue
                plans.append(GraphqlQueryInput(
                    field=name, argument=arg_name,
                    select_typename=return_type[0] not in {"SCALAR", "ENUM"},
                ))
                if len(plans) >= _MAX_QUERY_INPUTS:
                    return tuple(plans)
        break
    return tuple(plans)


def graphql_schema_operations(
    observation: Mapping[str, object],
) -> tuple[tuple[str, str], ...]:
    """Return (query|mutation|subscription, operation) from a valid schema."""

    schema = _schema(observation)
    if schema is None:
        return ()
    types = schema["types"]

    roots: dict[str, str] = {}
    for kind in ("query", "mutation", "subscription"):
        entry = schema.get(kind + "Type")
        if isinstance(entry, dict) and isinstance(entry.get("name"), str):
            name = entry["name"]
            if _NAME.fullmatch(name):
                roots[name] = kind
    if "query" not in roots.values():
        return ()

    operations: set[tuple[str, str]] = {("query", "__schema")}
    for entry in types:
        if not isinstance(entry, dict) or entry.get("kind") != "OBJECT":
            continue
        type_name = entry.get("name")
        fields = entry.get("fields")
        if (
            not isinstance(type_name, str) or not _NAME.fullmatch(type_name)
            or type_name.startswith("__")
            or not isinstance(fields, list) or len(fields) > 1000
        ):
            continue
        root_kind = roots.get(type_name)
        if root_kind is None:
            # Object fields are part of a selection set, not independently
            # invocable root operations. A later field-level analyzer can use
            # schema structure without inflating endpoint coverage here.
            continue
        for field in fields:
            name = field.get("name") if isinstance(field, dict) else None
            if not isinstance(name, str) or not _NAME.fullmatch(name) or name.startswith("__"):
                continue
            operations.add((root_kind, name))
            if len(operations) >= _MAX_OPERATIONS:
                return tuple(sorted(operations))
    return tuple(sorted(operations))
