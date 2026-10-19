"""Compare upload extension handling using fixed-size, inert text markers.

Acceptance is an observation, never proof of script execution. All traffic goes
through the shared collector, including approval, scope and budget checks.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import time
import zlib
from base64 import b64decode
from dataclasses import dataclass, field, replace
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit
from uuid import uuid4

from bs4 import BeautifulSoup

from hacklipse.application import RuntimeEvidenceCollector
from hacklipse.application.errors import AgentContractError
from hacklipse.domain import (
    AgentResult, AgentResultStatus, Evidence, EvidenceRequest, HttpRequestSpec,
    Surface, TaskEnvelope,
)
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore
from hacklipse.ports.errors import ApprovalRequired, BudgetExceeded, PolicyViolation
from .request_safety import has_state_changing_get

UPLOAD_TYPE = "File Upload"
UPLOAD_ANALYZER = "file_upload_analyzer"
UPLOAD_FORM = "file_upload_form"
UPLOAD_RESULT = "file_upload_extension_result"
UPLOAD_RISK_EXTENSIONS = (
    ".php", ".svg", ".html", ".phtml", ".php5",
    ".php3", ".php4", ".php6", ".php7", ".php8", ".pht", ".phar", ".phps",
    ".asp", ".aspx", ".ashx", ".asmx", ".jsp", ".jspx", ".cgi", ".pl", ".py",
    ".htm", ".shtml", ".xhtml", ".svgz",
    ".PHP", ".PhP", ".SVG", ".HTML",
    ".jpg.php", ".png.php", ".php.jpg", ".php.png", ".jpg.svg", ".svg.jpg", ".php.",
)
UPLOAD_EXTENSIONS = (
    ".txt", ".jpg", ".png", *UPLOAD_RISK_EXTENSIONS, ".jpeg", ".gif", ".webp",
    ".bmp", ".ico", ".pdf", ".csv", ".json", ".xml", ".zip", ".tar", ".gz",
    ".docx", ".xlsx", "",
)
_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_.\[\]-]{0,63}\Z")
_BOUNDARY = "hacklipseUploadBoundary"
UPLOAD_PROFILES = {
    "text_octet": ("text", "application/octet-stream"),
    "text_image": ("text", "image/png"),
    "png_octet": ("png", "application/octet-stream"),
    "png_image": ("png", "image/png"),
    "jpeg_octet": ("jpeg", "application/octet-stream"),
    "jpeg_image": ("jpeg", "image/jpeg"),
}
# 각 이미지 종류의 기준 요청. "정상 이미지를 아예 수락하지 않는 서버"인지를 이 좌표로
# 판정하므로, PNG만 두면 JPEG 매직바이트를 요구하는 서버에서 모든 변형이 영구히 스킵된다.
_IMAGE_CONTROL_CASES = {(".png", "png_image"), (".jpg", "jpeg_image")}
_IMAGE_CONTROL_EXTENSIONS = {extension for extension, _ in _IMAGE_CONTROL_CASES}
_NATURAL_EXTENSION = {"png": ".png", "jpeg": ".jpg"}
# 저장은 했지만 경로를 알려주지 않는 서버를 위한 고정 목록. 업로드 URL 기준으로
# 풀리는 관용적인 저장 위치만 담는다. 값을 에이전트나 LLM이 고르지 못하게 하려고
# 중앙에서 고정하며, 아래 상한만큼만 쓰고 한 번 맞으면 그 위치만 재사용한다.
_CONVENTIONAL_DIRECTORIES = (
    "uploads/", "upload/", "/uploads/", "/upload/", "files/", "/files/",
    "images/", "img/", "media/", "", "static/uploads/", "/static/uploads/",
)
_MAX_CONVENTIONAL_PROBES = len(_CONVENTIONAL_DIRECTORIES)
# 최소 baseline JPEG(1x1, 3성분). getimagesize나 이미지 디코더로 재검증하는 서버까지
# 통과해야 하므로 FFD8 두 바이트가 아니라 실제로 디코딩되는 파일을 쓴다. marker는
# 아래에서 COM segment로 끼워 넣으므로 이 상수 자체는 고정이고 요청마다 같다.
_JPEG_TEMPLATE = b64decode(
    "/9j/wAARCAABAAEDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQA"
    "AAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVW"
    "V1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ"
    "2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQA"
    "AQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RV"
    "VldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX"
    "2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9sAQwATExMTExMgExMgLSAgIC09LS0tLT1NPT09PT1NXU1NTU1NTV1dXV1dXV1dcHBw"
    "cHBwg4ODg4OTk5OTk5OTk5OT/9sAQwEXGBglIyVAIyNAmWhVaJmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZ"
    "mZmZmZmZmZmZmZmZmZmZ/90ABAAB/9oADAMBAAIRAxEAPwDiqKKKAP/Z"
)


@dataclass(frozen=True)
class UploadFormPlan:
    url: str
    parameter: str
    accept: str
    fields: tuple[tuple[str, str], ...] = field(default=(), repr=False)


def upload_payload(marker: str, profile: str) -> bytes:
    """A real one-pixel PNG or JPEG carries only an inert, unique text comment."""
    if not re.fullmatch(r"upload[a-f0-9]{32}", marker) or profile not in UPLOAD_PROFILES:
        raise ValueError("upload payload needs a bounded marker and profile")
    kind = UPLOAD_PROFILES[profile][0]
    if kind == "text":
        return marker.encode("ascii")
    if kind == "jpeg":
        comment = marker.encode("ascii") + b"\x00"
        return (_JPEG_TEMPLATE[:2] + b"\xff\xfe"
                + struct.pack(">H", len(comment) + 2) + comment + _JPEG_TEMPLATE[2:])

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
            + chunk(b"tEXt", b"Comment\0" + marker.encode("ascii"))
            + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00\xff"))
            + chunk(b"IEND", b""))


def upload_response_problem(observation: dict) -> tuple[str, str] | None:
    """Keep file-policy rejections distinct from auth, quota and transport failures."""
    status = observation.get("status")
    body = observation.get("body")
    messages: list[str] = []
    if isinstance(body, str) and len(body) <= 32768:
        try:
            payload = json.loads(body)
        except ValueError:
            payload = None
        if isinstance(payload, dict):
            pending = [payload.get(key) for key in ("error", "errors", "message", "detail")]
            for _ in range(3):
                nested = []
                for item in pending[:16]:
                    if isinstance(item, str):
                        messages.append(item[:2048])
                    elif isinstance(item, dict):
                        nested.extend(item.values())
                    elif isinstance(item, list):
                        nested.extend(item)
                pending = nested
        elif status in {400, 403, 413, 422}:
            messages.append(BeautifulSoup(body, "html.parser").get_text(" ", strip=True))
    message = " ".join(messages).casefold()
    csrf = r"(?:csrf|cross.site.request|verification.token|authenticity.token)"
    failure = r"(?:invalid|missing|expired|mismatch|failed|failure|forbidden|incorrect|required)"
    if re.search(rf"{csrf}[^.;:,\n]{{0,60}}{failure}|{failure}[^.;:,\n]{{0,60}}{csrf}", message):
        return "blocked", "csrf_failed"
    for pattern, reason in (
        (r"extension", "extension_rejected"),
        (r"mime|media.type|content.type", "mime_rejected"),
        (r"file.content|magic.bytes|invalid.image|corrupt.image|file.signature", "content_rejected"),
        (r"file.type", "file_type_rejected"),
    ):
        if (status in {200, 400, 403, 415, 422} and re.search(pattern, message)
                and re.search(r"invalid|unsupported|forbidden|disallowed|not.allowed|not.supported|not.permitted|reject", message)):
            return "rejected", reason
    if status in {401, 403}:
        return "blocked", "authentication_or_permission_required"
    if status == 413:
        return "blocked", "size_limit"
    if status == 429:
        return "blocked", "rate_limited"
    if status == 415:
        return "rejected", "unsupported_media_type"
    if status in {301, 302, 303, 307, 308}:
        location = observation.get("location")
        if isinstance(location, str):
            try:
                parts = {part.casefold() for part in urlsplit(location).path.split("/")}
                if parts & {"login", "signin", "sign-in", "authenticate"}:
                    return "blocked", "authentication_or_permission_required"
            except ValueError:
                pass
    if observation.get("type") == "http_error":
        return "inconclusive", "transport_error"
    if isinstance(status, int) and status >= 500:
        return "inconclusive", "server_error"
    return None


def upload_form_plans(body: str, base_url: str) -> tuple[UploadFormPlan, ...]:
    """Read successful form controls; never guess missing user input."""
    if "multipart/form-data" not in body.casefold():
        return ()
    plans = []
    soup = BeautifulSoup(body, "html.parser")
    forms = soup.find_all("form")
    forms_by_id = {}
    controls_by_form = {id(form): [] for form in forms}
    for form in forms:
        if form.get("id"):
            forms_by_id.setdefault(form["id"], form)
    for control in soup.find_all(["input", "select", "textarea", "button"], attrs={"name": True}):
        owner = forms_by_id.get(control["form"]) if control.has_attr("form") else control.find_parent("form")
        if owner is not None and control.get("name") and not control.has_attr("disabled") and not control.find_parent("fieldset", disabled=True):
            controls_by_form[id(owner)].append(control)
    for form in forms:
        if (str(form.get("method", "get")).upper() != "POST"
                or str(form.get("enctype", "")).split(";", 1)[0].strip().casefold() != "multipart/form-data"):
            continue
        controls = controls_by_form[id(form)]
        files = [control for control in controls if control.name == "input" and str(control.get("type", "")).casefold() == "file"]
        if len(files) != 1 or len(controls) > 17:
            continue
        fields = []
        supported = True
        submit_count = 0
        for control in controls:
            name = control["name"]
            kind = str(control.get("type", "submit" if control.name == "button" else "text")).casefold()
            if (not _FIELD.fullmatch(name) or kind in {"password", "image"}
                    or any(control.has_attr(attr) for attr in ("formaction", "formmethod", "formenctype"))
                    or control is not files[0] and name == files[0]["name"]):
                supported = False
                break
            if kind in {"file", "button", "reset"}:
                continue
            if kind in {"checkbox", "radio"} and not control.has_attr("checked"):
                continue
            if kind == "submit":
                submit_count += 1
            if control.name == "select":
                options = [option for option in control.find_all("option") if not option.has_attr("disabled")]
                selected = [option for option in options if option.has_attr("selected")]
                if control.has_attr("multiple"):
                    supported = False
                    break
                option = (selected or options or [None])[0]
                value = str(option.get("value", option.get_text())) if option else ""
            elif control.name == "textarea":
                value = control.get_text()
            else:
                value = str(control.get("value", "on" if kind in {"checkbox", "radio"} else ""))
            if (len(value.encode("utf-8")) > 4096 or _BOUNDARY in value
                    or control.has_attr("required") and not value
                    or re.search(r"\b(delete|erase|remove|purchase|transfer|reset)\b", name + " " + value, re.I)):
                supported = False
                break
            fields.append((name, value))
        # shortcut: JS-only and ambiguous multi-submit/multi-file forms need an observed browser replay.
        if not supported or submit_count > 1:
            continue
        url = urljoin(base_url, form.get("action") or base_url)
        try:
            parsed = urlsplit(url)
            if (_origin(url) != _origin(base_url) or parsed.query or parsed.fragment
                    or parsed.username or parsed.password):
                continue
        except ValueError:
            continue
        plans.append(UploadFormPlan(url, files[0]["name"], str(files[0].get("accept", ""))[:256], tuple(fields)))
    return tuple(dict.fromkeys(plans))[:8]


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme.casefold() == "https" else 80)
    return parsed.scheme.casefold(), (parsed.hostname or "").casefold(), port


def upload_request(
    surface_id: str, parameter: str, marker: str, extension: str,
    *, profile: str = "text_octet", fields: tuple[tuple[str, str], ...] = (),
) -> EvidenceRequest:
    if (not _FIELD.fullmatch(parameter) or not re.fullmatch(r"upload[a-f0-9]{32}", marker)
            or extension not in UPLOAD_EXTENSIONS):
        raise ValueError("upload probes require a bounded field, marker and extension")
    payload = upload_payload(marker, profile)
    if (len(fields) > 16 or any(not _FIELD.fullmatch(name) or name == parameter
            or len(value.encode("utf-8")) > 4096 or _BOUNDARY in value for name, value in fields)):
        raise ValueError("upload form fields must be bounded and separate from the file")
    body = b""
    for name, value in fields:
        body += (f'--{_BOUNDARY}\r\nContent-Disposition: form-data; name="{name}"\r\n'
                 'Content-Type: text/plain; charset=utf-8\r\n\r\n').encode("ascii")
        body += value.encode("utf-8") + b"\r\n"
    body += (f"--{_BOUNDARY}\r\n"
            f'Content-Disposition: form-data; name="{parameter}"; filename="{marker}{extension}"\r\n'
            f"Content-Type: {UPLOAD_PROFILES[profile][1]}\r\n\r\n").encode("ascii")
    body += payload + f"\r\n--{_BOUNDARY}--\r\n".encode("ascii")
    return EvidenceRequest(
        evidence_type="http_response", surface_id=surface_id,
        reason=f"inert upload extension check {extension} {profile} {marker}", suggested_tool="http_post",
        http_request=HttpRequestSpec(method="POST", body=body.decode("latin-1"), body_encoding="latin-1",
            headers=(("Content-Type", f"multipart/form-data; boundary={_BOUNDARY}"),)),
    )


_REFERENCE_ATTRIBUTE = re.compile(r"""(?:href|src)\s*=\s*("|')([^"']{1,2048})\1""", re.IGNORECASE)

def uploaded_file_url(observation: dict, upload_url: str, filename: str) -> str | None:
    """Never fetch arbitrary response links or follow a redirect automatically."""
    references = [observation.get("location")]
    for row in observation.get("headers", ()):
        if isinstance(row, (tuple, list)) and len(row) == 2 and str(row[0]).casefold() == "location":
            references.append(row[1])
    body = observation.get("body")
    if isinstance(body, str) and len(body) <= 32768:
        try:
            value = json.loads(body)
        except ValueError:
            value = None
        pending = [value]
        for _ in range(3):
            nested = []
            for item in pending[:16]:
                if isinstance(item, dict):
                    references.extend(item.get(key) for key in ("url", "path", "file_url", "download_url", "location"))
                    nested.extend(child for child in item.values() if isinstance(child, (dict, list)))
                elif isinstance(item, list):
                    nested.extend(item[:8])
            pending = nested
        # 고전적인 업로드 폼은 저장 경로를 JSON이 아니라 HTML 링크로 돌려준다. 서버가
        # 스스로 적어 보낸 참조 중 방금 올린 파일 이름을 담은 것만 받는다. 임의 링크를
        # 따라가는 것이 아니라 "이 파일이 여기 있다"는 서버의 진술만 읽는 것이다.
        if filename:
            references.extend(
                match.group(2) for match in _REFERENCE_ATTRIBUTE.finditer(body)
                if filename in match.group(2)
            )
    references.sort(key=lambda reference: not (isinstance(reference, str) and filename in reference))
    for reference in references[:32]:
        url = safe_retrieval_url(reference, upload_url)
        if url is not None:
            return url
    return None


def safe_retrieval_url(reference: object, upload_url: str) -> str | None:
    """업로드 뒤 자동으로 GET해도 되는 회수 대상인지 한 곳에서 판정한다.

    응답이 알려준 참조든 관용 경로든 같은 규칙을 지나야 한다. 규칙이 두 군데로 갈리면
    한쪽만 느슨해지는 것을 알아채기 어렵다.
    """

    if (not isinstance(reference, str) or len(reference) > 2048
            or any(ord(char) <= 32 or ord(char) > 126 for char in reference)):
        return None
    try:
        url = urljoin(upload_url, reference)
        parsed = urlsplit(url)
        query = parse_qsl(parsed.query, keep_blank_values=True)
    except ValueError:
        return None
    safe_query = all(name in {"id", "file", "file_id", "download"}
                     and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value) for name, value in query)
    decoded_path = unquote(unquote(parsed.path))
    if (parsed.scheme in {"http", "https"} and _origin(url) == _origin(upload_url)
            and not parsed.username and not parsed.password and not parsed.fragment
            and len(query) <= 4 and safe_query and not has_state_changing_get(url)
            and ".." not in decoded_path.split("/") and "\\" not in decoded_path
            and parsed.path and (parsed.path != urlsplit(upload_url).path or query)):
        return url
    return None


def upload_probe_plan(extensions: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    """Prioritize genuine controls and distinct server families before rare suffixes."""
    controls = ((".png", "png_image"), (".jpg", "jpeg_image"),
                (".png", "png_octet"), (".png", "text_image"), (".jpg", "jpeg_octet"))
    primary = (".txt", ".png", ".jpg", ".php", ".svg", ".html", ".asp", ".aspx", ".jsp", ".cgi")
    cases = [case for case in controls if case[0] in extensions]
    cases.extend((extension, "text_octet") for extension in primary if extension in extensions)
    cases.extend((extension, profile) for extension in (".php", ".svg", ".html") if extension in extensions
                 for profile in ("text_image", "png_octet", "png_image", "jpeg_image"))
    # 확장자와 내용을 동시에 보는 서버는 "정상 이미지 + 이미지 확장자를 포함한 위험
    # 확장자" 조합에서만 갈린다. 이중 확장자는 그에 맞는 이미지 종류로만 보낸다.
    cases.extend(case for case in (
        (".jpg.php", "jpeg_image"), (".jpg.php", "jpeg_octet"),
        (".png.php", "png_image"), (".jpg.svg", "jpeg_image"),
    ) if case[0] in extensions)
    cases.extend((extension, "text_octet") for extension in extensions)
    return tuple(dict.fromkeys(cases))


def upload_policy_differences(rows: list[dict]) -> list[dict]:
    """Only infer sensitivity from accepted/rejected pairs with one changed dimension."""
    by_case = {(row["extension"], row["profile"]): row for row in rows}
    differences = []
    for row in rows:
        comparisons = []
        kind, _ = UPLOAD_PROFILES[row["profile"]]
        if row["profile"].endswith("_image"):
            comparisons.append(("mime", row["extension"], kind + "_octet"))
        if kind != "text":
            comparisons.append(("content", row["extension"], "text_" + row["profile"].split("_", 1)[1]))
        natural = _NATURAL_EXTENSION.get(kind, ".png")
        if row["extension"] != natural:
            comparisons.append(("extension", natural, row["profile"]))
        for dimension, extension, profile in comparisons:
            control = by_case.get((extension, profile))
            if (control and {control["outcome"], row["outcome"]} == {"accepted", "rejected"}):
                differences.append({"dimension": dimension, "extension": row["extension"],
                                    "profile": row["profile"], "control_outcome": control["outcome"],
                                    "probe_outcome": row["outcome"]})
    return differences


def check_upload_extensions(
    collector: RuntimeEvidenceCollector, task: TaskEnvelope, surface: Surface,
    parameter: str, extensions: tuple[str, ...] = UPLOAD_EXTENSIONS,
    *, form_page: Surface | None = None, probes: tuple[tuple[str, str], ...] | None = None,
) -> tuple[list[dict], tuple[str, ...]]:
    """Record persisted acceptance, explicit type rejection, and uncertainty separately."""
    if surface.method != "POST" or parameter not in surface.parameters or not _FIELD.fullmatch(parameter):
        raise AgentContractError("upload check needs an observed POST file field")
    if "http_post" not in task.allowed_tools or "http_get" not in task.allowed_tools:
        raise AgentContractError("upload check needs HTTP upload and retrieval tools")
    if form_page is not None and (
        form_page.run_id != task.run_id or form_page.method != "GET"
        or _origin(form_page.url) != _origin(surface.url)
    ):
        raise AgentContractError("upload form page must be a same-run, same-origin GET surface")
    cases = probes if probes is not None else upload_probe_plan(extensions)
    if any(extension not in UPLOAD_EXTENSIONS or profile not in UPLOAD_PROFILES for extension, profile in cases):
        raise AgentContractError("unsupported upload probe case")
    rows = [{"extension": extension, "profile": profile,
             "content_kind": UPLOAD_PROFILES[profile][0], "mime_type": UPLOAD_PROFILES[profile][1],
             "outcome": "not_tested", "reason": "request_budget"} for extension, profile in cases]
    ids: list[str] = []
    accepted_image_kinds: set[str] = set()
    stored_directory: list[str] = []
    conventional_used = 0
    deadline = time.monotonic() + max(0, task.timeout_seconds - 1)

    def attempt_retrieval(url: str, row: dict, marker: str, extension: str, profile: str) -> str:
        """회수 대상 하나를 확인한다. accepted | next | stop 중 하나를 돌려준다."""

        try:
            fetch_id, fetched = collector.collect_with_result(
                task.run_id, url,
                EvidenceRequest(evidence_type="http_response", surface_id=surface.surface_id,
                    reason=f"verify inert uploaded file {marker}{extension}", suggested_tool="http_get",
                    http_request=HttpRequestSpec(method="GET")),
                task_id=task.task_id, validation_id=task.validation_id,
                credential_ref=task.credential_ref, timeout_seconds=min(8.0, max(0.1, deadline - time.monotonic())),
            )
        except (ApprovalRequired, PolicyViolation):
            row.update(reason="retrieval_policy_blocked")
            return "next"
        except BudgetExceeded:
            return "stop"
        ids.append(fetch_id)
        row["evidence_ids"].append(fetch_id)
        data = fetched.observation
        problem = upload_response_problem(data)
        if problem:
            row.update(outcome="blocked" if problem[0] == "blocked" else "inconclusive",
                       reason="retrieval_" + problem[1])
            if problem[0] == "blocked" or problem[1] == "transport_error":
                for pending in rows:
                    if pending["outcome"] == "not_tested":
                        pending.update(outcome="blocked", reason=problem[1])
                return "stop"
            return "next"
        payload = upload_payload(marker, profile)
        if not (data.get("status") == 200 and not data.get("truncated")
                and (fetched.content_hash == hashlib.sha256(payload).hexdigest()
                     or UPLOAD_PROFILES[profile][0] == "text" and data.get("body") == marker)):
            return "next"
        basename = unquote(urlsplit(url).path.rsplit("/", 1)[-1])
        suffix = next((suffix for suffix in sorted(UPLOAD_EXTENSIONS, key=len, reverse=True)
                       if suffix and basename.casefold().endswith(suffix.casefold())),
                      "." + basename.rsplit(".", 1)[-1].casefold() if "." in basename else "")
        if not re.fullmatch(r"\.[A-Za-z0-9.]{1,24}", suffix):
            suffix = ""
        served_type = str(data.get("content_type", "")).split(";", 1)[0].strip().casefold()
        if served_type not in {"image/png", "image/jpeg", "image/svg+xml", "text/html", "text/plain",
                               "application/octet-stream", "application/pdf"}:
            served_type = "other"
        row.update(outcome="accepted", reason="stored_marker_retrieved",
                   renamed=basename != marker + extension, stored_extension=suffix,
                   served_content_type=served_type)
        return "accepted"
    for (extension, profile), row in zip(cases, rows):
        if time.monotonic() >= deadline:
            row["reason"] = "time_budget"
            continue
        if task.request_budget - len(ids) < (3 if form_page else 2):
            continue
        # 정상 이미지를 아예 수락하지 않는 서버에서는 MIME·내용 변형에 요청을 쓰지
        # 않는다. 각 이미지 종류의 기준 확장자는 그 판단의 재료이므로 먼저 보낸다.
        kind = UPLOAD_PROFILES[profile][0]
        unlocked = accepted_image_kinds if kind == "text" else accepted_image_kinds & {kind}
        if (profile != "text_octet" and extension not in _IMAGE_CONTROL_EXTENSIONS
                and not unlocked and probes is None):
            row["reason"] = "normal_image_not_verified"
            continue
        marker = "upload" + uuid4().hex
        fields = ()
        try:
            if form_page is not None:
                refresh_id, fresh = collector.collect_with_result(
                    task.run_id, form_page.url,
                    EvidenceRequest(evidence_type="http_response", surface_id=surface.surface_id,
                        reason="refresh upload form controls", suggested_tool="http_get",
                        http_request=HttpRequestSpec(method="GET", query_parameters=form_page.observed_query)),
                    task_id=task.task_id, validation_id=task.validation_id,
                    credential_ref=task.credential_ref, timeout_seconds=min(8.0, max(0.1, deadline - time.monotonic())),
                )
                ids.append(refresh_id)
                fresh_body = fresh.observation.get("body")
                plans = [plan for plan in upload_form_plans(fresh_body, form_page.url)
                         if plan.url == surface.url and plan.parameter == parameter] if (
                    fresh.observation.get("status") == 200 and isinstance(fresh_body, str)
                    and str(fresh.observation.get("content_type", "")).split(";", 1)[0].strip().casefold() == "text/html"
                    and not fresh.observation.get("truncated")
                ) else []
                if len(plans) != 1:
                    for pending in rows:
                        if pending["outcome"] == "not_tested":
                            pending.update(outcome="blocked", reason="fresh_form_unavailable")
                    break
                fields = plans[0].fields
            request = upload_request(surface.surface_id, parameter, marker, extension, profile=profile, fields=fields)
            upload_id, response = collector.collect_with_result(
                task.run_id, surface.url, request, task_id=task.task_id,
                validation_id=task.validation_id, credential_ref=task.credential_ref,
                timeout_seconds=min(8.0, max(0.1, deadline - time.monotonic())),
            )
        except (ApprovalRequired, PolicyViolation):
            for pending in rows:
                if pending["outcome"] == "not_tested":
                    pending.update(outcome="blocked", reason="approval_or_policy_blocked")
            break
        except BudgetExceeded:
            break
        ids.append(upload_id)
        row.update(outcome="inconclusive", reason="upload_response_unverified", evidence_ids=[upload_id])
        observation = response.observation
        status = observation.get("status")
        row["status"] = status
        # A generic 400/403/422 can mean CSRF, authentication or content validation.
        problem = upload_response_problem(observation)
        if problem:
            row.update(outcome=problem[0], reason=problem[1])
            if problem[0] == "blocked" or problem[1] == "transport_error":
                for pending in rows:
                    if pending["outcome"] == "not_tested":
                        pending.update(outcome="blocked", reason=problem[1])
                break
            continue
        if status not in {200, 201, 202, 204, 301, 302, 303, 307, 308}:
            continue
        # 응답이 저장 위치를 말해주지 않는 서버도 파일은 남긴다. 그때만 중앙에서 고정한
        # 관용 위치를 상한만큼 한 번 훑고, 한 번 맞으면 이후에는 그 위치만 쓴다.
        named = uploaded_file_url(observation, surface.url, marker + extension)
        if named is not None:
            targets = [named]
        elif stored_directory:
            targets = [url for url in (safe_retrieval_url(
                stored_directory[0] + marker + extension, surface.url),) if url]
        else:
            allowance = _MAX_CONVENTIONAL_PROBES - conventional_used
            prefixes = _CONVENTIONAL_DIRECTORIES[:max(0, allowance)]
            conventional_used += len(prefixes)
            targets = [url for url in (
                safe_retrieval_url(prefix + marker + extension, surface.url) for prefix in prefixes
            ) if url]
        stop = False
        for target in targets:
            if task.request_budget - len(ids) < 1 or time.monotonic() >= deadline:
                break
            action = attempt_retrieval(target, row, marker, extension, profile)
            if action == "stop":
                stop = True
                break
            if action == "accepted":
                if named is None and not stored_directory:
                    # 우리가 만든 대상이므로 경로는 반드시 그 파일명으로 끝난다.
                    stored_directory.append(
                        urlsplit(target).path[: -len(marker + extension)] or "/"
                    )
                if (extension, profile) in _IMAGE_CONTROL_CASES:
                    accepted_image_kinds.add(kind)
                break
        if stop:
            break
    return rows, tuple(ids)


class FileUploadAnalyzer:
    def __init__(self, *, candidate_store: CandidateStore, surface_store: SurfaceStore,
                 evidence_store: EvidenceStore, collector: RuntimeEvidenceCollector):
        self._candidates = candidate_store
        self._surfaces = surface_store
        self._evidence = evidence_store
        self._collector = collector

    def handle(self, task: TaskEnvelope) -> AgentResult:
        if task.candidate_id is None:
            raise AgentContractError("upload analysis requires a candidate")
        candidate = self._candidates.get(task.run_id, task.candidate_id)
        surface = self._surfaces.get(task.run_id, candidate.surface_id)
        if candidate.vulnerability_type != UPLOAD_TYPE or task.surface_id != surface.surface_id:
            raise AgentContractError("invalid upload analysis task")
        evidence = self._evidence.get_many(task.run_id, task.evidence_ids)
        plan = next((item.observation for item in evidence
                     if item.surface_id == surface.surface_id and item.created_by == "recon"
                     and item.observation.get("type") == UPLOAD_FORM
                     and item.observation.get("parameter") in surface.parameters), None)
        if plan is None:
            raise AgentContractError("upload analysis requires an observed upload form")
        form_page = (self._surfaces.get(task.run_id, plan["source_surface_id"])
                     if plan.get("refresh_form") else None)
        rows, collected = check_upload_extensions(
            self._collector, replace(task, request_budget=max(0, task.request_budget - (3 if form_page else 2))),
            surface, plan["parameter"], form_page=form_page,
        )
        observation_id = f"evi-{uuid4()}"
        self._evidence.append(Evidence(
            evidence_id=observation_id, run_id=task.run_id, surface_id=surface.surface_id,
            created_by=UPLOAD_ANALYZER, evidence_type="observation", source_task_id=task.task_id,
            observation={"type": UPLOAD_RESULT, "parameter": plan["parameter"],
                         "declared_accept": plan.get("accept", ""), "results": rows,
                         "source_surface_id": plan.get("source_surface_id"),
                         "refresh_form": bool(form_page), "policy_differences": upload_policy_differences(rows),
                         "limitation": "extension/content-type handling only; no execution proof"},
        ))
        return AgentResult(task_id=task.task_id, status=AgentResultStatus.COMPLETED,
                           candidate_ids=(candidate.candidate_id,),
                           new_evidence_ids=(*collected, observation_id))
