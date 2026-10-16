"""렌더링된 UI를 관측한다. 브라우저의 HTTP는 모두 공용 Collector로 중계한다."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from hacklipse.application import RuntimeEvidenceCollector
from hacklipse.domain import EvidenceRequest, ExecutionRequest, HttpRequestSpec, TaskEnvelope
from hacklipse.ports import RunStore
from hacklipse.ports.errors import ApprovalRequired, BudgetExceeded, PolicyViolation

from .browser_runtime import _origin, _origin_key, _url_in_scope
from .xss_execution import RAW_HASH_CANARY, RAW_HASH_PARAMETER

_FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\[\]-]{0,79}$")
_SECRET = re.compile(r"password|passwd|token|csrf|secret|session|authorization|credential|username|api.?key|email", re.I)
_ACTION = re.compile(r"menu|tab|detail|edit|new|create|register|search|filter|advanced|expand|open|view|메뉴|상세|편집|신규|등록|검색|필터|더보기|열기|보기", re.I)
_DESTRUCTIVE = re.compile(r"delete|remove|logout|log out|sign out|save|submit|confirm|purchase|pay\b|삭제|제거|로그아웃|저장|결제|확정", re.I)
_HEADERS = frozenset({"accept", "content-type", "rsc", "next-router-state-tree", "next-router-prefetch", "next-url", "x-requested-with"})
_MAX_OBSERVATIONS = 200


def _names(values) -> tuple[str, ...]:
    return tuple(dict.fromkeys(x for x in values if isinstance(x, str) and _FIELD.fullmatch(x)))[:64]


def _query(url: str) -> tuple[tuple[str, str], ...]:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if parsed.fragment:
        pairs.extend(parse_qsl(urlsplit(parsed.fragment).query, keep_blank_values=True))
    return tuple((k, v if not _SECRET.search(k) and len(v) <= 100 and "@" not in v else "")
                 for k, v in pairs
                 if _FIELD.fullmatch(k))[:64]


def request_structure(url: str, method: str, content_type: str, body: str | None) -> dict:
    """파라미터 이름과 형식만 남긴다. 본문·쿠키·헤더 값은 결과에 넣지 않는다."""

    media = content_type.split(";", 1)[0].strip().lower()
    fields: tuple[str, ...] = ()
    if body and len(body) <= 65536:
        if media == "application/json":
            try:
                value = json.loads(body)
                if isinstance(value, dict):
                    fields = _names(value)
            except (ValueError, TypeError):
                pass
        elif media == "application/x-www-form-urlencoded":
            fields = _names(k for k, _ in parse_qsl(body, keep_blank_values=True))
        elif media == "multipart/form-data":
            fields = _names(re.findall(r'Content-Disposition:[^\r\n]*\bname="([^"]+)"', body, re.I))
    return {
        "type": "browser_request_structure",
        "source": "playwright_network",
        "method": method.upper(),
        "content_type": media,
        "query_parameter_names": list(_names(k for k, _ in _query(url))),
        "body_parameter_names": list(fields),
    }


@dataclass(frozen=True)
class BrowserReconResult:
    evidence_ids: tuple[str, ...]
    observations: tuple[tuple[str | None, dict], ...]


class _CollectorTransport:
    """route.continue_/fetch를 사용하지 않는다. 각 전송은 중앙 정책·예산을 거친다."""

    def __init__(self, *, collector, task, scope, remember, limit, deadline,
                 evidence_type="browser_recon_fetch", reason="observe rendered UI request"):
        self.collector = collector
        self.task = task
        self.scope = scope
        self.remember = remember
        self.limit = limit
        self.deadline = deadline
        self.evidence_type = evidence_type
        self.reason = reason
        self.attempts = 0
        self.sent = 0
        self.blocked = 0
        self.evidence_ids: list[str] = []
        self.observations: list[tuple[str | None, dict]] = []
        self.cache: dict[str, dict] = {}

    def in_scope(self, url: str) -> bool:
        try:
            return _url_in_scope(url, self.scope, _origin_key(self.task.target_url))
        except ValueError:
            return False

    def handle(self, route) -> None:
        req = route.request
        if not self.in_scope(req.url):
            self.blocked += 1
            route.abort("blockedbyclient")
            return
        # 바이너리·스트리밍 연결은 UI 입력 좌표 탐색에 필요하지 않다.
        if req.resource_type not in {"document", "script", "stylesheet", "fetch", "xhr", "other"}:
            route.abort("blockedbyclient")
            return
        method = req.method.upper()
        headers = req.headers
        body = req.post_data
        shape = request_structure(req.url, method, headers.get("content-type", ""), body)
        is_surface = req.resource_type in {"document", "fetch", "xhr"}
        surface_id = None
        if is_surface:
            surface_id = self.remember(
                req.url, method,
                _names((*shape["query_parameter_names"], *shape["body_parameter_names"])),
                _query(req.url), ("browser_request",),
            )
        def block(reason):
            self.blocked += 1
            shape.update(sent=False, blocked_reason=reason)
            if is_surface and len(self.observations) < _MAX_OBSERVATIONS:
                self.observations.append((surface_id, shape))
            route.abort("blockedbyclient")

        # 폼 제출은 요청 형태만 관측한다. 정상 POST 템플릿/승인으로 가장하지 않는다.
        if method not in {"GET", "HEAD", "OPTIONS"}:
            block("form_observation_only")
            return
        if body is not None and len(body) > 65536:
            block("body_limit")
            return
        static = method == "GET" and req.resource_type in {"script", "stylesheet"}
        response = self.cache.get(req.url) if static else None
        if response is None:
            if self.attempts >= self.limit or time.monotonic() >= self.deadline:
                block("request_or_time_budget")
                return
            tool = "http_get"
            if tool not in self.task.allowed_tools:
                block("tool_not_allowed")
                return
            self.attempts += 1
            try:
                evidence_id, result = self.collector.collect_with_result(
                    self.task.run_id, req.url,
                    EvidenceRequest(
                        evidence_type=self.evidence_type, surface_id=surface_id,
                        reason=self.reason, suggested_tool=tool,
                        http_request=HttpRequestSpec(
                            method=method, body=body,
                            headers=tuple((k, v) for k, v in headers.items() if k.lower() in _HEADERS),
                        ),
                    ),
                    task_id=self.task.task_id,
                    timeout_seconds=max(0.01, self.deadline - time.monotonic()),
                    credential_ref=self.task.credential_ref,
                )
            except (PolicyViolation, ApprovalRequired, BudgetExceeded) as error:
                block(type(error).__name__)
                return
            self.sent += 1
            self.evidence_ids.append(evidence_id)
            response = dict(result.observation)
            if static and response.get("status") == 200 and not response.get("truncated"):
                self.cache[req.url] = response
        if is_surface and len(self.observations) < _MAX_OBSERVATIONS:
            shape.update(sent=True, status=response.get("status"))
            self.observations.append((surface_id, shape))
        status = response.get("status")
        if type(status) is not int or response.get("truncated"):
            route.abort("failed")
            return
        fulfilled_headers = {}
        for name, value in response.get("headers", []):
            if name.lower() not in {"content-length", "content-encoding", "transfer-encoding", "connection"}:
                fulfilled_headers[name] = (fulfilled_headers[name] + "\n" + value
                                           if name in fulfilled_headers else value)
        route.fulfill(status=status, headers=fulfilled_headers, body=response.get("body") or "")


# DOM만 읽으며 입력 값은 반환하지 않는다. 메뉴/탭 조작 뒤에도 같은 snapshot을 사용한다.
_SNAPSHOT = """() => ({
 links: [...document.querySelectorAll('a[href],area[href]')].slice(0,200).map(e=>e.href),
 forms: [...document.forms].slice(0,12).map(f=>({url:f.action, method:(f.method||'get').toUpperCase(),
   names:[...f.elements].map(e=>e.name).filter(Boolean), content_type:f.enctype})),
 actions: [...document.querySelectorAll('button,[role=tab],[role=button],summary,[aria-expanded]')]
   .map((e,i)=>({index:i, role:e.getAttribute('role')||'', tag:e.tagName,
     type:e.getAttribute('type')||'', form:!!e.form,
     expand:e.hasAttribute('aria-expanded'), text:(e.innerText||e.getAttribute('aria-label')||'').slice(0,80),
     visible:!!(e.getClientRects().length)&&!e.disabled})).filter(e=>e.visible).slice(0,100)
})"""
_ACTION_SELECTOR = 'button,[role=tab],[role=button],summary,[aria-expanded]'


class PlaywrightRecon:
    def __init__(self, *, collector: RuntimeEvidenceCollector, run_store: RunStore,
                 session_cookies: Callable | None = None, max_pages: int = 6, max_actions: int = 12):
        self._collector = collector
        self._runs = run_store
        self._cookies = session_cookies
        self._max_pages = max_pages
        self._max_actions = max_actions

    def discover(self, task: TaskEnvelope, *, remember: Callable,
                 request_budget: int, timeout_seconds: float,
                 select_next: Callable[[tuple[tuple[str, str], ...], int, float], str | None] | None = None) -> BrowserReconResult:
        deadline = time.monotonic() + min(timeout_seconds, 45.0)
        transport = _CollectorTransport(
            collector=self._collector, task=task, scope=self._runs.get(task.run_id).scope,
            remember=remember, limit=request_budget, deadline=deadline,
        )
        status = "completed"
        stop_reason = "frontier_exhausted"
        visits = 0
        actions = 0
        hash_probes = 0
        hash_reflections = 0
        planner_selections = 0
        pending: list[str] = []
        try:
            from playwright.sync_api import Error, sync_playwright
        except ImportError:
            return BrowserReconResult((), ((None, {
                "type": "browser_recon_summary", "status": "unavailable",
                "stop_reason": "playwright_missing",
            }),))
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, args=["--disable-background-networking"])
                try:
                    context = browser.new_context(service_workers="block", accept_downloads=False)
                    context.route("**/*", transport.handle)
                    context.route_web_socket("**/*", lambda ws: ws.close())
                    # WebRTC는 HTTP route hook을 거치지 않는다.
                    context.add_init_script("window.RTCPeerConnection = undefined; window.webkitRTCPeerConnection = undefined;")
                    if self._cookies is not None:
                        cookies = self._cookies(ExecutionRequest(
                            execution_id="browser-recon-session", run_id=task.run_id,
                            task_id=task.task_id, tool="http_get", target_url=task.target_url,
                            credential_ref=task.credential_ref, surface_id=None,
                            purpose="seed isolated browser session",
                        ))
                        context.add_cookies([{"name": k, "value": v, "url": _origin(task.target_url)} for k, v in cookies])
                    page = context.new_page()
                    pending = [task.target_url]
                    pending_surface_ids: dict[str, str] = {}
                    visited: set[str] = set()
                    seen_actions: set[tuple] = set()
                    seen_forms: set[tuple] = set()
                    seen_filters: set[tuple[str, int]] = set()

                    def settle():
                        try:
                            page.wait_for_load_state("networkidle", timeout=min(1500, max(1, int((deadline-time.monotonic())*1000))))
                        except Error:
                            pass

                    def snapshot():
                        data = page.evaluate(_SNAPSHOT)
                        if transport.in_scope(page.url):
                            remember(page.url, "GET", _names(k for k, _ in _query(page.url)), _query(page.url), ("browser_navigation",))
                        for url in data["links"]:
                            if transport.in_scope(url):
                                pending_surface_ids[url] = remember(
                                    url, "GET", _names(k for k, _ in _query(url)),
                                    _query(url), ("browser_dom",),
                                )
                                if url not in visited and url not in pending:
                                    pending.append(url)
                        for form in data["forms"]:
                            if transport.in_scope(form["url"]) and form["method"] in {"GET", "POST"}:
                                names = _names(form["names"])
                                sid = remember(form["url"], form["method"], names, (), ("browser_form",))
                                if len(transport.observations) < _MAX_OBSERVATIONS:
                                    transport.observations.append((sid, {
                                        "type": "browser_form_structure", "source": "rendered_dom",
                                        "method": form["method"], "parameter_names": list(names),
                                        "content_type": form["content_type"],
                                    }))
                        return data

                    while pending and visits < self._max_pages and transport.attempts < request_budget and time.monotonic() < deadline:
                        if select_next is not None and visits and len(pending) > 1:
                            options = tuple(
                                (url, pending_surface_ids[url]) for url in pending
                                if url not in visited and url in pending_surface_ids
                            )
                            if len(options) > 1:
                                selected = select_next(
                                    options, request_budget - transport.attempts,
                                    max(0.0, deadline - time.monotonic()),
                                )
                                if selected in {url for url, _ in options}:
                                    pending.remove(selected)
                                    pending.insert(0, selected)
                                    planner_selections += 1
                        url = pending.pop(0)
                        if url in visited:
                            continue
                        visited.add(url)
                        visits += 1
                        try:
                            response = page.goto(url, wait_until="domcontentloaded", timeout=max(1, min(10000, int((deadline-time.monotonic())*1000))))
                            settle()
                            for _ in range(4):
                                if time.monotonic() >= deadline or transport.attempts >= request_budget:
                                    break
                                data = snapshot()
                                if actions < self._max_actions:
                                    filters = page.locator('input[type=search],input[role=searchbox],input[placeholder*="search" i],input[placeholder*="검색"],select')
                                    for i in range(min(filters.count(), 4)):
                                        if actions >= self._max_actions or time.monotonic() >= deadline:
                                            break
                                        control = filters.nth(i)
                                        key = (page.url, i)
                                        if key in seen_filters or not control.is_visible() or not control.is_enabled():
                                            continue
                                        seen_filters.add(key)
                                        if control.evaluate("e => e.tagName") == "SELECT":
                                            choices = control.locator("option")
                                            if choices.count() > 1:
                                                control.select_option(index=1, timeout=500)
                                                actions += 1
                                        elif control.is_editable() and not control.input_value():
                                            control.fill("hacklipse-control", timeout=500)
                                            actions += 1
                                    settle()
                                    data = snapshot()
                                # React 등은 name 없는 입력을 상태로 보유한다. submit handler가
                                # 만든 fetch/XHR를 관측하고 변경 요청은 transport에서 중단한다.
                                form_key = (page.url, tuple((f["url"], tuple(f["names"])) for f in data["forms"]))
                                visible_forms = page.locator("form:visible")
                                if visible_forms.count() and form_key not in seen_forms and actions < self._max_actions:
                                    seen_forms.add(form_key)
                                    try:
                                        form = visible_forms.first
                                        controls = form.locator('input:not([type=hidden]):not([type=password]):not([type=file]),textarea')
                                        for i in range(min(controls.count(), 12)):
                                            control = controls.nth(i)
                                            kind = (control.get_attribute("type") or "text").lower()
                                            if kind not in {"text", "search", "email", "number"} or not control.is_visible() or not control.is_editable():
                                                continue
                                            if control.input_value():
                                                continue
                                            control.fill("recon@example.invalid" if kind == "email" else "1" if kind == "number" else "hacklipse-control", timeout=500)
                                        form.evaluate("f => f.requestSubmit()")
                                        actions += 1
                                        settle()
                                        data = snapshot()
                                    except Error:
                                        status = "partial"
                                eligible = [a for a in data["actions"] if
                                    not _DESTRUCTIVE.search(a["text"]) and
                                    not (a["form"] and a["type"] != "button") and
                                    (a["role"] == "tab" or a["tag"] == "SUMMARY" or a["expand"] or _ACTION.search(a["text"])) and
                                    (page.url, a["role"], a["text"], a["index"]) not in seen_actions]
                                if not eligible or actions >= self._max_actions:
                                    break
                                action = min(eligible, key=lambda a: 2 if re.search(r"detail|상세", a["text"], re.I)
                                             and a["role"] != "tab" else 0)
                                seen_actions.add((page.url, action["role"], action["text"], action["index"]))
                                control = page.locator(_ACTION_SELECTOR).nth(action["index"])
                                current_text = control.evaluate("e => (e.innerText||e.getAttribute('aria-label')||'').slice(0,80)")
                                if current_text != action["text"] or _DESTRUCTIVE.search(current_text):
                                    continue
                                control.click(timeout=1000)
                                actions += 1
                                settle()
                                snapshot()
                            current = urlsplit(page.url)
                            if (
                                response is not None
                                and "text/html" in response.headers.get("content-type", "").lower()
                                and not current.query and not current.fragment
                                and transport.in_scope(page.url)
                                and transport.attempts < request_budget
                                and time.monotonic() < deadline
                            ):
                                # 값만 가진 해시는 HTTP 입력이 아니다. 무해한 값의 실제
                                # DOM 반사를 확인한 페이지에만 client Surface를 발행한다.
                                hash_probes += 1
                                target = page.url
                                try:
                                    page.evaluate("marker => { location.hash = marker }", RAW_HASH_CANARY)
                                    page.wait_for_function(
                                        "marker => !!document.body && document.body.innerHTML.includes(marker)",
                                        arg=RAW_HASH_CANARY,
                                        timeout=min(750, max(1, int((deadline-time.monotonic())*1000))),
                                    )
                                except Error:
                                    pass
                                else:
                                    sid = remember(
                                        target + "#" + RAW_HASH_CANARY, "GET",
                                        (RAW_HASH_PARAMETER,), (), ("browser_hash_probe",),
                                    )
                                    hash_reflections += 1
                                    if len(transport.observations) < _MAX_OBSERVATIONS:
                                        transport.observations.append((sid, {
                                            "type": "browser_hash_reflection",
                                            "source": "active_inert_marker",
                                            "parameter": RAW_HASH_PARAMETER,
                                        }))
                        except Error:
                            # 예산/승인으로 의존 요청이 막혀도 이미 관측한 결과는 남긴다.
                            status = "partial"
                finally:
                    browser.close()
        except Error:
            status = "unavailable" if visits == 0 else "partial"
        if status == "unavailable":
            stop_reason = "browser_unavailable"
        elif time.monotonic() >= deadline:
            status = "bounded"
            stop_reason = "time_budget"
        elif transport.attempts >= request_budget:
            status = "bounded"
            stop_reason = "request_budget"
        elif pending and visits >= self._max_pages:
            status = "bounded"
            stop_reason = "page_limit"
        elif actions >= self._max_actions:
            status = "bounded"
            stop_reason = "action_limit"
        elif status == "partial":
            stop_reason = "ui_error"
        transport.observations.append((None, {
            "type": "browser_recon_summary", "status": status,
            "page_count": visits, "action_count": actions,
            "hash_probe_count": hash_probes, "hash_reflection_count": hash_reflections,
            "planner_selection_count": planner_selections,
            "request_count": transport.sent, "blocked_request_count": transport.blocked,
            "unvisited_page_count": len(pending), "stop_reason": stop_reason,
        }))
        return BrowserReconResult(tuple(transport.evidence_ids), tuple(transport.observations))
