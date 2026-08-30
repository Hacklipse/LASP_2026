"""표준 라이브러리 HTML 파서만으로 공격 표면을 찾는 결정적 Recon Agent."""

from __future__ import annotations

from collections.abc import Callable
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit
from uuid import uuid4

from hacklipse.application import RuntimeEvidenceCollector
from hacklipse.application.errors import AgentContractError
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Evidence,
    EvidenceRequest,
    Surface,
    TaskEnvelope,
)
from hacklipse.ports import EvidenceStore, SurfaceStore

# HttpExecutionRuntime이 GET 실행에 사용하는 도구 이름과 맞춘다(tests/test_http_runtime.py).
RECON_TOOL = "http_get"

# 결정적 Recon 단계에서 실제 요청 없이도 판단할 수 있는 유일한 신호: 파라미터 "이름"이
# 파일·경로·URL을 가리키는 것처럼 보이는가. Router.DEFAULT_RULES의 "url_or_file_parameter"
# 규칙과 맞아야 ROUTE 단계가 Candidate를 만들 수 있다(orchestrator.py:119).
_FILE_OR_URL_PARAM_HINTS = (
    "file",
    "page",
    "path",
    "template",
    "doc",
    "include",
    "folder",
    "dir",
    "load",
    "view",
    "download",
    "src",
    "url",
    "redirect",
    "dest",
    "target",
)


def _looks_like_file_or_url_parameter(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _FILE_OR_URL_PARAM_HINTS)


class _SurfaceHTMLParser(HTMLParser):
    """폼과 링크에서 (url, method, parameters) 튜플만 뽑아내는 최소 파서."""

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self._base_url = base_url
        self.surfaces: list[tuple[str, str, tuple[str, ...]]] = []
        self._seen: set[tuple[str, str, tuple[str, ...]]] = set()
        self._form_action: str | None = None
        self._form_method = "GET"
        self._form_params: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key: value for key, value in attrs if value is not None}
        if tag == "form":
            self._form_action = values.get("action", self._base_url)
            self._form_method = values.get("method", "GET").upper()
            self._form_params = []
        elif tag in ("input", "select", "textarea") and self._form_action is not None:
            name = values.get("name")
            if name:
                self._form_params.append(name)
        elif tag == "a":
            self._record_link(values.get("href"))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # 자체 종료 태그(<input .../>)도 일반 시작 태그와 동일하게 처리한다.
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._finalize_form()

    def close(self) -> None:
        super().close()
        # 닫는 태그가 없는 폼(HTML 오류)도 손실 없이 기록한다.
        self._finalize_form()

    def _finalize_form(self) -> None:
        if self._form_action is None:
            return
        url = urljoin(self._base_url, self._form_action).split("?", 1)[0]
        self._add_surface(url, self._form_method, tuple(self._form_params))
        self._form_action = None
        self._form_params = []

    def _record_link(self, href: str | None) -> None:
        if not href:
            return
        resolved = urljoin(self._base_url, href)
        parsed = urlsplit(resolved)
        if parsed.scheme not in ("http", "https"):
            return
        params = tuple(name for name, _ in parse_qsl(parsed.query))
        url = resolved.split("?", 1)[0]
        self._add_surface(url, "GET", params)

    def _add_surface(self, url: str, method: str, params: tuple[str, ...]) -> None:
        key = (url, method, params)
        if key in self._seen:
            return
        self._seen.add(key)
        self.surfaces.append(key)


class ReconAgent:
    """대상 URL을 한 번 요청하고 응답에서 공격 표면을 구조화해 저장한다.

    LLM을 쓰지 않는다: 크롤링·폼 추출은 결정적 작업이라 판단 품질이 오르지 않고,
    이 버전 자체가 이후 LLM 기반 Recon과 비교할 연구 대조군이 된다.
    """

    def __init__(
        self,
        *,
        collector: RuntimeEvidenceCollector,
        evidence_store: EvidenceStore,
        surface_store: SurfaceStore,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._collector = collector
        self._evidence = evidence_store
        self._surfaces = surface_store
        self._id_factory = id_factory or (lambda: str(uuid4()))

    def handle(self, task: TaskEnvelope) -> AgentResult:
        """대상 URL을 수집 경계를 거쳐 요청하고 Surface·Evidence를 채운다."""

        if task.target_url is None:
            raise AgentContractError("recon task is missing a target url")
        if RECON_TOOL not in task.allowed_tools:
            raise AgentContractError("recon tool is not allowed by the task")

        root_surface_id = f"surface-{self._id_factory()}"
        root_url = task.target_url.split("?", 1)[0]
        root_params = tuple(name for name, _ in parse_qsl(urlsplit(task.target_url).query))

        fetch_evidence_id = self._collector.collect(
            task.run_id,
            task.target_url,
            EvidenceRequest(
                evidence_type="page_fetch",
                surface_id=root_surface_id,
                reason=f"initial recon fetch of {task.target_url}",
                suggested_tool=RECON_TOOL,
            ),
            task_id=task.task_id,
            timeout_seconds=task.timeout_seconds,
        )
        fetch_evidence = self._evidence.get(task.run_id, fetch_evidence_id)

        surface_ids = [root_surface_id]
        evidence_ids = [fetch_evidence_id]
        self._store_surface(task.run_id, root_surface_id, root_url, "GET", root_params)
        evidence_ids.extend(
            self._flag_suspect_parameters(task.run_id, root_surface_id, root_params)
        )

        body = fetch_evidence.observation.get("body")
        if isinstance(body, str) and body:
            parser = _SurfaceHTMLParser(root_url)
            parser.feed(body)
            parser.close()
            for url, method, params in parser.surfaces:
                surface_id = f"surface-{self._id_factory()}"
                self._store_surface(task.run_id, surface_id, url, method, params)
                surface_ids.append(surface_id)
                evidence_ids.extend(
                    self._flag_suspect_parameters(task.run_id, surface_id, params)
                )

        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=tuple(dict.fromkeys(evidence_ids)),
            surface_ids=tuple(dict.fromkeys(surface_ids)),
        )

    def _store_surface(
        self, run_id: str, surface_id: str, url: str, method: str, params: tuple[str, ...]
    ) -> None:
        self._surfaces.add(
            Surface(
                surface_id=surface_id,
                run_id=run_id,
                url=url,
                method=method,
                parameters=params,
            )
        )

    def _flag_suspect_parameters(
        self, run_id: str, surface_id: str, params: tuple[str, ...]
    ) -> list[str]:
        """Router가 매칭할 수 있게 파일·URL로 보이는 파라미터만 Observation으로 남긴다."""

        evidence_ids: list[str] = []
        for name in params:
            if not _looks_like_file_or_url_parameter(name):
                continue
            evidence_id = f"evi-{self._id_factory()}"
            self._evidence.append(
                Evidence(
                    evidence_id=evidence_id,
                    run_id=run_id,
                    surface_id=surface_id,
                    created_by="recon",
                    evidence_type="observation",
                    observation={"type": "url_or_file_parameter", "parameter": name},
                )
            )
            evidence_ids.append(evidence_id)
        return evidence_ids
