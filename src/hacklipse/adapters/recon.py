"""HTML과 JS 번들에서 공격 표면을 찾는 결정적 Recon Agent.

세 경로로 표면을 모은다.

    ① 서버 렌더링 HTML   폼·링크 파싱 (전통 웹앱)
    ② 다단계 크롤링      발견한 링크를 다시 요청 (인증 후 보호 페이지 도달)
    ③ JS 번들 정적 분석  SPA는 초기 HTML이 비어 있고 엔드포인트가 번들에 문자열로 남는다

③이 필요한 이유 — Angular/React 앱의 최초 HTML에는 링크도 폼도 없다. 그러나 런타임에
URL을 만들어야 하므로 경로가 소스에 리터럴로 박힌다. 브라우저 없이 정규식으로 뽑을 수
있고, 처음 보는 앱에서도 동작한다(학습 데이터 암기가 아니라 실제 관측이다).

브라우저를 띄우지 않으므로 동적으로 조립되는 URL과 코드 스플리팅된 청크는 놓친다.
그건 헤드리스 Runtime의 몫으로 남긴다.

LLM을 쓰지 않는다: 크롤링과 폼 추출은 결정적 작업이라 판단 품질이 오르지 않고, 이 버전
자체가 이후 LLM 기반 Recon과 비교할 연구 대조군이 된다.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import parse_qsl, urljoin, urlsplit
from uuid import uuid4

from bs4 import BeautifulSoup

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

DEFAULT_MAX_PAGES = 10
DEFAULT_MAX_SCRIPTS = 3

# 남은 예산의 이 비율까지만 정찰에 쓴다. 정찰이 예산을 다 먹으면 뒤의 Analysis가
# 아무것도 못 한다 — 찾기만 하고 확인은 못 하는 상태가 된다.
_RECON_BUDGET_SHARE = 0.5

# JS 리터럴에서 절대 경로를 뽑는다. 템플릿 리터럴의 `${host}/path` 형태도 받는다.
_JS_PATH = re.compile(
    r"""["'`](?:\$\{[^}]{0,60}\})?(/[A-Za-z0-9][A-Za-z0-9._~/-]{0,100}?)(?=["'`?])"""
)
# `/path?param=`에서 파라미터 이름까지 얻는다. 앞에 `/`가 오면 `//host/path` 즉 외부
# URL의 일부이므로 제외한다 — 이 필터가 없으면 소셜 공유 링크가 전부 섞여 들어온다.
_JS_PATH_PARAM = re.compile(
    r"""(?<![/A-Za-z0-9._~-])(/[A-Za-z0-9][A-Za-z0-9._~/-]{0,100})\?([A-Za-z0-9_]{1,40})="""
)

# 결정적 Recon 단계에서 실제 요청 없이도 판단할 수 있는 유일한 신호: 파라미터 "이름"이
# 파일·경로·URL을 가리키는 것처럼 보이는가. Router.DEFAULT_RULES의 "url_or_file_parameter"
# 규칙과 맞아야 ROUTE 단계가 Candidate를 만들 수 있다.
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

_MAX_SCRIPT_BYTES = 4 * 1024 * 1024
_PATH_OBJECT_ID = re.compile(r"^[0-9]{1,10}$")
_PATH_RESOURCE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,39}$")
_SINGULAR_OBJECT_RESOURCES = frozenset(
    {
        "account",
        "address",
        "basket",
        "cart",
        "invoice",
        "order",
        "profile",
        "record",
        "user",
    }
)


def _looks_like_file_or_url_parameter(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _FILE_OR_URL_PARAM_HINTS)


class ReconAgent:
    """대상을 크롤링하고 응답에서 공격 표면을 구조화해 저장한다."""

    def __init__(
        self,
        *,
        collector: RuntimeEvidenceCollector,
        evidence_store: EvidenceStore,
        surface_store: SurfaceStore,
        max_pages: int = DEFAULT_MAX_PAGES,
        max_scripts: int = DEFAULT_MAX_SCRIPTS,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        if max_pages < 1:
            raise ValueError("recon must fetch at least one page")
        self._collector = collector
        self._evidence = evidence_store
        self._surfaces = surface_store
        self._max_pages = max_pages
        self._max_scripts = max_scripts
        self._id_factory = id_factory or (lambda: str(uuid4()))

    def handle(self, task: TaskEnvelope) -> AgentResult:
        """예산 안에서 크롤링하며 Surface·Evidence를 채운다."""

        if task.target_url is None:
            raise AgentContractError("recon task is missing a target url")
        if RECON_TOOL not in task.allowed_tools:
            raise AgentContractError("recon tool is not allowed by the task")

        origin = urlsplit(task.target_url)
        page_budget = self._page_budget(task)

        pending: list[str] = [task.target_url]
        fetched: set[str] = set()
        scripts: list[str] = []
        evidence_ids: list[str] = []
        # 발견과 수집은 다르다 — 크롤링 예산이 모자라도 발견한 URL은 Surface로 남긴다.
        # (url, method, parameters) 조합으로 중복을 막는다.
        surfaces: dict[tuple[str, str, tuple[str, ...]], str] = {}

        def remember(
            url: str,
            method: str,
            names: tuple[str, ...],
            observed: tuple[tuple[str, str], ...] = (),
        ) -> str:
            clean_url = url.split("?", 1)[0]
            path_identifier = _path_identifier(clean_url)
            key_url = _canonical_surface_url(clean_url, path_identifier)
            key = (key_url, method, names)
            existing = surfaces.get(key)
            if existing is not None:
                return existing
            surface_id = f"surface-{self._id_factory()}"
            surfaces[key] = surface_id
            self._store_surface(
                task.run_id,
                surface_id,
                clean_url,
                method,
                names,
                observed=observed,
                path_identifier=path_identifier,
            )
            evidence_ids.extend(
                self._flag_suspect_parameters(task.run_id, surface_id, names)
            )
            return surface_id

        while pending and len(fetched) < page_budget:
            url = pending.pop(0)
            if url in fetched:
                continue
            fetched.add(url)

            surface_id = remember(url, "GET", _query_names(url), _query_pairs(url))
            evidence_id, evidence = self._fetch(task, url, surface_id)
            evidence_ids.append(evidence_id)

            body = evidence.observation.get("body")
            if not isinstance(body, str) or not body:
                continue

            links, forms, sources = _parse_page(body, url)
            for form_url, method, names in forms:
                remember(form_url, method, names)
            for link in links:
                if not _same_origin(link, origin):
                    continue
                # 예산과 무관하게 표면으로 기록하고, 여유가 있으면 크롤링까지 한다.
                remember(link, "GET", _query_names(link), _query_pairs(link))
                if link not in fetched and link not in pending:
                    pending.append(link)
            for source in sources:
                if source not in scripts and _same_origin(source, origin):
                    scripts.append(source)

        # 번들 분석은 크롤링 뒤에 한다. 남은 예산 안에서만 스크립트를 받는다.
        affordable = max(min(self._max_scripts, page_budget - len(fetched)), 0)
        for source in scripts[:affordable]:
            fetched.add(source)
            for url, names in self._discover_from_script(task, source, origin):
                remember(url, "GET", names)

        surface_ids = list(surfaces.values())
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=tuple(dict.fromkeys(evidence_ids)),
            surface_ids=tuple(dict.fromkeys(surface_ids)),
        )

    def _page_budget(self, task: TaskEnvelope) -> int:
        """정찰이 쓸 요청 수. 뒤 단계가 쓸 예산을 남긴다."""

        if task.request_budget <= 0:
            return 1
        share = max(int(task.request_budget * _RECON_BUDGET_SHARE), 1)
        return max(min(self._max_pages, share), 1)

    def _fetch(
        self, task: TaskEnvelope, url: str, surface_id: str | None
    ) -> tuple[str, Evidence]:
        """중앙 수집 경계를 거쳐 한 문서를 가져온다."""

        evidence_id = self._collector.collect(
            task.run_id,
            url,
            EvidenceRequest(
                evidence_type="page_fetch",
                surface_id=surface_id,
                reason=f"recon fetch of {url}",
                suggested_tool=RECON_TOOL,
            ),
            task_id=task.task_id,
            timeout_seconds=task.timeout_seconds,
        )
        return evidence_id, self._evidence.get(task.run_id, evidence_id)

    def _discover_from_script(
        self, task: TaskEnvelope, source: str, origin
    ) -> list[tuple[str, tuple[str, ...]]]:
        """JS 번들을 받아 경로 리터럴에서 Surface 후보를 만든다."""

        _, evidence = self._fetch(task, source, None)
        body = evidence.observation.get("body")
        if not isinstance(body, str) or not body or len(body) > _MAX_SCRIPT_BYTES:
            return []

        parameters: dict[str, set[str]] = {}
        for match in _JS_PATH_PARAM.finditer(body):
            parameters.setdefault(match.group(1), set()).add(match.group(2))
        paths = {match.group(1) for match in _JS_PATH.finditer(body)}
        paths.update(parameters)

        base = f"{origin.scheme}://{origin.netloc}"
        return [
            (f"{base}{path}", tuple(sorted(parameters.get(path, ()))))
            for path in sorted(paths)
        ]

    def _store_surface(
        self,
        run_id: str,
        surface_id: str,
        url: str,
        method: str,
        params: tuple[str, ...],
        *,
        observed: tuple[tuple[str, str], ...] = (),
        path_identifier: tuple[str, int, str] | None = None,
    ) -> None:
        path_name, path_index, path_value = path_identifier or (None, None, None)
        self._surfaces.add(
            Surface(
                surface_id=surface_id,
                run_id=run_id,
                url=url,
                method=method,
                parameters=params,
                observed_query=observed,
                path_identifier=path_name,
                path_identifier_index=path_index,
                observed_path_identifier=path_value,
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


def _parse_page(
    body: str, base_url: str
) -> tuple[list[str], list[tuple[str, str, tuple[str, ...]]], list[str]]:
    """HTML에서 링크·폼·스크립트 출처를 뽑는다.

    lxml 파서는 닫는 태그가 없는 폼처럼 깨진 HTML도 복구한다 — 취약한 대상일수록
    HTML이 깨져 있을 확률이 높아 관용적인 파서가 필요하다.
    """

    soup = BeautifulSoup(body, "lxml")

    links = []
    for anchor in soup.find_all("a", href=True):
        resolved = urljoin(base_url, anchor["href"])
        if urlsplit(resolved).scheme in ("http", "https"):
            links.append(resolved)

    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or base_url
        names = tuple(
            dict.fromkeys(
                field["name"]
                for field in form.find_all(
                    ["input", "select", "textarea"], attrs={"name": True}
                )
                if field["name"]
            )
        )
        forms.append(
            (
                urljoin(base_url, action).split("?", 1)[0],
                (form.get("method") or "GET").upper(),
                names,
            )
        )

    sources = [
        urljoin(base_url, script["src"]) for script in soup.find_all("script", src=True)
    ]
    return links, forms, sources


def _query_names(url: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(name for name, _ in parse_qsl(urlsplit(url).query)))


def _query_pairs(url: str) -> tuple[tuple[str, str], ...]:
    """관측된 query 값을 이름별로 한 번씩 보존한다."""

    pairs: dict[str, str] = {}
    for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        pairs.setdefault(name, value)
    return tuple(pairs.items())


def _path_identifier(url: str) -> tuple[str, int, str] | None:
    """`/users/17` 형태에서 논리 식별자명·세그먼트 위치·관측값을 얻는다.

    모든 숫자 경로를 객체로 보면 버전(`/v1/`)이나 연도까지 후보가 된다. 따라서 숫자
    바로 앞이 복수형 리소스명인 경우만 결정적으로 인정한다.
    """

    segments = urlsplit(url).path.split("/")
    for index in range(len(segments) - 1, 1, -1):
        value = segments[index]
        resource = segments[index - 1]
        if _PATH_OBJECT_ID.fullmatch(value) is None:
            continue
        lowered = resource.casefold()
        if _PATH_RESOURCE.fullmatch(resource) is None:
            continue
        if lowered.endswith("s") and len(resource) > 1:
            singular = resource[:-1]
        elif lowered in _SINGULAR_OBJECT_RESOURCES:
            singular = resource
        else:
            continue
        return f"{singular.casefold()}_id", index, value
    return None


def _canonical_surface_url(
    url: str, path_identifier: tuple[str, int, str] | None
) -> str:
    """서로 다른 concrete ID 링크를 동일 REST Surface 하나로 중복 제거한다."""

    if path_identifier is None:
        return url
    name, index, _ = path_identifier
    parsed = urlsplit(url)
    segments = parsed.path.split("/")
    segments[index] = "{" + name + "}"
    path = "/".join(segments)
    return parsed._replace(path=path).geturl()


def _same_origin(url: str, origin) -> bool:
    parsed = urlsplit(url)
    return parsed.scheme in ("http", "https") and parsed.netloc == origin.netloc
