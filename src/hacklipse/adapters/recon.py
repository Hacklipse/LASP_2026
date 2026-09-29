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
from collections.abc import Callable, Sequence
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
from hacklipse.ports import IterativeReconPlanner, ReconAction, ReconObservation

from .llm_iterative_recon import (
    AGENTIC_RECON_PLANNER,
    build_recon_action_observation,
    find_stored_recon_action,
    recon_action_status_detail,
)
from .llm_parameter_names import alias_parameter_names
from .llm_recon_planner import (
    RECON_PLANNER,
    ReconCandidate,
    ReconPlan,
    ReconPlanner,
    build_recon_plan_observation,
    find_stored_recon_plan,
    recon_plan_status_detail,
)
from .path_traversal_analysis import (
    RESTRICTED_FILE_OBSERVATION,
    UNLINKED_RENDER_PARAMETER_OBSERVATION,
)

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
# SPA가 서버 렌더링 문서로 빠져나갈 때 쓰는 navigation sink. 단순 경로 리터럴과
# 달리 실제 HTML 문서일 가능성이 높으므로, 번들에서 발견한 뒤 예산 안에서 방문한다.
# 특정 제품의 경로 이름이 아니라 브라우저 API와 상대경로의 결합만 본다.
_JS_DOCUMENT_NAVIGATION = re.compile(
    r"""(?:window\.)?location\.(?:assign|replace)\([^)]{0,160}?["'`](/[A-Za-z0-9][A-Za-z0-9._~/-]{0,100})["'`]"""
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

# 템플릿 보간에서 끊기는 경로는 디렉터리까지만 남긴다. `${host}/ftp/order_${id}.pdf`
# 같은 리터럴은 파일명을 알 수 없지만 그 디렉터리는 실재하는 표면이다.
_JS_DIRECTORY = re.compile(
    r"""["'`](?:\$\{[^}]{0,60}\})?(/[A-Za-z0-9][A-Za-z0-9._~/-]{0,100}/)[A-Za-z0-9._~-]{0,40}\$\{"""
)
_JS_BARE_NUMERIC_PATH = re.compile(r"/\d+")
# SPA 클라이언트 라우트와 그 query 파라미터. 라우트 이동과 파라미터 선언이 서로
# 앞뒤 어느 쪽에도 올 수 있어 좁은 창 안에서 함께 나타나는 짝만 취한다.
# 따옴표 종류는 큰따옴표로 고정하지 않는다 — Angular 컴파일러 버전에 따라 배열 리터럴을
# 백틱으로 내보내기도 한다(`navigate([`/search`],i)`). 다른 JS 정규식들과 같은
# ["'`] 문자 클래스를 쓴다.
_JS_ROUTE_NAVIGATE = re.compile(r"""navigate\(\[["'`]/([A-Za-z0-9._~-]{1,40})["'`]\]""")
_JS_ROUTE_QUERY_PARAM = re.compile(r"""queryParams:\{([A-Za-z_][A-Za-z0-9_]{0,30}):""")
_ROUTE_BINDING_WINDOW = 200

# 웹 서버가 그대로 내주면 안 되는 확장자. 이런 파일이 표면으로 노출되어 있으면
# 서버가 직접 거부하는지, 우회 경로로는 제공되는지 확인할 가치가 있다.
_RESTRICTED_FILE_EXTENSIONS = (
    ".bak",
    ".conf",
    ".config",
    ".db",
    ".env",
    ".gg",
    ".ini",
    ".kdbx",
    ".key",
    ".log",
    ".pem",
    ".pyc",
    ".sql",
    ".yaml",
    ".yml",
)

# HTML 폼에 노출되지 않아도 서버 템플릿 엔진이 공통적으로 해석하는 렌더 옵션.
# Recon은 이를 관측값으로 가장하지 않고 ``source``가 붙은 추론 Evidence로 남긴다.
# 능동 POST는 Analysis의 승인·고정 safe-file 경계 뒤에서만 일어난다.
_UNLINKED_RENDER_PARAMETERS = ("layout",)

_MAX_SCRIPT_BYTES = 4 * 1024 * 1024
# 한 round에서 모델이 비교할 좌표를 제한한다. 선택된 좌표는 다음 round의 창으로
# 이동하므로 이 값 밖의 Surface가 영구히 사라지는 것은 아니다. 응답 전체를 매번 다시
# 보내지 않고 현재 선택지와 직전 실행 문맥만 전달해 반복 prompt 비용을 제한한다.
_MAX_AGENTIC_SELECTABLE = 32
_MAX_AGENTIC_CONTEXT = 2
_MAX_AGENTIC_OBSERVATIONS = _MAX_AGENTIC_SELECTABLE + _MAX_AGENTIC_CONTEXT
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


def _client_routes(body: str) -> dict[str, tuple[str, ...]]:
    """SPA 라우트 이름과 그 라우트가 받는 query 파라미터를 짝지어 뽑는다.

    번들은 minify 되어 있어 `navigate(["/search"], i)` 처럼 파라미터 선언이 변수로
    분리되기도 한다. 선언과 이동이 같은 함수 안에 있다는 성질만 이용해 좁은 창
    안에서 함께 나타나는 짝을 취한다. 창을 넓히면 무관한 라우트가 섞인다.
    """

    routes: dict[str, set[str]] = {}
    for match in _JS_ROUTE_QUERY_PARAM.finditer(body):
        start = max(0, match.start() - _ROUTE_BINDING_WINDOW)
        window = body[start : match.end() + _ROUTE_BINDING_WINDOW]
        nearby = _JS_ROUTE_NAVIGATE.search(window)
        if nearby is None:
            continue
        routes.setdefault(nearby.group(1), set()).add(match.group(1))
    return {route: tuple(sorted(names)) for route, names in routes.items()}


def _looks_like_restricted_file(url: str) -> bool:
    """웹으로 내주면 안 되는 확장자를 가진 파일 경로인지 본다."""

    name = urlsplit(url).path.rsplit("/", 1)[-1].lower()
    return any(name.endswith(suffix) for suffix in _RESTRICTED_FILE_EXTENSIONS)


def _deterministic_url_key(url: str) -> tuple[str, str, str, str, str, str]:
    """비교·회귀 모드에서 crawl frontier를 고정하는 URL 정렬 키."""

    parsed = urlsplit(url)
    return (
        parsed.scheme.casefold(),
        parsed.netloc.casefold(),
        parsed.path or "/",
        parsed.query,
        parsed.fragment,
        url,
    )


def _deterministic_pending(
    urls: Sequence[str], protected: Sequence[str] | set[str] = ()
) -> list[str]:
    """보호 URL을 먼저, 나머지를 정규 URL 순서로 고정한다."""

    unique = tuple(dict.fromkeys(urls))
    protected_set = set(protected)
    return [
        *sorted(
            (url for url in unique if url in protected_set),
            key=_deterministic_url_key,
        ),
        *sorted(
            (url for url in unique if url not in protected_set),
            key=_deterministic_url_key,
        ),
    ]


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
        surface_collection_mode: str = "adaptive",
        seed_urls: Sequence[str] = (),
        infer_unlinked_render_parameters: bool = True,
        id_factory: Callable[[], str] | None = None,
        planner: ReconPlanner | None = None,
        iterative_planner: IterativeReconPlanner | None = None,
    ) -> None:
        if max_pages < 1:
            raise ValueError("recon must fetch at least one page")
        if surface_collection_mode not in {"adaptive", "deterministic"}:
            raise ValueError("unsupported surface collection mode")
        if planner is not None and iterative_planner is not None:
            raise ValueError("only one recon planner may be configured")
        self._collector = collector
        self._evidence = evidence_store
        self._surfaces = surface_store
        self._max_pages = max_pages
        self._max_scripts = max_scripts
        self._surface_collection_mode = surface_collection_mode
        self._seed_urls = tuple(dict.fromkeys(seed_urls))
        self._infer_unlinked_render_parameters = infer_unlinked_render_parameters
        self._id_factory = id_factory or (lambda: str(uuid4()))
        # None이면(휴리스틱 프로필) 아래 두 번째 crawl() 직전 분기 자체가 실행되지
        # 않아 기존 결정적 동작과 한 줄도 다르지 않다.
        self._planner = planner
        self._iterative_planner = iterative_planner

    def handle(self, task: TaskEnvelope) -> AgentResult:
        """예산 안에서 크롤링하며 Surface·Evidence를 채운다."""

        if task.target_url is None:
            raise AgentContractError("recon task is missing a target url")
        if RECON_TOOL not in task.allowed_tools:
            raise AgentContractError("recon tool is not allowed by the task")

        origin = urlsplit(task.target_url)
        targeted = task.surface_id is not None
        if targeted:
            target = self._surfaces.get(task.run_id, task.surface_id)
            if (
                target.url != task.target_url
                or target.method.upper() != "GET"
                or target.parameters
                or origin.fragment
            ):
                raise AgentContractError("targeted recon requires an existing simple GET surface")
        page_budget = 1 if targeted else self._page_budget(task)

        for seed_url in self._seed_urls:
            if not _same_origin(seed_url, origin):
                raise AgentContractError("recon seed URL belongs to another origin")
        # SPA 홈페이지와 별도 서버 렌더링 페이지처럼 서로 링크되지 않은 진입점을
        # 한 Recon 세션에서 함께 탐색할 수 있다. Juice Shop의 인증된 /profile이
        # 대표적이다.
        pending = (
            [task.target_url]
            if targeted
            else list(dict.fromkeys((task.target_url, *self._seed_urls)))
        )
        pending_discovery_types: dict[str, set[str]] = {
            url: {"seed"} for url in pending
        }
        fetched: set[str] = set()
        scripts: list[str] = []
        document_pages: set[str] = set()
        if targeted:
            # A second pass only visits this selected document. Preserve the
            # document-page form signal normally set during first-pass script discovery.
            document_pages.add(task.target_url)
        navigation_pages: set[str] = set()
        evidence_ids: list[str] = []
        planner_status: str | None = None
        # 발견과 수집은 다르다 — 크롤링 예산이 모자라도 발견한 URL은 Surface로 남긴다.
        # (url, method, parameters) 조합으로 중복을 막는다. 같은 run_id로 다시 호출되면
        # (프로세스 재시작 후 재개 등) 이미 저장된 Surface를 먼저 채워 넣어 같은 URL에
        # 매번 새 surface_id가 발급되지 않게 한다. 안 그러면 §3.7 저장 계획 재사용의
        # offered_surface_ids 비교가 재개 때마다 어긋난다 — id_factory가 uuid4처럼
        # 호출마다 다른 값을 내는 게 기본값이기 때문이다.
        surfaces: dict[tuple[str, str, tuple[str, ...]], str] = {
            (
                _canonical_surface_url(existing.url, _path_identifier(existing.url)),
                existing.method,
                existing.parameters,
            ): existing.surface_id
            for existing in self._surfaces.list_by_run(task.run_id)
        }
        # pending에 오른 URL의 surface_id. Planner 후보를 만들 때 URL로 Store를 다시
        # 뒤지지 않고 이 dict로 바로 대응시킨다.
        pending_surface_ids: dict[str, str] = {}
        surface_discovery_types: dict[str, set[str]] = {}
        recently_fetched_surface_ids: list[str] = []

        def remember(
            url: str,
            method: str,
            names: tuple[str, ...],
            observed: tuple[tuple[str, str], ...] = (),
            discovery_types: Sequence[str] = (),
        ) -> str:
            clean_url = url.split("?", 1)[0]
            path_identifier = _path_identifier(clean_url)
            key_url = _canonical_surface_url(clean_url, path_identifier)
            key = (key_url, method, names)
            existing = surfaces.get(key)
            if existing is not None:
                surface_discovery_types.setdefault(existing, set()).update(
                    discovery_types
                )
                return existing
            surface_id = f"surface-{self._id_factory()}"
            surfaces[key] = surface_id
            surface_discovery_types.setdefault(surface_id, set()).update(
                discovery_types
            )
            self._store_surface(
                task.run_id,
                surface_id,
                clean_url,
                method,
                names,
                observed=observed,
                path_identifier=path_identifier,
                discovery_types=tuple(dict.fromkeys(discovery_types)),
            )
            evidence_ids.extend(
                self._flag_suspect_parameters(task.run_id, surface_id, names)
            )
            if _looks_like_restricted_file(clean_url):
                evidence_ids.append(
                    self._flag_restricted_file(task.run_id, surface_id, clean_url)
                )
            return surface_id

        def crawl(
            *,
            protected: Sequence[str] | set[str] = (),
            max_visits: int | None = None,
        ) -> int:
            visited = 0
            while pending and len(fetched) < page_budget:
                if max_visits is not None and visited >= max_visits:
                    break
                if self._surface_collection_mode == "deterministic":
                    pending[:] = _deterministic_pending(pending, protected)
                url = pending.pop(0)
                if url in fetched:
                    continue
                fetched.add(url)
                visited += 1

                surface_id = remember(
                    url,
                    "GET",
                    _query_names(url),
                    _query_pairs(url),
                    tuple(sorted(pending_discovery_types.get(url, {"discovered"}))),
                )
                evidence_id, evidence = self._fetch(task, url, surface_id)
                evidence_ids.append(evidence_id)
                recently_fetched_surface_ids.append(surface_id)
                del recently_fetched_surface_ids[:-_MAX_AGENTIC_CONTEXT]

                body = evidence.observation.get("body")
                if not isinstance(body, str) or not body:
                    continue
                if not _is_html_response(evidence):
                    # JSON/API 응답 안의 escaped HTML 조각을 실제 링크나 폼으로 오인하면
                    # `/api/\"https:/...` 같은 실행 불가능한 Surface가 생긴다. API 본문은
                    # status/content-type 관찰로 남기되 HTML parser에는 넣지 않는다.
                    continue

                links, forms, sources = _parse_page(body, url)
                for form_url, method, names in forms:
                    form_surface_id = remember(
                        form_url, method, names, discovery_types=("html_form",)
                    )
                    if (
                        self._infer_unlinked_render_parameters
                        and method == "POST"
                        and url in document_pages
                    ):
                        evidence_ids.extend(
                            self._flag_unlinked_render_parameters(
                                task.run_id, form_surface_id
                            )
                        )
                for link in links:
                    if not _same_origin(link, origin):
                        continue
                    # 예산과 무관하게 표면으로 기록하고, 여유가 있으면 크롤링까지 한다.
                    pending_surface_ids[link] = remember(
                        link,
                        "GET",
                        _query_names(link),
                        _query_pairs(link),
                        discovery_types=("html_link",),
                    )
                    pending_discovery_types.setdefault(link, set()).add("html_link")
                    if link not in fetched and link not in pending:
                        pending.append(link)
                for source in sources:
                    if source not in scripts and _same_origin(source, origin):
                        scripts.append(source)
            return visited

        # 비교 모드에서도 사용자가 지정한 시작 URL은 항상 먼저 본다.
        initial_urls = tuple(pending)
        crawl(
            protected=initial_urls,
            max_visits=(len(initial_urls) if self._iterative_planner is not None else None),
        )

        # 번들 분석은 크롤링 뒤에 한다. 남은 예산 안에서만 스크립트를 받는다.
        affordable = max(min(self._max_scripts, page_budget - len(fetched)), 0)
        script_sources = (
            sorted(scripts, key=_deterministic_url_key)
            if self._surface_collection_mode == "deterministic"
            else scripts
        )
        for source in script_sources[:affordable]:
            fetched.add(source)
            for url, names, should_crawl, is_navigation in self._discover_from_script(
                task, source, origin
            ):
                discovery_type = (
                    "browser_navigation" if is_navigation else "script_literal"
                )
                pending_surface_ids[url] = remember(
                    url, "GET", names, discovery_types=(discovery_type,)
                )
                pending_discovery_types.setdefault(url, set()).add(discovery_type)
                # 번들이 가리킨 디렉터리와 서버 문서 navigation은 실제 응답을 봐야
                # 내부 파일이나 HTML 폼을 발견할 수 있다.
                if should_crawl:
                    document_pages.add(url)
                # 그중 실제 문서 이동만 Planner가 뒤로 밀 수 없는 보호 대상이다.
                # 디렉터리 추측과 달리 여기에 서버 렌더링 폼이 실제로 들어 있다.
                if is_navigation:
                    navigation_pages.add(url)
                # 기존 heuristic/hybrid는 문서·디렉터리만 방문한다. Agentic 경로는
                # 정답 seed 없이도 실제 JS/API 관찰에서 다음 GET을 고를 수 있어야
                # 하므로, 동일 origin에서 발견한 모든 GET Surface를 frontier에 둔다.
                if (
                    should_crawl or self._iterative_planner is not None
                ) and url not in fetched and url not in pending:
                    pending.append(url)

        if self._iterative_planner is not None and pending and not targeted:
            round_index = 0
            provider_fallback_status: str | None = None
            while pending and len(fetched) < page_budget:
                if self._surface_collection_mode == "deterministic":
                    pending[:] = _deterministic_pending(pending, navigation_pages)
                remaining_budget = max(page_budget - len(fetched), 0)
                candidates = self._recon_candidates(
                    task.run_id, pending, pending_surface_ids
                )
                selectable_surface_ids = tuple(
                    dict.fromkeys(candidate.surface_id for candidate in candidates)
                )[:_MAX_AGENTIC_SELECTABLE]
                if not selectable_surface_ids:
                    break
                observations = self._recon_observations(
                    task.run_id,
                    surface_discovery_types,
                    fetched,
                    selectable_surface_ids,
                    context_surface_ids=tuple(recently_fetched_surface_ids),
                )
                action, action_evidence_id, executed_surface_id = self._next_action(
                    task,
                    observations,
                    selectable_surface_ids,
                    remaining_budget,
                    round_index,
                    provider_fallback_status=provider_fallback_status,
                )
                if action.status in {
                    "fallback:timeout", "fallback:transport_error", "fallback:refused"
                }:
                    provider_fallback_status = action.status
                evidence_ids.append(action_evidence_id)
                planner_status = recon_action_status_detail(action)
                if action.action == "stop" or executed_surface_id is None:
                    break

                url_by_surface_id: dict[str, str] = {}
                for url in pending:
                    surface_id = pending_surface_ids.get(url)
                    if surface_id is not None:
                        url_by_surface_id.setdefault(surface_id, url)
                selected_url = url_by_surface_id.get(executed_surface_id)
                if selected_url is None:
                    break
                pending.remove(selected_url)
                pending.insert(0, selected_url)
                if crawl(max_visits=1) != 1:
                    break
                round_index += 1

        elif self._planner is not None and pending and not targeted:
            remaining_budget = max(page_budget - len(fetched), 0)
            candidates = self._recon_candidates(task.run_id, pending, pending_surface_ids)
            if candidates:
                plan, plan_evidence_id = self._plan(task, candidates, remaining_budget)
                evidence_ids.append(plan_evidence_id)
                planner_status = recon_plan_status_detail(plan)
                if self._surface_collection_mode == "deterministic":
                    # Planner 호출·결과는 감사를 위해 남기되 방문 집합은
                    # LLM 순서·stop에 좌우되지 않게 고정한다.
                    pending[:] = _deterministic_pending(pending, navigation_pages)
                else:
                    pending[:] = self._apply_plan(
                        plan, pending, pending_surface_ids, navigation_pages
                    )

        # 번들에서 찾은 디렉터리 목록(또는 Planner가 고른 순서)을 남은 예산 안에서 마저 본다.
        if self._iterative_planner is None:
            crawl(protected=navigation_pages)

        surface_ids = list(surfaces.values())
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=tuple(dict.fromkeys(evidence_ids)),
            surface_ids=tuple(dict.fromkeys(surface_ids)),
            message=planner_status,
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
            # Recon은 특정 취약점 Agent가 아니므로 Run 기본 세션을 쓴다. TaskFactory가
            # 선택한 참조를 전달하지 않으면 다중 취약점 Run에서 무인증으로 바뀐다.
            credential_ref=task.credential_ref,
        )
        return evidence_id, self._evidence.get(task.run_id, evidence_id)

    def _discover_from_script(
        self, task: TaskEnvelope, source: str, origin
    ) -> list[tuple[str, tuple[str, ...], bool, bool]]:
        """JS 번들을 받아 경로 리터럴에서 Surface 후보를 만든다."""

        _, evidence = self._fetch(task, source, None)
        body = evidence.observation.get("body")
        if not isinstance(body, str) or not body or len(body) > _MAX_SCRIPT_BYTES:
            return []

        parameters: dict[str, set[str]] = {}
        for match in _JS_PATH_PARAM.finditer(body):
            parameters.setdefault(match.group(1), set()).add(match.group(2))
        document_paths = {
            match.group(1) for match in _JS_DOCUMENT_NAVIGATION.finditer(body)
        }
        paths = {match.group(1) for match in _JS_PATH.finditer(body)}
        paths.update(parameters)
        paths.update(match.group(1) for match in _JS_DIRECTORY.finditer(body))
        # Angular 템플릿의 글자 수 표시는 ``value.length/10``을 렌더링하면서
        # ``/10`` 같은 문자열 리터럴을 만든다. 명시적 query 좌표나 실제 navigation이
        # 아닌 단일 숫자 루트 경로만 제거한다. ``/users/10``과
        # ``location.assign('/10')``은 각각 정상 REST/탐색 좌표이므로 보존한다.
        paths = {
            path
            for path in paths
            if not (
                _JS_BARE_NUMERIC_PATH.fullmatch(path)
                and path not in parameters
                and path not in document_paths
            )
        }

        base = f"{origin.scheme}://{origin.netloc}"
        # 실제 문서 이동을 먼저 방문한다. 일반 경로 수십 개를 정렬한 뒤 예산이
        # 소진되어 중요한 서버 렌더링 폼을 놓치는 일을 막는다.
        ordered_paths = (*sorted(document_paths), *sorted(paths - document_paths))
        found = [
            (
                f"{base}{path}",
                tuple(sorted(parameters.get(path, ()))),
                path in document_paths or path.endswith("/"),
                path in document_paths,
            )
            for path in ordered_paths
        ]
        found.extend(
            (f"{base}/#/{route}", names, False, False)
            for route, names in sorted(_client_routes(body).items())
        )
        return found

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
        discovery_types: tuple[str, ...] = (),
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
                discovery_types=discovery_types,
            )
        )

    def _flag_restricted_file(self, run_id: str, surface_id: str, url: str) -> str:
        """서버가 내주면 안 되는 확장자의 파일 표면을 Router 가 볼 수 있게 남긴다."""

        evidence_id = f"evi-{self._id_factory()}"
        self._evidence.append(
            Evidence(
                evidence_id=evidence_id,
                run_id=run_id,
                surface_id=surface_id,
                created_by="recon",
                evidence_type="observation",
                observation={
                    "type": RESTRICTED_FILE_OBSERVATION,
                    "parameter": urlsplit(url).path.rsplit("/", 1)[-1],
                },
            )
        )
        return evidence_id

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

    def _flag_unlinked_render_parameters(
        self, run_id: str, surface_id: str
    ) -> list[str]:
        """서버 렌더링 POST 폼에 제한된 비노출 옵션 후보를 남긴다."""

        evidence_ids: list[str] = []
        for name in _UNLINKED_RENDER_PARAMETERS:
            evidence_id = f"evi-{self._id_factory()}"
            self._evidence.append(
                Evidence(
                    evidence_id=evidence_id,
                    run_id=run_id,
                    surface_id=surface_id,
                    created_by="recon",
                    evidence_type="observation",
                    observation={
                        "type": UNLINKED_RENDER_PARAMETER_OBSERVATION,
                        "parameter": name,
                        "source": "bounded_unlinked_render_parameter",
                    },
                )
            )
            evidence_ids.append(evidence_id)
        return evidence_ids

    def _recon_candidates(
        self,
        run_id: str,
        pending: list[str],
        pending_surface_ids: dict[str, str],
    ) -> tuple[ReconCandidate, ...]:
        """호출 시점의 pending URL과 정확히 대응하는 Surface만 Planner 후보로 만든다."""

        observation_types: dict[str, list[str]] = {}
        for item in self._evidence.list_by_run(run_id):
            if item.evidence_type != "observation" or item.surface_id is None:
                continue
            observation_type = item.observation.get("type")
            if isinstance(observation_type, str):
                observation_types.setdefault(item.surface_id, []).append(
                    observation_type
                )

        candidates: list[ReconCandidate] = []
        for url in pending:
            surface_id = pending_surface_ids.get(url)
            if surface_id is None:
                continue
            surface = self._surfaces.get(run_id, surface_id)
            candidates.append(
                ReconCandidate(
                    surface_id=surface_id,
                    path=urlsplit(url).path or "/",
                    method=surface.method,
                    parameter_names=surface.parameters,
                    observation_types=tuple(
                        dict.fromkeys(observation_types.get(surface_id, ()))
                    ),
                )
            )
        return tuple(candidates)

    def _recon_observations(
        self,
        run_id: str,
        discovery_types: dict[str, set[str]],
        fetched_urls: set[str],
        focus_surface_ids: tuple[str, ...],
        *,
        context_surface_ids: tuple[str, ...] = (),
    ) -> tuple[ReconObservation, ...]:
        """Build the bounded answer-blind view for one action decision.

        The model receives every currently selectable coordinate plus only the most recent
        fetched coordinates. Older non-selectable observations remain in Evidence storage
        and the replay trace, but repeating them in every prompt does not help choose the
        next member of ``selectable_surface_ids``.
        """

        response_metadata: dict[str, tuple[int | None, str | None]] = {}
        for item in self._evidence.list_by_run(run_id):
            if item.surface_id is None or item.evidence_type != "http_response":
                continue
            status = item.observation.get("status")
            if type(status) is not int or not 100 <= status <= 599:
                status = None
            content_type = item.observation.get("content_type")
            if isinstance(content_type, str):
                content_type = _safe_recon_text(
                    content_type.split(";", 1)[0].strip().lower(), 100
                ) or None
            else:
                content_type = None
            response_metadata[item.surface_id] = (status, content_type)

        fetched_surface_urls = {
            _canonical_surface_url(
                url.split("?", 1)[0], _path_identifier(url.split("?", 1)[0])
            )
            for url in fetched_urls
        }
        observations: list[ReconObservation] = []
        for surface in self._surfaces.list_by_run(run_id):
            # A resumed run may already contain surfaces discovered in later rounds of a
            # previous attempt. Do not let that future state leak into an earlier round.
            if surface.surface_id not in discovery_types:
                continue
            metadata = (
                response_metadata.get(surface.surface_id)
                if surface.url in fetched_surface_urls
                else None
            )
            parsed = urlsplit(surface.url)
            path = parsed.path or "/"
            if parsed.fragment:
                path = f"{path}#{parsed.fragment}"
            path = _safe_recon_text(path, 512)
            if not path.startswith("/"):
                path = "/"
            observations.append(
                ReconObservation(
                    observation_id=f"recon-observation:{surface.surface_id}",
                    surface_id=surface.surface_id,
                    path=path,
                    method=surface.method.upper(),
                    parameter_names=alias_parameter_names(
                        surface.parameters
                    ).prompt_names,
                    discovery_types=tuple(
                        sorted(discovery_types.get(surface.surface_id, {"discovered"}))
                    ),
                    state="fetched" if metadata is not None else "discovered",
                    status_code=metadata[0] if metadata is not None else None,
                    content_type=metadata[1] if metadata is not None else None,
                )
            )
        focus = set(focus_surface_ids)
        context = set(context_surface_ids)
        observations = [
            item
            for item in observations
            if item.surface_id in focus or item.surface_id in context
        ]
        observations.sort(
            key=lambda item: (
                item.surface_id not in focus,
                item.surface_id not in context,
                item.state != "fetched",
                not bool(item.parameter_names),
            )
        )
        return tuple(observations[:_MAX_AGENTIC_OBSERVATIONS])

    def _next_action(
        self,
        task: TaskEnvelope,
        observations: tuple[ReconObservation, ...],
        selectable_surface_ids: tuple[str, ...],
        remaining_budget: int,
        round_index: int,
        *,
        provider_fallback_status: str | None = None,
    ) -> tuple[ReconAction, str, str | None]:
        """Restore or persist exactly one policy-checked iterative Recon action."""

        stored = find_stored_recon_action(
            self._evidence.list_by_run(task.run_id),
            observations,
            selectable_surface_ids,
            round_index=round_index,
        )
        if stored is not None:
            return stored

        if self._surface_collection_mode == "deterministic" or provider_fallback_status:
            selected = selectable_surface_ids[0]
            basis = next(
                (
                    (item.observation_id,)
                    for item in observations
                    if item.surface_id == selected
                ),
                (),
            )
            action = ReconAction(
                action="visit_surface",
                surface_id=selected,
                basis_observation_ids=basis,
                reason_code=(
                    "planner_failure" if provider_fallback_status else "expand_coverage"
                ),
                source="deterministic_fallback",
                status=provider_fallback_status or "fallback:deterministic_collection",
            )
        else:
            action = _policy_checked_recon_action(
                self._iterative_planner.decide(
                    task=task,
                    observations=observations,
                    selectable_surface_ids=selectable_surface_ids,
                    remaining_budget=remaining_budget,
                    round_index=round_index,
                ),
                observations,
                selectable_surface_ids,
            )

        executed_surface_id = (
            action.surface_id if action.action == "visit_surface" else None
        )
        evidence_id = f"evi-{self._id_factory()}"
        self._evidence.append(
            Evidence(
                evidence_id=evidence_id,
                run_id=task.run_id,
                surface_id=None,
                created_by=AGENTIC_RECON_PLANNER,
                evidence_type="observation",
                observation=build_recon_action_observation(
                    action,
                    observations,
                    selectable_surface_ids,
                    round_index=round_index,
                    remaining_budget=remaining_budget,
                    executed_surface_id=executed_surface_id,
                ),
            )
        )
        return action, evidence_id, executed_surface_id

    def _plan(
        self,
        task: TaskEnvelope,
        candidates: tuple[ReconCandidate, ...],
        remaining_budget: int,
    ) -> tuple[ReconPlan, str]:
        """저장된 계획을 재사용하거나, Planner를 불러 새 계획 Evidence를 남긴다."""

        offered_surface_ids = tuple(candidate.surface_id for candidate in candidates)
        stored = find_stored_recon_plan(
            self._evidence.list_by_run(task.run_id), offered_surface_ids
        )
        if stored is not None:
            return stored

        plan = self._planner.plan(
            task=task, candidates=candidates, remaining_budget=remaining_budget
        )
        evidence_id = f"evi-{self._id_factory()}"
        self._evidence.append(
            Evidence(
                evidence_id=evidence_id,
                run_id=task.run_id,
                surface_id=None,
                created_by=RECON_PLANNER,
                evidence_type="observation",
                observation=build_recon_plan_observation(plan, offered_surface_ids),
            )
        )
        return plan, evidence_id

    def _apply_plan(
        self,
        plan: ReconPlan,
        pending: list[str],
        pending_surface_ids: dict[str, str],
        protected: set[str],
    ) -> list[str]:
        """plan의 action과 allowlisted ID 순서를 실제 pending URL로 되돌린다.

        LLM이 만든 것은 순서와 continue/stop뿐이다. pending에 없는 URL은 Planner가
        어떤 ID를 내놓든 방문하지 않는다 — 새 URL을 만들지 않고, 코드가 이미 들고
        있던 pending_surface_ids 매핑을 뒤집어서만 찾는다.

        ``protected``는 번들의 실제 문서 이동(``location.assign`` 등)으로 판정된 표면이다.
        디렉터리 추측과 달리 여기에 서버 렌더링 폼이 실제로 들어 있다. Planner는 나머지의
        순서만 정하고 이것은 건드리지 못한다 — 빠지면 그 URL의 HTML 폼이 영영 파싱되지
        않아 POST Surface와 렌더 파라미터 신호가 통째로 사라지고, "검사했지만 없었다"와
        "애초에 검사하지 않았다"가 구분되지 않는다.

        제외뿐 아니라 **순서 강등도 막는다.** 정찰 예산은 pending 전부를 방문할 만큼
        넉넉하지 않아서, 보호 표면을 뒤로 미는 것은 제외하는 것과 결과가 같다. 그래서
        보호 표면은 원래 순서를 유지한 채 항상 앞에 둔다(``_discover_from_script``의
        ``ordered_paths``가 세우는 것과 같은 우선순위다).
        """

        # 원래 방문 순서를 유지한 채 보호 대상만 추린다.
        protected_order = [url for url in pending if url in protected]
        if plan.action == "stop":
            return protected_order

        url_by_surface_id: dict[str, str] = {}
        for url in pending:
            surface_id = pending_surface_ids.get(url)
            if surface_id is not None:
                url_by_surface_id.setdefault(surface_id, url)

        ranked = [
            url_by_surface_id[surface_id]
            for surface_id in plan.ranked_surface_ids
            if surface_id in url_by_surface_id and url_by_surface_id[surface_id] not in protected
        ]
        return [*protected_order, *ranked]


def _is_html_response(evidence: Evidence) -> bool:
    """Return whether a textual response is eligible for HTML structure parsing.

    Missing content type stays compatible with simple runtimes and old fixtures. An
    explicit non-HTML media type is authoritative: its body can still be observed, but
    HTML-looking strings inside JSON or JavaScript are data rather than page structure.
    """

    content_type = evidence.observation.get("content_type")
    if not isinstance(content_type, str) or not content_type.strip():
        return True
    media_type = content_type.split(";", 1)[0].strip().casefold()
    return media_type in {"text/html", "application/xhtml+xml"}


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


def _safe_recon_text(value: str, limit: int) -> str:
    """Keep target-controlled labels printable and bounded before LLM serialization."""

    return "".join(character if character.isprintable() else "\ufffd" for character in value)[
        :limit
    ]


def _policy_checked_recon_action(
    proposed: object,
    observations: tuple[ReconObservation, ...],
    selectable_surface_ids: tuple[str, ...],
) -> ReconAction:
    """Enforce the current-run coordinate allowlist independently of the planner."""

    observation_ids = {item.observation_id for item in observations}
    valid = isinstance(proposed, ReconAction) and all(
        item in observation_ids for item in proposed.basis_observation_ids
    )
    if valid and proposed.action == "stop":
        return proposed
    if valid and proposed.surface_id in selectable_surface_ids:
        return proposed

    selected = selectable_surface_ids[0]
    basis = next(
        (
            (item.observation_id,)
            for item in observations
            if item.surface_id == selected
        ),
        (),
    )
    rejected = ()
    if isinstance(proposed, ReconAction) and proposed.surface_id:
        rejected = (proposed.surface_id,)
    return ReconAction(
        action="visit_surface",
        surface_id=selected,
        basis_observation_ids=basis,
        reason_code="planner_failure",
        source="deterministic_fallback",
        status="fallback:invalid_response",
        rejected_surface_ids=rejected,
    )
