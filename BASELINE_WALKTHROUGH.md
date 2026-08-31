# 마일스톤 A 동작 설명 — LLM 없이 도는 파이프라인

Phase 1–5까지 구현된 결정적(deterministic) 파이프라인이 한 번의 Run에서 무엇을
어떤 순서로 하는지, 실제 코드 위치와 함께 정리한 문서다.

이 파이프라인에는 LLM이 한 줄도 들어가지 않는다. 전부 고정 규칙과 문자열 비교로
동작한다. 이것이 마일스톤 B(LLM 도입)와 비교할 **연구 대조군**이다.

- 대상 브랜치: `dev/dmswls`
- 런타임 의존성: 없음 (Python 3.10+ 표준 라이브러리만)
- 테스트: `PYTHONPATH=src python3 -m unittest discover -s tests`

---

## 목차

1. [전체 그림](#1-전체-그림)
2. [0단계 — 시작 전 관문](#2-0단계--시작-전-관문)
3. [1단계 — RECON](#3-1단계--recon-어디를-두드릴-수-있는지-찾기)
4. [2단계 — ROUTE](#4-2단계--route-누구한테-보낼지-정하기)
5. [3단계 — ANALYZE](#5-3단계--analyze-실제로-확인하기)
6. [4단계 — VALIDATE](#6-4단계--validate-안-믿고-다시-확인)
7. [5단계 — REPORT](#7-5단계--report)
8. [관통하는 설계 원칙 5가지](#8-관통하는-설계-원칙-5가지)
9. [지금 Finding이 0개인 이유](#9-지금-finding이-0개인-이유)

---

## 1. 전체 그림

```
start()
  ├ policy.validate_run          ← 스코프 밖이면 여기서 끝
  ├ budget.open_run
  │
  ├ RECON     recon.handle → collector.collect → HTTP → Evidence
  │           HTML 파싱 → Surface 저장 → 의심 파라미터 관찰
  │
  ├ ROUTE     router.route(surfaces, evidence) → Candidate
  │           관찰규칙(0.6~0.8) 우선, 구조규칙(0.2~0.3) 보조
  │
  ├ ANALYZE   analyzer.handle → NEEDS_EVIDENCE + 요청계획
  │             ↓ Orchestrator: surface 검사 + tool 검사
  │           collector.collect × N → Evidence
  │             ↓
  │           analyzer.handle 재호출 → control/probe 비교 → "reflection"
  │
  ├ VALIDATE  validation_id 발급
  │           validator.handle → NEEDS_EVIDENCE (Analysis 증적 인정 안 함)
  │             ↓ collector.collect (validation_id 각인)
  │           validator.handle 재호출 → SUSPECTED / BLOCKED
  │             ↓ Orchestrator: 세션·출처·Surface·proof 4중 재검사
  │
  └ REPORT    Finding Store만 읽어서 Markdown
```

### 계층 구조

```
domain/     ← 순수 데이터 + 불변식. 아무것도 import 하지 않는다
  ↑
ports/      ← Protocol(인터페이스)만. 구현 없음
  ↑
application/ ← Orchestrator, Collector. ports만 바라본다
  ↑
adapters/   ← 실제 구현(HTTP, 저장소, 규칙 Agent)
  ↑
bootstrap.py ← 여기서만 조립
```

의존 방향이 한쪽으로만 흐르는지는 [tests/test_dependency_direction.py](tests/test_dependency_direction.py)가
검사한다. `domain`이 `adapters`를 import하면 테스트가 깨진다.

### 핵심 데이터 타입

| 타입 | 뜻 | 정의 |
|---|---|---|
| `Run` | 한 번의 진단 세션 | [models.py:125](src/hacklipse/domain/models.py#L125) |
| `Surface` | 공격 표면 (URL+메서드+파라미터) | [models.py:262](src/hacklipse/domain/models.py#L262) |
| `Evidence` | 관찰된 사실 | [models.py:245](src/hacklipse/domain/models.py#L245) |
| `Candidate` | 아직 검증 안 된 가설 | [models.py:274](src/hacklipse/domain/models.py#L274) |
| `ValidationResult` | 독립 검증 결과 | [models.py:324](src/hacklipse/domain/models.py#L324) |
| `Finding` | 확정된 취약점 | [models.py:357](src/hacklipse/domain/models.py#L357) |
| `TaskEnvelope` | Agent에게 보내는 작업 지시서 | [models.py:192](src/hacklipse/domain/models.py#L192) |

전부 `@dataclass(frozen=True, slots=True)`다. **한 번 만들면 못 고친다.**
상태를 바꾸려면 `Candidate.set_status()`처럼 새 복사본을 만들어야 한다
([models.py:292-296](src/hacklipse/domain/models.py#L292-L296)).

Evidence는 특히 중요하다 — Store Protocol에 `update`가 아예 없다.
`append`와 조회만 있다. **증적은 추가만 되고 수정·삭제되지 않는다.**

---

## 2. 0단계 — 시작 전 관문

`app.orchestrator.start(RunRequest(...))` 한 줄로 시작한다.
**Run 객체를 만들기 전에** 대상부터 검사한다.

[orchestrator.py:98-115](src/hacklipse/application/orchestrator.py#L98-L115)

```python
def start(self, request: RunRequest) -> Run:
    # Run을 만들기 전에 Scope를 검사하여 잘못된 대상이 저장되지 않게 한다.
    self._policy.validate_run(request)                      # 102
    run = Run(
        run_id=f"run-{self._id_factory()}",                 # 103
        target_url=request.target_url,
        scope=request.scope,
        policy_profile=request.policy_profile,
        request_budget=request.request_budget,
    )
    self._runs.add(run)
    self._budget.open_run(run.run_id, run.request_budget)   # 112
    run = self._state.transition(run, RunPhase.RECON)       # 113
    self._runs.save(run)
    return self.resume(run.run_id)
```

순서가 중요하다. 정책 검사(102)가 Run 생성(103)보다 **앞에** 있다.
스코프 밖 대상은 저장소에 기록조차 남지 않는다.

### 스코프 검사가 실제로 막는 것

[policy.py:33-48](src/hacklipse/adapters/policy.py#L33-L48)

```python
@staticmethod
def _validate_url(url: str, scope: RunScope) -> None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise PolicyViolation("target must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise PolicyViolation("inline credentials are not allowed")
    # 대소문자와 마지막 점 표기 차이로 allowlist 검사가 우회되지 않게 정규화한다.
    allowed_hosts = {host.casefold().rstrip(".") for host in scope.allowed_hosts}
    hostname = parsed.hostname.casefold().rstrip(".")
    if hostname not in allowed_hosts:
        raise PolicyViolation(f"host is outside the run scope: {hostname}")
    path = parsed.path or "/"
    if not any(path.startswith(prefix) for prefix in scope.allowed_path_prefixes):
        raise PolicyViolation(f"path is outside the run scope: {path}")
```

| 검사 | 막는 것 |
|---|---|
| scheme allowlist | `file:///etc/passwd`, `ftp://`, `gopher://` |
| 인라인 자격증명 | `http://user:pass@internal/` — 호스트 파싱 혼란 유발 |
| `.casefold()` | `LOCALHOST` 대문자 우회 |
| `.rstrip(".")` | `localhost.` — 후행 점은 DNS에서 같은 호스트지만 문자열은 다르다 |
| path prefix | 허용 경로를 `/vulnerabilities/`로 좁혔을 때 `/admin` 접근 |

그리고 스코프 자체가 비어 있을 수 없다 —
[models.py:101-107](src/hacklipse/domain/models.py#L101-L107)이
`allowed_hosts`가 빈 집합이면 거부한다. *"비어 있는 범위는 사실상 무제한 또는
오설정으로 해석될 수 있으므로"*. **"전부 허용"이라는 상태가 존재하지 않는다.**

### 단계 순서는 표로 강제된다

[state_machine.py:12-21](src/hacklipse/application/state_machine.py#L12-L21)

```python
_allowed: dict[RunPhase, frozenset[RunPhase]] = {
    RunPhase.INIT:     frozenset({RunPhase.RECON, RunPhase.FAILED}),
    RunPhase.RECON:    frozenset({RunPhase.ROUTE, RunPhase.FAILED}),
    RunPhase.ROUTE:    frozenset({RunPhase.ANALYZE, RunPhase.REPORT, RunPhase.FAILED}),
    RunPhase.ANALYZE:  frozenset({RunPhase.VALIDATE, RunPhase.FAILED}),
    RunPhase.VALIDATE: frozenset({RunPhase.REPORT, RunPhase.FAILED}),
    RunPhase.REPORT:   frozenset({RunPhase.DONE, RunPhase.FAILED}),
    RunPhase.DONE:     frozenset(),
    RunPhase.FAILED:   frozenset(),
}
```

앞으로만 간다. RECON에서 VALIDATE로 건너뛸 수 없고, DONE/FAILED에서는
아무 데도 못 간다. ROUTE만 분기가 둘인데, Candidate가 없으면 ANALYZE를 건너뛰고
REPORT로 간다 ([orchestrator.py:132](src/hacklipse/application/orchestrator.py#L132)).

실행 루프는 [orchestrator.py:126-145](src/hacklipse/application/orchestrator.py#L126-L145)
하나가 전부다.

```python
while run.phase not in {RunPhase.DONE, RunPhase.FAILED}:
    if run.phase is RunPhase.RECON:
        run = self._recon(run)
        run = self._state.transition(run, RunPhase.ROUTE)
    elif run.phase is RunPhase.ROUTE:
        run = self._route(run)
        next_phase = RunPhase.ANALYZE if run.candidate_ids else RunPhase.REPORT
        run = self._state.transition(run, next_phase)
    ...
    self._runs.save(run)          # 145: 매 단계마다 저장
```

**Orchestrator는 "다음에 뭘 할지"만 결정하고 "어떻게 할지"는 전혀 모른다.**
`_recon`, `_route` 같은 메서드는 전부 하위 컴포넌트 호출과 결과 병합뿐이다.
이게 노션 §4 "Centralized Control + Delegated Implementation"의 코드 형태다.

145줄에서 매 단계 저장하기 때문에 중간에 죽어도 `resume(run_id)`로 이어서
돌릴 수 있다 ([test_persistence_resume.py](tests/test_persistence_resume.py)).

---

## 3. 1단계 — RECON: 어디를 두드릴 수 있는지 찾기

### 3.1 Task를 만들어 넘긴다

[orchestrator.py:153-163](src/hacklipse/application/orchestrator.py#L153-L163)

```python
def _recon(self, run: Run) -> Run:
    task = self._task_factory.recon(
        run,
        agent_type=self._config.recon_agent_type,
        request_budget=self._budget.remaining(run.run_id),   # 남은 예산을 실어보냄
    )
    result = self._tasks.execute(task)
    self._require_completed(result, "recon")
    return self._merge_agent_result(run, result)
```

Task 내용은 [task_factory.py:18-28](src/hacklipse/application/task_factory.py#L18-L28):

```python
def recon(self, run: Run, *, agent_type: str, request_budget: int) -> TaskEnvelope:
    return self._base(
        run,
        agent_type=agent_type,
        request_budget=request_budget,
        target_url=run.target_url,
        allowed_tools=("http_get",),      # ← 쓸 수 있는 도구는 이것뿐
    )
```

`allowed_tools`가 **화이트리스트**다. Recon은 `http_get` 외에 아무것도 못 쓴다.
[recon.py:143-144](src/hacklipse/adapters/recon.py#L143-L144)에서 Agent가
스스로 이걸 확인하고, 나중에 Collector도 다시 확인한다
([execution.py:109-110](src/hacklipse/application/execution.py#L109-L110)).

`TaskEnvelope`에 **자격증명 필드가 없다는 점**도 중요하다
([models.py:192-221](src/hacklipse/domain/models.py#L192-L221)).
Phase 8 계획의 *"credential 원문은 Task에 절대 안 실림"*이 타입으로 강제돼 있다.

### 3.2 유일한 외부 실행 통로

Recon이 첫 요청을 보낼 때 [recon.py:150-161](src/hacklipse/adapters/recon.py#L150-L161)에서
`self._collector.collect(...)`를 부른다. 이게 **이 프로젝트에서 네트워크로 나가는
유일한 경로**다.

[execution.py:42-100](src/hacklipse/application/execution.py#L42-L100)

```python
def collect(self, run_id, target_url, spec, *, task_id, validation_id=None) -> str:
    # 저장된 Run을 신뢰 기준으로 사용해 Task가 임의 정책을 주입하지 못하게 한다.
    run = self._runs.get(run_id)                      # 53
    execution_id = f"exec-{self._id_factory()}"
    http_request = spec.http_request or HttpRequestSpec()
    request = ExecutionRequest(
        execution_id=execution_id, run_id=run_id, task_id=task_id,
        tool=spec.suggested_tool, target_url=target_url,
        surface_id=spec.surface_id, purpose=spec.reason,
        method=http_request.method,
        query_parameters=http_request.query_parameters,
        headers=http_request.headers,
        body=http_request.body,
        request_kind=http_request.request_kind,
        validation_id=validation_id,
    )
    # 실제 호출 직전에 Scope와 예산을 검사해 우회 실행을 막는다.
    self._policy.validate_execution(run, request)     # 73  ← 정책
    self._budget.consume(run.run_id, 1)               # 74  ← 예산
    result = self._runtime.execute(request)           # 75  ← 실제 요청
    if result.execution_id != execution_id:
        raise AgentContractError("runtime result does not match execution request")

    # Runtime 결과는 메시지로 중계하지 않고 Evidence Store에 먼저 기록한다.
    evidence_id = f"evi-{self._id_factory()}"
    observation = dict(result.observation)
    observation.setdefault("request_kind", request.request_kind.value)   # 83
    observation.setdefault("requested_url", request.resolved_url)        # 84
    observation.setdefault("method", request.method.upper())             # 85
    self._evidence.append(
        Evidence(
            evidence_id=evidence_id,
            run_id=run.run_id,
            surface_id=request.surface_id,
            created_by=f"execution_runtime:{request.tool}",   # 91 ← 출처 도장
            evidence_type=result.evidence_type,
            source_task_id=task_id,                          # 93 ← 누가 시켰나
            validation_id=validation_id,                     # 94 ← 어느 세션
            observation=observation,
            artifact_refs=result.artifact_refs,
            content_hash=result.content_hash,
        )
    )
    return evidence_id
```

**여기서 짚어야 할 것 5개:**

**① 53줄 — Task가 아니라 Store에서 Run을 다시 읽는다.**
Task가 위조된 정책이나 스코프를 실어 보내도 소용없다. 신뢰의 원천은 항상 저장소다.

**② 73-75줄 순서.** 정책 → 예산 → 실행. 이 세 줄이 **모든 외부 요청이 통과하는
병목**이다. 이 순서를 우회하는 경로가 코드베이스에 없다.

**③ 76-77줄 — 응답 대조.** Runtime이 다른 요청의 결과를 돌려주면 거부한다.

**④ 83-85줄 — `setdefault`로 메타데이터를 강제 주입.**
Runtime 구현이 바뀌어서 `requested_url`이나 `request_kind`를 안 넣어도,
Collector가 채워 넣는다. control/probe 구분이 사라지면 3단계 분석이 통째로
무너지기 때문에 여기서 보험을 든다.

**⑤ 91-94줄 — provenance(출처) 각인.**

| 필드 | 값 | 나중에 쓰이는 곳 |
|---|---|---|
| `created_by` | `execution_runtime:http_get` | Validator가 "Agent가 지어낸 게 아니다" 확인 |
| `source_task_id` | 요청한 Task ID | 감사 추적 |
| `validation_id` | 검증 세션 ID (없으면 `None`) | 세션 격리 |

이 세 개가 4단계 판정의 전제조건이 된다.

### 3.3 실제 HTTP 전송

[http_runtime.py](src/hacklipse/adapters/http_runtime.py)가 안전 경계의 바깥 끝이다.
파일 최상단 docstring이 이걸 명시한다 —
*"이 클래스 뒤부터가 통제 불가능한 외부 세계다."*

**안전장치 3개:**

**① 리다이렉트를 안 따라간다** — [http_runtime.py:39-49](src/hacklipse/adapters/http_runtime.py#L39-L49)

```python
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """3xx 응답을 따라가지 않고 HTTPError로 올려보낸다.

    PolicyGate는 원래 URL만 검증하므로, urlopen이 302를 자동으로 따라가면
    allowlist 밖 도메인으로 요청이 새어 나갈 수 있다.
    """
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None      # None을 반환하면 urllib이 따라가지 않는다
```

**정책 검사를 통과한 URL과 실제로 요청이 도달한 URL이 달라지는 것**을 막는다.
`localhost`만 허용했는데 대상이 `302 → evil.com`을 주면, 리다이렉트를 따라가는
순간 스코프 밖으로 요청이 나간다. 대신 리다이렉트 시도 자체를 증적으로 남긴다
([http_runtime.py:173-175](src/hacklipse/adapters/http_runtime.py#L173-L175)에서
`Location` 헤더까지 기록 — *"어디로 보내려 했는지 남긴다"*).

**② 환경변수 프록시를 무시한다** — [http_runtime.py:73-75](src/hacklipse/adapters/http_runtime.py#L73-L75)

```python
self._opener = urllib.request.build_opener(
    _NoRedirect, urllib.request.ProxyHandler({})
)
```

`http_proxy` 환경변수가 설정돼 있으면 urllib이 자동으로 그 프록시를 경유한다.
로컬 대상 요청이 외부 프록시로 새는 걸 막는다. 검증은
[test_http_runtime.py:302-309](tests/test_http_runtime.py#L302-L309)에서
죽은 프록시를 환경변수에 심어놓고 요청이 성공하는지로 확인한다.

**③ 네트워크 오류를 예외가 아니라 증적으로** — [http_runtime.py:185-208](src/hacklipse/adapters/http_runtime.py#L185-L208)

```python
def _error_result(self, request, requested_url, method, error, started):
    """네트워크 오류를 예외 대신 http_error 증적으로 변환한다."""
    return ExecutionResult(
        execution_id=request.execution_id,
        evidence_type="http_error",
        observation={
            "type": "http_error",
            "error_kind": _classify_error(error),   # timeout/connection_refused/dns/connection
            "message": str(getattr(error, "reason", error)),
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        },
    )
```

**"연결이 거부됐다"도 관측 사실이다.** 예외로 터뜨리면 그 사실이 사라진다.
`elapsed_ms`는 나중에 time-based blind SQLi(SLEEP 주입) 판정의 유일한 신호원이
되므로 오류 경로에서도 측정한다.

**응답 처리에서 눈여겨볼 것:**

```python
raw = b"" if method == "HEAD" else response.read(self._max_body + 1)   # 141
truncated = len(raw) > self._max_body                                   # 142
raw = raw[: self._max_body]                                             # 143
```

상한+1을 읽어서 **잘렸는지 여부를 판별**한다. 그냥 상한까지만 읽으면 정확히
상한 크기인 응답과 잘린 응답을 구분할 수 없다.

```python
headers = [[key.lower(), value] for key, value in response.headers.items()]   # 151
```

dict가 아니라 **[이름, 값] 목록**이다. `Set-Cookie`처럼 같은 이름이 여러 번
오는 헤더를 dict에 넣으면 마지막 것만 남는다. 향후 IDOR 검증에서 쿠키 리플레이가
필요하므로 전부 보존한다.

```python
if method != "HEAD" and _is_textual(content_type):
    observation["body"] = raw.decode(_charset(content_type), errors="replace")   # 169
else:
    observation["body"] = None                                                   # 171
```

이미지·PDF 같은 바이너리를 강제로 문자열화하지 않는다. 대신 크기와 SHA-256만
남긴다([http_runtime.py:182](src/hacklipse/adapters/http_runtime.py#L182)).

그리고 요청 헤더에 `Accept-Encoding: identity`를 **강제로 덮어쓴다**
([http_runtime.py:92-98](src/hacklipse/adapters/http_runtime.py#L92-L98)) —
urllib은 gzip을 자동 해제하지 않으므로, 압축 응답을 받으면 3단계의 문자열 비교가
전부 실패한다.

### 3.4 HTML에서 공격 표면 추출

[recon.py:53-116](src/hacklipse/adapters/recon.py#L53-L116)의 `_SurfaceHTMLParser`가
표준 라이브러리 `html.parser`만으로 파싱한다.

```python
def handle_starttag(self, tag, attrs):
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
```

`<form>`을 만나면 수집 모드로 들어가고, 안의 `<input>`/`<select>`/`<textarea>`의
`name`을 모은다. `</form>`에서 하나의 Surface로 확정한다.

**깨진 HTML 대응** — [recon.py:86-90](src/hacklipse/adapters/recon.py#L86-L90):

```python
def close(self) -> None:
    super().close()
    # 닫는 태그가 없는 폼(HTML 오류)도 손실 없이 기록한다.
    self._finalize_form()
```

`</form>`이 없는 페이지에서도 폼을 잃지 않는다. 취약한 대상일수록 HTML이
깨져 있을 확률이 높다.

**자체 종료 태그** — [recon.py:78-80](src/hacklipse/adapters/recon.py#L78-L80):
`<input ... />` 형태는 `handle_startendtag`로 들어오므로 별도로 받아서
같은 처리로 넘긴다.

**링크 필터** — [recon.py:99-108](src/hacklipse/adapters/recon.py#L99-L108):

```python
resolved = urljoin(self._base_url, href)
parsed = urlsplit(resolved)
if parsed.scheme not in ("http", "https"):
    return                                    # mailto:, javascript:, tel: 제외
params = tuple(name for name, _ in parse_qsl(parsed.query))
url = resolved.split("?", 1)[0]
```

상대 경로를 절대 URL로 만들고(`urljoin`), `http(s)`가 아니면 버린다.
쿼리 문자열은 파라미터 이름만 뽑고 URL 본체와 분리해서 저장한다.

### 3.5 의심 파라미터에 관찰만 남긴다

[recon.py:28-45](src/hacklipse/adapters/recon.py#L28-L45)

```python
_FILE_OR_URL_PARAM_HINTS = (
    "file", "page", "path", "template", "doc", "include", "folder",
    "dir", "load", "view", "download", "src", "url", "redirect",
    "dest", "target",
)

def _looks_like_file_or_url_parameter(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _FILE_OR_URL_PARAM_HINTS)
```

[recon.py:203-224](src/hacklipse/adapters/recon.py#L203-L224)에서 매칭되면
Evidence를 남긴다:

```python
observation={"type": "url_or_file_parameter", "parameter": name}
```

**Recon은 여기서 아무 판단도 하지 않는다.** "Path Traversal 취약점"이 아니라
"이런 이름의 파라미터가 있다"만 쓴다. 이게 **관찰(Observation) vs 주장(Claim)**
분리의 실제 코드다.

> Recon이 LLM을 쓰지 않는 이유는 [recon.py:118-123](src/hacklipse/adapters/recon.py#L118-L123)
> 클래스 docstring에 있다 — *"크롤링·폼 추출은 결정적 작업이라 판단 품질이 오르지 않고,
> 이 버전 자체가 이후 LLM 기반 Recon과 비교할 연구 대조군이 된다."*

---

## 4. 2단계 — ROUTE: 누구한테 보낼지 정하기

[orchestrator.py:165-179](src/hacklipse/application/orchestrator.py#L165-L179)

```python
def _route(self, run: Run) -> Run:
    surfaces = self._surfaces.list_by_run(run.run_id)              # run_id로 범위 한정
    evidence = self._evidence.get_many(run.run_id, run.evidence_ids)
    decisions = self._router.route(run, surfaces, evidence)
    candidate_ids = list(run.candidate_ids)
    for decision in decisions:
        candidate = decision.candidate
        # Router가 다른 Run의 Candidate를 섞는 계약 위반을 차단한다.
        if candidate.run_id != run.run_id:                          # 175
            raise AgentContractError("router returned a candidate for another run")
        self._candidates.add(candidate)
        candidate_ids.append(candidate.candidate_id)
    return run.with_updates(candidate_ids=tuple(dict.fromkeys(candidate_ids)))
```

모든 Store 조회에 `run_id`가 들어간다. 다른 Run의 데이터가 섞일 수 없다.
175줄은 Router 구현이 잘못돼도 오염이 퍼지지 않게 하는 이중 확인이다.

### 규칙표 두 개

**A — 관찰 기반 (강함)** [routing.py:39-45](src/hacklipse/adapters/routing.py#L39-L45)

```python
DEFAULT_RULES = (
    RoutingRule("reflection",            "XSS",            "xss_analyzer",  0.8),
    RoutingRule("sql_error",             "SQLi",           "sqli_analyzer", 0.8),
    RoutingRule("object_id_auth",        "Access Control", "access_control_analyzer", 0.8),
    RoutingRule("url_or_file_parameter", "Path Traversal", "path_traversal_analyzer", 0.6),
    RoutingRule("template_error",        "SSTI",           "ssti_analyzer", 0.7),
)
```

Evidence의 `observation["type"]`을 키로 매칭한다. Recon이 남긴
`"url_or_file_parameter"`가 여기 `Path Traversal` 규칙에 걸린다.

**B — 구조 기반 (탐색용, 약함)** [routing.py:50-54](src/hacklipse/adapters/routing.py#L50-L54)

```python
DEFAULT_SURFACE_RULES = (
    SurfaceRoutingRule("XSS",  "xss_analyzer",  priority=0.30),
    SurfaceRoutingRule("SQLi", "sqli_analyzer", priority=0.30),
    SurfaceRoutingRule("SSTI", "ssti_analyzer", priority=0.20),
)
```

매칭 조건은 [routing.py:32-35](src/hacklipse/adapters/routing.py#L32-L35):

```python
def matches(self, surface: Surface) -> bool:
    if surface.method.upper() not in self.methods:      # 기본 ("GET",)
        return False
    return bool(surface.parameters) if self.requires_parameters else True
```

### 왜 B가 필요한가 — 닭과 달걀

XSS는 `"reflection"` 관찰이 있어야 라우팅된다(규칙 A). 그런데 반사를 확인하려면
요청을 보내야 하고, 요청을 보내려면 먼저 XSS 분석가에게 라우팅돼야 한다.
**Recon만으로는 이 고리를 못 끊는다.**

규칙 B가 끊는다 — "파라미터 있는 GET Surface면 일단 XSS 분석가한테 보내서
직접 확인시켜라." 주석에도 명시돼 있다
([routing.py:47-49](src/hacklipse/adapters/routing.py#L47-L49)) —
*"실제 취약점 판정이 아니라 탐색 대상을 만드는 규칙이므로 기존 Evidence 규칙보다
낮은 priority를 사용한다."*

> **설계 대안과의 비교:** 반사 탐지 프로브를 Recon에 넣는 방법도 있었다.
> 그러면 Recon이 순수 구조 정찰이 아니게 되어 대조군으로서의 성격이 흐려지고,
> 프로브 로직이 Recon과 Analysis 두 곳에 흩어진다. 지금 방식은 Recon을 구조
> 정찰로 남기고 프로브를 Analysis 한 곳에 모은다.

### 병합 규칙 — A가 이긴다

[routing.py:78-121](src/hacklipse/adapters/routing.py#L78-L121)

```python
decisions: dict[tuple[str, str], RouteDecision] = {}    # 키: (surface_id, vuln_type)

for item in evidence:            # ① 관찰 규칙 먼저
    ...
    key = (item.surface_id, rule.vulnerability_type)
    if key in decisions:
        continue                 # 같은 조합은 하나만
    decisions[key] = RouteDecision(candidate=candidate, priority=rule.priority)

for surface in surfaces:         # ② 구조 규칙 나중
    if surface.run_id != run.run_id:
        continue
    for rule in self._surface_rules:
        key = (surface.surface_id, rule.vulnerability_type)
        # 같은 취약점에 강한 Evidence 규칙이 이미 매칭됐다면 그것을 유지한다.
        if key in decisions:                              # 106-108
            continue
        decisions[key] = RouteDecision(candidate=candidate, priority=rule.priority)

return tuple(sorted(decisions.values(), key=lambda i: i.priority, reverse=True))
```

`(surface_id, vulnerability_type)` 조합을 키로 쓰는 dict라서, **같은 Surface에
같은 취약점 Candidate가 중복 생성되지 않는다.** A를 먼저 돌리고 B에서
`if key in decisions: continue`로 건너뛰므로, 실제 관찰 근거가 있는 쪽이 이긴다.

마지막에 priority 내림차순 정렬 — 근거가 강한 대상부터 분석한다. 예산이
중간에 소진돼도 중요한 것부터 처리된 상태가 된다.

---

## 5. 3단계 — ANALYZE: 실제로 확인하기

여기가 핵심이다. XSS를 예로 든다 — [xss_analysis.py](src/hacklipse/adapters/xss_analysis.py)

### 5.1 Analyzer는 실행 능력이 없다

[xss_analysis.py:35-46](src/hacklipse/adapters/xss_analysis.py#L35-L46)

```python
def __init__(
    self,
    *,
    candidate_store: CandidateStore,
    surface_store: SurfaceStore,
    evidence_store: EvidenceStore,
    id_factory: Callable[[], str] | None = None,
) -> None:
```

**주입받는 게 Store 3개뿐이다.** `RuntimeEvidenceCollector`도 `ExecutionRuntime`도
없다. Analyzer가 `urlopen`을 부르고 싶어도 부를 객체가 없다.
이건 규율이 아니라 **구조적 불가능**이다.

비교하면 [recon.py:125-137](src/hacklipse/adapters/recon.py#L125-L137)의 Recon은
`collector`를 받는다. Recon은 Orchestrator가 직접 지시한 최초 1회 요청을
수행하는 특수 케이스이기 때문이다. Analysis/Validation은 아니다.

### 5.2 사전 검증

[xss_analysis.py:110-131](src/hacklipse/adapters/xss_analysis.py#L110-L131)

```python
def _resolve_task(self, task) -> tuple[Candidate, Surface, tuple[str, ...]]:
    if task.candidate_id is None or task.surface_id is None or task.target_url is None:
        raise AgentContractError("xss analysis task is missing candidate or surface context")
    if XSS_ANALYSIS_TOOL not in task.allowed_tools:
        raise AgentContractError("xss analysis HTTP tool is not allowed by the task")

    candidate = self._candidates.get(task.run_id, task.candidate_id)
    if candidate.vulnerability_type != "XSS":
        raise AgentContractError("heuristic XSS analyzer received a non-XSS candidate")
    if candidate.surface_id != task.surface_id:
        raise AgentContractError("xss candidate and task reference different surfaces")

    surface = self._surfaces.get(task.run_id, task.surface_id)
    if surface.url != task.target_url:
        raise AgentContractError("xss analysis task target does not match its surface")
    if surface.method.upper() != "GET" or not surface.parameters:
        raise AgentContractError("xss baseline supports parameterized GET surfaces only")

    parameters = tuple(dict.fromkeys(surface.parameters))   # 중복 파라미터명 제거
    return candidate, surface, parameters
```

6중 확인이다. 특히 `surface.url != task.target_url` — Task가 지시한 대상과
Store에 저장된 Surface가 다르면 거부한다. **Task를 통해 다른 대상으로 요청을
유도하는 걸 막는다.**

마지막 줄은 `?a=1&a=2` 같은 중복 파라미터 이름을 하나로 접는다. 안 하면 같은
파라미터에 프로브를 두 번 보내게 된다.

### 5.3 요청 "계획"을 세운다

파라미터가 `name`, `q` 두 개면
[xss_analysis.py:139-168](src/hacklipse/adapters/xss_analysis.py#L139-L168)이
요청 3개를 만든다:

| # | 종류 | 쿼리 | 목적 |
|---|---|---|---|
| 1 | CONTROL | `?name=hacklipse-control&q=hacklipse-control` | 기준선 |
| 2 | PROBE | `?name=hacklipse7331&q=hacklipse-control` | `name` 검사 |
| 3 | PROBE | `?name=hacklipse-control&q=hacklipse7331` | `q` 검사 |

```python
for parameter in parameters:
    requests.append(
        _request(
            surface.surface_id,
            tuple(
                (name, _REFLECTION_MARKER if name == parameter else _CONTROL_VALUE)
                for name in parameters
            ),
            HttpRequestKind.PROBE,
            reason=f"XSS baseline reflection probe for parameter {parameter} ...",
        )
    )
```

**파라미터마다 하나씩만 마커를 바꾼다.** 전부 동시에 넣으면 어느 파라미터가
반사됐는지 구분할 수 없다. 파라미터 N개면 요청은 N+1개(control 1 + probe N).

### 5.4 마커는 페이로드가 아니다

[xss_analysis.py:23-25](src/hacklipse/adapters/xss_analysis.py#L23-L25)

```python
XSS_ANALYSIS_TOOL = "http_get"
_CONTROL_VALUE = "hacklipse-control"
_REFLECTION_MARKER = "hacklipse7331"
```

`<script>alert(1)</script>`가 **아니다.** 우연히 나올 리 없는 고유 문자열이다.

| 항목 | 페이로드 방식 | 마커 방식 (현재) |
|---|---|---|
| 대상 상태 변경 | 가능 (저장형 XSS면 DB에 남음) | 없음 |
| WAF 반응 | 차단·경보 발생 | 안 걸림 |
| 증명하는 것 | "실행됐다" | "입력이 출력으로 샜다" |
| 오탐 | 필터 우회 여부에 따라 흔들림 | 문자열 일치, 결정적 |

**"입력이 출력에 반사된다"는 XSS의 필요조건이다.** 이것만으로 취약점을 확정할
수는 없지만(그건 4단계), 반사가 없으면 XSS도 없다. 대상을 건드리지 않고
필요조건만 결정적으로 확인하는 방식이다.

글로벌 규칙(CLAUDE.md §6 "Minimum-Impact PoC")의 *"benign marker를 쓸 것"*이
그대로 반영돼 있다.

### 5.5 요청을 반환하고 멈춘다

[xss_analysis.py:48-71](src/hacklipse/adapters/xss_analysis.py#L48-L71)

```python
def handle(self, task: TaskEnvelope) -> AgentResult:
    candidate, surface, parameters = self._resolve_task(task)
    requests = self._requests(candidate, surface, parameters)
    evidence = tuple(self._evidence.get_many(task.run_id, task.evidence_ids))
    collected = tuple(
        _matching_evidence(evidence, surface.url, request) for request in requests
    )
    missing = tuple(
        request for request, item in zip(requests, collected) if item is None
    )

    if missing:
        if task.request_budget < len(missing):
            raise AgentContractError(
                "xss baseline lacks budget for its remaining evidence requests"
            )
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.NEEDS_EVIDENCE,     # "못 끝냈다"
            evidence_requests=missing,                    # "이거 대신 보내주세요"
            candidate_ids=(candidate.candidate_id,),
        )
```

**같은 `handle()`이 두 번 불린다.** 첫 호출에서는 Evidence가 없으니 전부
`missing`이고, `NEEDS_EVIDENCE`를 반환한다. Orchestrator가 수집한 뒤 다시
부르면 `missing`이 비고 판정으로 넘어간다. 상태를 Agent 안에 들고 있지 않고
매번 Store에서 재구성하기 때문에 가능한 구조다 — 그래서 중간에 죽어도 재개된다.

62-65줄의 예산 자기검열도 눈여겨볼 것. 요청 개수가 남은 예산을 넘으면 아예
시작하지 않는다. 절반만 보내고 중간에 예산이 떨어지면 control 없이 probe만
있는 상태가 되어 판정이 불가능해진다.

### 5.6 Orchestrator가 검사하고 실행한다

[orchestrator.py:219-241](src/hacklipse/application/orchestrator.py#L219-L241)

```python
# Agent는 실행하지 않고 요청만 반환한다. 실제 실행은 중앙 수집 Task가 맡는다.
for request in result.evidence_requests:
    if request.surface_id != candidate.surface_id:
        raise AgentContractError(
            "analysis evidence request references a different surface"      # 221-224
        )
    if request.suggested_tool not in task.allowed_tools:
        raise AgentContractError(
            "analysis requested a tool that is not allowed by its task"     # 225-228
        )
    collection_task = self._task_factory.evidence_collection(
        current, candidate, request,
        target_url=surface.url,                    # ← Store의 Surface URL을 쓴다
        agent_type=self._config.evidence_collector_agent_type,
        request_budget=self._budget.remaining(run.run_id),
    )
    collection = self._tasks.execute(collection_task)
    self._require_completed(collection, "evidence collection")
    current = self._merge_agent_result(current, collection)
    candidate = candidate.add_evidence(collection.new_evidence_ids)
    self._candidates.save(candidate)
```

**221-228줄이 이 프로젝트에서 제일 중요한 8줄이다.**

Analyzer가 "다른 Surface를 찔러보겠다"거나 "`http_post`를 쓰겠다"고 하면 그
자리에서 터진다. 지금은 결정적 코드라 그럴 일이 없지만 —
**Task 7에서 여기에 LLM이 들어와도 이 8줄은 그대로 있다.** LLM이 만든 요청이
검사 없이 나가는 구간이 생기지 않는다. 이게 Phase 6 전에 이 구조를 만들어둔
이유다.

`target_url`도 Agent가 준 게 아니라 Store에서 읽은 `surface.url`을 쓴다
(232줄). Agent는 어디로 보낼지 정할 수 없다. **뭘 보낼지만 제안한다.**

반복 상한은 [orchestrator.py:192](src/hacklipse/application/orchestrator.py#L192):

```python
for evidence_round in range(self._config.max_evidence_rounds + 1):
```

기본 `max_evidence_rounds=1`
([orchestrator.py:55](src/hacklipse/application/orchestrator.py#L55))이므로
최대 2회다. 소진되면
[orchestrator.py:216-217](src/hacklipse/application/orchestrator.py#L216-L217)에서
에러. **무한 루프가 불가능하다.**

### 5.7 요청 명세도 검증된다

Agent가 `EvidenceRequest`에 담는 `HttpRequestSpec`은 생성 시점에 검증된다 —
[models.py:157-177](src/hacklipse/domain/models.py#L157-L177)

```python
def __post_init__(self) -> None:
    if not self.method or _HTTP_METHOD.fullmatch(self.method) is None:
        raise DomainInvariantError("HTTP method must be a valid token")
    ...
    for name, value in self.headers:
        lowered = name.casefold()
        if not name or _HTTP_METHOD.fullmatch(name) is None:
            raise DomainInvariantError("HTTP header name must be a valid token")
        if lowered in _FORBIDDEN_REQUEST_HEADERS:
            raise DomainInvariantError(f"HTTP header is controlled by the runtime: {name}")
        if "\r" in value or "\n" in value:
            raise DomainInvariantError("HTTP header value cannot contain line breaks")
```

금지 헤더 목록 — [models.py:79-92](src/hacklipse/domain/models.py#L79-L92):

```python
_FORBIDDEN_REQUEST_HEADERS = frozenset({
    "accept-encoding", "authorization", "connection", "content-length",
    "cookie", "host", "proxy-authorization", "proxy-connection",
    "transfer-encoding", "user-agent",
})
```

| 헤더 | 막는 이유 |
|---|---|
| `host` | 스코프 검사를 URL로 했는데 Host 헤더로 다른 서버를 노림 |
| `cookie`, `authorization` | 자격증명이 Agent 명세를 통해 흘러다니는 걸 차단 |
| `accept-encoding`, `user-agent` | Runtime의 안전·식별 경계. 덮어쓰기 금지 |
| `content-length`, `transfer-encoding` | HTTP request smuggling |
| `proxy-*` | 프록시 우회 |

그리고 `\r`/`\n` 차단은 **CRLF 인젝션**(헤더 값에 개행을 넣어 헤더나 본문을
추가로 주입)을 막는다.

같은 검증이 `ExecutionRequest`에서 한 번 더 돈다 —
[models.py:453-461](src/hacklipse/domain/models.py#L453-L461):

```python
def __post_init__(self) -> None:
    # Runtime 직전 객체도 동일한 명세 검증을 통과시켜 직접 생성 경로의 우회를 막는다.
    HttpRequestSpec(
        method=self.method, query_parameters=self.query_parameters,
        headers=self.headers, body=self.body, request_kind=self.request_kind,
    )
```

`HttpRequestSpec`을 거치지 않고 `ExecutionRequest`를 직접 만들어도 같은 검사를
받는다.

### 5.8 수집된 걸 다시 읽어서 판정

Orchestrator가 Analyzer를 **다시 호출**한다. 이번엔 Evidence가 채워져 있다.

[xss_analysis.py:191-207](src/hacklipse/adapters/xss_analysis.py#L191-L207)

```python
def _matching_evidence(evidence, target_url, request) -> Evidence | None:
    if request.http_request is None:
        return None
    expected_url = _resolved_url(target_url, request.http_request.query_parameters)
    expected_kind = request.http_request.request_kind.value
    for item in reversed(evidence):                  # 최신 것부터
        observation = item.observation
        if (
            item.created_by.startswith("execution_runtime:")     # 중앙 수집분만
            and observation.get("requested_url") == expected_url
            and observation.get("request_kind") == expected_kind  # control/probe
            and str(observation.get("method", "GET")).upper() == "GET"
        ):
            return item
    return None
```

`reversed()`로 도는 이유는 재실행 시 같은 URL의 Evidence가 여러 개 있을 수 있고,
**최신 것을 써야** 하기 때문이다.

`requested_url` 계산은 [xss_analysis.py:210-218](src/hacklipse/adapters/xss_analysis.py#L210-L218)이
Collector 쪽 `resolved_url` ([models.py:464-474](src/hacklipse/domain/models.py#L464-L474))과
같은 로직을 쓴다 — 기존 쿼리를 보존하면서 새 파라미터를 `&`로 이어붙이고,
fragment는 버린다(HTTP 요청 대상에 포함되지 않으므로).

### 5.9 반사 판정

[xss_analysis.py:242-249](src/hacklipse/adapters/xss_analysis.py#L242-L249)

```python
def _is_reflected(control_body: str | None, probe_body: str | None) -> bool:
    """고정 marker가 control에는 없고 probe에는 있을 때만 반사로 인정한다."""
    return bool(
        probe_body is not None
        and _REFLECTION_MARKER in probe_body
        and (control_body is None or _REFLECTION_MARKER not in control_body)
    )
```

**control 비교가 왜 필요한가:** 페이지가 원래부터 `hacklipse7331`을 갖고 있다면
(캐시된 이전 요청, 로그 표시, 에러 메시지 등) probe만 봐서는 반사인지 구분이
안 된다. control은 그 오탐을 잡는 장치다. **A/B 대조 실험의 축소판이다.**

반사가 확인되면 새 Evidence를 남긴다 —
[xss_analysis.py:85-101](src/hacklipse/adapters/xss_analysis.py#L85-L101):

```python
observation={
    "type": "reflection",
    "parameter": parameter,
    "control_evidence_id": control.evidence_id,     # 근거 ①
    "probe_evidence_id": probe.evidence_id,         # 근거 ②
}
```

**"XSS다"가 아니라 "반사됐다"만 쓴다.** 그리고 그 판단의 원본 증거 2개 ID를
같이 남긴다. 나중에 누구든 되짚어서 원본 응답 본문을 확인할 수 있다.

[xss_analysis.py:226-239](src/hacklipse/adapters/xss_analysis.py#L226-L239)의
`_has_reflection()`은 같은 (파라미터, control ID, probe ID) 조합의 Evidence가
이미 있으면 중복 기록하지 않는다. 재개 시 Evidence가 불어나지 않는다.

---

## 6. 4단계 — VALIDATE: 안 믿고 다시 확인

### 6.1 Validator는 Analyzer의 결론을 못 본다

[task_factory.py:51-71](src/hacklipse/application/task_factory.py#L51-L71)

```python
def validation(self, run, candidate, *, validation_id, agent_type, request_budget):
    """Candidate/Evidence 참조만 전달하는 Validation Task를 생성한다."""
    return self._base(
        run,
        agent_type=agent_type,
        request_budget=request_budget,
        surface_id=candidate.surface_id,
        candidate_id=candidate.candidate_id,
        evidence_ids=candidate.evidence_ids,     # ← ID만. 본문 없음
        allowed_tools=("http_get",),
        validation_id=validation_id,             # ← 이번 세션 ID
    )
```

Analysis Task([task_factory.py:30-49](src/hacklipse/application/task_factory.py#L30-L49))와
비교하면 **`target_url`이 빠져 있다.** Validator는 대상 URL조차 Task로 받지 않고
Store에서 직접 읽어야 한다.

`candidate.hypothesis`(Analyzer의 가설 문장)도 안 실린다.
[validation.py:21-23](src/hacklipse/adapters/validation.py#L21-L23) 주석이
명시한다 — *"Analysis Agent의 자유 서술 결론(hypothesis)은 여기서도 참고하지
않는다."*

노션 §10 "Validation 독립성"의 코드 형태다. **Validator가 Analyzer에 동조할
경로 자체를 없앤다.**

### 6.2 세션 ID 발급

[orchestrator.py:254-255](src/hacklipse/application/orchestrator.py#L254-L255)

```python
validation = None
validation_id = f"validation-{self._id_factory()}"      # Candidate마다 새로 발급
```

이 ID가 [orchestrator.py:313](src/hacklipse/application/orchestrator.py#L313)에서
Evidence 수집 Task에 실리고, Collector가
[execution.py:94](src/hacklipse/application/execution.py#L94)에서 Evidence에
각인한다.

### 6.3 인정 조건 — 4중 필터

[validation.py:134-140](src/hacklipse/adapters/validation.py#L134-L140)

```python
def _is_reproduction_evidence(evidence: Evidence, validation_id: str) -> bool:
    return bool(
        evidence.validation_id == validation_id                     # ① 이번 세션 것
        and evidence.source_task_id is not None                     # ② 추적 가능
        and evidence.created_by.startswith("execution_runtime:")    # ③ 중앙 수집분
        and str(evidence.observation.get("type")) in _REPRODUCTION_EVIDENCE_TYPES  # ④
    )
```

| 필터 | 탈락하는 것 |
|---|---|
| ① `validation_id` 일치 | 이전 Validation 세션의 응답, Analysis가 만든 응답(`validation_id=None`) |
| ② `source_task_id` 존재 | 출처 추적이 안 되는 Evidence |
| ③ `execution_runtime:` 접두사 | Agent가 만든 Evidence (`heuristic_xss_analyzer`, `recon`) |
| ④ 응답 유형 | Recon의 구조 관찰(`url_or_file_parameter`) |

**Analysis가 방금 받아온 200 OK 응답도 인정 안 된다.**
Validator는 반드시 자기 세션에서 다시 쏴봐야 한다.

[validation.py:26-29](src/hacklipse/adapters/validation.py#L26-L29) 주석이
설명한다 — *"최초 Recon이 남긴 신호 관측과는 구분되는, Validator 자신이 직접
수행을 요청한 독립적인 재요청의 결과만 재현 근거로 인정한다."*

이 동작은 [test_validation.py:167-179](tests/test_validation.py#L167-L179)에서
직접 검증된다 — 다른 세션 ID의 200 응답을 넣고 `NEEDS_EVIDENCE`가 나오는지 확인.

### 6.4 판정 — 그리고 왜 CONFIRMED가 없는가

[validation.py:82-111](src/hacklipse/adapters/validation.py#L82-L111)

```python
def _decide(self, task, reproduction) -> AgentResult:
    """범용 HTTP 상태 대신 세션 실행 가능 여부만 보수적으로 판정한다."""
    latest = reproduction[-1]
    status = latest.observation.get("status")
    blocked = latest.observation.get("type") == "http_error"
    validation = ValidationResult(
        ...
        verdict=(ValidationVerdict.BLOCKED if blocked else ValidationVerdict.SUSPECTED),
        reason=(... "but no vulnerability-specific proof was produced"),
        reproduction_count=len(reproduction),
    )
```

**200 OK든 404든 500이든 전부 `SUSPECTED`다.**

이전 버전에는 2xx/3xx면 `CONFIRMED`를 주는 코드가 있었는데 삭제됐다.
HTTP 상태 코드는 취약점의 증거가 아니기 때문이다 — 정상 페이지도 200을 준다.
`test_http_status_alone_never_confirms_or_rejects`
([test_validation.py:140-150](tests/test_validation.py#L140-L150))가 이 성질을
고정한다.

`BLOCKED`는 "취약하지 않다"가 아니라 **"확인할 수 없었다"**다. 연결 거부·타임아웃
같은 상황을 안전 판정으로 오독하지 않게 유형을 분리했다.

### 6.5 CONFIRMED의 조건 — 3중 관문

**관문 1 — 도메인 불변식** [models.py:344-353](src/hacklipse/domain/models.py#L344-L353)

```python
if self.verdict is ValidationVerdict.CONFIRMED:
    if self.proof is None:
        raise DomainInvariantError("confirmed validation requires vulnerability-specific proof")
    if not set(self.proof.evidence_ids).issubset(self.evidence_ids):
        raise DomainInvariantError("validation proof evidence must be included in validation evidence")
```

`ValidationProof` 없이 `CONFIRMED`인 객체는 **생성 자체가 불가능하다.**
proof가 인용한 Evidence는 판정이 인용한 Evidence의 부분집합이어야 한다 —
proof만 아는 비밀 증거를 못 만든다.

`ValidationProof` 자체도 검증된다
([models.py:314-320](src/hacklipse/domain/models.py#L314-L320)) — 구조화된
`ValidationProofType`이어야 하고, Evidence를 참조해야 하고, 재현된 효과를
설명해야 한다.

**관문 2 — Orchestrator 재검사** [orchestrator.py:385-419](src/hacklipse/application/orchestrator.py#L385-L419)

```python
evidence = self._evidence.get_many(run.run_id, validation.evidence_ids)
if validation.reproduction_count != len(evidence):
    raise AgentContractError("validation reproduction count does not match its evidence")
for item in evidence:
    if item.validation_id != expected_validation_id:
        raise AgentContractError("... evidence from another provenance")
    if not item.created_by.startswith("execution_runtime:"):
        raise AgentContractError("... must reference centrally collected runtime evidence")
    if item.source_task_id is None:
        raise AgentContractError("... missing its collection task provenance")
    if item.surface_id != candidate.surface_id:
        raise AgentContractError("... evidence from another surface")

if validation.verdict is ValidationVerdict.CONFIRMED:
    expected_proof = _PROOF_TYPE_BY_VULNERABILITY.get(candidate.vulnerability_type)
    if expected_proof is None or validation.proof is None:
        raise AgentContractError("confirmed validation has no supported vulnerability proof")
    if validation.proof.proof_type is not expected_proof:
        raise AgentContractError("validation proof type does not match the candidate vulnerability")
```

**Validator가 인용한 Evidence를 하나하나 다시 조회해서 재검사한다.**
Validator의 자기 신고를 믿지 않는다. `reproduction_count`가 실제 Evidence 개수와
다르면 거부 — 숫자를 부풀릴 수 없다.

취약점 유형 대응표는
[orchestrator.py:38-44](src/hacklipse/application/orchestrator.py#L38-L44):

```python
_PROOF_TYPE_BY_VULNERABILITY = {
    "XSS":            ValidationProofType.XSS_EXECUTION,
    "SQLi":           ValidationProofType.SQLI_EFFECT,
    "Access Control": ValidationProofType.UNAUTHORIZED_OBJECT_ACCESS,
    "Path Traversal": ValidationProofType.PATH_TRAVERSAL_FILE_READ,
    "SSTI":           ValidationProofType.SSTI_EXECUTION,
}
```

XSS Candidate에 `sqli_effect` proof를 붙이면 거부된다.

**관문 3 — Finding 생성 팩토리** [models.py:379-410](src/hacklipse/domain/models.py#L379-L410)

```python
@classmethod
def from_confirmed(cls, *, finding_id, candidate, validation) -> Finding:
    if validation.verdict is not ValidationVerdict.CONFIRMED:
        raise DomainInvariantError("only confirmed validation can create a finding")
    if candidate.run_id != validation.run_id:
        raise DomainInvariantError("candidate and validation must belong to the same run")
    if validation.candidate_id != candidate.candidate_id:
        raise DomainInvariantError("validation must refer to the candidate")
    if not validation.evidence_ids:
        raise DomainInvariantError("confirmed validation must reference evidence")
```

Finding으로 승격되는 유일한 경로다
([orchestrator.py:327-335](src/hacklipse/application/orchestrator.py#L327-L335)).
`Finding` 자체도 `__post_init__`에서 verdict가 CONFIRMED인지 다시 확인한다
([models.py:371-376](src/hacklipse/domain/models.py#L371-L376)).

---

## 7. 5단계 — REPORT

[orchestrator.py:341-355](src/hacklipse/application/orchestrator.py#L341-L355)

```python
def _report(self, run: Run) -> Run:
    existing = self._reports.list_by_run(run.run_id)
    if existing:                       # 재개 시 보고서를 두 번 만들지 않는다
        return run.with_updates(report_ids=tuple(i.report_id for i in existing))
    task = self._task_factory.report(run, agent_type=self._config.report_agent_type)
    result = self._tasks.execute(task)
    ...
    for report in result.reports:
        if report.run_id != run.run_id:
            raise AgentContractError("report belongs to another run")
```

Report Task는 [task_factory.py:99-107](src/hacklipse/application/task_factory.py#L99-L107)에서
`finding_ids`와 `request_budget=0`만 받는다. **예산이 0이라 요청을 보낼 수 없다.**

[reporting.py:26-49](src/hacklipse/adapters/reporting.py#L26-L49)

```python
def handle(self, task: TaskEnvelope) -> AgentResult:
    # Report Agent는 Candidate를 다시 판단하지 않고 Finding Store만 읽는다.
    findings = [
        self._findings.get(task.run_id, finding_id) for finding_id in task.finding_ids
    ]
    lines = ["# Security assessment report", "", f"Run: `{task.run_id}`", ""]
    if not findings:
        lines.append("No confirmed findings were produced.")
    for finding in findings:
        # 보고 전에 Finding이 참조하는 Evidence가 실제 Run에 존재하는지 확인한다.
        self._evidence.get_many(task.run_id, finding.evidence_ids)
        lines.extend([...])
```

Report Agent는 판단을 다시 하지 않는다. Finding Store만 읽고 렌더링한다.
38줄에서 Evidence 실재 여부를 다시 확인한다 — **존재하지 않는 증거를 인용하는
보고서가 나갈 수 없다.**

지금 돌리면 `"No confirmed findings were produced."`가 나온다.

---

## 8. 관통하는 설계 원칙 5가지

### ① 외부 실행은 단 하나의 경로

모든 요청이 [execution.py:73-75](src/hacklipse/application/execution.py#L73-L75)
세 줄을 통과한다.

```python
self._policy.validate_execution(run, request)   # 정책
self._budget.consume(run.run_id, 1)             # 예산
result = self._runtime.execute(request)         # 실행
```

기본 Runtime은 아무것도 안 한다 —
[runtime.py:7-15](src/hacklipse/adapters/runtime.py#L7-L15):

```python
class DisabledExecutionRuntime:
    """Runtime이 명시적으로 주입되기 전에는 모든 외부 실행을 거부한다."""
    def execute(self, request):
        raise ExternalExecutionDisabled(
            f"external execution is disabled (tool={request.tool}, run={request.run_id})"
        )
```

[bootstrap.py:86-87](src/hacklipse/bootstrap.py#L86-L87)에서 이게 기본값이다.
`HttpExecutionRuntime`을 명시적으로 주입해야만 네트워크를 친다.
**실수로 요청이 나가는 경로가 없다.**

### ② Agent는 제안하고 Orchestrator가 집행한다

| 주체 | 할 수 있는 것 | 할 수 없는 것 |
|---|---|---|
| Analysis/Validation Agent | `EvidenceRequest` 반환 | 요청 실행, 대상 URL 결정, 도구 선택 |
| Orchestrator | 검사 후 실행 지시 | 취약점 판단 |
| Collector | 정책·예산 확인 후 Runtime 호출 | 판단 |
| Runtime | HTTP 전송 | 판단 |

구조적 보장: Analyzer 생성자에 Collector/Runtime이 없다
([xss_analysis.py:35-46](src/hacklipse/adapters/xss_analysis.py#L35-L46),
[validation.py:40-47](src/hacklipse/adapters/validation.py#L40-L47)).

### ③ 관찰과 주장을 분리한다

| 관찰 (Evidence에 저장) | 주장 (별도 타입) |
|---|---|
| `{"type": "url_or_file_parameter", "parameter": "page"}` | `Candidate.hypothesis` |
| `{"type": "reflection", "parameter": "name", ...}` | `ValidationResult.verdict` |
| `{"type": "http_response", "status": 200, "body": ...}` | `Finding` |

Evidence에는 사실만 들어간다. 판단은 Candidate/ValidationResult/Finding에
따로 담기고, 각각 자기가 근거로 삼은 Evidence ID를 반드시 들고 있다.

### ④ 모든 조회는 Run 범위

Store Protocol의 모든 메서드가 `run_id`를 첫 인자로 받는다
([ports/repositories.py](src/hacklipse/ports/repositories.py)).

```python
self._surfaces.get(run.run_id, candidate.surface_id)
self._evidence.get_many(task.run_id, task.evidence_ids)
self._candidates.get(run.run_id, candidate_id)
```

다른 Run의 데이터를 실수로 읽을 수 없다. Run 간 오염이 타입 수준에서 막힌다.

### ⑤ 증적은 추가만 된다

`EvidenceStore` Protocol에 `update`/`delete`가 없다. `append`와 조회뿐이다.
`Evidence`는 `frozen=True`라 만든 뒤 필드를 못 바꾼다.
SQLite 스키마([sqlite_store.py](src/hacklipse/adapters/sqlite_store.py))에도
UPDATE 경로가 없다.

**한 번 관측된 사실은 나중에 불편해져도 사라지지 않는다.**

---

## 9. 지금 Finding이 0개인 이유

마일스톤 A를 로컬 대상에 돌리면 결과는 이렇다:

```
Surface       발견됨
Candidate     생성됨
reflection    탐지됨 (XSS 반사가 있는 경우)
Validation    전부 SUSPECTED
Finding       0개
Report        "No confirmed findings were produced."
```

**버그가 아니다.** `CONFIRMED`에는 `ValidationProof`가 필요한데
([models.py:345-347](src/hacklipse/domain/models.py#L345-L347)), 그걸 만드는
코드가 아직 없다. 그게 Task 7의 범위다.

이건 *"증명하지 못하면 확정하지 않는다"*를 코드로 강제한 결과다.
자동화 도구가 200 OK 하나로 "취약점 발견!"을 외치는 것과 정반대 방향이다.

### 연구 비교축에 미치는 영향

마일스톤 A vs B를 "Finding 개수"로 비교할 수 없다. A는 항상 0이다.

**대신 쓸 수 있는 지표:**

| 지표 | 출처 |
|---|---|
| 발견한 Surface 수 | `surfaces.list_by_run()` |
| 생성한 Candidate 수 / 유형 분포 | `candidates.list_by_run()` |
| `reflection` 신호 수 | Evidence 중 `type == "reflection"` |
| 총 HTTP 요청 수 | `budget` 소비량 |
| 신호 1개당 요청 수 (효율) | 위 둘의 비 |
| 반복 라운드 소진 횟수 | Task 실패 로그 |

Task 8의 baseline 비교 작업에서 이 지표들을 수집하는 게 실제 할 일이다.

---

## 부록 — 관련 파일

| 역할 | 파일 |
|---|---|
| 워크플로 통제 | [orchestrator.py](src/hacklipse/application/orchestrator.py) |
| 단계 전이 규칙 | [state_machine.py](src/hacklipse/application/state_machine.py) |
| 외부 실행 경계 | [execution.py](src/hacklipse/application/execution.py) |
| Task 생성 | [task_factory.py](src/hacklipse/application/task_factory.py) |
| Task 실행·재시도 | [task_executor.py](src/hacklipse/application/task_executor.py) |
| 데이터 타입·불변식 | [models.py](src/hacklipse/domain/models.py) |
| 정찰 | [recon.py](src/hacklipse/adapters/recon.py) |
| 라우팅 | [routing.py](src/hacklipse/adapters/routing.py) |
| XSS 분석 | [xss_analysis.py](src/hacklipse/adapters/xss_analysis.py) |
| 검증 | [validation.py](src/hacklipse/adapters/validation.py) |
| HTTP 전송 | [http_runtime.py](src/hacklipse/adapters/http_runtime.py) |
| 정책 | [policy.py](src/hacklipse/adapters/policy.py) |
| 보고 | [reporting.py](src/hacklipse/adapters/reporting.py) |
| 조립 | [bootstrap.py](src/hacklipse/bootstrap.py) |

### 대상 범위 (계획서)

Phase 3부터 실제 요청이 나간다. 초기 대상은 **로컬 컨테이너(DVWA / juice-shop)로
한정**하고 `RunScope.allowed_hosts`를 `localhost`로 고정한다. 실서비스나 외부
대상으로 옮기려면 그 대상에 대한 별도 인가 확인이 선행되어야 한다.
