# Router LLM 적용 작업 기록

Notion 「2026 연구과제 / Agent별 LLM 역할」 §4 Vulnerability Router가 정의한
"규칙 기반 우선 + LLM 보조" Hybrid Routing 구현 기록이다.

추적 이슈: [#24](https://github.com/Hacklipse/LASP_2026/issues/24)

| 브랜치 | 역할 | 상태 |
| --- | --- | --- |
| `feat/hybrid-router-integration` | D — Rule 우선 병합, 배선 | 1단계 완료 |
| `feat/llm-router-advisor` | C — LLM 답 검증·정규화 | 1단계 완료 |

배선(`standard_router`)은 C의 구현체를 조립하는 작업이라 의존 방향상 C 커밋 위에 올렸다.

3단계 Juice Shop E2E까지 완료했다. 이슈 #24의 완료 기준을 모두 충족한다.

---

## D 1단계 — 계약 확정 (2026-09-10)

**분기점** `dev/dmswls` (`baf2a0c`)

### 1. 작업 목적

Hybrid Routing 중 **통합 계층**을 구현한다. 실제 LLM 호출은 C 브랜치가 맡으므로,
D는 Advisor가 붙을 자리와 계약만 만든다.

이 단계에 LLM 코드는 들어가지 않는다. 목표는 두 가지다.

1. C가 구현할 인터페이스를 확정한다
2. `advisor=None`일 때 기존 동작이 완전히 보존됨을 테스트로 잠근다

C보다 D를 먼저 진행한 이유는 D가 정하는 Protocol이 C의 계약이기 때문이다. 순서가
반대이면 C는 인터페이스를 추측해서 구현하게 되고 재작업이 발생한다.

### 2. 선행 결정

**Advisor의 반환 타입을 제안 목록으로 정했다.** Advisor는 Candidate를 만들지 않는다.
`candidate_id` 부여, priority 결정, 저장은 모두 Router와 Orchestrator에 남는다.

이 방식을 택한 이유는 두 가지다. Advisor가 잘못된 값을 내놓아도 Router가 마지막
관문에서 한 번 더 거를 수 있다. 그리고 C와 D의 책임 경계가 명확히 갈린다. 선례인
`llm_recon_planner`도 같은 구조이며, Planner는 순서만 반환하고 Surface 생성은
`recon.py`가 담당한다.

### 3. 구현 내용

#### 3.1 계약 정의

`adapters/routing.py`에 `RouteSuggestion`과 `RouterAdvisor` Protocol을 추가했다.

```python
@dataclass(frozen=True, slots=True)
class RouteSuggestion:
    surface_id: str
    vulnerability_type: str
    agent_type: str
    reason: str = ""

class RouterAdvisor(Protocol):
    def advise(self, run, surfaces, evidence,
               routed: frozenset[tuple[str, str]]) -> Sequence[RouteSuggestion]: ...
```

`evidence_ids` 필드를 의도적으로 두지 않았다. Advisor의 판단은 관측(Observation)이
아니라 주장(Claim)이므로, 자기가 보지 않은 Evidence를 근거로 달 수 없다. 세부구현 §7의
Observation·Claim 분리 원칙을 타입 수준에서 강제한 것이다.

`reason`은 Evidence 기록용이며 TaskEnvelope로 전달하지 않는다. 다른 Agent의 장문
추론을 Task에 싣지 않는다는 §5 계약 때문이다.

네 번째 인자 `routed`는 규칙이 이미 결정한 `(surface_id, vulnerability_type)` 조합이다.
구현체가 중복 제안을 피하는 데 사용하며, 제안하더라도 Router가 규칙 결정을 유지한다.

Protocol을 C의 파일이 아니라 D의 파일에 둔 이유는 C의 파일이 아직 없는 상태에서 D가
작업을 시작해야 하기 때문이다. C는 `from hacklipse.adapters import RouterAdvisor,
RouteSuggestion`으로 가져다 쓴다.

#### 3.2 병합 구조

`route()`에 3단계를 추가했다. 순서는 Evidence 규칙 → Surface 규칙 → Advisor다.

기존 두 단계와 동일하게 `if key in decided: continue`로 양보하므로, **"LLM이 Rule을
덮어쓰지 않는다"가 검사 한 줄이 아니라 병합 순서 자체로 보장된다.** 조건문을 실수로
지우는 방식으로는 이 불변식이 깨지지 않는다.

#### 3.3 우선순위

`ADVISOR_PRIORITY = 0.15`로 고정했다. 현재 규칙 최저값은 SSTI 탐색의 0.20이다.

priority는 정렬에만 쓰이는 값이 아니라 예산이 모자랄 때 무엇을 포기하는지에 대한
결정이다. 따라서 설명 가능한 규칙 판정이 LLM 제안 때문에 잘려서는 안 된다.

#### 3.4 검증 관문

`_advisor_decisions()`가 제안마다 여섯 가지를 확인한다. 모든 위반은 **항목 단위로
폐기하며 Run을 중단시키지 않는다.**

| 검사 | 근거 |
| --- | --- |
| `RouteSuggestion` 타입인가 | 구조 오염 차단 |
| Surface가 현재 Run에 존재하는가 | Run 격리 |
| `(유형, agent_type)`이 허용 목록에 있는가 | 미등록 agent는 `AgentUnavailable`을 유발한다 |
| 상태 변경 파라미터가 아닌가 | 비밀번호 변경·삭제 폼 차단 |
| fragment와 client_route가 일치하는가 | SPA 라우트를 HTTP Analyzer로 보내는 예산 낭비 차단 |
| 이미 결정된 키가 아닌가 | 규칙 우선 |

Orchestrator의 `_route()`에도 Run 격리 검사가 있으나, 위반 시 `AgentContractError`로
Run 전체가 실패한다. Advisor가 한 번 헛짚었다고 나머지 검사까지 버릴 이유가 없으므로
항목 위반은 Router에서 먼저 걸러낸다. `llm_recon_planner`가 구조 위반과 항목 위반을
나눠 다루는 것과 같은 이유다.

**허용 목록을 별도로 만들지 않고 규칙 목록에서 도출했다.**

```python
self._allowed_pairs = frozenset(
    (rule.vulnerability_type, rule.agent_type)
    for rule in (*rules, *surface_rules)
)
```

이렇게 하면 `standard_router()`의 `--vuln` 필터와 `IMPLEMENTED_ANALYZERS` 필터가
자동으로 상속된다. 목록을 두 벌 관리하면 어긋나는 순간 Dispatcher가 Run을 실패시킨다.

#### 3.5 실패 처리

Advisor 호출을 `try/except Exception`으로 감쌌다. LLM 장애가 곧 Run 실패가 되어서는
안 되기 때문이다. 예외가 발생하면 빈 결과를 반환하고 규칙 결정만으로 진행한다.

### 4. 테스트

`tests/test_routing.py`에 `AdvisorRoutingTests` 8개를 추가했다.

| 테스트 | 검증 대상 |
| --- | --- |
| `test_absent_advisor_produces_the_same_result_as_before` | `advisor=None` 동일성 |
| `test_advisor_fills_only_the_type_rules_left_empty` | 빈 자리만 채움, priority, `evidence_ids` 없음, `routed` 전달 |
| `test_advisor_cannot_overwrite_a_rule_decision` | 규칙 판정 보존 |
| `test_advisor_failure_still_returns_the_rule_decisions` | 예외 시 완주 |
| `test_unregistered_agent_suggestion_is_dropped_item_by_item` | 미등록 agent만 폐기, 유효 제안은 생존 |
| `test_suggestion_for_another_run_surface_is_dropped` | Run 격리 |
| `test_advisor_cannot_bypass_the_state_changing_form_guard` | 안전 필터 우회 불가 |
| `test_http_agent_is_not_given_a_client_route_surface` | fragment 표면 차단 |

대역으로 `_StubAdvisor`와 `_RaisingAdvisor`를 두었다. LLM도 API 키도 필요하지 않다.

### 5. 결과

```plain text
Ran 437 tests — OK
```

| | 테스트 |
| --- | --- |
| 작업 전 기준선 (`baf2a0c`) | 429 |
| 작업 후 | 437 |
| 신규 | 8 |
| 회귀 | 0 |

기존 429개가 모두 통과하므로 규칙 동작에 변화가 없음이 확인된다.

**변경 파일**

- `src/hacklipse/adapters/routing.py` (+156)
- `tests/test_routing.py` (+207)
- `src/hacklipse/adapters/__init__.py` — `RouteSuggestion`·`RouterAdvisor` export

### 6. 미해결 사항

**Advisor의 Claim을 Evidence Store에 기록하는 경로가 아직 없다.**
`_advisor_decisions()`가 상태 문자열(`advisor_ok:accepted=2,rejected=1`)을 함께
반환하지만 현재 `route()`에서 폐기한다.

원인은 `_route()`가 Evidence를 읽기만 하고 쓰지 않으며, Router는 Agent가 아니라
TaskEnvelope도 `AgentResult`도 없다는 점이다. 기록 경로를 `RouteDecision` 확장으로
할지 Port 반환 타입 변경으로 할지 결정되지 않았다. 결정 후 한 줄 연결로 끝나도록
자리만 만들어 두었으며 코드에 주석으로 사유를 남겼다.

`AgentResultStatus.NEEDS_EVIDENCE`는 Agent 전용 흐름이므로 Router에는 적용하지 않는다.

### 7. 다음 단계

C가 `adapters/llm_router_advisor.py`에서 `RouterAdvisor`를 구현한다. Protocol이
확정됐으므로 D의 Evidence 기록·bootstrap 배선과 병렬로 진행 가능하다.

D의 후속 작업은 Evidence 기록 경로 결정과 `bootstrap.standard_router()`에 advisor
주입을 추가하는 것이다.

---

## C 1단계 — Advisor 구현 (2026-09-10)

**분기점** `dev/dmswls` (`baf2a0c`)
**선행** D 1단계의 `RouterAdvisor` Protocol

### 1. 작업 목적

D가 확정한 `RouterAdvisor` Protocol을 LLM으로 구현한다. 규칙이 분류하지 못한 Surface에
대해 "이 표면은 어떤 취약점 유형으로 볼 만한가"만 제안한다.

Advisor는 Candidate를 만들지 않고, Store에 쓰지 않으며, 외부 요청도 하지 않는다.
Router가 넘겨준 Surface와 Evidence를 읽고 제안 목록만 반환한다.

### 2. 선행 결정

**LLM이 `agent_type`을 고르지 않는다.** LLM이 고르는 것은 `surface_id`와
`vulnerability_type` 두 가지뿐이며, 담당 Agent는 표면 모양을 보고 Python이 해석한다.

XSS는 담당 Analyzer가 둘이다. 서버가 본문에 값을 돌려주는 반사는 `xss_analyzer`,
SPA의 DOM sink는 `browser_xss_analyzer`가 맡는다. 따라서 유형 이름만으로는 Agent를
정할 수 없고, fragment 여부라는 구조적 사실이 있어야 결정된다. 이 판단은 추측이 아니라
관측 가능한 사실이므로 LLM이 아니라 코드가 담당한다.

이 결정의 부수 효과로 **LLM이 미등록 `agent_type`을 만들어낼 경로 자체가 사라진다.**
제안 가능한 범위는 주입받은 `AnalyzerChoice` 목록으로 닫혀 있다.

### 3. 구현 내용

`adapters/llm_router_advisor.py`를 새로 만들었다. 구조는 `llm_recon_planner`를 따른다.

#### 3.1 제안 가능 범위

```python
@dataclass(frozen=True, slots=True)
class AnalyzerChoice:
    vulnerability_type: str
    agent_type: str
    client_route: bool = False
```

Advisor는 이 목록을 주입받고, `_resolve_agent()`가 유형과 fragment 여부로 Agent를
결정한다. 목록에 없는 유형이 제안되면 해석에 실패해 해당 항목이 폐기된다.

#### 3.2 제안 대상 선정

전체 Surface를 그대로 싣지 않는다. 두 단계로 줄인다.

- 상태를 바꾸는 폼은 제외한다. 규칙이 후보로 만들지 않는 표면은 물어볼 대상도 아니다
- 표면 모양에서 배정 가능한 유형을 규칙이 이미 전부 채웠으면 제외한다

남은 표면이 없으면 **LLM을 호출하지 않는다.** 물어볼 것이 없다는 사실은 결정적이므로
비용을 쓸 이유가 없다.

정렬은 규칙이 아무것도 만들지 못한 표면을 먼저 놓는다. 조용히 검사에서 빠지는 표면이
이 기능의 본래 대상이기 때문이다.

`DEFAULT_MAX_SURFACES = 40`으로 상한을 둔다. Juice Shop 실측 Surface가 140개이므로
상한이 없으면 프롬프트가 비대해지고 비용이 표면 수에 비례해 늘어난다. Router가 Run당
한 번만 호출하므로 이 상한이 곧 기능 전체의 비용 상한이다.

#### 3.3 프롬프트 위생

Surface 메타데이터와 구조화된 Observation 유형만 싣는다. 구체적으로는 `surface_id`,
메서드, path, client_route 여부, 파라미터 **이름**, 관측 유형 이름, 이미 채워진 유형이다.

`Surface.observed_query`에는 token 같은 실제 값이 담기므로 이름만 골라 쓴다. 전체 URL
대신 path만 사용해 query 값이 실리는 경로를 막는다. 응답 본문과 자격증명은 어느 것도
프롬프트에 들어가지 않는다.

#### 3.4 응답 검증

구조 위반과 항목 위반을 나눠 다룬다.

| 위반 | 처리 |
| --- | --- |
| 응답이 객체가 아님, `suggestions`가 배열이 아님 | 전체를 버리고 빈 제안 반환 |
| 제공하지 않은 `surface_id` | 해당 항목만 폐기 |
| 해석 불가능한 `vulnerability_type` | 해당 항목만 폐기 |
| 항목이 객체가 아니거나 필드 타입이 잘못됨 | 해당 항목만 폐기 |
| 이미 규칙이 채운 조합, 같은 응답 안의 중복 | 해당 항목만 폐기 |

`probing.py`의 `validate_probe_selection()`은 참고하지 않는다. 그 함수는 Analysis Agent가
실행 대상을 확정하는 계약이라 존재하지 않는 선택을 `AgentContractError`로 올리는 것이
맞다. 여기 선택은 실행 값이 아니라 검사 대상에 대한 제안이므로, 잘못된 개별 항목 때문에
나머지 유효한 제안까지 버릴 이유가 없다.

#### 3.5 실패 처리

`LlmTimeout`·`LlmTransportError`·`LlmResponseFormatError`·`LlmRefused`는 잡아서 빈 제안을
반환한다. Router가 다시 잡아 주지만, 여기서 먼저 처리해야 "왜 빈 제안인가"가 이 계층에
남는다.

`LlmCredentialsMissing`은 일부러 잡지 않는다. 키 없이 Advisor를 배선한 것은 실행 중
장애가 아니라 구성 오류이며, 조용히 규칙만 돌면 "LLM을 켰는데 규칙 결과가 나왔다"는
오독을 만든다. `llm_recon_planner`와 같은 기준이다.

### 4. 테스트

`tests/test_llm_router_advisor.py`에 20개를 추가했다. `llm_recon_planner`의 테스트 구성을
따라 여섯 그룹으로 나눴다.

| 그룹 | 개수 | 검증 대상 |
| --- | --- | --- |
| `ValidSuggestionTests` | 3 | 정상 제안, 표면 모양 기반 Agent 해석, 호출 생략 |
| `ItemViolationTests` | 6 | 없는 표면·유형, 중복, 형식 오류, client_route 불일치 |
| `StructuralViolationTests` | 3 | payload 구조 파괴 |
| `TransportFailureTests` | 2 | 복구 가능 실패 4종, 자격증명 누락 전파 |
| `OfferSelectionTests` | 3 | 상태 변경 폼 제외, 정렬 순서, 상한 |
| `PromptHygieneTests` | 2 | 필요한 메타데이터만 실림, 관측 값 미포함 |
| `RouterIntegrationTests` | 1 | 실제 Router에 꽂아 규칙 판정 보존 확인 |

대역으로 `_FakeLlmClient`와 `_RaisingLlmClient`를 두었다. API 키 없이 전부 실행된다.

### 5. 결과

```plain text
Ran 457 tests — OK
```

| | 테스트 |
| --- | --- |
| 기준선 (`baf2a0c`) | 429 |
| D 1단계 후 | 437 |
| C 1단계 후 | 457 |
| C 신규 | 20 |
| 회귀 | 0 |

**변경 파일**

- `src/hacklipse/adapters/llm_router_advisor.py` (신규)
- `tests/test_llm_router_advisor.py` (신규)

### 6. 미해결 사항

**`LlmCredentialsMissing`이 Router에서 흡수된다.** Advisor는 이 예외를 통과시키지만
`RuleBasedVulnerabilityRouter._advisor_decisions()`가 모든 예외를 잡으므로 실제로는
규칙만으로 조용히 진행된다.

지시서의 "무슨 일이 있어도 Router는 완주한다"와 충돌하는 지점이며, 해결은 Router의
예외 처리를 좁히는 것이 아니라 **bootstrap이 배선 시점에 키를 확인하는 것**이 맞다.
실행 중에 발견할 문제가 아니라 구성 단계에서 막을 문제이기 때문이다. D의 후속 작업이다.

### 7. 다음 단계

D가 `bootstrap.standard_router()`에 advisor 주입을 추가한다. 이때 `AnalyzerChoice`
목록을 라우팅 규칙에서 도출해야 `--vuln` 필터와 `IMPLEMENTED_ANALYZERS` 필터가 함께
상속된다.

Evidence 기록 경로 결정도 여전히 남아 있다.

---

## 3단계 — Juice Shop E2E (2026-09-10)

### 1. 결과

네 조건을 모두 실행했고 전부 완주했다. 대상은 `bkimminich/juice-shop` 컨테이너다.

| | Analysis | Router | Candidate | 검증 | Finding | LLM 호출 | 입력 token | 예산 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 규칙 | 규칙 | 14 | 14/14 | 3 | 0 | 0 | 48/80 |
| 2 | LLM | 규칙 | 14 | 14/14 | 3 | 14 | 1,960 | 42/80 |
| 3 | 규칙 | **LLM** | **15** | 15/15 | 3 | **1** | 3,138 | 48/80 |
| 4 | LLM | **LLM** | **15** | 15/15 | 3 | 16 | 5,242 | 42/80 |

Candidate 내역은 조건 1·2가 XSS 7 · SQLi 4 · Path Traversal 2 · SSTI 1이고, 조건 3·4는
Path Traversal이 3으로 늘어 15가 된다. Finding은 네 조건 모두 Path Traversal 1 · SQLi 1 ·
XSS 1로 동일하다.

기준선(조건 1)은 팀 문서의 최신 LLM 실행과 Surface 140개·파라미터 11종·Candidate 14개·
검증 14/14가 정확히 일치한다. 환경이 올바르게 구축됐다는 근거다.

팀 문서의 2026-09-06 휴리스틱 실측(Surface 95, Finding 8)과 다른 것은 그 뒤 커밋
`1ea34fa`가 제한 확장자 우회 라우팅을 기본 비활성화해 Path Traversal Finding이 6에서
1로 줄었고, Recon 개선으로 Surface가 95에서 140으로 늘었기 때문이다. 현재 코드 기준으로는
위 수치가 맞다.

### 2. 검증된 것

**축 분리가 작동한다.** 조건 3이 결정적이다. `Agent 구성`이 `heuristic`으로 찍히면서 LLM은
정확히 1회 호출됐다. Analysis는 휴리스틱 그대로 두고 Router만 LLM을 쓴 것이며, Advisor를
Run당 한 번만 부르는 설계도 함께 확인된다.

**Advisor가 규칙이 비워 둔 자리를 채운다.** Path Traversal Candidate가 2에서 3으로 늘었다.
규칙이 분류하지 못한 표면 하나를 Advisor가 제안했다.

**규칙 판정이 보존된다.** 네 조건의 Finding 수와 유형이 모두 같다. Advisor가 규칙 결과를
덮어쓰지 않았다.

**오탐이 늘지 않았다.** 새 Candidate는 검증까지 진행됐으나(15/15) Finding이 되지 않았다.
Validation proof gate가 정상 작동한 것이며, 제안이 틀렸을 때 걸러진다는 뜻이다.

**임시 계정 정리가 매 실행 검증됐다.** 모든 실행 후 `Users: 24` · `hacklipse 잔여: 0`을
확인했다. 바인드 마운트가 라이브 DB를 가리킨다는 근거이기도 하다 — 복사본이었다면
컨테이너 안에 계정이 남는다.

### 3. 비용

Advisor 1회 호출에 입력 약 3,100 token이 든다. `DEFAULT_MAX_SURFACES = 40` 상한이 그대로
반영된 크기이며, 조건 2 대비 조건 4의 입력 증가분(1,960 → 5,242)과 일치한다.

조건 4의 LLM 호출이 14에서 16으로 늘어난 것은 Advisor 1회와 새 Candidate에 대한 Analysis
1회로 설명된다.

### 4. 해석에 주의할 점

**Finding이 늘지 않은 것이 Advisor가 무용하다는 뜻은 아니다.** 이번 대상에서 규칙이 놓친
표면이 실제 취약점이 아니었을 뿐이다. 지시서가 정한 현 단계의 성공 기준은 탐지율이 아니라
파이프라인 완주이며, 그것은 충족됐다.

**1회 실행이므로 성능 판단의 근거가 되지 않는다.** 정량 비교는 반복 실행·고정 데이터셋·
blind 평가가 갖춰진 뒤의 별도 과제다.

### 5. 환경 구축 — WSL2 권한 문제

팀원이 공유한 실행 문서는 macOS 기준이라 그대로 적용되지 않았다. 컨테이너가 uid 65532로
실행되는데 바인드 마운트한 호스트 디렉터리는 호스트 사용자 소유라 세 번 막혔다.

| 시도 | 결과 |
| --- | --- |
| 기본 사용자 + 호스트 소유 디렉터리 | `SQLITE_CANTOPEN` — DB 파일을 만들지 못한다 |
| `--user $(id -u)`로 실행 | `/juice-shop/logs`, `.well-known/csaf/` 등 이미지 내부 경로에서 `EACCES` |
| 기본 사용자 + 디렉터리 777 | 기동 성공. 단 DB가 65532 소유 0644라 호스트가 쓰지 못한다 |

최종 해법은 기본 사용자로 띄운 뒤 **같은 디렉터리를 마운트한 별도 root 컨테이너로
`chmod 666`**을 거는 것이다. 호스트 `sudo`가 필요 없고 컨테이너와 호스트가 모두 DB에 쓸 수
있다. Juice Shop 이미지는 distroless라 `docker exec`로 셸을 쓸 수 없으므로 별도 컨테이너가
필요하다.

```bash
mkdir -p ~/juice-shop
docker create --name juiceshop-seed bkimminich/juice-shop
docker cp juiceshop-seed:/juice-shop/data ~/juice-shop/data
docker rm juiceshop-seed
chmod 777 ~/juice-shop/data

docker run -d --name hacklipse-juiceshop -p 3000:3000 \
  -v "$HOME/juice-shop/data:/juice-shop/data" bkimminich/juice-shop

# DB 생성을 기다린 뒤 양방향 쓰기 권한을 연다
docker run --rm -u 0 -v "$HOME/juice-shop/data:/data" ubuntu:latest \
  bash -c 'chmod 666 /data/juiceshop.sqlite*; chmod 777 /data'
```

`data/`를 먼저 꺼내는 이유는 그 안에 `datacreator.ts`·`static/` 같은 시드 파일이 있기
때문이다. 빈 디렉터리를 마운트하면 이 파일들이 가려져 앱이 뜨지 않는다.

`journal_mode`는 `delete`이므로 WAL·SHM 파일 권한은 문제되지 않는다.

브라우저 XSS 검증에는 chromium과 headless shell이 모두 필요하다. `playwright install
chromium`만으로는 `chrome-headless-shell`이 없어 실행되지 않는다.

```bash
playwright install chromium
playwright install chromium-headless-shell
```

### 6. 재현 명령

```bash
DB=~/juice-shop/data/juiceshop.sqlite
RUN="python scripts/run_juice_shop_baseline.py http://127.0.0.1:3000/"

echo y | $RUN --vuln all --profile heuristic --juice-shop-db $DB
echo y | $RUN --vuln all --profile llm --llm-provider gemini --juice-shop-db $DB
echo y | $RUN --vuln all --profile heuristic --router-advisor --llm-provider gemini --juice-shop-db $DB
echo y | $RUN --vuln all --profile llm --router-advisor --llm-provider gemini --juice-shop-db $DB
```

실행 후에는 매번 정리를 검증한다. 스크립트의 "정리 완료" 출력만 믿지 않는다.

```bash
python -c "
import sqlite3, os
c = sqlite3.connect('file:'+os.path.expanduser('~/juice-shop/data/juiceshop.sqlite')+'?mode=ro', uri=True)
print('Users:', c.execute('SELECT COUNT(*) FROM Users').fetchone()[0])
print('hacklipse 잔여:', c.execute(\"SELECT COUNT(*) FROM Users WHERE email LIKE 'hacklipse%'\").fetchone()[0])
"
```

---

## 실행 옵션

### 두 축은 독립이다

`--profile`은 Analysis Agent를, `--router-advisor`는 Router를 각각 결정한다. 서로를
암시하지 않는다.

| 명령 | Analysis | Router | 무엇을 보는가 |
| --- | --- | --- | --- |
| `--profile heuristic` | 규칙 | 규칙 | 대조군 |
| `--profile llm` | LLM | 규칙 | Analysis LLM 효과 (기존 실험군) |
| `--profile heuristic --router-advisor` | 규칙 | LLM | **Router LLM 단독 효과** |
| `--profile llm --router-advisor` | LLM | LLM | 결합 효과 |

`--profile llm`의 의미를 바꾸지 않은 것은 의도적이다. Router까지 포함하도록 바꾸면 이미
기록된 `--profile llm` 측정치(Finding 4개·예산 45/80·LLM 14회)와 새 측정치가 같은
이름표를 달고 다른 조건이 된다. 옵션을 늘리면 과거 기록이 그대로 유효하다.

세 번째 조합이 특히 유용하다. Analysis를 고정한 채 Router만 바꾸므로 라우팅 판단의
기여를 단독으로 분리할 수 있다.

### 사용법

```bash
DB=~/juice-shop/data/juiceshop.sqlite
RUN="python scripts/run_juice_shop_baseline.py http://127.0.0.1:3000/"

# 대조군
$RUN --vuln all --profile heuristic --juice-shop-db $DB

# Router LLM 단독
$RUN --vuln all --profile heuristic --router-advisor \
     --llm-provider gemini --juice-shop-db $DB

# 결합
$RUN --vuln all --profile llm --router-advisor \
     --llm-provider gemini --juice-shop-db $DB
```

### 자격증명

`--router-advisor`는 `--profile heuristic`에서도 LLM Client를 필요로 한다. 키가 없으면
**Run이 시작되기 전에** `LlmCredentialsMissing`으로 실패한다.

```
router advisor was requested without an LlmClient;
pass one or drop the router advisor option
```

조용히 규칙만 돌지 않는 이유는, 그렇게 되면 "Router LLM을 켰는데 규칙 결과가 나왔다"는
오독이 생기기 때문이다. 키 유무는 Run을 돌려 봐야 아는 사실이 아니라 이미 확정된
구성이므로 배선 시점에 막는다.

환경변수는 provider에 따라 `GEMINI_API_KEY` 또는 `ANTHROPIC_API_KEY`다.

### 실행 조건 확인

진행 로그 첫 줄에 조건이 찍힌다.

```plain text
Run 시작: vuln=all, profile=llm/gemini (gemini-3.5-flash-lite), router=advisor, request_budget=80
```

`router=advisor`면 Advisor가 붙은 것이고 `router=rules`면 규칙만 돈 것이다. **측정치를
기록할 때 이 줄을 함께 남겨야 한다** — 아래 미해결 사항 참고.

### 동작 범위

Advisor는 규칙이 비워 둔 자리만 채운다. 규칙이 이미 만든
`(surface_id, vulnerability_type)` 조합은 덮어쓰지 않으며, 제안으로 만들어진 Candidate는
`priority=0.15`로 규칙 최저값(0.20)보다 뒤에 실행된다.

`--vuln xss`처럼 유형을 제한하면 Advisor도 그 유형만 제안할 수 있다. 제안 가능 목록을
필터링된 규칙에서 도출하기 때문이다.

한 Run에서 LLM에게 보여 주는 Surface는 최대 40개다(`DEFAULT_MAX_SURFACES`). Router는
Run당 한 번만 호출하므로 이 상한이 곧 기능 전체의 비용 상한이다.

### 미해결 — 실행 조건이 저장되지 않는다

`--profile`과 `--router-advisor` 값은 콘솔 로그에만 남고 저장소에는 기록되지 않는다.
`Run` 모델에 분석 프로필 필드가 없어서 SQLite만 보면 어떤 조건으로 돌린 Run인지 복원할
수 없다(`policy_profile`은 보안 정책이며 항상 `"safe"`다).

당장은 로그를 함께 기록하는 것으로 대응하고, 근본 해결은 `RunRequest`·`Run`에 분석 조건
필드를 추가하는 별도 작업이다. Router 범위가 아니라 도메인·저장소 작업이다.

---

## 개발 환경

```bash
conda create -n lasp python=3.12 -y
conda activate lasp
pip install -e .
python -m unittest discover -s tests
```

`pip install -e .`로 editable 설치하므로 `PYTHONPATH=src`는 필요하지 않다.

브라우저 바이너리(`playwright install chromium`)는 단위 테스트에 필요하지 않다.
Juice Shop 실제 대상을 치는 E2E 단계에서만 필요하다.
