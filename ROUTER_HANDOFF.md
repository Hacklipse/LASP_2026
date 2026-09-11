# Router 조 작업 인수인계

Router 조(C·D)가 `feat/hybrid-router-integration`에서 만든 결과물을 다른 팀에 설명하는
문서다. **무엇이 바뀌었고, 그 변화가 각자의 작업에 어떤 영향을 주는지**를 다룬다.

- 추적 이슈: [#24](https://github.com/Hacklipse/LASP_2026/issues/24)
- PR: [#25](https://github.com/Hacklipse/LASP_2026/pull/25) (`dev/dmswls` 대상, OPEN)
- 상세 작업 기록: `ROUTER_LLM_WORKLOG.md`

---

## 1. 한 줄 요약

**Router가 규칙으로 분류하지 못한 표면을 LLM에게 물어볼 수 있게 됐다.** 기본값은 꺼져
있으며, 켜지 않으면 기존과 완전히 동일하게 동작한다.

```
Recon ──▶ Router ──▶ Analysis ──▶ Validation ──▶ Report
           ^^^^^^
       규칙 우선 + LLM 보조
```

---

## 2. 왜 만들었나

기존 Router는 이미 아는 `observation.type`만 분류했다. 규칙에 없는 표면은 **Candidate가
아예 만들어지지 않아 조용히 검사에서 빠졌다.** Run 결과 어디에도 남지 않으므로 "검사했는데
없었다"와 "애초에 검사하지 않았다"가 구분되지 않았다.

표면이 하나 늘 때마다 사람이 `DEFAULT_RULES`에 줄을 추가해야 했고, 실제로
`unlinked_render_parameter_candidate` 규칙이 그렇게 들어갔다. 잘 만든 자동화이긴 하지만
Agentic하지는 않았다.

---

## 3. 가장 중요한 원칙 — 규칙이 항상 이긴다

**LLM을 꺼도, 실패해도, 이상한 답을 줘도 Router는 완주한다.** 규칙이 이미 분류한 것은
LLM이 건드리지 못한다.

이것은 측정을 위한 편의가 아니라 프레임워크 요구사항이다. 규칙 판정은 설명 가능하고
재현 가능한데, LLM 추측이 그것을 덮어쓰면 도구 전체의 신뢰성이 떨어진다.

구현상 이 불변식은 **검사 한 줄이 아니라 병합 순서 자체로** 보장된다.

```
1단계  Evidence 규칙   (priority 0.55 ~ 0.9)
2단계  Surface 규칙    (priority 0.20 ~ 0.40)   ← 1단계가 채운 자리는 건너뜀
3단계  LLM Advisor     (priority 0.15)          ← 1·2단계가 채운 자리는 건너뜀
```

`(surface_id, vulnerability_type)`을 키로 앞 단계가 이미 채웠으면 뒤 단계는 양보한다.
조건문을 실수로 지우는 방식으로는 이 성질이 깨지지 않는다.

Advisor 후보의 priority가 규칙 최저값보다 낮은 것도 같은 이유다. priority는 정렬용 숫자가
아니라 **예산이 모자랄 때 무엇을 포기하는지에 대한 결정**이므로, 설명 가능한 규칙 판정이
LLM 제안 때문에 잘려서는 안 된다.

---

## 4. 실행 방법

### 축이 세 개다

`--recon` · `--router` · `--profile`은 서로 독립이다. 하나가 다른 하나를 암시하지 않는다.

| 옵션 | 대상 | 기본값 |
| --- | --- | --- |
| `--recon {heuristic,hybrid}` | Recon Planner | `heuristic` |
| `--router {heuristic,hybrid}` | **Router (이 작업)** | `heuristic` |
| `--profile {heuristic,llm}` | Analysis Agent 5종 | `heuristic` |

축을 분리한 이유는 **기여를 분리해서 볼 수 있어야** 하기 때문이다. Analysis를 고정한 채
Router만 바꾸면 라우팅 판단의 효과만 남는다.

그리고 `--profile llm`의 의미를 바꾸지 않았다. 이미 기록된 `--profile llm` 측정치와 새
측정치가 같은 이름표를 달고 다른 조건이 되는 것을 피하기 위해서다.

### 명령

```bash
DB=~/juice-shop/data/juiceshop.sqlite
RUN="python scripts/run_juice_shop_baseline.py http://127.0.0.1:3000/"

# 대조군 — 기존과 동일
$RUN --vuln all --profile heuristic --juice-shop-db $DB

# Router만 LLM (Analysis는 규칙 그대로)
$RUN --vuln all --profile heuristic --router hybrid \
     --llm-provider gemini --juice-shop-db $DB

# 결합
$RUN --vuln all --profile llm --router hybrid \
     --llm-provider gemini --juice-shop-db $DB
```

`--router-advisor`는 `--router hybrid`의 호환 별칭이다. 초기 PR에서 쓰던 이름이며 계속
동작한다.

### 자격증명

`--router hybrid`는 `--profile heuristic`에서도 LLM Client를 필요로 한다. 키가 없으면
**Run이 시작되기 전에** 실패한다.

```
hybrid router requires an explicit LlmClient
```

조용히 규칙만 돌지 않는 이유는, 그렇게 되면 "Router LLM을 켰는데 규칙 결과가 나왔다"는
오독이 생기기 때문이다. 키 유무는 Run을 돌려 봐야 아는 사실이 아니라 이미 확정된 구성이므로
배선 시점에 막는다.

환경변수는 `GEMINI_API_KEY` 또는 `ANTHROPIC_API_KEY`다.

### 실행 조건 확인

진행 로그 첫 줄에 조건이 찍힌다. **측정치를 기록할 때 이 줄을 함께 남겨야 한다.**

```plain text
Recon: heuristic; Router: hybrid; 비교: False; 판단 기록: artifacts/routing-decisions.jsonl
Run 시작: vuln=all, profile=llm/gemini (...), router=hybrid, request_budget=80
```

---

## 5. 팀별로 알아야 할 것

### Analysis Agent 팀

**Advisor가 만든 Candidate는 `evidence_ids`가 비어 있다.** 이것은 버그가 아니라 의도다.
Advisor의 판단은 관측(Observation)이 아니라 주장(Claim)이므로, 자기가 보지 않은 Evidence를
근거로 달 수 없다(세부구현 §7).

따라서 Analyzer는 `candidate.evidence_ids`가 항상 채워져 있다고 가정하면 안 된다. 규칙이
Surface만 보고 만든 탐색 Candidate도 원래부터 비어 있었으므로, 새로 생긴 제약은 아니다.

`Candidate`에 `exploration_parameters` 필드가 추가됐다. Router가 관측된 Surface에서 고른
탐색 입력 이름이며, **관측 Evidence도 성공 증거도 아니다.** Analyzer는 사용 전에 실제
Surface 소속과 실행 정책을 다시 검증해야 한다.

Advisor가 만든 Candidate도 다른 Candidate와 동일하게 Validation을 거친다. **proof 없이
Finding이 되는 경로는 없다.**

### Recon 팀

Router의 입력 계약은 바뀌지 않았다. `route(run, surfaces, evidence)` 그대로다.

다만 Advisor가 Surface **메타데이터**를 LLM 프롬프트에 싣는다. 싣는 것은 `surface_id`,
메서드, path, fragment 여부, 파라미터 **이름**, 관측 유형 이름뿐이다.

**`Surface.observed_query`의 값은 싣지 않는다.** 거기에는 token 같은 실제 값이 담기기
때문이다. 전체 URL 대신 path만 쓴다. Recon이 Surface에 새 필드를 추가할 때 그 값이 민감할
수 있다면 알려주면 좋겠다 — 프롬프트 포함 여부를 검토해야 한다.

Surface 수가 늘어나면 Advisor 프롬프트 비용이 늘어날 수 있으나, 상한이 40개로 막혀 있어
선형으로 증가하지는 않는다.

### Knowledge 팀

Router는 KnowledgeBase를 사용하지 않는다. Advisor에 KnowledgeHint를 전달하지 않으며,
과거 사례로 Candidate를 만들지 않는다.

Knowledge를 라우팅 우선순위에 반영하는 것은 검토해 볼 만하지만, priority가 곧 예산 배분
결정이라 신중해야 한다. 아직 하지 않았다.

### Orchestrator·저장소를 다루는 팀

`_route()`의 계약은 바뀌지 않았다. Router는 여전히 `tuple[RouteDecision, ...]`만 반환하고
저장은 Orchestrator가 한다.

**Router는 Agent가 아니다.** TaskEnvelope도 `AgentResult`도 없고 Evidence Store에 쓸 통로가
없다. `AgentResultStatus.NEEDS_EVIDENCE` 흐름은 Router에 적용되지 않으니 그쪽으로 연결하려
하지 않는 편이 좋다.

---

## 6. 안전 경계 — Advisor가 넘지 못하는 선

LLM 제안은 Candidate가 되기 전에 여러 관문을 지난다. **모든 위반은 항목 단위로 폐기되며
Run을 중단시키지 않는다.**

| 검사 | 이유 |
| --- | --- |
| 이번 Run의 Surface인가 | Run 격리 |
| `(유형, agent_type)`이 허용 목록에 있는가 | 미등록 agent는 `AgentUnavailable`로 Run을 죽인다 |
| 상태 변경 파라미터가 아닌가 | 비밀번호 변경·삭제 폼 차단 |
| fragment ↔ client_route 일치 | SPA 라우트를 HTTP Analyzer로 보내는 예산 낭비 차단 |
| Analyzer의 실행 계약에 맞는가 | 메서드·필수 파라미터 확인 |
| 이미 규칙이 정한 자리가 아닌가 | 규칙 우선 |

허용 목록은 **별도로 관리하지 않고 라우팅 규칙에서 도출한다.** 그래서 `--vuln xss`로
제한하면 Advisor도 XSS만 제안할 수 있고, 미구현 Analyzer는 애초에 제안 대상이 아니다.
목록을 두 벌 관리하면 어긋나는 순간 Dispatcher가 Run을 죽인다.

LLM은 `agent_type`을 고르지 않는다. `surface_id`와 `vulnerability_type`만 고르고, 담당
Agent는 표면 모양을 보고 코드가 해석한다. XSS의 담당 Analyzer가 둘인 것(서버 반사
`xss_analyzer`, SPA DOM sink `browser_xss_analyzer`)은 fragment 여부라는 **관측 가능한
사실**로 갈리므로 추측의 영역이 아니다.

---

## 7. 비용

Router는 **Run당 LLM을 한 번만 호출한다.** Surface마다 부르지 않는다.

- 프롬프트에 싣는 Surface는 최대 40개(`DEFAULT_MAX_SURFACES`)
- 규칙이 이미 모든 배정 가능 유형을 채운 표면은 제외
- 남은 표면이 없으면 **호출 자체를 하지 않는다**

실측으로 Advisor 1회 호출에 입력 약 3,100 token이 든다.

주의할 점은 **이 비용이 예산 모델에 잡히지 않는다**는 것이다. `BudgetManager`는 HTTP 요청
개수만 세고 LLM 토큰은 진행 화면 표시용으로만 집계된다. Router뿐 아니라 Analysis·Recon의
LLM 비용도 마찬가지이며, 도구별 예산 가중치는 프레임워크 차원의 별도 과제다.

---

## 8. 실측 — Gemini · Juice Shop 최종 실험

`--compare-routers`로 한 번의 Recon 결과를 두 Router에 동일하게 넣고 비교했다.

```plain text
Target            http://127.0.0.1:3000/
Analysis profile  heuristic
Recon             heuristic
Router            hybrid (paired comparison)
Model             gemini-3.5-flash-lite
Scope             all (Access Control은 별도 실행)
Request budget    100
```

### 동일 입력 검증

| 항목 | 결과 |
| --- | ---: |
| `same_router_input` / `same_raw_recon_input` / `paired_run` | 모두 `true` |
| Surface | 140 / 140 |
| Evidence | 20 / 20 |
| Heuristic Candidate | 14 |
| Hybrid Candidate | 14 |
| Added / Removed / Changed | **0 / 0 / 0** |

### 실행 결과

| 항목 | 결과 |
| --- | ---: |
| Run 상태 | `done` |
| 검증 | 14 / 14 |
| Finding | 4 (Path Traversal 1 · SQLi 1 · SSTI 1 · XSS 1) |
| 요청 사용량 | 51 / 100 |
| LLM 호출 | **1** |
| 입력 / 출력 token | 3,093 / 119 |
| Heuristic Router 지연 | 약 0.5 ms |
| Hybrid Router 지연 | 약 8,531 ms |

### 무엇이 확인됐나

**Gemini는 Path Traversal 제안 1개를 반환했으나 `incompatible_surface`로 차단됐다.**
해당 Surface가 Analyzer의 실제 실행 계약과 맞지 않았기 때문이다. Candidate로 추가되지
않았고 Finding으로도 이어지지 않았다.

**규칙 결과가 그대로 보존됐다.** Added / Removed / Changed가 모두 0이다. 실제 Gemini
호출에서도 규칙 판정이 변경되지 않는 안전 경계가 확인됐다.

**Analysis가 휴리스틱인데 LLM이 정확히 1회 호출됐다.** 축 분리와 Run당 1회 호출 설계가
함께 확인된다.

### 비용과 이득

**이번 Run의 탐지 이득은 0이다.** 비용은 LLM 호출 1회와 약 8.5초의 지연이다. 규칙 Router의
지연이 0.5 ms인 것과 비교하면 라우팅 단계에서만 네 자릿수 배의 차이가 난다.

다만 이는 **부적절한 제안이 안전하게 차단된 결과**이기도 하다. 잘못된 LLM 제안이 Candidate와
Finding으로 이어지지 않는다는 것이 실제 호출로 입증됐다.

> ⚠️ **1회 실행이므로 성능 판단의 근거가 아니다.** 이번 대상에서 Gemini의 제안이 실행
> 계약과 맞지 않았을 뿐이며, Hybrid Router의 효과를 부정하는 결과도 긍정하는 결과도 아니다.
> 탐지율·오탐률 정량 비교는 반복 실행·고정 데이터셋·blind 평가가 갖춰진 뒤의 별도 과제다.

### 참고 — 초기 구현 시점의 측정

`_supports_suggestion()`(실행 계약 검사)이 들어오기 전 C·D 초기 구현에서는 같은 제안이
**통과해 Candidate 15개가 됐고**, Validation까지 진행된 뒤 Finding이 되지 않았다.

계약 검사가 추가되면서 **거부 시점이 Validation 이후에서 라우팅 단계로 앞당겨졌다.**
최종 판정은 같고 소비하는 예산만 줄었다. 두 측정은 코드 버전과 request budget(80 대 100)이
다르므로 직접 비교하지 않는 편이 좋다.

---

## 9. 실험 지원 기능

라우팅 판단을 감사·비교하기 위한 도구가 함께 들어 있다.

| 옵션 | 용도 |
| --- | --- |
| `--routing-log <경로>` | 라우팅 결정을 append-only JSONL로 기록 (기본 `artifacts/routing-decisions.jsonl`) |
| `--compare-routers` | 같은 Recon 입력을 두 Router에 넣고 비교. **분석은 `--router`가 고른 쪽만** 수행 |
| `--router-review {weak,ambiguous}` | 후보 채택 정책 변형 |

`--compare-routers`의 shadow 결과는 저장·실행되지 않는다. 외부 요청과 Finding은 primary
Router에만 귀속되므로, 비교 때문에 대상에 추가 요청이 나가지 않는다.

---

## 10. 아직 열려 있는 것

**Advisor의 판단이 Evidence Store에 기록되지 않는다.** Router는 Agent가 아니라 Evidence를
쓸 통로가 없다. 기록 경로를 `RouteDecision` 확장으로 할지 Port 반환 타입 변경으로 할지
정하지 못했다. 현재는 `--routing-log` JSONL이 그 역할을 부분적으로 대신한다.

**실행 조건이 저장소에 기록되지 않는다.** `--profile`·`--router` 값은 콘솔 로그와 라우팅
로그에만 남고 `Run` 모델에는 없다. SQLite만 보면 어떤 조건으로 돌린 Run인지 복원할 수 없다
(`policy_profile`은 보안 정책이며 항상 `"safe"`다). 근본 해결은 `RunRequest`·`Run`에 분석
조건 필드를 추가하는 것이며 **Router 범위가 아니라 도메인·저장소 작업이다.**

**Access Control은 여전히 `all`에 통합되지 않았다.** Advisor가 이 문제를 풀지 못한다.
`/rest/basket/{id}` 같은 객체 ID는 크롤링으로 나오지 않고 임의로 만들면 열거가 되므로,
표면 발견 계약을 먼저 정해야 한다.

**실행 계약에 맞지 않는 Surface를 Advisor 호출 전에 걸러낼지 미정이다.** 최종 실험에서
Gemini의 제안이 `incompatible_surface`로 차단됐는데, 그 Surface를 애초에 프롬프트에 싣지
않았다면 token과 지연을 줄일 수 있었다. 다만 사전에 너무 좁히면 규칙이 놓친 표면을
발견한다는 본래 목적과 충돌할 수 있어 판단이 필요하다. PR [#25](https://github.com/Hacklipse/LASP_2026/pull/25)의
리뷰 포인트에 올려 두었다.

**두 Router의 Analysis 성능을 반복 측정할지 미정이다.** paired 비교는 라우팅 판단만
대조하며 실제 Analyzer는 primary 후보만 실행한다(`analysis_comparison_available: false`는
오류가 아니라 이 설계의 결과다). 분석 단계까지 비교하려면 별도 실험 설계가 필요하다.

---

## 11. 검증 상태

```plain text
Ran 499 tests — OK
```

| | 테스트 |
| --- | --- |
| 작업 전 기준선 (`baf2a0c`) | 429 |
| 현재 (`b5600b6`) | **499** |
| 회귀 | **0** |

핵심 회귀 방지 테스트는 **`--router heuristic`일 때 기존 결과와 동일함**을 잠그는 것이다.
Advisor 관련 테스트는 모두 대역(`_FakeLlmClient`·`_StubAdvisor`)을 쓰므로 **LLM도 API 키도
없이 실행된다.**

### 실행 방법

```bash
conda create -n lasp python=3.12 -y
conda activate lasp
pip install -e .
python -m unittest discover -s tests
```

`pip install -e .`로 editable 설치하므로 `PYTHONPATH=src`는 필요하지 않다. 브라우저
바이너리는 단위 테스트에 필요하지 않으며, Juice Shop 실제 대상을 치는 E2E에서만
`playwright install chromium` 및 `chromium-headless-shell`이 필요하다.

---

## 12. 코드 위치

| 파일 | 내용 |
| --- | --- |
| `adapters/routing.py` | `RouterAdvisor` Protocol, `RouteSuggestion`, 3단 병합 |
| `adapters/llm_router_advisor.py` | LLM 구현. 제안 대상 선정·프롬프트·응답 검증 |
| `adapters/routing_audit.py` | 라우팅 결정 감사와 입력 지문 |
| `adapters/paired_routing.py` | 두 Router 동시 실행 비교 |
| `bootstrap.py` `standard_router()` | 조립과 자격증명 확인 |
| `tests/test_routing.py` | 규칙 보존·배선 |
| `tests/test_llm_router_advisor.py` | Advisor 검증 |

질문이나 계약 변경 요청은 이슈 [#24](https://github.com/Hacklipse/LASP_2026/issues/24)에
남겨 주면 된다.
