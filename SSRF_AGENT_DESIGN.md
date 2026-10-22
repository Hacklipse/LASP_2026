# SSRF Agent 설계와 구현 단계

## 판정 경계

SSRF 검사는 두 질문을 분리한다. (1) 관측된 입력값 때문에 대상 서버가 외부 HTTP
요청을 했는가? (2) 그 목적지가 해당 기능에서 허용되지 않아야 하는가? 서로 다른
일회성 callback 두 번은 첫 질문의 재현 근거이지만, 둘째 질문의 답은 아니다.
대상이 원래 임의의 공개 URL을 가져오는 기능이라면 callback 수신만으로 Finding을
생성하지 않는다.

대상 앱의 목적지 규칙은 스캐너의 Run Scope와 다른 개념이다. Run Scope는 우리
요청의 허가 범위를 코드로 강제한다. 목적지 규칙은 대상 기능의 예상 동작이며,
명세·버전이 맞는 소스/설정·운영자 제공 정보에서 수집하고 출처를 기록한다.
UI 문구나 LLM 추론만으로는 규칙을 확정하지 않는다. 규칙을 확인하지 못하면
`server_fetch_observed`까지만 기록하고 Candidate는 `SUSPECTED`로 남긴다.

## 수비적 기본 경로 (구현 완료)

Callback 또는 별도 확인 서비스를 설정하지 않은 기본 Run은 네트워크 확인 요청을
만들지 않는다. Recon은 관측된 GET URL 입력 좌표와 공개 명세에 선언된 GET URL 입력
좌표를 `ssrf_url_fetch_review`로만 기록한다. 이 기록에는 Surface ID, 파라미터 이름,
발견 출처와 `verification_performed=false`만 들어가며 URL 값은 들어가지 않는다.
Router에는 SSRF Candidate를 등록하지 않고 CLI와 Dashboard에는 `Recon URL 좌표
분류 완료 / 운영자 검토 대기 / 서버 요청 확인 미수행`으로 표시한다. Recon이 만든
기록을 사람의 수동 분석 완료로 세지 않는다. 확인 미수행은 취약점 부재
판정이 아니다.

확인 결과를 나중에 수동으로 연결할 때는 `SsrfExecutionApproval`, Surface에 결합된
`DestinationPolicy`, URL 원문이 없는 `ServerRequestObservation` 계약을 사용한다.
메모리 Provider는 네트워크 요청을 시작하지 않고 정제된 관측만 제공하며, 순수 판정
함수는 서로 다른 Analysis/Validation 세션, 같은 승인 주소 참조, 출처 확인 여부와
목적지 정책을 결정적으로 검사한다. 독립 관측만 있고 정책이 없으면 `SUSPECTED`,
해당 Surface의 금지 정책까지 있으면 `CONFIRMED`, 허용 정책이면 `REJECTED`이다.
Provider 관측 ID는 중앙 Evidence ID와 구별한다. 중앙 Collector가 승인된 좌표,
확인 서비스 참조, 출처, 시각, 독립 세션을 다시 검사한 뒤 별도 Evidence ID로 변환한다.
Validation은 현재 세션의 중앙 Evidence와 정책 출처를 담은 판정 Evidence만 표준
proof에 연결한다. Orchestrator는 기존 provenance·proof 계약을 통과한 결과만
Finding으로 승격한다.

## Recon 이후 운영자 검토 (선택적 경로)

CLI의 `--ssrf-review` 또는 Dashboard의 `SSRF Recon 후 운영자 검토`를 선택하면
Recon 뒤, Router 실행 전에 같은 Run을 잠시 대기시킨다. 현재 Run의 GET URL형
입력 중 정확한 Surface와 파라미터 하나를 고르고, 같은 Surface의 정제된 목적지
단서를 참고할 수 있다. Callback 전략은 로컬 또는 명시적으로 선택한
Interactsh Provider가 있을 때만 활성화된다. 선택한 좌표의 callback 확인을
승인하면 해당 좌표에서만 Analysis/Validation의 독립 callback A/B를
실행한다. 내부 Canary 전략은 Callback Provider 없이도 실행할 수 있으며,
운영자가 정확한 비민감 Canary URL과 별도 실행 동의를 제공해야 한다.
정확한 URL과 marker는 Run 한정 보호 메모리에만 두고 일반 Evidence·TaskStore·
진행 이벤트에는 저장하지 않는다. Runtime 응답이나 artifact에 값이 반사돼도
Evidence 생성 전에 정확한 값과 인코딩 변형을 제거하며, Run이 `DONE` 또는
`FAILED`가 되면 callback ticket·Provider 수신 기록·검토 상태와 함께 보호
메모리에서도 폐기한다. 목적지 규칙은 선택 입력이며, 알고 있을
때만 `allowed`/`forbidden`과 정책 출처·참조를 별도로 등록한다. 정책이 없어도
Canary 접근 관측은 수행할 수 있지만 결과는 `SUSPECTED`이다. 건너뛰면 SSRF
후보를 실행하지 않는다. URL 원문, 헤더, credential은 정책 참조로 받지 않는다.

승인·정책·좌표는 정제된 중앙 Evidence로 저장해 같은 Run의 재개 시 복원한다.
등록한 좌표에 관측 Provider가 주입돼 있으면 Analysis/Validation의 독립 관측을
중앙 Evidence로 변환한다. CLI는 이 Provider를 자동 주입하지 않고 callback 서비스로
기존 검사 경로를 선택한 좌표에만 적용한다. Dashboard는 callback과 Provider가 모두
없으면 검토 메타데이터만 남기며 SSRF Candidate를 실행하지 않는다.

기본 CLI와 Dashboard는 별도의 `ServerRequestObservationProvider`를 자동
구성하지 않는다. 운영자 소유 관측 서비스를 실제로 연결하려면 신뢰 가능한
Provider 어댑터를 `build_local_application`에 주입해야 한다. 테스트에서는 메모리
Provider로 중앙 Evidence·판정·Finding 계약을 검증한다. 따라서 UI에서 정책을
등록했다는 사실만으로 실제 서버 요청 확인이 이뤄지거나 Finding이 생기지는 않는다.

## Recon 목적지 단서와 두 단계 결과 (구현 완료)

Recon은 허가된 수집 과정에서 실제로 읽은 공개 API 명세·전달된 JavaScript·응답·
오류에 내부 서비스 URL/호스트가 **명시적으로 나타난 경우에만** SSRF용 목적지
단서를 기록한다. 입력 좌표(`GET /api/fetch`의 `url` 등)와 목적지 단서는 다른
Evidence로 분리한다. 단서에는 출처 Evidence ID, 문서/자산 종류, 관측 여부,
추출 위치와 신뢰도를 붙이고, 보고서·LLM·감사 로그에는 내부 주소 원문을 기본으로
노출하지 않는다. 기능 설명에서 떠올린 서비스명은 `inferred_hypothesis`로만
기록하며, 관측 사실 또는 허가된 탐침 목적지로 승격하지 않는다. 벤치마크 정답,
비공개 Compose/소스 설정은 URL-only Recon의 관측 입력으로 섞지 않는다.

SSRF Analysis는 이 단서를 후속 검증의 우선순위와 운영자 검토에만 활용한다.
내부 주소를 발견하거나 LLM이 추측했다는 이유만으로 요청하지 않는다. 실제
접근에는 운영자가 승인한 정확한 비민감 읽기 전용 목적지, 스캐너 실행 Scope의
별도 허가, 상태 변경 차단, 요청 예산 및 중앙 Collector 경유가 필요하다. 외부
LLM을 쓰는 경우 내부 주소 원문이나 토폴로지는 별도 전송 동의 없이 보내지 않는다.

결과는 **표면 관측**과 **취약점 확정**을 별개의 축으로 표시한다.

- 새 token A/B의 HTTP callback이 같은 입력 좌표에서 재현되면 리포트의 별도
  `SSRF 콜백 표면` 항목에 `콜백 반응 재현`으로 표시한다. 발신 주체 귀속이 여전히
  `unverified`이면 그 한계도 함께 명시한다. 이것은 `ValidationVerdict.CONFIRMED`
  또는 취약점 `Finding`이 아니며, 확정 취약점 수에도 포함하지 않는다.
- 허가된 내부 canary와 출처가 있는 금지 목적지 규칙의 위반이 독립 재현되거나,
  내부 목적지 없이도 명시적 목적지 제한을 외부 callback으로 우회했음이 입증된
  경우에만 별도 SSRF 취약점 proof/`CONFIRMED` Finding으로 승격한다. 운영자
  제공 규칙은 그 출처를 표시하며 프레임워크가 진실성을 자동 보증하지 않는다.
- 안전한 목적지·규칙 증거가 없으면 추가 내부망 탐침 없이 표면 관측 결과로
  마무리하고, 취약점 Candidate는 `SUSPECTED`로 유지한다. callback 미설정,
  미수신, DNS 전용, Provider 오류는 각각 `미검사`, `신호 없음`, `DNS만 관측`,
  `검증 불가`로 구분한다. 어느 것도 `취약점 없음`을 뜻하지 않는다.

Recon은 공개 응답에 명시된 내부 HTTP(S) URL만 `ssrf_destination_hint` Evidence로
저장한다. query·fragment·userinfo와 민감 Path segment는 제거하며, 출처 Evidence와
문서 종류, Run-keyed HMAC fingerprint, `probe_authorized=false`를 함께 기록한다.
LLM Analysis에는 원문 대신 단서 개수·출처 종류·host kind와 이미 마스킹된
path 의미만 제공한다. Report facts v5는 callback A/B가
독립 재현된 입력점을 `SSRF callback 표면`으로 별도 표시하고 확정 Finding 수에는
포함하지 않는다. CLI의 명시적 canary 승인 경로만 추가 내부 검증을 수행한다.
`CONFIRMED`/`Finding` 의미는 callback만으로 재정의하지 않았다.

## 첫 버전의 실행 경계

- Recon이 실제로 기록한 서버측 GET Surface와 URL 성격의 query 필드만 사용한다.
- 명시적으로 선택한 공개 또는 사설 Interactsh의 HTTPS callback 도메인만
  운영 목적지로 사용한다. 기본값은 `off`이며 공개 서비스는 제3자 메타데이터 전송
  동의가 필요하다. 사설 서버는 주소를 설정하고 callback 도메인과 보호 서버 토큰은
  필요할 때만 설정한다.
  로컬 실험 옵션에서만 loopback HTTP 예외를 열며, 대상도 같은 호스트의 loopback
  프로세스여야 한다. 토큰과 URL은 callback 서비스가 발급하며 LLM이 임의 URL을
  만들지 않는다.
- Analysis는 control과 한 필드만 바꾼 probe를 중앙 Collector로 요청한다.
  PolicyGate는 전송 직전에 callback origin을 다시 확인한다.
- callback 조회는 요청 발급·전송·수신 시각, 고유 token, HTTP 여부, 발신 주소를
  중앙 Evidence로 묶는다. 현재 발신 주체 귀속은 `unverified`로 보존한다. URL
  반사·500·DNS 조회만으로 서버측 HTTP 요청을 확정하지 않고, 테스트 장비나
  미리보기 봇을 배제할 증명이 없으면 취약점 Finding으로 승격하지 않는다.
- Validation은 새 token으로 독립 재현한다. 같은 token으로 여러 번 들어온 HEAD/GET은
  재현 2회가 아니다. 대상의 목적지 규칙과 우회 증거가 없으면 Finding은 만들지 않는다.
- 내부망·메타데이터·파일 스킴, POST, 리다이렉트 체인, DNS rebinding은 첫 버전의
  자동 탐침 범위 밖이다.

## 구현 순서와 현재 상태

1. **완료:** URL 성격의 관측된 GET 입력 선택, control/probe 명세, 등록된
   callback origin을 벗어난 probe의 중앙 차단과 단위 테스트.
2. **계약·중앙 수집 및 로컬 실험 Provider 완료:** callback 서비스 Port는 같은
   key의 ticket을 재발급할 때 값이 같아야 한다. Collector는 Run·Candidate·Validation
   세션별 ticket을 분리한다. 대상 요청 전에는 발급된 URL과 probe 값을 대조하고,
   실제 실행된 probe에 맞는 수신만 중앙 Evidence로 저장한다.
   원본 token·발신자 정보는 저장하지 않으며, HTTP와 DNS를 구분한다. 로컬 수신기는
   `127.0.0.1`에만 바인딩하고 ticket·hit를 메모리에 보관한다. 서비스가 지정되지
   않으면 SSRF 자동 라우팅을 활성화하지 않는다.
3. **전용 도구 호출 수직 슬라이스 및 로컬 수신 검증 완료:** callback
   서비스가 구성된 경우에만 관측된 GET URL 입력을 SSRF 후보로 라우팅한다.
   Heuristic은 첫 좌표를, LLM Analysis는 `get_surface_context` →
   `probe_observed_url_input` → `read_probe_result`의 구조화 JSON action으로 최대
   두 관측 좌표를 시도한다. 도구 grant·좌표 소속·중복·Validation용 요청 2회 예약은
   코드가 검사하고, 실제 HTTP는 중앙 Collector만 실행한다. 좌표별 ticket과
   선택·허용/거절·결과 Evidence를 저장해 같은 좌표를 재탐침하지 않는다. 모델
   오류는 아직 시도하지 않은 관측 좌표의 결정적 선택으로 복구한다. Validation은
   HTTP callback이 온 좌표만 새 ticket B로 재현한다. 두 callback이 와도 대상
   정책과 발신 주체의 신뢰 가능한 증명이 없어 `SUSPECTED`이며 Finding은 없다.
   fake Provider/Runtime의 1좌표 무반응→2좌표 반응과 실제 로컬 HTTP 양성·음성
   대상의 A/B를 검증했다. CLI와 Dashboard는 명시적 옵션에서만 수신기를 시작하고,
   Router가 서비스가 있을 때만 SSRF를 배정한다. 실행 기록과 화면에는 별도
   callback 발급·조회 횟수 및 Analysis/Validation HTTP 수신 횟수를 표시한다.
4. **Interactsh CLI bridge 구현·모의 검증 완료, 실서버 검증 남음:** 공개 모드는
   동의 후 `oast.pro` 단일 서버, 사설 모드는 입력한 HTTPS 서버와 선택적 보호 토큰을
   사용한다. 공식 CLI가 발급한 64개의 고유 hostname을 ticket으로 쓰고 JSONL
   interaction을 HTTP(S)/DNS·ticket별로 정규화한다. 원시 요청은 저장하거나 Agent에
   넘기지 않는다. 선택한 callback 도메인 이외의 발급 URL은 시작 단계에서 거부한다.
   원격 OAST는 최대 20초 동안 HTTP 수신을 기다리며, DNS만 먼저 와도 대기를 끝내지 않는다.
   실제 공개·사설 서버 연결과 대상 callback 왕복은 아직 수행하지 않았다.
5. **독립 Canary proof 수직 슬라이스 구현, 실대상 검증 남음:** Callback 성공 여부와
   무관하게 운영자가 승인한 비민감 canary URL을 관측된 같은 GET 좌표에만
   넣는다. Analysis와 Validation은 각각 control/probe를 실행한다. 운영자가 금지
   목적지 규칙의 구조화된 근거를 제공하고, 독립 Validation control에는
   canary marker가 없고 probe 응답에만 있으면 SSRF 전용 proof로 확정한다.
   marker와 내부 응답 본문은 Evidence·LLM에 저장하지 않는다. URL·규칙·marker가
   없으면 기존처럼 `SUSPECTED`이다. 이 정책 참조는 운영자의 주장으로서,
   프레임워크가 규칙 자체의 진실성을 자동 검증한 것은 아니다.
6. **남음:** callback 발신 주체의 신뢰 가능한 귀속, 명세/설정 출처를 자동으로
   검증하는 목적지 규칙 경로, 동일 배포 조건의 안전 쌍 반복 검증, Report의
   SSRF 전용 비용 표현, 공개/사설 OAST 반복 평가와 재시작 세션 복구.
   현재 canary가 없는 일반 대상에서 A/B callback만으로는 `SUSPECTED`이다.

2026-10-20 로컬 DynAST FastAPI 취약 앱에서 `auto/base-url`, agentic Recon,
heuristic Router·Analysis, 요청 상한 300으로 첫 실제 수직 슬라이스를 확인했다.
Recon이 `/api/fetch`의 URL 입력을 발견했고, callback A·B 각각 HTTP 1건,
별도 운영자 소유 임시 canary에 대한 앱 컨테이너의 GET 1건과 응답 marker가
Validation에서 재현되어 SSRF Finding 1개가 생성됐다(159/300 요청 사용).
canary 이름·URL은 실행자가 제공했으며 Agent 코드나 프롬프트에는 DynAST 정답을
고정하지 않았다. 임시 canary 컨테이너는 제거했다. 이 결과는 취약 앱 한 번의
양성 smoke test이다. 안전 버전 standalone에 대한 별도 smoke test도 수행했다:
52 Surface, SSRF Candidate 1개, Analysis HTTP callback 0건, SSRF Finding 0개,
131/300 요청 사용. 안전 버전용 canary는 도달 가능함을 사전 확인했고, 실행 후
임시 서버·컨테이너를 제거했다. 취약 버전은 Compose, 안전 버전은 standalone이므로
이 둘을 엄격한 동일 배포 조건의 성능 A/B로 주장하지 않는다. 공개/사설 OAST,
LLM SSRF 좌표 선택의 실제 반복 검증도 아직 남았다.

OAST 미선택 Run에는 Callback Capability를 등록하지 않는다. 다만 정확한 실행
승인과 Canary가 등록된 Surface에는 독립 Canary Capability를 등록할 수 있다.
CLI bridge는 설치된
`interactsh-client` 1.3.1의 `-json`·`-payload-store-file` 동작을 기준으로
구현했다. 현재 Provider 세션은 프로세스 내에서만 유지되므로 중단 후 같은 ticket
조회가 안 되면 검증 불가로 처리해야 한다. 로컬 수신기도 재시작을 가로지르는
ticket 영속성이 없다. 현재 모델
인터페이스는 JSON action이며 native function calling과
공용 Tool Broker/MCP는 별도 노션 계획의 후속 단계다. 두 관측 URL형 필드가 있는
경우 비선택 필드는 control/probe 양쪽에서 동일한 무해 값으로 고정한다.

## Callback Provider 선택

개발 중에는 fake Provider로 계약과 재개 동작을 검증한다. 공개 Interactsh는
명시적 선택·동의가 있어야 하며 기밀성 요구가 높으면 사설 서버를 사용한다.
Juice Shop과 같은 로컬 대상이라도
대상 프로세스·컨테이너에서 도달 가능한 주소, 신뢰 가능한 HTTPS 인증서, ticket별
HTTP 수신 조회 API가 필요하다. `127.0.0.1`은 요청을 보내는 대상 서버 자신을
가리킬 수 있으므로 callback 주소로 가정하지 않는다. `--ssrf-local-callback`은
운영 경로의 정책을 완화하지 않는, 같은 네트워크 공간의 로컬 프로세스 전용
실험 설정이다. Docker 대상이나 범용 원격 대상에는 바로 적용할 수 없다.

공개 request catcher는 수동 smoke test에는 쓸 수 있지만, 수신 기록의 접근 통제·
보존 기간·출처 귀속·API 안정성을 팀이 보장하지 못하면 자동 판정 Provider로
연결하지 않는다. 어느 방식이든 A/B 수신만으로 `CONFIRMED`를 만들지 않는다.

## 2026-10-21 current implementation contract

This section is the authoritative implementation status. Earlier milestone notes
describe how the branch evolved; where they differ, this section wins.

### Three separate conclusions

1. Recon classifies a URL-processing coordinate and stores
   `ssrf_url_fetch_review` with `REVIEW_REQUIRED`. It does not claim that an
   operator review or a network verification ran.
2. A callback or approved internal canary may prove a server-side request. The
   result remains `SUSPECTED` without an independently reproduced violation of a
   trusted destination policy for the exact Surface and destination origin.
3. `CONFIRMED` requires independent Analysis and Validation evidence plus the
   exact policy described below. Callback A/B alone is never a confirmed Finding.

CLI and Dashboard render Recon-only work as “Recon URL coordinates classified /
operator review pending / verification not performed / not used for testing yet”.
Only central `ssrf_review_registration` Evidence permits “operator review
registered”. Verification not performed is never rendered as “no vulnerability”.

### Independent callback, marker-canary and owned-receiver strategies

- `ssrf.callback_observed_url_query` / `observed_url_callback_probe`
- `ssrf.callback_declared_url_query` / `declared_url_callback_probe`
- `ssrf.internal_canary_observed_url_query` /
  `observed_url_internal_canary_probe`
- `ssrf.internal_canary_declared_url_query` /
  `declared_url_internal_canary_probe`
- `ssrf.internal_request_log_observed_url_query` /
  `observed_url_internal_request_log_probe`
- `ssrf.internal_request_log_declared_url_query` /
  `declared_url_internal_request_log_probe`

Callback capabilities require a callback Provider. Internal-canary capabilities
can run without it when an exact canary, execution approval and matching review
registration exist. Control/probe and Analysis/Validation Evidence remain separate.
A callback Provider failure does not invalidate an internal-canary result. Each
strategy reserves its own independent Validation requests before execution.
An internal canary does not require a destination policy: without one, a reproduced
server request remains `SUSPECTED`. CLI and Dashboard treat policy attestation as a
separate optional step and bind the canary directly to the selected Surface.

The marker-canary strategy proves a fetch only when an operator-supplied exact
marker occurs in the probe response body or response headers and not in the
control. A generic status change, `Location` value, redirect or reflected URL is
not proof. The blind owned-receiver strategy is a separate Port and requires an
explicitly injected service with `operator_owned=true`. It issues a fresh secret
ticket for Analysis A and Validation B and accepts only the receiver's inbound
HTTP log for that exact ticket after the centrally recorded target probe. Public
Interactsh is never promoted to this trust boundary merely because it implements
the same issue/poll methods. Receiver failure blocks only this strategy; it does
not invalidate a marker-canary or public callback result.

Both internal strategies still separate reachability from vulnerability. Fresh
A/B reproduction without a policy is `SUSPECTED`; `CONFIRMED` additionally needs
a trusted forbidden policy bound to the same Surface and normalized destination
origin. An Analysis-only observation also remains `SUSPECTED`, because the first
server request was observed even though independent reproduction is missing.

### Structured destination policy

Execution approval authorizes one exact Surface and opaque verification-service
reference. It does not assert that the destination is forbidden. A policy contains
`policy_id`, exact `surface_ids`, normalized `destination_origin`, a closed rule
and assertion, closed `source_type`, source-formatted `source_reference`,
`approved_by`, aware `created_at`, and `evidence_status` (`attested` or
`verified`). Canonical sources and reference prefixes are:

- `operator_attestation` / `operator:`
- `config_allowlist` / `config:`
- `openapi_allowlist` / `openapi:`

Manual CLI/Dashboard input may create only `operator_attestation`. A
`config_allowlist` or `openapi_allowlist` policy must come from a trusted Evidence
adapter that verified the referenced restriction; the HTTP form cannot assert one
by submitting a string.

An OpenAPI URL parameter declaration is not a policy. OpenAPI/configuration counts
only when it explicitly states a destination restriction. Confirmation requires a
forbidden rule, `target_must_not_reach_destination`, attested/verified evidence,
exact Surface binding and exact normalized origin match. An allowed rule is normal
behavior; missing or mismatched policy remains suspected.

### Destination intelligence and secret boundary

Recon stores only sanitized `destination_origin`, redacted `path_hint`, a run-keyed
non-reversible `destination_fingerprint`, provenance `source`, `host_kind`,
`observed=true`, and `probe_authorized=false`. Userinfo, query, fragment,
percent-encoded/high-entropy segments, UUID/JWT/API-key-like values and values after
sensitive path keywords are removed before Evidence creation. A hint never grants
probe authority.

Report facts contain counts, closed source/status values, flags and stable reason
codes; they never contain callback tokens, canary markers, full internal URLs,
credentials, OAST session data or unmasked destination data. The SSRF Analysis
LLM may receive only bounded aggregate hint metadata (count, closed provenance,
closed `host_kind`) and an already-redacted `path_hint`. It never receives an
origin, raw URL, exact execution endpoint, marker, credential or authorization to
probe a hint. CLI/Dashboard may show the same already-redacted Recon origin/path
hints to the local operator, explicitly marked “not probed”. A Recon hint remains
intelligence only and cannot by itself become an execution approval or destination
policy. CLI and Dashboard ask separately whether the operator wants to use a
selected hint as the exact canary destination. When the operator consents, the
supplied exact URL must match the hint's origin, redacted path and Run-scoped HMAC
fingerprint and the approval is bound to the selected Surface. A different
path/origin, a hint from another Run, or reuse on another Surface fails closed.
The exact URL is kept only in protected Run memory; Evidence stores the consent
flag and opaque references. Because secret-bearing path parts are redacted before
fingerprinting, such a hint cannot be bound back to its original secret URL; the
operator must decline hint use and provide a separate safe canary address.

Exact callback URLs/tokens and canary URLs/markers are protected before TaskStore,
progress-event and ordinary Evidence serialization. Reflected exact values are
removed recursively from observations and artifact references. The active Run
keeps only the material needed for execution in protected process memory; terminal
`DONE`/`FAILED` finalization purges the canary, callback tickets and buffered hits,
review-gate state and matching PolicyGate material. Persisted records keep opaque
references and sanitized evidence, not a resumable plaintext endpoint.

### Reported states and remaining limitations

Report, CLI and Dashboard distinguish untested; operator-review pending; callback
observed without policy proof; canary observed with policy pending; confirmed
policy violation; callback or observation Provider blocked; execution approval
pending; policy evidence pending; Validation budget insufficient; and
allowed-destination normal behavior.

Default CLI and Dashboard remain passive and start no local/public/private callback
Provider. Public Interactsh requires explicit third-party metadata consent. CLI
and Dashboard implement exact marker-canary URL entry, execution consent, optional
Recon-hint binding and optional operator policy attestation. The explicit
`--ssrf-owned-local-receiver` CLI option and Dashboard local-research checkbox
create an operator-owned receiver as a separate instance from the callback
Provider. Both require the post-Recon review gate and a second, exact-Surface
execution consent before the receiver strategy is registered; ordinary `auto`
runs never enable it. The generated ticket URL is not shown or persisted. A
production receiver adapter is still not configured automatically. Public/private
Interactsh round-trip testing is still outstanding, and in-memory
callback/observation sessions are not restart-persistent.

Implemented on this branch are the independent callback/marker-canary/
owned-receiver capabilities,
per-strategy Analysis and Validation evidence, two-request Validation reservation,
structured Surface/origin-bound destination policy, pre-Evidence destination
sanitization with Run-keyed HMAC fingerprints, masked LLM context, separated
callback/canary report states, exact opt-in Recon-hint binding, protected
task/progress serialization and terminal
secret cleanup. Remaining limitations are production callback-source attribution,
real public/private Interactsh and production owned-receiver round trips,
restart-safe protected Provider state,
automatic verification of trusted deployment/configuration policy sources, and
the first-version probe scope (observed GET query coordinates only; POST bodies,
redirect-chain testing, DNS rebinding, metadata services and arbitrary internal
network probing remain outside the automatic path).
