# Graph Report - .  (2026-08-12)

## Corpus Check
- Corpus is ~6,759 words - fits in a single context window. You may not need a graph.

## Summary
- 441 nodes · 995 edges · 30 communities (27 shown, 3 thin omitted)
- Extraction: 93% EXTRACTED · 7% INFERRED · 0% AMBIGUOUS · INFERRED: 72 edges (avg confidence: 0.67)
- Token cost: 30,056 input · 0 output

## Community Hubs (Navigation)
- Orchestrator and Agent Contracts
- Reporting and Execution Adapters
- End-to-End Workflow Tests
- In-Memory Candidate Store
- Agent, Router, Budget Wiring
- Architecture Docs and Rationale
- Domain Models and Run Phases
- Budget/Memory Adapters, Port Errors
- Bootstrap and Retry Policy
- Task Records and Task Store Port
- Local Task Dispatcher and Retry
- Allowlist Policy Gate
- Execution Runtime Contracts
- Knowledge Plane
- Run Scope and Architecture Invariants
- In-Memory Budget Manager
- Rule-Based Vulnerability Router
- In-Memory Run Store
- Run State Machine
- In-Memory Evidence Store
- Routing and Domain Errors
- Disabled Execution Runtime
- Run Request Validation
- Validation Result and Finding Rules
- Store Duplicate-ID Guards
- In-Memory Finding Store
- In-Memory Task Store
- Dependency Direction Tests
- Package Entry Point
- Packaging Metadata

## God Nodes (most connected - your core abstractions)
1. `Run` - 43 edges
2. `DomainInvariantError` - 33 edges
3. `TaskEnvelope` - 32 edges
4. `Candidate` - 27 edges
5. `build_local_application()` - 23 edges
6. `Evidence` - 23 edges
7. `AgentResult` - 23 edges
8. `Orchestrator` - 21 edges
9. `AgentContractError` - 17 edges
10. `TaskRecord` - 17 edges

## Surprising Connections (you probably didn't know these)
- `Serena Project Config: 2026` --references--> `Hacklipse Research Architecture`  [INFERRED]
  .serena/project.yml → README.md
- `Python as sole project language` --conceptually_related_to--> `Standard-library-only constraint (Python 3.10+)`  [INFERRED]
  .serena/project.yml → README.md
- `RuntimeEvidenceCollector` --uses--> `AgentContractError`  [INFERRED]
  src/hacklipse/application/execution.py → src/hacklipse/application/errors.py
- `OrchestratorConfig` --uses--> `RunStateMachine`  [INFERRED]
  src/hacklipse/application/orchestrator.py → src/hacklipse/application/state_machine.py
- `Orchestrator` --uses--> `RunStateMachine`  [INFERRED]
  src/hacklipse/application/orchestrator.py → src/hacklipse/application/state_machine.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Five layers split by dependency direction** — readme_domain, readme_ports, readme_application, readme_adapters, readme_bootstrap [EXTRACTED 1.00]
- **Execution containment: deny-by-default runtime, explicit agent registration, safety boundary in adapters** — readme_deny_by_default_runtime, readme_explicit_agent_registration, readme_execution_safety_boundary, readme_bootstrap [INFERRED 0.85]

## Communities (30 total, 3 thin omitted)

### Community 0 - "Orchestrator and Agent Contracts"
Cohesion: 0.05
Nodes (44): AgentContractError, RuntimeError, Agent, Router, Runtime이 선언된 계약 밖의 데이터를 반환할 때 발생한다., Run 처리 중 특정 워크플로 단계가 실패했음을 외부에 전달한다., WorkflowExecutionError, 증적 요청을 검증하고 Runtime 결과를 append-only Evidence로 저장한다., Port를 통해 도메인 객체와 컴포넌트를 조정하는 사용 사례 계층., Orchestrator (+36 more)

### Community 1 - "Reporting and Execution Adapters"
Cohesion: 0.06
Nodes (30): InMemoryReportStore, Run별 ReportArtifact를 메모리에 보관한다., MarkdownReportAgent, 확정 Finding을 사람이 읽을 수 있는 Markdown으로 변환한다., 판정 변경이나 외부 요청 없이 confirmed Finding만 렌더링한다., Task에 지정된 Finding을 조회해 하나의 Markdown 산출물을 만든다., 외부 실행을 정책·예산·Evidence 저장 경계 안에서 수행한다., 모든 Runtime 결과를 먼저 Evidence로 바꾸는 정책 통제 Worker. (+22 more)

### Community 2 - "End-to-End Workflow Tests"
Cohesion: 0.10
Nodes (17): ConfirmingValidationFixtureAgent, EndToEndWorkflowTests, EvidenceSeekingValidationFixtureAgent, LocalFixtureRuntime, 외부 네트워크 없이 전체 워크플로 연결을 검증하는 통합 테스트., 첫 호출에는 추가 증적을 요구하고 두 번째 호출에 확정하는 대역., 네트워크 호출 없이 브라우저 실행 결과 형태만 반환하는 Runtime 대역., 정상 흐름과 추가 증적 분기가 끝까지 연결되는지 검사한다. (+9 more)

### Community 3 - "In-Memory Candidate Store"
Cohesion: 0.12
Nodes (9): InMemoryCandidateStore, Candidate의 분석·검증 진행 상태를 메모리에 보관한다., Evidence Observation을 규칙과 대조해 중복 없는 Candidate를 만든다., Candidate, 아직 독립 검증을 통과하지 않은 취약점 가설., 기존 순서를 유지하면서 중복 없이 Evidence 참조를 합친다., 분석·검증 진행 상태가 변경된 Candidate 복사본을 만든다., CandidateStore (+1 more)

### Community 4 - "Agent, Router, Budget Wiring"
Cohesion: 0.11
Nodes (12): Protocol, Agent 호출과 취약점 라우팅에 필요한 추상 계약., Application이 Agent 또는 Worker를 호출할 때 사용하는 유일한 경계., Observation을 Candidate와 담당 Analysis Agent 결정으로 변환한다., TaskDispatcher, VulnerabilityRouter, BudgetManager, Exception (+4 more)

### Community 5 - "Architecture Docs and Rationale"
Cohesion: 0.15
Nodes (17): Serena Project Config: 2026, Python as sole project language, adapters layer (local implementations), application layer (orchestration, state transition, task execution), bootstrap layer (composition root), Deny-by-default execution runtime, Split by dependency direction, domain layer (workflow vocabulary and invariants) (+9 more)

### Community 6 - "Domain Models and Run Phases"
Cohesion: 0.19
Nodes (15): datetime, Enum, 전체 Run 순서를 중앙 통제하되 세부 구현은 각 컴포넌트에 위임한다., AgentResultStatus, 시스템 전 계층이 공유하는 최소 도메인 모델과 핵심 불변식., Evidence 생성 시각을 비교 가능한 UTC 기준으로 반환한다., 한 번의 점검 Run이 거치는 상위 워크플로 상태., Task 저장소에서 관리하는 실행 생명주기. (+7 more)

### Community 7 - "Budget/Memory Adapters, Port Errors"
Cohesion: 0.18
Nodes (13): 외부 인프라 없이 Run별 요청 단위를 추적하는 예산 Adapter., 개발·테스트용 메모리 저장소 Adapter 모음., _save(), ArchitectureError, BudgetExceeded, DuplicateRecord, RuntimeError, Port와 Adapter 사이에서 공통으로 사용하는 계약 예외. (+5 more)

### Community 8 - "Bootstrap and Retry Policy"
Cohesion: 0.17
Nodes (13): MemoryStoreBundle, 로컬 조립 시 필요한 개별 메모리 저장소를 한 묶음으로 제공한다., BoundedRetryPolicy, Exception, 지정한 최대 시도 횟수 안에서 복구 가능한 오류만 재시도한다., 정책·예산·구성 오류를 제외한 실패의 재시도 가능 여부를 반환한다., build_local_application(), LocalApplication (+5 more)

### Community 9 - "Task Records and Task Store Port"
Cohesion: 0.19
Nodes (7): Application 계층에서 발생하는 워크플로·Agent 계약 예외., Task 저장, Dispatcher 호출, 재시도를 하나의 실행 경계로 묶는다., TaskEnvelope와 현재 실행 상태·시도 횟수를 함께 저장한다., 상태 갱신용 새 TaskRecord를 반환한다., TaskRecord, Task 실행 이력과 시도 상태를 관리하는 저장소 계약., TaskStore

### Community 10 - "Local Task Dispatcher and Retry"
Cohesion: 0.17
Nodes (8): LocalTaskDispatcher, 현재 프로세스 안에서 Agent를 선택·호출하는 Dispatcher Adapter., 로컬 개발과 테스트에 사용하는 프로세스 내부 Dispatcher., Agent 유형과 구현체를 한 번만 등록한다., Task의 agent_type에 맞는 구현을 찾아 호출한다., 실패 종류와 시도 횟수로 재실행을 제한하는 Retry Adapter., AgentUnavailable, 요청된 Agent 유형에 등록된 Worker가 없을 때 발생한다.

### Community 11 - "Allowlist Policy Gate"
Cohesion: 0.23
Nodes (8): AllowlistPolicyGate, URL allowlist와 안전 HTTP method를 검사하는 정책 Adapter., 네트워크 요청 없이 문자열 수준에서 대상 Scope를 강제한다., Run 시작 대상이 선언된 Scope 안에 있는지 검사한다., 실행 직전 Run 소유권, URL Scope, HTTP method 정책을 검사한다., URL의 scheme·host·path가 명시적 allowlist에 포함되는지 확인한다., PolicyViolation, Run 또는 실행 요청이 승인된 정책·Scope를 벗어날 때 발생한다.

### Community 12 - "Execution Runtime Contracts"
Cohesion: 0.20
Nodes (7): ExecutionRequest, ExecutionResult, 정책과 예산 검사를 거쳐 Execution Runtime으로 보낼 실행 요청., Runtime 실행 결과 중 Evidence로 변환할 데이터., 정책, 예산, 재시도처럼 Control Plane을 보조하는 계약., HTTP·브라우저·도구 실행을 캡슐화하는 외부 실행 계약., safe 정책에서 상태 변경 가능성이 있는 POST 실행을 막는다.

### Community 13 - "Knowledge Plane"
Cohesion: 0.24
Nodes (8): KnowledgeCase, KnowledgeQuery, 별도 Knowledge Plane에 전달하는 최소 검색 조건., 민감정보 제거·일반화 후 재사용할 수 있는 지식 단위., KnowledgeBase, Protocol, Evidence Store와 분리된 Knowledge Plane 검색·발행 계약., 대상 Evidence와 의도적으로 분리한 Knowledge Plane 경계.

### Community 14 - "Run Scope and Architecture Invariants"
Cohesion: 0.20
Nodes (7): 한 Run에서 접근이 허용된 호스트와 경로 범위., RunScope, ArchitectureInvariantTests, 허용되지 않은 호스트는 Run이나 Task 생성 전에 거부한다., Runtime 미설정 상태에서는 외부 도구가 절대 실행되지 않아야 한다., INIT에서 DONE으로 건너뛰는 잘못된 상태 전이를 차단한다., 구현체가 바뀌어도 유지되어야 하는 규칙을 검사한다.

### Community 15 - "In-Memory Budget Manager"
Cohesion: 0.28
Nodes (5): InMemoryBudgetManager, 최소 요청 단위만 계산하며 향후 비용·시간 기반 구현으로 교체할 수 있다., 예산을 사용하는 Task를 시작할 최소 잔여량이 있는지 확인한다., 실제 외부 실행에 사용한 예산 단위를 차감한다., Run에 남아 있는 요청 단위를 반환한다.

### Community 16 - "Rule-Based Vulnerability Router"
Cohesion: 0.25
Nodes (6): 아키텍처 Port를 만족하는 교체 가능한 로컬 구현체를 공개한다., Observation 유형 하나에 대응하는 취약점 유형·Agent·우선순위., 결정적인 초기 Router이며 모호한 사례는 향후 다른 구현으로 교체할 수 있다., RoutingRule, RuleBasedVulnerabilityRouter, 아키텍처의 핵심 안전 규칙과 도메인 불변식을 검증한다.

### Community 17 - "In-Memory Run Store"
Cohesion: 0.22
Nodes (4): _get(), InMemoryRunStore, Run 상태를 프로세스 메모리에 보관한다., 저장된 객체가 호출자에게서 변경되지 않도록 복사본을 반환한다.

### Community 18 - "Run State Machine"
Cohesion: 0.25
Nodes (6): Exception, Run 상태 전이 규칙을 워크플로 실행 코드와 분리한다., 허용된 전이인지 검사한 뒤 새로운 Run 상태를 반환한다., 활성 Run을 FAILED로 전환하고 원인을 보존한다., 상태 전이 규칙만 담당하며 Agent 호출이나 저장은 수행하지 않는다., RunStateMachine

### Community 19 - "In-Memory Evidence Store"
Cohesion: 0.25
Nodes (4): InMemoryEvidenceStore, Evidence를 덮어쓰지 않고 추가하며 Run 범위로만 읽게 한다., 새 Evidence ID만 추가하고 기존 Evidence 수정은 허용하지 않는다., Evidence가 요청한 Run에 속할 때만 반환한다.

### Community 20 - "Routing and Domain Errors"
Cohesion: 0.29
Nodes (5): Observation 유형을 전문 Analysis Agent로 연결하는 규칙 기반 Router., 도메인 불변식 위반을 표현하는 공통 예외., 인프라에 의존하지 않는 핵심 도메인 타입과 불변식을 공개한다., Router가 생성한 Candidate와 분석 우선순위., RouteDecision

### Community 21 - "Disabled Execution Runtime"
Cohesion: 0.29
Nodes (6): DisabledExecutionRuntime, 외부 실행 Port의 안전한 기본 구현., 어떠한 네트워크·도구 실행도 하지 않고 명시적 예외를 발생시킨다., Runtime이 명시적으로 주입되기 전에는 모든 외부 실행을 거부한다., ExternalExecutionDisabled, 안전한 기본 Runtime이 외부 실행을 거부했음을 나타낸다.

### Community 22 - "Run Request Validation"
Cohesion: 0.32
Nodes (6): DomainInvariantError, 시스템의 핵심 도메인 규칙을 위반하려 할 때 발생한다., Finding, Validation을 통과하여 보고 가능한 확정 취약점., 사용자가 새로운 점검 Run을 시작할 때 전달하는 입력., RunRequest

### Community 23 - "Validation Result and Finding Rules"
Cohesion: 0.32
Nodes (5): Candidate에 대한 독립 검증 결과와 근거 Evidence., 검증된 Candidate만 Finding으로 승격한다., ValidationResult, suspected 판정은 Finding으로 승격할 수 없어야 한다., confirmed라도 근거 Evidence가 없으면 Finding 생성이 실패해야 한다.

### Community 24 - "Store Duplicate-ID Guards"
Cohesion: 0.29
Nodes (3): _add(), 중복 ID를 거부하고 외부 변경을 막기 위해 복사본을 저장한다., ValueError

### Community 26 - "In-Memory Task Store"
Cohesion: 0.33
Nodes (3): InMemoryTaskStore, Task 생명주기와 시도 이력을 입력 순서대로 보관한다., 특정 Run에 속한 Task만 등록 순서대로 반환한다.

### Community 27 - "Dependency Direction Tests"
Cohesion: 0.33
Nodes (4): DependencyDirectionTests, 핵심 계층이 외부 구현 계층을 역참조하지 않는지 정적으로 검사한다., AST import 목록을 이용해 단방향 의존 규칙을 검증한다., domain·ports·application이 자신보다 바깥 계층을 import하지 않아야 한다.

## Knowledge Gaps
- **5 isolated node(s):** `hacklipse`, `Serena Project Config: 2026`, `Python as sole project language`, `Notion 상세구현 보충 (detailed implementation supplement)`, `Local verification suite (unittest discover -s tests)`
  These have ≤1 connection - possible missing edges or undocumented components.
- **3 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Run` connect `Orchestrator and Agent Contracts` to `Reporting and Execution Adapters`, `In-Memory Candidate Store`, `Agent, Router, Budget Wiring`, `Domain Models and Run Phases`, `Budget/Memory Adapters, Port Errors`, `Allowlist Policy Gate`, `Execution Runtime Contracts`, `Run Scope and Architecture Invariants`, `In-Memory Run Store`, `Run State Machine`, `Routing and Domain Errors`, `Run Request Validation`?**
  _High betweenness centrality (0.129) - this node is a cross-community bridge._
- **Why does `Candidate` connect `In-Memory Candidate Store` to `Orchestrator and Agent Contracts`, `Reporting and Execution Adapters`, `Domain Models and Run Phases`, `Budget/Memory Adapters, Port Errors`, `Routing and Domain Errors`, `Run Request Validation`, `Validation Result and Finding Rules`?**
  _High betweenness centrality (0.070) - this node is a cross-community bridge._
- **Why does `DomainInvariantError` connect `Run Request Validation` to `Orchestrator and Agent Contracts`, `Reporting and Execution Adapters`, `In-Memory Candidate Store`, `Domain Models and Run Phases`, `Task Records and Task Store Port`, `Execution Runtime Contracts`, `Knowledge Plane`, `Run Scope and Architecture Invariants`, `Run State Machine`, `Routing and Domain Errors`, `Validation Result and Finding Rules`, `Store Duplicate-ID Guards`?**
  _High betweenness centrality (0.062) - this node is a cross-community bridge._
- **Are the 3 inferred relationships involving `Run` (e.g. with `DomainInvariantError` and `.test_safe_policy_rejects_state_changing_execution()`) actually correct?**
  _`Run` has 3 INFERRED edges - model-reasoned connections that need verification._
- **Are the 21 inferred relationships involving `DomainInvariantError` (e.g. with `AgentResult` and `AgentResultStatus`) actually correct?**
  _`DomainInvariantError` has 21 INFERRED edges - model-reasoned connections that need verification._
- **Are the 3 inferred relationships involving `Candidate` (e.g. with `DomainInvariantError` and `.test_confirmed_finding_requires_supporting_evidence()`) actually correct?**
  _`Candidate` has 3 INFERRED edges - model-reasoned connections that need verification._
- **What connects `hacklipse`, `Serena Project Config: 2026`, `Python as sole project language` to the rest of the system?**
  _5 weakly-connected nodes found - possible documentation gaps or missing edges._