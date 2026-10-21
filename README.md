# Hacklipse research architecture

This repository contains the executable architecture skeleton for the research
project. The current source of truth is the Notion
[연구과제](https://app.notion.com/p/3876dc1c5ab5807aaaa9c2cf45bd90b9)
page, especially
[상세구현 보충](https://app.notion.com/p/3b86dc1c5ab580e7b764c99d53851812).
This README intentionally does not duplicate that specification.

The code is split by dependency direction:

- `domain`: stable workflow vocabulary and invariants
- `ports`: replaceable component contracts
- `application`: orchestration, state transition, and task execution
- `adapters`: local implementations for dispatch, policy, storage, routing,
  reporting, budgets, retries, and the execution safety boundary
- `bootstrap`: composition root; this is the only place that assembles adapters

The core uses the Python 3.10+ standard library; Recon and browser adapters
also require the packages listed in `pyproject.toml`.
The default execution runtime rejects every external tool call. Real Recon,
Analysis, and Validation agents must be explicitly registered by the caller.

Juice Shop runs default to 20 requests for one vulnerability type and 80 for
discovery or all-type scans. Larger experiments must set `--request-budget`
explicitly; the Dashboard accepts an explicit budget up to 500. For benchmark
runs, pass `--code-version` (or fill in **Code version** in the Dashboard).
The run profile and JSONL result record that label, execution modes, approval
and authentication flags, request ceiling, and requests used. Compare runs
under the same budget and target state.
Router analysis deltas require two completed, independent runs with matching
Recon inputs, execution conditions, and a nonempty matching code version. A
different Router mode is the intended comparison axis; changing code versions
requires a separate experiment. Authentication is recorded only as a flag, so
the operator must still verify the same principal and target state externally.

Agentic Recon limits LLM decisions to three calls of at most 15 seconds each,
using the task's remaining time for each call. It then visits remaining safe
surfaces in deterministic order and records unvisited surface IDs and the stop
reason. Its collection summary separates attempted URLs, HTTP responses,
successful fetches, and parsed responses. POST Path Traversal probes remain
unavailable until a verified normal request template and safe proof target
exist. Stored POST candidates are blocked without sending a synthesized request.

Recon prioritizes application/page/layout chunks over framework runtime scripts,
within a limit of eight scripts and the existing crawl budget. Pass
`--browser-recon` to either CLI runner, or enable **브라우저 Recon** in the
Dashboard, to also inspect Chromium-rendered links and SPA routes, menus, tabs,
detail/edit controls, filters, and forms. Install Chromium once with
`.venv/bin/python -m playwright install chromium`.

Browser Recon intercepts fetch/XHR and page resources. Each actual HTTP request,
including redirect hops, passes through the shared Collector's policy, budget,
session, sanitizer and audit log. It restricts traffic to the exact target origin
and Run path scope; service workers, WebSockets and binary/streaming resources
are blocked. Static assets may be reused in memory during a browser session.
The browser gets the remaining Recon share (at most half the Task request
budget), up to six page visits, twelve UI actions and 45 seconds. These are
bounded discovery limits, not a claim of exhaustive UI coverage.

Form inspection uses neutral inputs and captures attempted method, content type,
and query/body field names. Mutating requests are aborted before transmission;
their evidence says `sent=false`. Body values, credentials and tokens are not
stored in request-shape observations. These observations do not constitute a
verified normal POST template and do not enable POST Path Traversal probes.
The browser option is persisted in the Run profile and comparison logs, and its
summary distinguishes partial/unavailable/budget-limited discovery.
On visited HTML pages without a query or existing fragment, browser Recon may
check whether a harmless hash marker reaches the DOM. Such an active observation
creates a client Surface; XSS Analysis checks reflection and independent
Validation must reproduce script execution before a Finding is confirmed.
Browser XSS page dependencies also pass through the shared Collector and consume
the Run request budget; mutating subrequests are blocked.

For a local benchmark smoke (replace the URL with `dynast-bench target nextjs`):

```bash
.venv/bin/python scripts/run_dynast_baseline.py http://127.0.0.1:13322/ \
  --code-version YOUR_CODE_VERSION
```

The DynAST runner defaults to `auto/base-url`, browser Recon enabled, heuristic
Recon/Router/Analysis and a request ceiling of 80. It writes a unique Markdown
report and JSONL log per run under `artifacts/dynast-bench/`; `--report-out` and
`--routing-log` override these paths. Use `--no-browser-recon` for a static crawl.
The existing LLM, budget and approval options remain available. The entry point
shares the common auto workflow but rejects targeted modes and account/database
setup options. It does not start/reset the benchmark or read its answer keys;
prepare the app with the DynAST CLI first. These artifacts are diagnostic reports,
not DynAST scorer-format exports.
The CLI and routing log report Analyzer capability gaps in heuristic runs too;
a zero-Candidate result can mean that the discovered surfaces have no supported
input coordinate, even when browser Recon collected pages successfully.

Run the local verification suite with:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The Juice Shop runner accepts `--orchestrator hybrid` as an independent LLM
option. After routing, the advisor may select one already discovered, unread,
same-scope GET page for an extra Recon visit. The application checks the
selected surface and remaining request budget, persists the choice for resume,
and continues normally when the model fails or returns an invalid choice. The
default `--orchestrator heuristic` keeps the existing one-pass workflow.

Both local runners also accept `--report {heuristic,llm}`. The default renders
the deterministic v2 facts report; `llm` appends a bounded, non-authoritative
narrative and falls back to the same facts when the model fails. Narrative
calls, tokens, elapsed time, fallback status, and rejected sentences are
recorded without generated prose in the run-result JSONL, alongside the
`report_facts_hash` the report itself printed, which identifies the facts both
modes rendered.

The v2 report opens with the run's non-sensitive execution conditions -- analysis
profile, recon, router, orchestrator, validation and report modes, and the LLM
provider and model -- read from the `RunExecutionProfile` persisted with the run.
A run restored from a database written before those conditions were recorded says
so instead of printing the defaults. These conditions are rendered only; they are
never added to the narrator's facts, because the allowed narrator inputs are a
closed list that does not include them.

The v2 facts also carry the run's LLM call count and token totals as measured up
to the moment the report is built. The narrative's own call is deliberately not
counted: the facts are collected before the narrator runs, which is what keeps
them identical whether or not the narrator is attached. A run with no usage
meter reports the counts as unknown rather than zero, so "the LLM was off" and
"nothing measured it" stay distinguishable.

`scripts/compare_reports.py` measures the narrator off/on axis. `replay` renders
both reports from a fixed fixture without contacting a target or a provider, and
`--failure` injects each narrator failure to measure the fallback path. `logs`
compares the latest completed run of each mode only when the recorded non-report
execution conditions and request budget match. Its fallback and rejected-sentence
rates include only runs with matching conditions and the same report model. Both report
fact preservation, offered-set citation containment, status representation, and
narrator cost. Neither establishes semantic accuracy: the fixed-fixture human
blind review that the measurement contract also requires is not part of this
tool. Keep the target and its state fixed when collecting the runs.

# Arbitrary File Read detector

The `Arbitrary File Read` agent proves that a server opens a path it was not
meant to serve. The `Path Traversal` agent stays separate and proves a different
fact — that the server follows an escape sequence it was handed.

It works three ways, all on observed GET coordinates:

- an observed query input, carrying the fixed absolute proof path;
- a path that carries its input as `name=value` (`/file=web_assets/app.js`),
  replacing only the span the value occupies, never appending a query;
- when the absolute path is refused, a read that leaves the directory the
  observed values live in. That one escalation is why a target which rejects
  both the escape sequence and the absolute path can still be proven.

The file to read is fixed per probe kind in the domain, so neither an agent nor
a model can choose another one, and only a marker seen in the probe and absent
from the control confirms. Validation repeats the pair independently. Analyzer
and module docstrings carry the probe contract and the cases it cannot reach;
bodies of any kind are the main one.

Run the common pipeline against an authorized local application:

```bash
python scripts/run_baseline.py 'http://127.0.0.1:8000/download?file=sample' 80
```

Being merged in from `feat/arbitrary-file-read-detection-plan`: a table of
probe values (relative depths and encoded forms beside the absolute path), a
coordinate that replaces one path segment, and a check of whether the proof
file is already public on the same origin. Until those land the agent sends one
value per coordinate, reaches no path-segment input, and does not check whether
the file was public to begin with.
