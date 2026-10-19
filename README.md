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

The standard `Arbitrary File Read` analysis agent probes observed GET query inputs
and file-serving URL path segments with approved, non-sensitive local-file
targets. It compares a control response
with the file probe, then independently repeats the pair during validation.
Validation also checks whether the proof file is directly public on the same
origin.
Only that reproduction can create an `arbitrary_file_read` proof and a finding.
The existing `Path Traversal` agent and proof remain separate.

Run the common pipeline against an authorized local application:

```bash
python scripts/run_baseline.py 'http://127.0.0.1:8000/download?file=sample' 80
```

The defaults probe a bounded set of absolute, relative-depth, and encoded forms
of `/etc/os-release`. Keep target startup and scoring outside the detector
process.

The common local runner accepts only `localhost` and `127.0.0.1`. The execution policy
allows one configured proof path per request and the stored evidence omits file
contents. The detector preserves observed query options, mutates one declared
input at a time, shares controls across proof targets, and retries independently
observed signals during validation. It handles GET query and selected file-serving
path inputs. Validation reason codes are retained on non-confirmed candidates and
included in the JSON summary; verified POST templates and JSON bodies remain future
work. The detector is included in `standard_router()` alongside the other implemented
analysis pipelines and does not require a vulnerability-specific runner.
