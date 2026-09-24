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

There are no runtime dependencies outside the Python 3.10+ standard library.
The default execution runtime rejects every external tool call. Real Recon,
Analysis, and Validation agents must be explicitly registered by the caller.

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
