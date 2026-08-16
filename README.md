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
