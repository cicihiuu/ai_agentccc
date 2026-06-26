# Delivery Contents

This package is trimmed for handoff and should be delivered as the standalone `python_mvp/` module package.

## Must Deliver

- `src/ai_security_agent/`
  - main package code
  - `d_side/` contains the packaged D-side implementation
  - `modules/` contains the bridge points used by the rest of the MVP
  - `agent/` contains runtime, state store, and plan execution support
  - `api/` contains the local workbench service and static UI
- `tests/`
  - regression checks for packaged modules, runtime, orchestrator, report, and schemas
- `fixtures/demo_run.json`
  - fixture replay input for non-live demonstration
- `profiles/`
  - example execution profiles
- `skills/`
  - module skill declarations used by the packaged runtime
- `scripts/start_pikachu.ps1`
  - local target/lab startup helper
- `scripts/start_workbench.ps1`
  - local workbench startup helper
- `run_demo.py`
  - simple CLI entry
- `requirements.txt`
  - minimal dependency list
- `README.md`
  - run and test instructions
- `DELIVERY_CONTENTS.md`
  - delivery scope and directory explanation

## D-Side Implementation Included

The packaged D-side flow in `src/ai_security_agent/d_side/` covers:

- bounded recon
- bounded backup acquisition
- controlled archive handling
- lightweight static audit
- structured follow-up summary generation
- workflow context synchronization
- workflow state persistence and restore
- downstream consumer-input handoff for SQL, JS, and POC modules

## Not Included On Purpose

- local virtual environment files
- IDE metadata
- Python bytecode caches
- previously generated reports
- previously generated run-state snapshots
- background planning and course-analysis documents that are not required to run or extend the package

## Handoff Guidance

The receiver should treat `src/ai_security_agent/d_side/` as the packaged D-side implementation surface and `src/ai_security_agent/orchestrator.py` plus `src/ai_security_agent/agent/runtime.py` as the main integration points into the wider MVP flow.
