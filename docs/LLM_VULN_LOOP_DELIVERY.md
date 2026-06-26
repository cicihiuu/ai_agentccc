# LLM Vulnerability Discovery Loop Delivery

## Outcome

The v2 system has been upgraded from a v2-only multi-step scanner into a regression-tested LLM-guided vulnerability discovery loop:

```text
observation -> hypothesis -> action -> tool execution -> feedback -> replanning -> verification -> verified-only report
```

The implementation keeps the existing rule engine as fallback/guardrail, but the main execution path now exposes skill-guided prompts, decision telemetry, atomic tools, child-agent contributions, progress guards, category-specific verification gates, benchmark coverage, and delivery-grade report artifacts.

## Core Components

- Main loop:
  - `src/ai_security_agent/v2/engine.py`
  - `StepPromptBuilder`
  - `DecisionRecord` progress/stagnation telemetry
  - fallback taxonomy and stagnation guard
- Skill strategy layer:
  - `src/ai_security_agent/v2/skills.py`
  - `SkillCard` strategy package fields
  - child task policies and output contracts
- Atomic tools:
  - `src/ai_security_agent/v2/tools.py`
  - HTTP/HTML/JS extraction
  - browser action state machine
  - session/auth replay
  - SSRF probe helpers
  - SQL/POC bridge compatibility
- Child agents:
  - `src/ai_security_agent/v2/service.py`
  - backup, JS-derived API, XSS, and auth differential child loops
  - child `recommended_next_tests` routed back into main step context
- Verification/reporting:
  - `src/ai_security_agent/v2/service.py`
  - `src/ai_security_agent/v2/reporting.py`
  - verified-only report gate
  - evidence completeness, proof source, proof type, promotion reason
- UI/API:
  - `src/ai_security_agent/api/static/index.html`
  - v2 snapshot includes `coverage_metrics`
  - report JSON/HTML/PDF includes benchmark summary

## Implemented Capabilities

### LLM-guided step execution

Each step can build a skill-specific prompt with:

- target and step goal
- allowed tools
- verification requirements
- success criteria
- stop conditions
- false-positive rules
- recent observations and leads
- verification gap
- replan hints after no-progress rounds

### Progress and fallback guardrails

Decision records capture:

- skill and step name
- input summary
- observation references
- verification goal
- confidence and stop candidate
- progress score
- stagnation rounds
- duplicate action ratio
- fallback reason

Standard fallback reasons include:

- `llm_unavailable`
- `missing_api_key`
- `provider_timeout`
- `provider_rate_limited`
- `invalid_json`
- `empty_decision`
- `tool_not_allowed`
- `stagnation_guard_triggered`

### Atomic tool coverage

Implemented and regression-tested tool contracts include:

- `extract_links_from_html`
- `extract_forms_from_html`
- `extract_parameters_from_response`
- `replay_request_with_mutation`
- `extract_js_endpoints`
- `extract_fetch_calls`
- `extract_dom_sinks`
- `map_source_routes`
- `save_session`
- `load_session`
- `switch_session`
- `clone_session`
- `same_request_different_session_replay`
- `build_ssrf_probe_set`
- `parser_confusion_probe`
- browser actions: `goto`, `fill`, `submit`, `execute_js`, `get_dom`, `get_console_logs`, `get_network_events`, `screenshot`

### Child-agent loop and feedback

Child agents now emit structured output contexts:

- `recommended_next_tests`
- `endpoint_seeds`
- `route_candidates`
- `session_seeds`
- `xss_probe_urls`
- verified finding IDs

Main steps receive completed child contributions through `step_contexts["child_contributions"]`. `poc_verify` is regression-tested to consume child recommendations in its generated verification case.

### Verification gate

Formal reports remain verified-only. Category-specific gates reject weak evidence:

- XSS requires browser/DOM/execution-context evidence, not reflection alone.
- Auth requires identity-bound differential evidence.
- SSRF requires callback/OOB or trusted side channel.
- SQL requires boolean/time/docker/strategy/differential proof.
- Backup/config evidence is normalized and sensitive samples remain masked.

### Benchmark acceptance

Benchmark manifest:

- `fixtures/v2_benchmark_manifest.json`

CI acceptance covers:

- SQL
- XSS
- Auth
- SSRF
- Backup/JS/Config

The fixture benchmark asserts expected steps, child agents, tools, verified categories, fallback ceilings, round ceilings, and report fields.

## Report Artifacts

Generated report payload includes:

- `execution_summary`
- `coverage_metrics`
- `benchmark_summary`
- `verified_findings`
- `verification_records`
- `attack_paths`
- `appendix.unverified_leads`

HTML/PDF reports render the benchmark summary alongside execution details.

## Validation Commands

Fast targeted regression:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_v2_engine tests.test_v2_api tests.test_api_app tests.test_frontend_static tests.test_v2_tools -v
```

Full regression:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Current full baseline:

```text
71 tests, OK
```

## Current Limits

- Browser execution is a lightweight stateful backend suitable for CI and deterministic evidence flow; it is not yet Playwright/Chromium-backed.
- Real LLM provider smoke depends on external API credentials such as `DEEPSEEK_API_KEY`.
- SQL deep rules are preserved and partially wrapped as structured tools; further decomposition is possible but not required for current acceptance.
- The benchmark target is a deterministic fixture harness, not a deployed multi-container public lab.

## Final Acceptance Status

The current implementation satisfies the original landing goal for a demonstrable LLM vulnerability discovery loop:

- multi-step main Agent
- dynamic child Agents
- skill-guided prompts
- atomic tool layer
- no-progress detection
- fallback taxonomy
- child feedback consumption
- verified-only reporting
- benchmark coverage metrics
- HTML/PDF/JSON report artifacts
- full regression suite passing
