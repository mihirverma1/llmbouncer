# llm-bouncer Week 1 Implementation Plan (guided — you write the code)

> **How this plan works:** This is a *learning* build. You (the author) write every line of rail logic and every test. Each task gives you the interface, what the code must do, the concept behind it, the test intent, exact commands, and acceptance checks — **not** the solution. Claude reviews after each task. Boilerplate with no learning value (packaging, the dataclass already fixed in the spec) is provided verbatim so you don't retype it.

**Goal:** A `pip install -e .`-able `llm-bouncer` library with a composable rail pipeline, three input rails, a three-state result type, a JSONL audit log, and a passing test suite.

**Architecture:** `Rail` objects each expose `check(text) -> RailResult`. A `Pipeline` runs an ordered list, short-circuits on BLOCK, swaps text on TRANSFORM. Every check writes one audit line. See spec: `docs/superpowers/specs/2026-07-20-llm-bouncer-week1-design.md`.

**Tech Stack:** Python 3.14, `uv`, `pytest`, PyYAML. `src/` layout.

## Global Constraints
- Import package `llm_bouncer`; distribution name `llm-bouncer`.
- Python ≥ 3.11 (dataclasses, `str | None` unions, `Enum`). You have 3.14.
- Injection patterns live in a YAML data file, never hardcoded in `.py`.
- Audit log stores an **input hash, never raw input text**.
- TDD: test first, watch it fail, implement minimal, watch it pass, commit.
- Commit after every task. Public repo push is your call (not automated).
- No Redis / external services (YAGNI). No MCP, context/output rails, or red-team (later weeks).

## File structure (locked)
```
src/llm_bouncer/__init__.py        # exports: Pipeline, RailResult, Verdict, Severity
src/llm_bouncer/result.py          # Verdict, Severity, RailResult, PipelineResult
src/llm_bouncer/rails/base.py      # Rail base/protocol
src/llm_bouncer/rails/length.py    # LengthRail (+ rate)
src/llm_bouncer/rails/injection.py # InjectionRail
src/llm_bouncer/rails/secrets.py   # SecretsRail
src/llm_bouncer/audit.py           # JSONL audit logger
src/llm_bouncer/data/injection_patterns.yaml
tests/test_length.py  tests/test_pipeline.py  tests/test_injection.py  tests/test_secrets.py  tests/test_audit.py
```

---

### Task 1: Repo skeleton + editable install

**Files:** Create `pyproject.toml`, `src/llm_bouncer/__init__.py` (empty for now), `tests/__init__.py`.

**You get this boilerplate (no learning in retyping packaging):**
```toml
# pyproject.toml
[project]
name = "llm-bouncer"
version = "0.0.1"
description = "Drop-in guardrails for LLM and MCP apps"
requires-python = ">=3.11"
dependencies = ["pyyaml>=6.0"]

[project.optional-dependencies]
dev = ["pytest>=8.0"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/llm_bouncer"]
```

- [ ] **Step 1:** Create the files above. `__init__.py` empty.
- [ ] **Step 2:** `uv venv && source .venv/bin/activate`
- [ ] **Step 3:** `uv pip install -e ".[dev]"`
- [ ] **Step 4:** Verify: `python -c "import llm_bouncer; print('ok')"` → prints `ok`.
- [ ] **Step 5:** Commit: `git add -A && git commit -m "chore: package skeleton + editable install"`

**Acceptance:** package imports; `pytest` runs (0 tests) without collection error.

---

### Task 2: The result types (`result.py`)

**Files:** Create `src/llm_bouncer/result.py`, `tests/test_result.py`.

**Interfaces (produces — later tasks depend on these exact names):**
- `Verdict` enum: `ALLOW`, `BLOCK`, `TRANSFORM`
- `Severity` enum: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- `RailResult(verdict, rail, reason="", severity=Severity.LOW, text=None, metadata={})`
- `PipelineResult(blocked: bool, final_text: str | None, blocking: RailResult | None, results: list[RailResult])`

The `RailResult` dataclass body is fixed in the spec (ADR-002) — copy it. `PipelineResult` you design to the fields above (use `field(default_factory=...)` for the list; know *why* mutable defaults need it — that's the concept: shared-mutable-default trap).

- [ ] **Step 1 (test-first):** In `tests/test_result.py`, YOU write tests asserting: a default `RailResult(Verdict.ALLOW, "length")` has `severity==LOW`, `text is None`, `metadata=={}`; two separate `RailResult`s do **not** share the same `metadata` dict object (the mutable-default check).
- [ ] **Step 2:** Run `pytest tests/test_result.py -v` → FAIL (module missing).
- [ ] **Step 3:** Write `result.py`. Copy `RailResult` from the spec; define the two enums and `PipelineResult`.
- [ ] **Step 4:** `pytest tests/test_result.py -v` → PASS.
- [ ] **Step 5:** Commit `feat: result types (RailResult, PipelineResult, Verdict, Severity)`.

**Acceptance:** tests green; the two-instances-don't-share-metadata test passes.

---

### Task 3: The `Rail` contract (`rails/base.py`)

**Files:** Create `src/llm_bouncer/rails/__init__.py`, `src/llm_bouncer/rails/base.py`.

**Interface (produces):** `Rail` with `name: str` and `check(self, text: str) -> RailResult`.

**Concept to decide (your ADR-001 learning):** base class vs `typing.Protocol`. A base class can share helpers (e.g. a `_result(...)` factory); a Protocol is pure structural typing. Pick one, note why in ADR-001's Consequences.

- [ ] **Step 1:** Write `base.py` defining the contract. No test file of its own — it's exercised through the rails.
- [ ] **Step 2:** `python -c "from llm_bouncer.rails.base import Rail"` → no error.
- [ ] **Step 3:** Commit `feat: Rail base contract`.

**Acceptance:** importable; every later rail subclasses/satisfies it.

---

### Task 4: `LengthRail` (the "hello world" rail)

**Files:** Create `src/llm_bouncer/rails/length.py`, `tests/test_length.py`.

**Interface:** `LengthRail(max_len: int)`; `check(text)` → `BLOCK` severity `LOW` when `len(text) > max_len`, else `ALLOW`. Set `rail="length"`, a clear `reason`, and `metadata={"length": len(text), "max_len": max_len}`.

- [ ] **Step 1 (test-first):** YOU write `test_length.py`: a string over the limit → `verdict==BLOCK`; a string under → `verdict==ALLOW`; boundary (`len == max_len`) → `ALLOW` (decide `>` vs `>=` and test the exact boundary you chose).
- [ ] **Step 2:** `pytest tests/test_length.py -v` → FAIL.
- [ ] **Step 3:** Implement `LengthRail` (rate limiting comes in Task 9 — length only now).
- [ ] **Step 4:** `pytest tests/test_length.py -v` → PASS.
- [ ] **Step 5:** Commit `feat: LengthRail`.

**Acceptance:** all three cases pass; boundary behavior is explicit and tested.

---

### Task 5: `Pipeline` (`pipeline.py`)

**Files:** Create `src/llm_bouncer/pipeline.py`, `tests/test_pipeline.py`.

**Interface (produces):** `Pipeline(rails: list[Rail])`; `check(text: str) -> PipelineResult`. Semantics fixed in spec "Pipeline aggregation rule": run in order; first BLOCK short-circuits; TRANSFORM swaps working text and continues; all-ALLOW returns final text + full results list.

- [ ] **Step 1 (test-first):** YOU write `test_pipeline.py` using real `LengthRail` + a tiny fake rail you define in the test:
  - all-ALLOW → `blocked is False`, `final_text == input`, `len(results) == n`.
  - a rail BLOCKs → `blocked is True`, `blocking.rail` is that rail, and rails **after** it did NOT run (assert results length proves short-circuit).
  - a TRANSFORM rail (fake, returns `Verdict.TRANSFORM` with `text="X"`) → downstream rail sees `"X"`; `final_text` reflects the swap.
- [ ] **Step 2:** `pytest tests/test_pipeline.py -v` → FAIL.
- [ ] **Step 3:** Implement `Pipeline.check`.
- [ ] **Step 4:** `pytest tests/test_pipeline.py -v` → PASS.
- [ ] **Step 5:** Update `src/llm_bouncer/__init__.py` to export `Pipeline, RailResult, Verdict, Severity`. Commit `feat: Pipeline with short-circuit + transform`.

**Acceptance:** short-circuit and text-swap both proven by assertions, not just happy path.

---

### Task 6: `InjectionRail` + YAML pattern pack (security core)

**Files:** Create `src/llm_bouncer/rails/injection.py`, `src/llm_bouncer/data/injection_patterns.yaml`, `tests/test_injection.py`. Also create your two eval lists (in the test file or `tests/fixtures/`).

**Interface:** `InjectionRail(patterns_path=None)` — loads the YAML pattern pack (default to the bundled `data/injection_patterns.yaml`); `check(text)` → `BLOCK` severity `HIGH` with `metadata={"pattern": <the matched pattern>}` on match, else `ALLOW`. Match case-insensitively.

**Concepts:** load bundled data via `importlib.resources` (not a hardcoded filesystem path). Regex vs plain substring — decide and note the tradeoff (regex catches variants, costs readability). This is the OWASP **LLM01 Prompt Injection** rail.

- [ ] **Step 1:** Draft `injection_patterns.yaml` — start with 8–12 patterns (e.g. instruction-override phrasings, role reassignment, system-prompt fishing). YOU curate these; they are the intelligence of the rail.
- [ ] **Step 2:** Write your **eval sets**: ≥10 attack strings (should block) and ≥10 benign strings (must NOT block — include tricky-but-innocent ones like a user *quoting* the phrase in a question).
- [ ] **Step 3 (test-first):** `test_injection.py` loops both sets, asserts block-rate on attacks and zero blocks on benign. Assert the acceptance numbers directly (≥8/10 attacks, 0/10 benign).
- [ ] **Step 4:** `pytest tests/test_injection.py -v` → FAIL.
- [ ] **Step 5:** Implement `InjectionRail` (load YAML, match, report).
- [ ] **Step 6:** `pytest tests/test_injection.py -v` → PASS. If benign strings trip it, tighten patterns — over-blocking is a real failure mode (note it in the threat model).
- [ ] **Step 7:** Commit `feat: InjectionRail with YAML pattern pack`.

**Acceptance:** ≥8/10 attacks blocked, 0/10 benign blocked, patterns loaded from YAML via resource loader.

---

### Task 7: `SecretsRail` (regex → entropy)

**Files:** Create `src/llm_bouncer/rails/secrets.py`, `tests/test_secrets.py`.

**Interface:** `SecretsRail(redact=False)`; `check(text)`:
- Known shapes via regex (AWS access key `AKIA...`, generic long API tokens, email, card-like digit runs) → `BLOCK` (or `TRANSFORM` with redacted `text` when `redact=True`), severity `HIGH`/`CRITICAL`, `metadata={"kind": <what matched>}`.
- High-entropy blob check for secrets that match no known shape.

**Concept (Claude will explain when you reach it):** Shannon entropy `H = -Σ p(c)·log2 p(c)` over the character distribution of a token; high H ⇒ looks random ⇒ likely a secret. You pick a threshold and a minimum token length to avoid flagging short words, then justify both in a test.

- [ ] **Step 1 (test-first):** `test_secrets.py`: a fake AWS key string → BLOCK; an email → BLOCK; a normal English sentence → ALLOW; a random 40-char token → BLOCK via entropy; with `redact=True`, verdict is TRANSFORM and `text` no longer contains the secret.
- [ ] **Step 2:** `pytest tests/test_secrets.py -v` → FAIL.
- [ ] **Step 3:** Implement regex matches first; get those tests green.
- [ ] **Step 4:** Add the entropy function + threshold; make the entropy test green without breaking the benign-sentence test (tune threshold/min-length).
- [ ] **Step 5:** Commit `feat: SecretsRail (regex + entropy, optional redaction)`.

**Acceptance:** all cases green; benign prose does not false-positive; redaction removes the secret span.

---

### Task 8: Audit log (`audit.py`) wired into `Pipeline`

**Files:** Create `src/llm_bouncer/audit.py`, `tests/test_audit.py`. Modify `src/llm_bouncer/pipeline.py` (call the logger inside `check`).

**Interface:** `AuditLogger(path)` with `log(input_text, result: PipelineResult)` → appends ONE JSON object per line containing: `timestamp` (ISO), `input_hash` (e.g. sha256 of input — **never raw text**), `blocked`, `final_verdict`, per-rail `[{rail, verdict, severity}]`, and `blocking_rail` or null.

**Concept:** why hash not store raw — audit logs leak if they hold user prompts/secrets. JSONL because it's append-only and streamable to the Week-3 report.

- [ ] **Step 1 (test-first):** `test_audit.py`: run a `Pipeline` (with an injected temp log path, e.g. `tmp_path` fixture) on a blocking input; read the file back; assert exactly one line, valid JSON, `blocked is True`, and the raw input string is **absent** from the file contents.
- [ ] **Step 2:** `pytest tests/test_audit.py -v` → FAIL.
- [ ] **Step 3:** Implement `AuditLogger`; wire `Pipeline.check` to accept an optional logger and call it before returning. (Keep pipeline usable with no logger too.)
- [ ] **Step 4:** `pytest -v` (whole suite) → PASS.
- [ ] **Step 5:** Commit `feat: JSONL audit log wired into Pipeline`.

**Acceptance:** one JSONL line per check; raw input never written; existing tests still green.

---

### Task 9: Rate limiting + ADR-003 writeup

**Files:** Modify `src/llm_bouncer/rails/length.py` (or create `rails/rate.py` — your call; note the decision). Add tests to `tests/test_length.py` (or `tests/test_rate.py`). Fill in `docs/decisions/ADR-003-rate-limit-scope.md` Consequences.

**Interface:** rate check keyed by a caller-supplied `key` (e.g. user id); allow N calls per rolling window of S seconds; over limit → `BLOCK` severity `MEDIUM`, `metadata={"key":..., "window_s":..., "limit":...}`. In-memory `dict[key] -> list[timestamp]`, per-process (ADR-003).

**Concept:** rolling window = drop timestamps older than `now - S`, then count. Deterministic tests need injectable time — pass a `now`/clock function so tests don't `sleep`.

- [ ] **Step 1 (test-first):** with an injected clock: N calls pass, call N+1 in the same window BLOCKs, and a call after the window slides passes again.
- [ ] **Step 2:** `pytest -v` → FAIL on new tests.
- [ ] **Step 3:** Implement with injectable clock.
- [ ] **Step 4:** `pytest -v` → PASS.
- [ ] **Step 5:** Write ADR-003 Consequences (per-process caveat, future swap point). Commit `feat: in-memory rate limiting + ADR-003`.

**Acceptance:** window behavior proven with a fake clock (no `sleep`); ADR-003 complete.

---

### Task 10: README 5-line demo + acceptance sweep

**Files:** Create `README.md`. Optionally `examples/quickstart.py`.

- [ ] **Step 1:** Write the 5-line usage example (build a `Pipeline`, `check` an obvious injection, show it BLOCKs). Must actually run.
- [ ] **Step 2:** Run it: `python examples/quickstart.py` → prints a BLOCK verdict for the injection.
- [ ] **Step 3:** Full acceptance sweep — confirm all four Week-1 criteria:
  1. `uv pip install -e .` + 5-line demo blocks an obvious injection ✅
  2. `pytest` green ✅
  3. Injection ≥8/10 attacks, 0/10 benign ✅
  4. Audit writes one JSONL line, input hashed not raw ✅
- [ ] **Step 4:** README: quickstart, the ADR list, how to run tests. Commit `docs: README + quickstart, Week-1 acceptance met`.

**Acceptance:** a stranger can `git clone`, install, run the demo, and see a block — from the README alone.

---

## Threat model (parallel task — draft as you go)
Keep a running `docs/threat-model.md`: table of *attacker goal × entry point → OWASP LLM Top-10 item → which rail covers it*. Week 1 fills the input-side rows (LLM01 injection, secret exfil). Empty rows are your Week 2–4 backlog. Not gated by a test — but do it; it drives the whole project.

## Self-review (done by planner)
- Spec coverage: all Week-1 deliverables (engine, 3 input rails, result type, audit, tests, acceptance) map to Tasks 1–10. ✅
- Placeholder scan: no solution code withheld *by accident* — omissions are deliberate (your learning); every step states what the code must do + acceptance. ✅
- Type consistency: `RailResult`/`PipelineResult`/`Verdict`/`Severity` names identical across Tasks 2, 4–9. `check()` signature consistent. ✅
