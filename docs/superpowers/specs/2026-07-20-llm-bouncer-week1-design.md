# llm-bouncer — Week 1 Design (core rail engine + input rails)

**Date:** 2026-07-20
**Status:** Approved
**Scope:** Week 1 only. Weeks 2–4 (MCP server, context/output rails, red-team harness, publishing) get their own specs later.

## Working agreement

- **Role split:** the toolkit author writes every line of code. Claude guides — explains concepts, reviews code, unblocks. Claude does **not** write the implementation. (Per the capstone rule: "Use AI to *explain* concepts, not to write your code.")
- This spec is the blueprint the author implements.

## Project facts

- **Repo root:** `/Users/miko/Bloc-it guardrail`
- **Distribution name:** `llm-bouncer` — **import package:** `llm_bouncer`
- **Demo victim app:** existing `rag-bot` at `/Users/miko/Documents/claude/Projects/MCP learining/rag-bot` (chromadb + Ollama RAG). Wired in Week 2, not Week 1.
- **Tooling:** `uv`, `pytest`, Python 3.14. `src/` layout, `pyproject.toml`.

## What Week 1 delivers

A `pip install -e .`-able library exposing a composable guardrail pipeline with three working input rails, a structured result type, an audit log, and a test suite. No MCP, no context/output rails, no red-team — those are later weeks.

## Architecture

```
user input
   │
   ▼
 Pipeline([ LengthRail, InjectionRail, SecretsRail ])
   │   run rails in order
   │   BLOCK      → short-circuit, return that RailResult
   │   TRANSFORM  → swap working text, continue
   │   ALLOW (all)→ return final text + list of per-rail results
   ▼
 audit log (one JSONL line per check)
```

### ADR-001 — API shape: composable `Pipeline` of `Rail` objects

**Decision:** A `Rail` is an object with `check(text) -> RailResult`. A `Pipeline` holds an ordered list of rails, runs them in sequence, short-circuits on the first BLOCK.

```python
pipe = Pipeline([LengthRail(max_len=2000), InjectionRail(), SecretsRail()])
result = pipe.check(user_input)
```

**Rejected:**
- *Flat functions* (`check_input(text, rails=[...])`) — dead-ends by Week 2; config + custom rails get ugly.
- *Decorator-first* (`@protect(...)`) — hides control flow, hard to extract verdict/audit, bad for MCP-server mode. Revisit as a Week-4 *adapter* layered on top of the pipeline.

**Why:** only the object pipeline survives all four weeks — MCP tools, red-team targets, and YAML config all bolt onto the same `Rail`/`Pipeline` contract. Full ADR: `docs/decisions/ADR-001-api-shape.md`.

### ADR-002 — verdict type: three-state `RailResult`

**Decision:** three verdicts — `ALLOW`, `BLOCK`, `TRANSFORM`. One dataclass used everywhere.

```python
class Verdict(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    TRANSFORM = "transform"

class Severity(Enum):
    LOW = "low"; MEDIUM = "medium"; HIGH = "high"; CRITICAL = "critical"

@dataclass
class RailResult:
    verdict: Verdict
    rail: str                    # which rail spoke, e.g. "injection"
    reason: str = ""             # human-readable why — feeds audit log + red-team report
    severity: Severity = Severity.LOW
    text: str | None = None      # set ONLY on TRANSFORM: the rewritten text
    metadata: dict = field(default_factory=dict)  # matched pattern, entropy score, etc.
```

**Rejected:** two-state allow/block — can't express rewriting rails (PII redaction, Week-2 context neutralization) without a later redesign.

**Why:** `TRANSFORM` covers redaction/neutralization for free. `severity` + `reason` + `rail` are exactly what the Week-3 report and audit log consume. Full ADR: `docs/decisions/ADR-002-verdict-type.md`.

### Pipeline aggregation rule (exact semantics)

1. `working_text = input`; `results = []`
2. For each rail in order:
   - `r = rail.check(working_text)`; append to `results`
   - `BLOCK` → stop, return `PipelineResult(blocked=True, final_text=None, blocking=r, results=results)`
   - `TRANSFORM` → `working_text = r.text`; continue
   - `ALLOW` → continue
3. All passed → return `PipelineResult(blocked=False, final_text=working_text, blocking=None, results=results)`
4. Write one audit line regardless of outcome.

(`PipelineResult` is a small container distinct from a single `RailResult` — decide its exact fields while implementing; must carry: blocked bool, final_text, the blocking result if any, full per-rail list.)

## The three input rails

### Rail 1 — `LengthRail` (+ rate)
- **Length:** `len(text) > max_len` → BLOCK, severity LOW. This is the "hello world" rail that proves the `Rail`/`Pipeline` contract end to end.
- **Rate:** in-memory `dict[key] -> list[timestamp]`, allow N calls per window. **Per-process only, not distributed** — documented as a known limit in an ADR (`ADR-003-rate-limit-scope.md`). No Redis (YAGNI).

### Rail 2 — `InjectionRail` (security core)
- **Week 1 = heuristics only.** A pattern pack (regex/keywords): "ignore previous instructions", "disregard the above", "you are now", "system prompt", role-override markers, etc.
- Match → BLOCK, severity HIGH, `metadata={"pattern": <matched>}`.
- **Patterns live in a YAML data file**, not hardcoded — mirrors the Week-3 attack-pack extensibility story.
- LLM classifier is a **stretch/ later**, not Week 1.
- **Author writes** both the attack-string list and the benign list — that is the core learning.

### Rail 3 — `SecretsRail`
- **Regex** for known shapes: AWS access key, generic API tokens, emails, credit-card-like digit runs.
- **Shannon entropy** check for high-entropy blobs (catches secrets that don't match a known shape).
- Match → BLOCK, or TRANSFORM(redact the span), severity HIGH/CRITICAL.
- Entropy is a concept Claude explains when reached; author codes the calculation.

## Audit log
- Every `Pipeline.check` appends **one JSONL line**: `timestamp`, `input_hash` (hash, **not** raw text — privacy), per-rail verdicts, final decision, blocking rail if any.
- JSONL = append-only, greppable, and directly consumable by the Week-3 report tooling.

## Package layout (target)
```
llm-bouncer/
├── pyproject.toml
├── src/llm_bouncer/
│   ├── __init__.py
│   ├── result.py          # Verdict, Severity, RailResult, PipelineResult
│   ├── pipeline.py        # Pipeline
│   ├── rails/
│   │   ├── base.py        # Rail protocol/base class
│   │   ├── length.py      # LengthRail (+ rate)
│   │   ├── injection.py   # InjectionRail
│   │   └── secrets.py     # SecretsRail
│   ├── audit.py           # JSONL audit logger
│   └── data/
│       └── injection_patterns.yaml
├── tests/
│   ├── test_length.py
│   ├── test_injection.py
│   ├── test_secrets.py
│   └── test_pipeline.py
└── docs/
    ├── decisions/         # ADRs
    └── superpowers/specs/ # this file
```

## Testing
- **Tests are the product's credibility.** One test file per rail: known-good (benign passes) + known-bad (attack blocks).
- Write test-first where sane (start each rail from its test).
- `test_pipeline.py` covers ordering, short-circuit on BLOCK, TRANSFORM text-swap, all-ALLOW passthrough.

## Week 1 acceptance criteria
1. `pip install -e .`, then a 5-line usage example runs and BLOCKs an obvious injection.
2. `pytest` green.
3. `InjectionRail` catches **≥8/10** hand-written attack strings, flags **0/10** benign strings.
4. Audit log writes one JSONL line per check, storing an input hash (not raw text).

## Suggested build order (each step reviewable)
1. Repo skeleton + `pyproject.toml` + `pip install -e .` works (empty package importable).
2. `result.py` — the enums + `RailResult` + `PipelineResult`. Test the dataclass defaults.
3. `rails/base.py` — the `Rail` contract.
4. `LengthRail` test-first → implement → green.
5. `Pipeline` test-first (using LengthRail) → implement → green.
6. `InjectionRail` + YAML pattern pack + attack/benign lists → green, hit ≥8/10 & 0/10.
7. `SecretsRail` (regex first, then entropy) → green.
8. `audit.py` JSONL logging wired into `Pipeline.check`.
9. Rate limiting into `LengthRail` (or its own rail) + ADR-003.
10. 5-line README demo proving acceptance #1.

## ADRs opened this week
- ADR-001 — API shape (Pipeline of Rail objects). **Decided.**
- ADR-002 — verdict type (three-state RailResult). **Decided.**
- ADR-003 — rate-limit scope (in-memory, per-process). **Decided, needs writeup.**
- Threat model table (attacker goal × entry point → OWASP LLM Top-10) — author drafts; becomes the feature backlog for later weeks.

## Out of scope for Week 1 (explicit)
MCP server, context rails, output rails, red-team harness, LLM-based rails, config YAML for enabling/disabling rails, Docker, publishing. All deferred to their own weekly specs.
