# ADR-001 — Public API shape: composable Pipeline of Rail objects

**Status:** Accepted — 2026-07-20

## Context
The toolkit needs a public API that survives four weeks of growth: input rails now, then context/output rails, an MCP server exposing rails as tools, a red-team harness targeting rails, and YAML-driven config. The shape chosen on day 1 constrains all of that.

## Options considered
1. **Composable `Pipeline` of `Rail` objects** — each rail is an object with `check(text) -> RailResult`; a `Pipeline` runs an ordered list and short-circuits on BLOCK.
2. **Flat functions** — `check_input(text, rails=["length", "injection"])`.
3. **Decorator-first** — `@guardrails.protect(rails=[...])` wrapping the user's call.

## Decision
Option 1.

## Consequences
- (Author: fill in — pluggability, custom rails, testability per rail, config mapping, MCP tool mapping. Note the upfront cost of a base class/protocol.)
- Decorator style is not dropped — revisit in Week 4 as an *adapter* built on top of the pipeline.

<!-- Author: expand Consequences and add any trade-offs you hit while implementing. -->
