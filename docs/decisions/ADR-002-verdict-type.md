# ADR-002 — Rail verdict type: three-state RailResult

**Status:** Accepted — 2026-07-20

## Context
Every rail must report a verdict in one uniform shape, because the audit log, the pipeline aggregation logic, and (later) the red-team report all consume it. Some rails don't just pass/fail — they rewrite text (PII redaction now, context neutralization in Week 2).

## Options considered
1. **Two-state:** `ALLOW` / `BLOCK`.
2. **Three-state:** `ALLOW` / `BLOCK` / `TRANSFORM` — TRANSFORM carries rewritten text forward.

## Decision
Option 2 (three-state), with a single `RailResult` dataclass: `verdict, rail, reason, severity, text (TRANSFORM only), metadata`.

## Consequences
- (Author: fill in — TRANSFORM enables redaction/neutralization with no later redesign; severity/reason/rail feed audit + report directly. Note any cost of the extra state in pipeline logic.)

<!-- Author: expand while implementing. -->
