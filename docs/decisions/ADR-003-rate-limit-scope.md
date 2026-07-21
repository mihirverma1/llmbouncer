# ADR-003 — Rate limiting: in-memory, per-process

**Status:** Accepted — 2026-07-20

## Context
The length/rate rail needs to cap calls per key per time window. Full distributed rate limiting (shared across processes/hosts) needs external state (e.g. Redis).

## Options considered
1. **In-memory** `dict[key] -> list[timestamp]`, per-process.
2. **Redis / external store**, shared across processes.

## Decision
Option 1 for Week 1. Documented limitation: counters reset on restart and are **not** shared across processes — not suitable for multi-worker production as-is.

## Consequences
- (Author: fill in — simplicity vs. the explicit production caveat; where a future swap point would live.)

<!-- Author: expand while implementing. YAGNI on Redis until a real deployment needs it. -->
