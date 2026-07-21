"""Result types shared by every rail and the pipeline.

See docs/design-notes.md ("result.py") for the reasoning behind these shapes —
the three-verdict design, string enum values, and the mutable-default trap.
"""

from dataclasses import dataclass, field
from enum import Enum


class Verdict(Enum):
    """What a rail decided about a piece of text."""

    ALLOW = "allow"
    BLOCK = "block"
    TRANSFORM = "transform"  # rewritten text carried in RailResult.text


class Severity(Enum):
    """Triage rank for a finding. Reporting only — does not affect control flow."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RailResult:
    """One rail's verdict on one piece of text.

    verdict/rail are required (no defaults, so they come first). `text` is set
    only on TRANSFORM. `metadata` uses default_factory, not `= {}`, to avoid the
    shared-mutable-default trap (see design-notes).
    """

    verdict: Verdict
    rail: str
    reason: str = ""
    severity: Severity = Severity.LOW
    text: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class PipelineResult:
    """The outcome of running a whole rail list over one input.

    `final_text` is None when blocked (never the offending string), so a caller
    who forgets to check `blocked` crashes rather than leaks. `results` is the
    full trace in execution order, including ALLOWs.
    """

    blocked: bool
    final_text: str | None
    blocking: "RailResult | None"
    results: list[RailResult] = field(default_factory=list)
