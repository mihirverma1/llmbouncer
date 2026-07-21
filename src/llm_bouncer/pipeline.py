"""Pipeline — runs an ordered rail list until one blocks.

See docs/design-notes.md ("pipeline.py") for the aggregation rule, why
short-circuiting is a security property, and the wants_key mechanism.
"""

from llm_bouncer.result import PipelineResult, Verdict


class Pipeline:
    """An ordered sequence of rails, run until one blocks.

    Order matters: cheap rails first, transforming rails after detectors that
    need the original text.

    Args:
        rails: Rails to run, in order. May be empty (everything passes).
        audit: Optional AuditLogger; writes one JSONL line per check.
    Raises:
        TypeError: If any element has no callable `check`.
    """

    def __init__(self, rails, audit=None) -> None:
        rails = list(rails)
        # Duck-typed on purpose (ADR-001): has a callable check, no isinstance.
        for index, rail in enumerate(rails):
            if not callable(getattr(rail, "check", None)):
                raise TypeError(f"rails[{index}] has no callable check() method: {rail!r}")
        self.rails = rails
        self.audit = audit

    def check(self, text: str, key: str | None = None) -> PipelineResult:
        """Run every rail in order, return the combined outcome.

        BLOCK stops immediately (a security property, not an optimisation);
        TRANSFORM swaps the working text; ALLOW continues. `key` is passed only to
        rails that declare `wants_key = True`. Blocked runs return final_text=None.
        """
        working_text = text
        results = []

        try:
            for rail in self.rails:
                if getattr(rail, "wants_key", False):
                    result = rail.check(working_text, key=key)
                else:
                    result = rail.check(working_text)
                results.append(result)

                if result.verdict is Verdict.BLOCK:
                    return self._finish(
                        text,
                        PipelineResult(blocked=True, final_text=None, blocking=result, results=results),
                    )

                if result.verdict is Verdict.TRANSFORM:
                    # A TRANSFORM with no text is a broken rail; failing loudly beats
                    # silently passing an "unredacted but reported redacted" secret.
                    if result.text is None:
                        raise ValueError(f"rail {result.rail!r} returned TRANSFORM with text=None")
                    working_text = result.text
        except Exception as exc:
            # A crashed rail is the one event that must not be invisible in the
            # log: the guardrail didn't run, and nothing else would record that.
            if self.audit is not None:
                self.audit.log(
                    text,
                    PipelineResult(blocked=True, final_text=None, blocking=None, results=results),
                    error=repr(exc),
                )
            raise

        return self._finish(
            text,
            PipelineResult(blocked=False, final_text=working_text, blocking=None, results=results),
        )

    def _finish(self, original_text: str, outcome: PipelineResult) -> PipelineResult:
        # Both exit paths funnel here so allowed runs are logged like blocked
        # ones (the ratio is what reveals an over-aggressive rail). Hash the
        # ORIGINAL text, not the transformed one.
        if self.audit is not None:
            self.audit.log(original_text, outcome)
        return outcome

    def __repr__(self) -> str:
        names = ", ".join(getattr(r, "name", "?") for r in self.rails)
        return f"<Pipeline [{names}]>"
