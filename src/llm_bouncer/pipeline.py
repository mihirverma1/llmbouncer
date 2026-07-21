"""Pipeline — runs an ordered list of rails over one piece of text.

This is the object users actually hold::

    pipeline = Pipeline([
        LengthRail(max_len=4000),
        InjectionRail(),
        SecretsRail(redact=True),
    ])

    outcome = pipeline.check(user_input)
    if outcome.blocked:
        return "Sorry, I can't process that."
    send_to_model(outcome.final_text)

The pipeline holds no knowledge of any specific rail. It calls `check()`, reads
`.verdict`, and folds the results together. That is the entire class, and it is
why adding a fourth rail requires changing nothing in this file.

Design source: docs/superpowers/specs/2026-07-20-llm-bouncer-week1-design.md,
section "Pipeline aggregation rule".
"""

from llm_bouncer.result import PipelineResult, Verdict


class Pipeline:
    """An ordered sequence of rails, run until one blocks.

    Order is significant, and it is the caller's most important decision. Two
    rules of thumb:

      - **Cheap before expensive.** `LengthRail` is a single integer comparison;
        `SecretsRail` runs several regexes and an entropy calculation over every
        token. Putting length first means a 5 MB paste is rejected before
        anything scans it.
      - **Transforming rails after the detectors that need the original.** A rail
        that redacts changes the text every later rail sees. If an injection
        pattern happened to live inside the span that got redacted, an
        `InjectionRail` placed afterwards would never see it.

    Args:
        rails: The rails to run, in order. May be empty (everything passes).
        audit: Optional `AuditLogger`. When given, one JSONL line is written per
            check, whatever the outcome.

    Raises:
        TypeError: If any element has no callable `check` method.
    """

    def __init__(self, rails, audit=None) -> None:
        rails = list(rails)

        # Validate the shape here, at construction, rather than discovering it
        # mid-request. Note this is duck typing, deliberately: it asks whether
        # the object *has* a callable `check`, not whether it subclasses `Rail`.
        # Anyone who prefers not to inherit from the base class can still pass a
        # plain object with a matching method, exactly as ADR-001 promises.
        for index, rail in enumerate(rails):
            if not callable(getattr(rail, "check", None)):
                raise TypeError(
                    f"rails[{index}] has no callable check() method: {rail!r}"
                )

        self.rails = rails
        self.audit = audit

    def check(self, text: str, key: str | None = None) -> PipelineResult:
        """Run every rail in order and return the combined outcome.

        The rule, exactly:

          1. `working_text` starts as `text`; `results` starts empty.
          2. For each rail in order, call `rail.check(working_text)` and append
             the result to `results` **regardless of verdict**.
             - BLOCK     -> stop immediately. Nothing after this rail runs.
             - TRANSFORM -> `working_text` becomes `result.text`; continue.
             - ALLOW     -> continue.
          3. If nothing blocked, return the working text — which includes every
             transform applied along the way.

        Two properties worth being explicit about:

        **Short-circuiting is a security property, not an optimisation.** Once
        text is known hostile, running further rails means feeding attacker-
        controlled input into more code — more regexes, more parsing, more
        surface. Stopping is the safe move. It also keeps the audit log honest:
        the trace ends where the decision was made.

        **ALLOW results are still recorded.** The `results` list is the full
        trace, not just the failure. Knowing that length and injection passed
        before secrets blocked is what makes an audit log worth reading, and what
        the Week-3 red-team report diffs against.

        Args:
            text: The input to check.
            key: Optional caller identity — a user id, API key id, or IP. Only
                rails that declare `wants_key = True` receive it; everything else
                is called as `check(text)` exactly as before.

                Most rails judge text alone, but a rate limiter has to know
                *whose* request this is, and that is knowledge only the caller
                has. Rather than widening every rail's signature, or having the
                pipeline introspect each `check` method (magic that breaks on
                decorators and `**kwargs`), a rail opts in with one explicit
                class attribute.

        Returns:
            A `PipelineResult`. When blocked, `final_text` is None — never the
            offending string — so a caller who forgets to check `.blocked` gets a
            loud failure instead of quietly forwarding hostile input.

        Raises:
            ValueError: If a rail returns TRANSFORM without replacement text.
        """
        working_text = text
        results = []

        for rail in self.rails:
            if getattr(rail, "wants_key", False):
                result = rail.check(working_text, key=key)
            else:
                result = rail.check(working_text)
            results.append(result)

            if result.verdict is Verdict.BLOCK:
                return self._finish(
                    text,
                    PipelineResult(
                        blocked=True,
                        final_text=None,
                        blocking=result,
                        results=results,
                    ),
                )

            if result.verdict is Verdict.TRANSFORM:
                # A TRANSFORM with no replacement text is a broken rail, not
                # hostile input, so this raises rather than returning a verdict.
                #
                # The alternative — silently treating it as ALLOW — is genuinely
                # dangerous: a redacting rail whose replacement went missing
                # would report "secret redacted" in the audit log while passing
                # the unredacted secret straight through to the model. Failing
                # loudly is the only safe reading.
                if result.text is None:
                    raise ValueError(
                        f"rail {result.rail!r} returned TRANSFORM with text=None"
                    )
                working_text = result.text

            # ALLOW needs no branch: fall through to the next rail.

        # Every rail passed. `working_text` carries any transforms that were
        # applied, so it may differ from the original `text` — that is the point.
        return self._finish(
            text,
            PipelineResult(
                blocked=False,
                final_text=working_text,
                blocking=None,
                results=results,
            ),
        )

    def _finish(self, original_text: str, outcome: PipelineResult) -> PipelineResult:
        """Write the audit line, then return the outcome.

        Both exit paths funnel through here so that a blocked run is logged
        exactly like an allowed one. Logging only blocks would be the obvious
        shortcut and the wrong one: the ratio of allowed to blocked traffic is
        what tells you whether a rail is too aggressive, and a log containing
        only blocks can never show you a false-positive rate.

        The ORIGINAL text is hashed, not the transformed one. A digest is only
        useful for correlating repeats, and a rewritten string would hash
        differently depending on which rails happened to fire — so the same
        attack would appear as several distinct hashes.
        """
        if self.audit is not None:
            self.audit.log(original_text, outcome)

        return outcome

    def __repr__(self) -> str:
        """Show the rail names, which is what you want when a test fails."""
        names = ", ".join(getattr(r, "name", "?") for r in self.rails)
        return f"<Pipeline [{names}]>"
